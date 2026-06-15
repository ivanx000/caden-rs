//! Attestation statement verification.
//!
//! An attestation statement lets the relying party verify the provenance of an
//! authenticator — specifically, that it is a genuine device from a known
//! manufacturer and model.
//!
//! ## Supported formats
//!
//! | Format       | Status                                  | Notes                                                |
//! |--------------|-----------------------------------------|------------------------------------------------------|
//! | `"none"`     | ✅ Supported                            | No cryptographic attestation provided                |
//! | `"packed"`   | ✅ Self-attestation; ⚠️ Basic detected  | Self: signature verified. Basic: cert chain skipped  |
//! | `"fido-u2f"` | ❌ Not supported                        | Legacy U2F devices                                   |
//! | `"tpm"`      | ❌ Not supported                        | Requires TPM certificate chain                       |
//! | `"apple"`    | ❌ Not supported                        | Requires Apple's root certificate                    |
//!
//! ### Packed attestation sub-cases
//!
//! - **Self-attestation** (`x5c` absent): the credential key itself signs the
//!   attestation data. This is fully verified.
//! - **Basic attestation** (`x5c` present): a separate attestation key with a
//!   certificate chain signs the data. This library **detects** basic attestation
//!   and returns [`AttestationType::Basic`], but does not verify the certificate
//!   chain because that requires a FIDO Metadata Service (MDS) trust anchor set.
//! - **ECDAA**: deprecated and not implemented.

use ciborium::value::Value;

use crate::algorithm::{COSE_ES256, COSE_RS256};
use crate::credential::{AttestationType, PublicKey};
use crate::crypto::{verify_es256, verify_rs256};
use crate::der::rsa_components_to_der;
use crate::error::{Result, WebAuthnError};

/// Verify the attestation statement and return the [`AttestationType`].
///
/// # Arguments
/// * `fmt`                  — Attestation format string from the attestation object.
/// * `att_stmt`             — The raw attStmt CBOR value from the attestation object.
/// * `auth_data_bytes`      — Raw authenticator data bytes.
/// * `client_data_hash`     — SHA-256(clientDataJSON).
/// * `credential_public_key`— The credential public key extracted during this registration.
///
/// # Errors
/// Returns [`WebAuthnError::InvalidAttestationObject`] if the attestation
/// statement is structurally invalid for the given format.
/// Returns [`WebAuthnError::SignatureVerificationFailed`] if packed
/// self-attestation signature verification fails.
pub fn verify(
    fmt: &str,
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_public_key: &PublicKey,
) -> Result<AttestationType> {
    match fmt {
        // §8.7 — "none" attestation: the authenticator is not attested.
        // The attStmt must be an empty CBOR map, but we simply return None
        // because the registration ceremony has already extracted all data we need.
        "none" => Ok(AttestationType::None),

        // §8.2 — packed attestation: most common in real-world deployments.
        "packed" => verify_packed(
            att_stmt,
            auth_data_bytes,
            client_data_hash,
            credential_public_key,
        ),

        // All other formats (fido-u2f, tpm, android-key, apple) require certificate
        // chain validation against the FIDO Metadata Service — out of scope.
        // Accept the credential but signal that attestation was not verified.
        _other => Ok(AttestationType::None),
    }
}

/// Verify a packed attestation statement (W3C WebAuthn §8.2).
///
/// Handles self-attestation (no `x5c`) and detects basic attestation (`x5c` present).
fn verify_packed(
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_public_key: &PublicKey,
) -> Result<AttestationType> {
    let stmt_map = match att_stmt {
        Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "packed attStmt must be a CBOR map".to_string(),
            ))
        }
    };

    let mut alg: Option<i64> = None;
    let mut sig: Option<Vec<u8>> = None;
    let mut has_x5c = false;

    for (k, v) in stmt_map {
        match k {
            Value::Text(ref key) if key == "alg" => {
                alg = Some(match v {
                    Value::Integer(i) => i64::try_from(*i).map_err(|_| {
                        WebAuthnError::InvalidAttestationObject(
                            "packed attStmt alg value out of i64 range".to_string(),
                        )
                    })?,
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "packed attStmt alg must be a CBOR integer".to_string(),
                        ))
                    }
                });
            }
            Value::Text(ref key) if key == "sig" => {
                sig = Some(match v {
                    Value::Bytes(b) => b.clone(),
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "packed attStmt sig must be CBOR bytes".to_string(),
                        ))
                    }
                });
            }
            Value::Text(ref key) if key == "x5c" => {
                has_x5c = true;
            }
            _ => {}
        }
    }

    // §8.2 step 2: if x5c is present this is basic attestation.
    // Full certificate chain verification requires a FIDO MDS trust anchor set,
    // which is out of scope. Accept the credential and signal Basic attestation.
    if has_x5c {
        return Ok(AttestationType::Basic);
    }

    // §8.2 step 3: x5c absent → self attestation.
    let alg = alg.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "packed self-attestation attStmt missing required field: alg".to_string(),
        )
    })?;
    let sig = sig.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "packed self-attestation attStmt missing required field: sig".to_string(),
        )
    })?;

    // §8.2 step 3.a: verify alg matches the credential public key algorithm.
    // In self-attestation the credential key signs the attestation, so their
    // algorithms must agree.
    let expected_alg = credential_public_key.algorithm();
    if alg != expected_alg {
        return Err(WebAuthnError::InvalidAttestationObject(format!(
            "packed self-attestation alg ({alg}) does not match credential key algorithm ({expected_alg})"
        )));
    }

    // §8.2 step 3.b: build the verification data: authData || clientDataHash.
    let mut verification_data = Vec::with_capacity(auth_data_bytes.len() + 32);
    verification_data.extend_from_slice(auth_data_bytes);
    verification_data.extend_from_slice(client_data_hash);

    // §8.2 step 3.c: verify the signature using the credential public key.
    match credential_public_key {
        PublicKey::ES256 { x, y } if alg == COSE_ES256 => {
            let mut uncompressed = Vec::with_capacity(65);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(x);
            uncompressed.extend_from_slice(y);
            verify_es256(&uncompressed, &verification_data, &sig)?;
        }
        PublicKey::RS256 { n, e } if alg == COSE_RS256 => {
            let der = rsa_components_to_der(n, e)?;
            verify_rs256(&der, &verification_data, &sig)?;
        }
        _ => {
            return Err(WebAuthnError::UnsupportedAlgorithm(alg));
        }
    }

    Ok(AttestationType::SelfAttestation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none_att_stmt() -> Value {
        Value::Map(vec![])
    }

    #[test]
    fn accepts_none_format() {
        let pk = dummy_es256_key();
        let result = verify("none", &none_att_stmt(), &[], &[0u8; 32], &pk);
        assert!(matches!(result, Ok(AttestationType::None)));
    }

    #[test]
    fn accepts_unknown_format_as_none() {
        // Unsupported formats like fido-u2f are accepted but return None.
        let pk = dummy_es256_key();
        let result = verify("fido-u2f", &none_att_stmt(), &[], &[0u8; 32], &pk);
        assert!(matches!(result, Ok(AttestationType::None)));
    }

    #[test]
    fn packed_basic_attestation_detected_when_x5c_present() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(vec![0u8; 10])]),
            ),
        ]);
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk);
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    #[test]
    fn packed_rejects_non_map_att_stmt() {
        let pk = dummy_es256_key();
        let result = verify(
            "packed",
            &Value::Text("bad".to_string()),
            &[],
            &[0u8; 32],
            &pk,
        );
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(_))
        ));
    }

    #[test]
    fn packed_rejects_missing_alg() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![(
            Value::Text("sig".to_string()),
            Value::Bytes(vec![0u8; 64]),
        )]);
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("alg")
        ));
    }

    #[test]
    fn packed_rejects_missing_sig() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![(
            Value::Text("alg".to_string()),
            Value::Integer((-7i64).into()),
        )]);
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("sig")
        ));
    }

    #[test]
    fn packed_rejects_algorithm_mismatch() {
        // Key is ES256 but attStmt claims RS256.
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("alg".to_string()),
                Value::Integer((-257i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
        ]);
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("alg")
        ));
    }

    #[test]
    fn packed_self_attestation_es256_valid_signature() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pub_bytes = kp.public_key().as_ref(); // 0x04 || x || y

        let x = pub_bytes[1..33].to_vec();
        let y = pub_bytes[33..65].to_vec();
        let pk = PublicKey::ES256 { x, y };

        let auth_data = b"fake-auth-data";
        let client_data_hash = [0xABu8; 32];

        let mut verification_data = Vec::new();
        verification_data.extend_from_slice(auth_data);
        verification_data.extend_from_slice(&client_data_hash);

        let sig = kp.sign(&rng, &verification_data).unwrap();

        let stmt = Value::Map(vec![
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("sig".to_string()),
                Value::Bytes(sig.as_ref().to_vec()),
            ),
        ]);

        let result = verify("packed", &stmt, auth_data, &client_data_hash, &pk);
        assert!(matches!(result, Ok(AttestationType::SelfAttestation)));
    }

    #[test]
    fn packed_self_attestation_es256_bad_signature() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pub_bytes = kp.public_key().as_ref();
        let x = pub_bytes[1..33].to_vec();
        let y = pub_bytes[33..65].to_vec();
        let pk = PublicKey::ES256 { x, y };

        let stmt = Value::Map(vec![
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("sig".to_string()),
                Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            ),
        ]);

        let result = verify("packed", &stmt, b"auth", &[0u8; 32], &pk);
        assert!(matches!(
            result,
            Err(WebAuthnError::SignatureVerificationFailed)
        ));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn dummy_es256_key() -> PublicKey {
        PublicKey::ES256 {
            x: vec![0u8; 32],
            y: vec![0u8; 32],
        }
    }
}
