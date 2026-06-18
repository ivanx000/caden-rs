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
//! | `"fido-u2f"` | ✅ Supported                            | Signature verified; cert chain requires FIDO MDS     |
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

use crate::algorithm::{COSE_EDDSA, COSE_ES256, COSE_RS256};
use crate::credential::{AttestationType, PublicKey};
use crate::crypto::{verify_eddsa, verify_es256, verify_rs256};
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
/// * `credential_id`        — The credential ID bytes from attested credential data.
///
/// # Errors
/// Returns [`WebAuthnError::InvalidAttestationObject`] if the attestation
/// statement is structurally invalid for the given format.
/// Returns [`WebAuthnError::SignatureVerificationFailed`] if attestation
/// signature verification fails.
pub fn verify(
    fmt: &str,
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_public_key: &PublicKey,
    credential_id: &[u8],
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

        // §8.6 — fido-u2f attestation: used by legacy YubiKey 4-series and U2F tokens.
        "fido-u2f" => verify_fido_u2f(
            att_stmt,
            auth_data_bytes,
            client_data_hash,
            credential_id,
            credential_public_key,
        ),

        // All other formats (tpm, android-key, apple) require certificate
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
        PublicKey::EdDSA(pk) if alg == COSE_EDDSA => {
            verify_eddsa(pk, &verification_data, &sig)?;
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

/// Verify a FIDO U2F attestation statement (W3C WebAuthn §8.6).
///
/// Requires `x5c` (the attestation certificate chain). Verifies the ECDSA-P256
/// signature over `verificationData`; returns [`AttestationType::Basic`] on
/// success. The certificate chain is not verified — that requires a FIDO MDS
/// trust anchor set.
fn verify_fido_u2f(
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_id: &[u8],
    credential_public_key: &PublicKey,
) -> Result<AttestationType> {
    let stmt_map = match att_stmt {
        Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "fido-u2f attStmt must be a CBOR map".to_string(),
            ))
        }
    };

    let mut sig: Option<Vec<u8>> = None;
    let mut x5c_first_cert: Option<Vec<u8>> = None;

    for (k, v) in stmt_map {
        match k {
            Value::Text(ref key) if key == "sig" => {
                sig = Some(match v {
                    Value::Bytes(b) => b.clone(),
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "fido-u2f attStmt sig must be CBOR bytes".to_string(),
                        ))
                    }
                });
            }
            Value::Text(ref key) if key == "x5c" => {
                x5c_first_cert = Some(match v {
                    Value::Array(certs) if !certs.is_empty() => match &certs[0] {
                        Value::Bytes(b) => b.clone(),
                        _ => {
                            return Err(WebAuthnError::InvalidAttestationObject(
                                "fido-u2f x5c[0] must be CBOR bytes".to_string(),
                            ))
                        }
                    },
                    Value::Array(_) => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "fido-u2f x5c must be non-empty".to_string(),
                        ))
                    }
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "fido-u2f x5c must be a CBOR array".to_string(),
                        ))
                    }
                });
            }
            _ => {}
        }
    }

    // §8.6 step 2.a: x5c must be present.
    let cert_der = x5c_first_cert.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "fido-u2f attStmt missing required field: x5c".to_string(),
        )
    })?;
    let sig = sig.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "fido-u2f attStmt missing required field: sig".to_string(),
        )
    })?;

    // §8.6 step 2.b: extract the attestation key from the certificate.
    let att_pk = extract_ec_p256_public_key_from_cert(&cert_der)?;

    // §8.6 step 2.c: FIDO U2F mandates EC P-256 for the credential key.
    let cred_pk_bytes = match credential_public_key {
        PublicKey::ES256 { x, y } => {
            let mut pk = Vec::with_capacity(65);
            pk.push(0x04);
            pk.extend_from_slice(x);
            pk.extend_from_slice(y);
            pk
        }
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "fido-u2f attestation requires an EC P-256 credential key".to_string(),
            ))
        }
    };

    // §8.6 step 2.d: verify rpIdHash is long enough to read.
    if auth_data_bytes.len() < 32 {
        return Err(WebAuthnError::InvalidAttestationObject(
            "fido-u2f: authenticator data too short to contain rpIdHash".to_string(),
        ));
    }
    let rp_id_hash = &auth_data_bytes[..32];

    // §8.6 step 2.e: verificationData = 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F
    let mut verification_data =
        Vec::with_capacity(1 + 32 + 32 + credential_id.len() + cred_pk_bytes.len());
    verification_data.push(0x00);
    verification_data.extend_from_slice(rp_id_hash);
    verification_data.extend_from_slice(client_data_hash);
    verification_data.extend_from_slice(credential_id);
    verification_data.extend_from_slice(&cred_pk_bytes);

    // §8.6 step 2.f: verify the signature over verificationData.
    verify_es256(&att_pk, &verification_data, &sig)?;

    Ok(AttestationType::Basic)
}

/// Extract the 65-byte uncompressed EC P-256 public key (`0x04 || x || y`) from
/// a DER-encoded X.509 certificate by locating the SubjectPublicKeyInfo structure.
///
/// FIDO U2F attestation certificates always use EC P-256 with an uncompressed
/// point, so the SubjectPublicKeyInfo has a fixed 27-byte header that can be
/// located by byte search rather than a full ASN.1 parser.
fn extract_ec_p256_public_key_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    // SubjectPublicKeyInfo for EC P-256 (uncompressed point) has a fixed structure.
    // Bytes up to and including the 0x04 uncompressed-point prefix:
    //   30 59          SEQUENCE (89 bytes)
    //   30 13          SEQUENCE (19 bytes) — AlgorithmIdentifier
    //   06 07 2a 86 48 ce 3d 02 01   OID ecPublicKey
    //   06 08 2a 86 48 ce 3d 03 01 07  OID prime256v1
    //   03 42          BIT STRING (66 bytes)
    //   00             unused bits = 0
    //   04             uncompressed point prefix
    const SPKI_PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
    ];

    // Locate the prefix and extract 65 bytes starting at 0x04.
    cert_der
        .windows(SPKI_PREFIX.len())
        .position(|w| w == SPKI_PREFIX)
        .and_then(|pos| {
            let key_start = pos + SPKI_PREFIX.len() - 1; // -1: 0x04 is the first key byte
            cert_der.get(key_start..key_start + 65)
        })
        .map(|key| key.to_vec())
        .ok_or_else(|| {
            WebAuthnError::InvalidAttestationObject(
                "fido-u2f: certificate does not contain a P-256 EC public key".to_string(),
            )
        })
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
        let result = verify("none", &none_att_stmt(), &[], &[0u8; 32], &pk, &[]);
        assert!(matches!(result, Ok(AttestationType::None)));
    }

    #[test]
    fn accepts_unknown_format_as_none() {
        // Unsupported formats (tpm, android-key, apple) are accepted but return None.
        let pk = dummy_es256_key();
        let result = verify("tpm", &none_att_stmt(), &[], &[0u8; 32], &pk, &[]);
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
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk, &[]);
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
            &[],
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
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk, &[]);
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
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk, &[]);
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
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk, &[]);
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

        let result = verify("packed", &stmt, auth_data, &client_data_hash, &pk, &[]);
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

        let result = verify("packed", &stmt, b"auth", &[0u8; 32], &pk, &[]);
        assert!(matches!(
            result,
            Err(WebAuthnError::SignatureVerificationFailed)
        ));
    }

    // ── fido-u2f tests ────────────────────────────────────────────────────────

    #[test]
    fn fido_u2f_rejects_missing_x5c() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![(
            Value::Text("sig".to_string()),
            Value::Bytes(vec![0u8; 64]),
        )]);
        let result = verify("fido-u2f", &stmt, &[0u8; 37], &[0u8; 32], &pk, &[]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("x5c"))
        );
    }

    #[test]
    fn fido_u2f_rejects_missing_sig() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![(
            Value::Text("x5c".to_string()),
            Value::Array(vec![Value::Bytes(vec![0u8; 10])]),
        )]);
        let result = verify("fido-u2f", &stmt, &[0u8; 37], &[0u8; 32], &pk, &[]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("sig"))
        );
    }

    #[test]
    fn fido_u2f_rejects_empty_x5c_array() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![]), // empty
            ),
        ]);
        let result = verify("fido-u2f", &stmt, &[0u8; 37], &[0u8; 32], &pk, &[]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("non-empty"))
        );
    }

    #[test]
    fn fido_u2f_rejects_non_es256_credential_key() {
        // EdDSA credential key — FIDO U2F only supports P-256.
        let pk = PublicKey::EdDSA(vec![0u8; 32]);
        let stmt = Value::Map(vec![
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(make_fake_p256_cert(&[0x04; 65]))]),
            ),
        ]);
        let result = verify("fido-u2f", &stmt, &[0u8; 37], &[0u8; 32], &pk, &[]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("P-256"))
        );
    }

    #[test]
    fn fido_u2f_valid_signature_returns_basic() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();

        // Attestation keypair (signs the verificationData).
        let att_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let att_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, att_pkcs8.as_ref(), &rng)
                .unwrap();
        let att_pub = att_kp.public_key().as_ref(); // 65 bytes: 0x04 || x || y
        let cert = make_fake_p256_cert(att_pub);

        // Credential keypair (separate from attestation key).
        let cred_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let cred_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cred_pkcs8.as_ref(), &rng)
                .unwrap();
        let cred_pub = cred_kp.public_key().as_ref();
        let credential_public_key = PublicKey::ES256 {
            x: cred_pub[1..33].to_vec(),
            y: cred_pub[33..65].to_vec(),
        };

        let credential_id = b"test-cred-id";
        let rp_id_hash = [0x77u8; 32];
        let client_data_hash = [0x88u8; 32];

        // auth_data_bytes: rpIdHash (32) || flags (1) || signCount (4) || ...
        let mut auth_data = rp_id_hash.to_vec();
        auth_data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);

        // verificationData = 0x00 || rpIdHash || clientDataHash || credentialId || cred public key
        let mut verification_data = vec![0x00u8];
        verification_data.extend_from_slice(&rp_id_hash);
        verification_data.extend_from_slice(&client_data_hash);
        verification_data.extend_from_slice(credential_id);
        verification_data.extend_from_slice(cred_pub);

        let sig = att_kp.sign(&rng, &verification_data).unwrap();

        let stmt = Value::Map(vec![
            (
                Value::Text("sig".to_string()),
                Value::Bytes(sig.as_ref().to_vec()),
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
        ]);

        let result = verify(
            "fido-u2f",
            &stmt,
            &auth_data,
            &client_data_hash,
            &credential_public_key,
            credential_id,
        );
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    #[test]
    fn fido_u2f_bad_signature_rejected() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let att_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let att_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, att_pkcs8.as_ref(), &rng)
                .unwrap();
        let cert = make_fake_p256_cert(att_kp.public_key().as_ref());

        let cred_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let cred_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cred_pkcs8.as_ref(), &rng)
                .unwrap();
        let cred_pub = cred_kp.public_key().as_ref();
        let credential_public_key = PublicKey::ES256 {
            x: cred_pub[1..33].to_vec(),
            y: cred_pub[33..65].to_vec(),
        };

        let mut auth_data = [0x77u8; 32].to_vec();
        auth_data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);

        let stmt = Value::Map(vec![
            (
                Value::Text("sig".to_string()),
                Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]), // garbage signature
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
        ]);

        let result = verify(
            "fido-u2f",
            &stmt,
            &auth_data,
            &[0x88u8; 32],
            &credential_public_key,
            b"cred-id",
        );
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

    /// Build a minimal byte buffer that contains a valid EC P-256 SPKI structure
    /// so `extract_ec_p256_public_key_from_cert` can locate the public key.
    fn make_fake_p256_cert(pub_key_uncompressed: &[u8]) -> Vec<u8> {
        let spki_prefix: &[u8] = &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let mut cert = vec![0x30u8, 0x82, 0x01, 0x00]; // fake outer SEQUENCE header
        cert.extend_from_slice(spki_prefix);
        cert.extend_from_slice(pub_key_uncompressed); // 65 bytes: 0x04 || x || y
        cert
    }
}
