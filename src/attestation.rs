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
//! | `"none"`          | ✅ Supported                            | No cryptographic attestation provided                    |
//! | `"packed"`        | ✅ Self-attestation; ⚠️ Basic detected  | Self: signature verified. Basic: cert chain skipped      |
//! | `"fido-u2f"`      | ✅ Supported                            | Signature verified; cert chain requires FIDO MDS         |
//! | `"android-key"`   | ✅ Supported                            | Signature + key-match verified; cert chain skipped       |
//! | `"tpm"`           | ❌ Not supported                        | Requires TPM certificate chain                           |
//! | `"apple"`         | ✅ Supported                            | Nonce + key-match verified; cert chain requires Apple MDS |
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

        // §8.4 — android-key attestation: Android Keystore-backed authenticators.
        "android-key" => verify_android_key(
            att_stmt,
            auth_data_bytes,
            client_data_hash,
            credential_public_key,
        ),

        // §8.8 — apple attestation: Face ID and Touch ID passkeys.
        "apple" => verify_apple(
            att_stmt,
            auth_data_bytes,
            client_data_hash,
            credential_public_key,
        ),

        // All other formats (tpm) require certificate chain validation against
        // the FIDO Metadata Service — out of scope.
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

/// Verify an Android Key attestation statement (W3C WebAuthn §8.4).
///
/// Requires `alg`, `sig`, and `x5c` in the attStmt. The attestation cert's
/// public key must equal the credential's public key (the key security property
/// of Android Key attestation: the Android Keystore proves the credential key
/// was generated inside a hardware-backed secure element). Verifies the
/// ECDSA-P256 signature over `authData || clientDataHash`; returns
/// [`AttestationType::Basic`] on success. The certificate chain is not verified
/// — that requires a FIDO MDS trust anchor set.
fn verify_android_key(
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_public_key: &PublicKey,
) -> Result<AttestationType> {
    let stmt_map = match att_stmt {
        Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "android-key attStmt must be a CBOR map".to_string(),
            ))
        }
    };

    let mut alg: Option<i64> = None;
    let mut sig: Option<Vec<u8>> = None;
    let mut x5c_first_cert: Option<Vec<u8>> = None;

    for (k, v) in stmt_map {
        match k {
            Value::Text(ref key) if key == "alg" => {
                alg = Some(match v {
                    Value::Integer(i) => i64::try_from(*i).map_err(|_| {
                        WebAuthnError::InvalidAttestationObject(
                            "android-key attStmt alg value out of i64 range".to_string(),
                        )
                    })?,
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "android-key attStmt alg must be a CBOR integer".to_string(),
                        ))
                    }
                });
            }
            Value::Text(ref key) if key == "sig" => {
                sig = Some(match v {
                    Value::Bytes(b) => b.clone(),
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "android-key attStmt sig must be CBOR bytes".to_string(),
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
                                "android-key x5c[0] must be CBOR bytes".to_string(),
                            ))
                        }
                    },
                    Value::Array(_) => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "android-key x5c must be non-empty".to_string(),
                        ))
                    }
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "android-key x5c must be a CBOR array".to_string(),
                        ))
                    }
                });
            }
            _ => {}
        }
    }

    // §8.4 step 1: all three fields are required.
    alg.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "android-key attStmt missing required field: alg".to_string(),
        )
    })?;
    let sig = sig.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "android-key attStmt missing required field: sig".to_string(),
        )
    })?;
    let cert_der = x5c_first_cert.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "android-key attStmt missing required field: x5c".to_string(),
        )
    })?;

    // §8.4 step 2: extract the EC P-256 public key from the attestation certificate.
    let att_pk = extract_ec_p256_public_key_from_cert(&cert_der)?;

    // §8.4 step 3: the credential public key must be ES256 and must match the
    // attestation certificate's public key byte-for-byte. This is the defining
    // security property of Android Key attestation — the Keystore proves the
    // credential key lives in a hardware-backed secure element.
    let cred_pk_uncompressed = match credential_public_key {
        PublicKey::ES256 { x, y } => {
            let mut pk = Vec::with_capacity(65);
            pk.push(0x04);
            pk.extend_from_slice(x);
            pk.extend_from_slice(y);
            pk
        }
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "android-key: attestation requires an ES256 (P-256) credential key".to_string(),
            ))
        }
    };

    if att_pk != cred_pk_uncompressed {
        return Err(WebAuthnError::InvalidAttestationObject(
            "android-key: credential public key does not match attestation certificate key"
                .to_string(),
        ));
    }

    // §8.4 step 4: build the verification data: authData || clientDataHash.
    let mut verification_data = Vec::with_capacity(auth_data_bytes.len() + 32);
    verification_data.extend_from_slice(auth_data_bytes);
    verification_data.extend_from_slice(client_data_hash);

    // §8.4 step 5: verify the ECDSA-P256 signature over verification_data.
    verify_es256(&att_pk, &verification_data, &sig)?;

    Ok(AttestationType::Basic)
}

/// Verify an Apple attestation statement (W3C WebAuthn §8.8).
///
/// Requires `x5c` in the attStmt. Verifies that:
/// 1. The credential certificate (x5c[0]) contains an Apple nonce extension
///    (OID 1.2.840.113635.100.8.2) whose value equals SHA-256(authData || clientDataHash).
/// 2. The credential certificate's EC P-256 public key equals the registered credential key.
///
/// Returns [`AttestationType::Basic`] on success. The certificate chain is not
/// verified — that requires Apple's root certificate and FIDO MDS integration.
fn verify_apple(
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_public_key: &PublicKey,
) -> Result<AttestationType> {
    let stmt_map = match att_stmt {
        Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "apple attStmt must be a CBOR map".to_string(),
            ))
        }
    };

    let mut x5c_first_cert: Option<Vec<u8>> = None;

    for (k, v) in stmt_map {
        if let Value::Text(ref key) = k {
            if key == "x5c" {
                x5c_first_cert = Some(match v {
                    Value::Array(certs) if !certs.is_empty() => match &certs[0] {
                        Value::Bytes(b) => b.clone(),
                        _ => {
                            return Err(WebAuthnError::InvalidAttestationObject(
                                "apple x5c[0] must be CBOR bytes".to_string(),
                            ))
                        }
                    },
                    Value::Array(_) => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "apple x5c must be non-empty".to_string(),
                        ))
                    }
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "apple x5c must be a CBOR array".to_string(),
                        ))
                    }
                });
            }
        }
    }

    // §8.8 step 1: x5c must be present.
    let cert_der = x5c_first_cert.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "apple attStmt missing required field: x5c".to_string(),
        )
    })?;

    // §8.8 step 2: expected nonce = SHA-256(authData || clientDataHash).
    let mut nonce_input = Vec::with_capacity(auth_data_bytes.len() + 32);
    nonce_input.extend_from_slice(auth_data_bytes);
    nonce_input.extend_from_slice(client_data_hash);
    let expected_nonce = crate::crypto::sha256(&nonce_input);

    // §8.8 step 3: extract the nonce from the Apple attestation OID extension.
    let cert_nonce = extract_apple_nonce_from_cert(&cert_der)?;

    // §8.8 step 4: nonce in the cert must equal the expected nonce.
    if cert_nonce != expected_nonce {
        return Err(WebAuthnError::InvalidAttestationObject(
            "apple: certificate nonce does not match SHA-256(authData || clientDataHash)"
                .to_string(),
        ));
    }

    // §8.8 step 5: the cert's public key must equal the registered credential key.
    // This proves the authenticator holds the private key.
    let cert_pk = extract_ec_p256_public_key_from_cert(&cert_der)?;
    let cred_pk_uncompressed = match credential_public_key {
        PublicKey::ES256 { x, y } => {
            let mut pk = Vec::with_capacity(65);
            pk.push(0x04);
            pk.extend_from_slice(x);
            pk.extend_from_slice(y);
            pk
        }
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "apple: attestation requires an ES256 (P-256) credential key".to_string(),
            ))
        }
    };

    if cert_pk != cred_pk_uncompressed {
        return Err(WebAuthnError::InvalidAttestationObject(
            "apple: credential public key does not match attestation certificate key".to_string(),
        ));
    }

    Ok(AttestationType::Basic)
}

/// Extract the 32-byte nonce from the Apple attestation OID extension
/// (OID 1.2.840.113635.100.8.2) in a DER-encoded X.509 certificate.
///
/// The extension value structure (after the extnValue OCTET STRING wrapper) is:
/// ```text
/// SEQUENCE {
///   SEQUENCE {
///     OCTET STRING <32 bytes — SHA-256(authData || clientDataHash)>
///   }
/// }
/// ```
fn extract_apple_nonce_from_cert(cert_der: &[u8]) -> Result<[u8; 32]> {
    // DER encoding of OID 1.2.840.113635.100.8.2
    const APPLE_NONCE_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02,
    ];

    let oid_pos = cert_der
        .windows(APPLE_NONCE_OID.len())
        .position(|w| w == APPLE_NONCE_OID)
        .ok_or_else(|| {
            WebAuthnError::InvalidAttestationObject(
                "apple: credential certificate missing Apple nonce extension \
                 (OID 1.2.840.113635.100.8.2)"
                    .to_string(),
            )
        })?;

    let after_oid = &cert_der[oid_pos + APPLE_NONCE_OID.len()..];

    // Skip the optional criticality flag (tag 0x01 = BOOLEAN).
    let ext_value_bytes = if after_oid.first() == Some(&0x01) {
        // BOOLEAN TLV: 01 01 [value] — always 3 bytes.
        after_oid.get(3..).unwrap_or(&[])
    } else {
        after_oid
    };

    // Parse extnValue: OCTET STRING wrapping the extension content.
    let ext_content = der_unwrap_octet_string(ext_value_bytes).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "apple: failed to parse extension extnValue OCTET STRING".to_string(),
        )
    })?;

    // SEQUENCE { SEQUENCE { OCTET STRING <32 bytes> } }
    let outer_seq = der_unwrap_sequence(ext_content).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "apple: failed to parse extension value outer SEQUENCE".to_string(),
        )
    })?;

    let inner_seq = der_unwrap_sequence(outer_seq).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "apple: failed to parse extension value inner SEQUENCE".to_string(),
        )
    })?;

    let nonce_bytes = der_unwrap_octet_string(inner_seq).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "apple: failed to parse nonce OCTET STRING in extension".to_string(),
        )
    })?;

    if nonce_bytes.len() != 32 {
        return Err(WebAuthnError::InvalidAttestationObject(format!(
            "apple: extension nonce must be 32 bytes, got {}",
            nonce_bytes.len()
        )));
    }

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(nonce_bytes);
    Ok(nonce)
}

/// Parse one DER TLV element. Returns `(tag, value, remaining)` or `None` if
/// the slice is too short.
fn der_parse_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    if data.len() < 2 {
        return None;
    }
    let (len, header_len) = if data[1] & 0x80 == 0 {
        (data[1] as usize, 2)
    } else {
        let num_bytes = (data[1] & 0x7f) as usize;
        if num_bytes == 0 || data.len() < 2 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for &b in &data[2..2 + num_bytes] {
            len = (len << 8) | b as usize;
        }
        (len, 2 + num_bytes)
    };
    let end = header_len.checked_add(len)?;
    if data.len() < end {
        return None;
    }
    Some((tag, &data[header_len..end], &data[end..]))
}

/// Unwrap a DER SEQUENCE (tag `0x30`), returning its contents.
fn der_unwrap_sequence(data: &[u8]) -> Option<&[u8]> {
    let (tag, contents, _) = der_parse_tlv(data)?;
    if tag == 0x30 {
        Some(contents)
    } else {
        None
    }
}

/// Unwrap a DER OCTET STRING (tag `0x04`), returning its contents.
fn der_unwrap_octet_string(data: &[u8]) -> Option<&[u8]> {
    let (tag, contents, _) = der_parse_tlv(data)?;
    if tag == 0x04 {
        Some(contents)
    } else {
        None
    }
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
        // Unsupported formats (tpm, apple) are accepted but return None.
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

    // ── android-key tests ────────────────────────────────────────────────────

    #[test]
    fn android_key_valid_signature_returns_basic() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();

        // In android-key, the attestation cert key == the credential key.
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pub_bytes = kp.public_key().as_ref(); // 65 bytes: 0x04 || x || y
        let cert = make_fake_p256_cert(pub_bytes);

        let credential_public_key = PublicKey::ES256 {
            x: pub_bytes[1..33].to_vec(),
            y: pub_bytes[33..65].to_vec(),
        };

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
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
        ]);

        let result = verify(
            "android-key",
            &stmt,
            auth_data,
            &client_data_hash,
            &credential_public_key,
            &[],
        );
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    #[test]
    fn android_key_bad_signature_rejected() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pub_bytes = kp.public_key().as_ref();
        let cert = make_fake_p256_cert(pub_bytes);

        let credential_public_key = PublicKey::ES256 {
            x: pub_bytes[1..33].to_vec(),
            y: pub_bytes[33..65].to_vec(),
        };

        let stmt = Value::Map(vec![
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("sig".to_string()),
                Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]), // garbage
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
        ]);

        let result = verify(
            "android-key",
            &stmt,
            b"auth-data",
            &[0u8; 32],
            &credential_public_key,
            &[],
        );
        assert!(matches!(
            result,
            Err(WebAuthnError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn android_key_rejects_missing_x5c() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
        ]);
        let result = verify("android-key", &stmt, &[], &[0u8; 32], &pk, &[]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("x5c"))
        );
    }

    #[test]
    fn android_key_rejects_missing_sig() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(make_fake_p256_cert(&[0x04; 65]))]),
            ),
        ]);
        let result = verify("android-key", &stmt, &[], &[0u8; 32], &pk, &[]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("sig"))
        );
    }

    #[test]
    fn android_key_rejects_key_mismatch() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();

        // Cert key and credential key are two different keypairs — mismatch.
        let cert_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let cert_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cert_pkcs8.as_ref(), &rng)
                .unwrap();
        let cert = make_fake_p256_cert(cert_kp.public_key().as_ref());

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

        let stmt = Value::Map(vec![
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
        ]);

        let result = verify(
            "android-key",
            &stmt,
            &[],
            &[0u8; 32],
            &credential_public_key,
            &[],
        );
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("does not match"))
        );
    }

    #[test]
    fn android_key_rejects_non_es256_credential_key() {
        // EdDSA credential key — android-key only supports P-256.
        let pk = PublicKey::EdDSA(vec![0u8; 32]);
        let stmt = Value::Map(vec![
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(make_fake_p256_cert(&[0x04; 65]))]),
            ),
        ]);
        let result = verify("android-key", &stmt, &[], &[0u8; 32], &pk, &[]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("ES256"))
        );
    }

    // ── apple tests ──────────────────────────────────────────────────────────

    #[test]
    fn apple_rejects_missing_x5c() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![]);
        let result = verify("apple", &stmt, &[], &[0u8; 32], &pk, &[]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("x5c"))
        );
    }

    #[test]
    fn apple_rejects_empty_x5c() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![(Value::Text("x5c".to_string()), Value::Array(vec![]))]);
        let result = verify("apple", &stmt, &[], &[0u8; 32], &pk, &[]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("non-empty"))
        );
    }

    #[test]
    fn apple_rejects_nonce_mismatch() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pub_bytes = kp.public_key().as_ref();
        let credential_public_key = PublicKey::ES256 {
            x: pub_bytes[1..33].to_vec(),
            y: pub_bytes[33..65].to_vec(),
        };

        // Cert contains the wrong nonce (all zeros instead of the expected hash).
        let wrong_nonce = [0u8; 32];
        let cert = make_fake_apple_cert(pub_bytes, &wrong_nonce);

        let stmt = Value::Map(vec![(
            Value::Text("x5c".to_string()),
            Value::Array(vec![Value::Bytes(cert)]),
        )]);

        // auth_data and client_data_hash that produce a different nonce.
        let result = verify(
            "apple",
            &stmt,
            b"auth-data",
            &[0xABu8; 32],
            &credential_public_key,
            &[],
        );
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("nonce"))
        );
    }

    #[test]
    fn apple_rejects_key_mismatch() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();

        // Cert key and credential key are two different keypairs.
        let cert_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let cert_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cert_pkcs8.as_ref(), &rng)
                .unwrap();
        let cert_pub = cert_kp.public_key().as_ref();

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

        let auth_data = b"auth-data";
        let client_data_hash = [0xABu8; 32];

        // Compute the correct nonce so the nonce check passes.
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(auth_data);
        nonce_input.extend_from_slice(&client_data_hash);
        let nonce = crate::crypto::sha256(&nonce_input);

        // Cert uses cert_pub (not the credential key) with the correct nonce.
        let cert = make_fake_apple_cert(cert_pub, &nonce);

        let stmt = Value::Map(vec![(
            Value::Text("x5c".to_string()),
            Value::Array(vec![Value::Bytes(cert)]),
        )]);

        let result = verify(
            "apple",
            &stmt,
            auth_data,
            &client_data_hash,
            &credential_public_key,
            &[],
        );
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("does not match"))
        );
    }

    #[test]
    fn apple_valid_returns_basic() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pub_bytes = kp.public_key().as_ref(); // 65 bytes: 0x04 || x || y
        let credential_public_key = PublicKey::ES256 {
            x: pub_bytes[1..33].to_vec(),
            y: pub_bytes[33..65].to_vec(),
        };

        let auth_data = b"fake-auth-data";
        let client_data_hash = [0xABu8; 32];

        // Compute nonce = SHA-256(authData || clientDataHash)
        let mut nonce_input = Vec::new();
        nonce_input.extend_from_slice(auth_data);
        nonce_input.extend_from_slice(&client_data_hash);
        let nonce = crate::crypto::sha256(&nonce_input);

        let cert = make_fake_apple_cert(pub_bytes, &nonce);

        let stmt = Value::Map(vec![(
            Value::Text("x5c".to_string()),
            Value::Array(vec![Value::Bytes(cert)]),
        )]);

        let result = verify(
            "apple",
            &stmt,
            auth_data,
            &client_data_hash,
            &credential_public_key,
            &[],
        );
        assert!(matches!(result, Ok(AttestationType::Basic)));
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

    /// Build a minimal byte buffer containing both the EC P-256 SPKI and the
    /// Apple nonce extension (OID 1.2.840.113635.100.8.2) so Apple attestation
    /// unit tests can exercise the full verify_apple() path.
    fn make_fake_apple_cert(pub_key_uncompressed: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
        let spki_prefix: &[u8] = &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        // DER encoding of OID 1.2.840.113635.100.8.2
        let apple_oid: &[u8] = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02,
        ];
        let mut cert = vec![0x30u8, 0x82, 0x01, 0x00]; // fake outer SEQUENCE header
        cert.extend_from_slice(spki_prefix);
        cert.extend_from_slice(pub_key_uncompressed); // 65 bytes: 0x04 || x || y
        cert.extend_from_slice(apple_oid);
        // extnValue: OCTET STRING { SEQUENCE { SEQUENCE { OCTET STRING nonce } } }
        // Lengths (all fit in one byte):
        //   OCTET STRING nonce: 04 20 + 32 bytes = 34 bytes
        //   Inner SEQUENCE:     30 22 + 34 bytes = 36 bytes
        //   Outer SEQUENCE:     30 24 + 36 bytes = 38 bytes
        //   extnValue wrapper:  04 26 + 38 bytes = 40 bytes
        cert.extend_from_slice(&[0x04, 0x26, 0x30, 0x24, 0x30, 0x22, 0x04, 0x20]);
        cert.extend_from_slice(nonce);
        cert
    }
}
