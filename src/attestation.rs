//! Attestation statement verification.
//!
//! An attestation statement lets the relying party verify the provenance of an
//! authenticator — specifically, that it is a genuine device from a known
//! manufacturer and model.
//!
//! ## Supported formats
//!
//! | Format       | Status                                  | Notes                                                          |
//! |--------------|-----------------------------------------|----------------------------------------------------------------|
//! | `"none"`          | ✅ Supported                       | No cryptographic attestation provided                          |
//! | `"packed"`        | ✅ Self-attestation; ✅ Basic       | Self and Basic: sig + full chain order verified                |
//! | `"fido-u2f"`      | ✅ Supported                       | Signature + full chain order verified                          |
//! | `"android-key"`   | ✅ Supported                       | Signature + key-match + full chain order verified              |
//! | `"tpm"`           | ✅ Supported                       | sig + certInfo + pubArea + full chain order verified           |
//! | `"apple"`         | ✅ Supported                       | Nonce + key-match + full chain order verified                  |
//!
//! ### Certificate chain verification
//!
//! All formats that carry an `x5c` array (leaf-first, DER-encoded) now verify
//! chain order: each certificate must be signed by the next one in the array.
//! When the relying party supplies trust anchors via
//! [`crate::RelyingParty::trust_anchors`], the root is additionally checked
//! against those anchors and the result is upgraded to
//! [`AttestationType::BasicVerified`].
//!
//! ### Packed attestation sub-cases
//!
//! - **Self-attestation** (`x5c` absent): the credential key itself signs the
//!   attestation data. Fully verified.
//! - **Basic attestation** (`x5c` present): a separate attestation key with a
//!   certificate chain signs the data. The signature over `authData ||
//!   clientDataHash` is verified using the leaf certificate's public key, and the
//!   full chain order is verified. If the leaf certificate carries the
//!   `id-fido-gen-ce-aaguid` extension (OID 1.3.6.1.4.1.45724.1.1.4), its value
//!   must match the AAGUID in authenticatorData (§8.2.1 step 2). If the leaf
//!   certificate has a Basic Constraints extension, its CA component must not
//!   be `true` (§8.2.1 Certificate Requirements).
//! - **ECDAA**: deprecated and not implemented.

use ciborium::value::Value;
use ring::digest;
use x509_parser::prelude::*;

use crate::algorithm::{COSE_EDDSA, COSE_ES256, COSE_RS256};
use crate::credential::{AttestationType, PublicKey};
use crate::crypto::{verify_eddsa, verify_es256, verify_rs256};
use crate::der::rsa_components_to_der;
use crate::error::{Result, WebAuthnError};

/// Extract a CBOR `x5c` array (leaf-first, DER-encoded) into `Vec<Vec<u8>>`.
///
/// Returns an error if `v` is not a non-empty CBOR array of byte strings.
fn extract_x5c_array(v: &Value) -> Result<Vec<Vec<u8>>> {
    let arr = match v {
        Value::Array(a) => a,
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "x5c must be a CBOR array".to_string(),
            ))
        }
    };
    if arr.is_empty() {
        return Err(WebAuthnError::InvalidAttestationObject(
            "x5c must be non-empty".to_string(),
        ));
    }
    arr.iter()
        .enumerate()
        .map(|(i, entry)| match entry {
            Value::Bytes(b) => Ok(b.clone()),
            _ => Err(WebAuthnError::InvalidAttestationObject(format!(
                "x5c[{i}] must be CBOR bytes"
            ))),
        })
        .collect()
}

/// Verify the `x5c` certificate chain order and optionally anchor the root.
///
/// Chain order: cert `i` must be signed by cert `i+1` (leaf-first ordering per
/// the WebAuthn spec). The issuer DN of cert `i` must equal the subject DN of
/// cert `i+1`.
///
/// Root check: when `trust_anchors` is non-empty the root certificate (the last
/// entry in `certs`) must be signed by one of the provided DER-encoded anchor
/// certificates. Returns [`AttestationType::BasicVerified`] on success or
/// [`WebAuthnError::AttestationRootUntrusted`] if none match.
///
/// When `trust_anchors` is empty, chain order is still verified but the root is
/// accepted unconditionally and [`AttestationType::Basic`] is returned.
fn verify_x5c_chain(certs: &[Vec<u8>], trust_anchors: &[Vec<u8>]) -> Result<AttestationType> {
    // §7.1 step 22 — verify chain order (leaf-first).
    for i in 0..certs.len().saturating_sub(1) {
        let (_, subject) = X509Certificate::from_der(&certs[i]).map_err(|_| {
            WebAuthnError::AttestationChainInvalid(format!(
                "x5c[{i}] is not a valid DER-encoded X.509 certificate"
            ))
        })?;
        let (_, issuer) = X509Certificate::from_der(&certs[i + 1]).map_err(|_| {
            WebAuthnError::AttestationChainInvalid(format!(
                "x5c[{}] is not a valid DER-encoded X.509 certificate",
                i + 1
            ))
        })?;

        if subject.issuer() != issuer.subject() {
            return Err(WebAuthnError::AttestationChainInvalid(format!(
                "x5c[{i}].issuer does not match x5c[{}].subject",
                i + 1
            )));
        }

        subject
            .verify_signature(Some(issuer.public_key()))
            .map_err(|_| {
                WebAuthnError::AttestationChainInvalid(format!(
                    "x5c[{i}] is not signed by x5c[{}]",
                    i + 1
                ))
            })?;
    }

    if trust_anchors.is_empty() {
        return Ok(AttestationType::Basic);
    }

    // §7.1 step 22 — verify the chain root against configured trust anchors.
    let root_der = &certs[certs.len() - 1];
    let (_, root) = X509Certificate::from_der(root_der).map_err(|_| {
        WebAuthnError::AttestationChainInvalid("x5c root certificate is not valid DER".to_string())
    })?;

    for anchor_der in trust_anchors {
        let Ok((_, anchor)) = X509Certificate::from_der(anchor_der) else {
            continue;
        };
        if root.verify_signature(Some(anchor.public_key())).is_ok() {
            return Ok(AttestationType::BasicVerified);
        }
    }

    Err(WebAuthnError::AttestationRootUntrusted)
}

/// OID for the `id-fido-gen-ce-aaguid` X.509 extension (FIDO Alliance).
const FIDO_GEN_CE_AAGUID_OID: &str = "1.3.6.1.4.1.45724.1.1.4";

/// Verify the attestation certificate's `id-fido-gen-ce-aaguid` extension, if
/// present, against the AAGUID reported in `authenticatorData` (W3C WebAuthn
/// §8.2.1 step 2). The extension is optional; when absent this check passes
/// trivially. When present, its DER value (`OCTET STRING` wrapping the 16-byte
/// AAGUID) must equal `aaguid` exactly — a mismatch means the certificate was
/// issued for a different authenticator model than the one that produced this
/// attestation.
///
/// A leaf certificate that fails to parse as DER is treated the same as one
/// without the extension: presence can't be determined, so there is nothing
/// to check here. Full DER validity is enforced separately by
/// [`verify_x5c_chain`] whenever a chain or trust anchor is actually in play.
fn verify_cert_aaguid_extension(cert_der: &[u8], aaguid: &[u8; 16]) -> Result<()> {
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        return Ok(());
    };

    for ext in cert.extensions() {
        if ext.oid.to_id_string() != FIDO_GEN_CE_AAGUID_OID {
            continue;
        }
        // extnValue content is itself a DER OCTET STRING wrapping the AAGUID:
        // 04 10 <16 bytes>.
        let matches = ext.value.len() == 18
            && ext.value[0] == 0x04
            && ext.value[1] == 0x10
            && ext.value[2..18] == aaguid[..];
        if !matches {
            return Err(WebAuthnError::AttestationAaguidMismatch);
        }
    }

    Ok(())
}

/// Verify that a packed attestation certificate is not itself a CA (W3C
/// WebAuthn §8.2.1: "The Basic Constraints extension MUST have the CA
/// component set to FALSE"). An attestation leaf that is itself a CA could be
/// misused to mint further certificates, so a `CA:TRUE` leaf is rejected.
///
/// Like [`verify_cert_aaguid_extension`], this only enforces the requirement
/// when it can be positively determined: a missing Basic Constraints
/// extension or an unparseable certificate is treated as "nothing to check"
/// rather than a hard failure, since many real-world attestation certificates
/// omit the extension entirely for non-CA end-entity certs rather than
/// including it with an explicit `CA:FALSE`.
fn verify_cert_is_not_ca(cert_der: &[u8]) -> Result<()> {
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        return Ok(());
    };
    let Ok(Some(basic_constraints)) = cert.basic_constraints() else {
        return Ok(());
    };
    if basic_constraints.value.ca {
        return Err(WebAuthnError::AttestationCertIsCa);
    }
    Ok(())
}

/// Verify the attestation statement and return the [`AttestationType`].
///
/// # Arguments
/// * `fmt`                  — Attestation format string from the attestation object.
/// * `att_stmt`             — The raw attStmt CBOR value from the attestation object.
/// * `auth_data_bytes`      — Raw authenticator data bytes.
/// * `client_data_hash`     — SHA-256(clientDataJSON).
/// * `credential_public_key`— The credential public key extracted during this registration.
/// * `credential_id`        — The credential ID bytes from attested credential data.
/// * `trust_anchors` — DER-encoded root CA certificates; when non-empty the
///   chain root is verified against these anchors.
/// * `aaguid` — The AAGUID from attested credential data, checked against the
///   attestation certificate's `id-fido-gen-ce-aaguid` extension when present
///   (packed format only; §8.2.1 step 2).
///
/// # Errors
/// Returns [`WebAuthnError::InvalidAttestationObject`] if the attestation
/// statement is structurally invalid for the given format.
/// Returns [`WebAuthnError::SignatureVerificationFailed`] if attestation
/// signature verification fails.
/// Returns [`WebAuthnError::AttestationChainInvalid`] if the `x5c` chain order
/// is broken.
/// Returns [`WebAuthnError::AttestationRootUntrusted`] if trust anchors are
/// configured but none match the chain root.
/// Returns [`WebAuthnError::AttestationAaguidMismatch`] if the packed
/// attestation certificate's AAGUID extension does not match `aaguid`.
#[allow(clippy::too_many_arguments)]
pub fn verify(
    fmt: &str,
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_public_key: &PublicKey,
    credential_id: &[u8],
    trust_anchors: &[Vec<u8>],
    aaguid: &[u8; 16],
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
            trust_anchors,
            aaguid,
        ),

        // §8.6 — fido-u2f attestation: used by legacy YubiKey 4-series and U2F tokens.
        "fido-u2f" => verify_fido_u2f(
            att_stmt,
            auth_data_bytes,
            client_data_hash,
            credential_id,
            credential_public_key,
            trust_anchors,
        ),

        // §8.4 — android-key attestation: Android Keystore-backed authenticators.
        "android-key" => verify_android_key(
            att_stmt,
            auth_data_bytes,
            client_data_hash,
            credential_public_key,
            trust_anchors,
        ),

        // §8.8 — apple attestation: Face ID and Touch ID passkeys.
        "apple" => verify_apple(
            att_stmt,
            auth_data_bytes,
            client_data_hash,
            credential_public_key,
            trust_anchors,
        ),

        // §8.3 — tpm attestation: TPM 2.0 certify attestation.
        "tpm" => verify_tpm(
            att_stmt,
            auth_data_bytes,
            client_data_hash,
            credential_public_key,
            trust_anchors,
        ),

        // All other formats are accepted but signal that attestation was not verified.
        _other => Ok(AttestationType::None),
    }
}

/// Verify a packed attestation statement (W3C WebAuthn §8.2).
///
/// Handles self-attestation (no `x5c`) and basic attestation (`x5c` present).
/// For basic attestation the signature over `authData || clientDataHash` is
/// verified using the leaf certificate's public key, and the full certificate
/// chain order is validated via [`verify_x5c_chain`].
fn verify_packed(
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_public_key: &PublicKey,
    trust_anchors: &[Vec<u8>],
    aaguid: &[u8; 16],
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
    let mut x5c_certs: Option<Vec<Vec<u8>>> = None;

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
                x5c_certs = Some(extract_x5c_array(v)?);
            }
            _ => {}
        }
    }

    if let Some(certs) = x5c_certs {
        // §8.2 step 2: x5c present → basic attestation.
        // Verify the attestation signature with the leaf cert's public key,
        // then validate the full certificate chain order.
        let alg = alg.ok_or_else(|| {
            WebAuthnError::InvalidAttestationObject(
                "packed basic-attestation attStmt missing required field: alg".to_string(),
            )
        })?;
        let sig = sig.ok_or_else(|| {
            WebAuthnError::InvalidAttestationObject(
                "packed basic-attestation attStmt missing required field: sig".to_string(),
            )
        })?;

        // §8.2 step 2.a: build verification data = authData || clientDataHash.
        let mut verification_data = Vec::with_capacity(auth_data_bytes.len() + 32);
        verification_data.extend_from_slice(auth_data_bytes);
        verification_data.extend_from_slice(client_data_hash);

        // §8.2 step 2.b: verify sig using the leaf certificate's public key.
        match alg {
            COSE_ES256 => {
                let att_pk = extract_ec_p256_public_key_from_cert(&certs[0])?;
                verify_es256(&att_pk, &verification_data, &sig)?;
            }
            COSE_RS256 => {
                let att_pk = extract_rsa_public_key_der_from_cert(&certs[0])?;
                verify_rs256(&att_pk, &verification_data, &sig)?;
            }
            other => return Err(WebAuthnError::UnsupportedAlgorithm(other)),
        }

        // §8.2.1 step 2: if the leaf cert carries the id-fido-gen-ce-aaguid
        // extension, its value must match authenticatorData's aaguid.
        verify_cert_aaguid_extension(&certs[0], aaguid)?;

        // §8.2.1: Basic Constraints CA component must not be true when present.
        verify_cert_is_not_ca(&certs[0])?;

        // §8.2 step 2.c: verify the x5c chain order and optionally the root.
        verify_x5c_chain(&certs, trust_anchors)
    } else {
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
}

/// Verify a FIDO U2F attestation statement (W3C WebAuthn §8.6).
///
/// Requires `x5c` (the attestation certificate chain). Verifies the ECDSA-P256
/// signature over `verificationData` using the leaf certificate's public key,
/// then validates the full `x5c` chain order via [`verify_x5c_chain`].
fn verify_fido_u2f(
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_id: &[u8],
    credential_public_key: &PublicKey,
    trust_anchors: &[Vec<u8>],
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
    let mut x5c_certs: Option<Vec<Vec<u8>>> = None;

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
                x5c_certs = Some(extract_x5c_array(v)?);
            }
            _ => {}
        }
    }

    // §8.6 step 2.a: x5c must be present.
    let certs = x5c_certs.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "fido-u2f attStmt missing required field: x5c".to_string(),
        )
    })?;
    let sig = sig.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "fido-u2f attStmt missing required field: sig".to_string(),
        )
    })?;

    // §8.6 step 2.b: extract the attestation key from the leaf certificate.
    let att_pk = extract_ec_p256_public_key_from_cert(&certs[0])?;

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

    // §8.6 step 2.g: verify the x5c chain order and optionally the root.
    verify_x5c_chain(&certs, trust_anchors)
}

/// Verify an Android Key attestation statement (W3C WebAuthn §8.4).
///
/// Requires `alg`, `sig`, and `x5c` in the attStmt. The attestation cert's
/// public key must equal the credential's public key (the key security property
/// of Android Key attestation: the Android Keystore proves the credential key
/// was generated inside a hardware-backed secure element). Verifies the
/// ECDSA-P256 signature over `authData || clientDataHash`, then validates the
/// full `x5c` chain order via [`verify_x5c_chain`].
fn verify_android_key(
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_public_key: &PublicKey,
    trust_anchors: &[Vec<u8>],
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
    let mut x5c_certs: Option<Vec<Vec<u8>>> = None;

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
                x5c_certs = Some(extract_x5c_array(v)?);
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
    let certs = x5c_certs.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "android-key attStmt missing required field: x5c".to_string(),
        )
    })?;

    // §8.4 step 2: extract the EC P-256 public key from the leaf certificate.
    let att_pk = extract_ec_p256_public_key_from_cert(&certs[0])?;

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

    // §8.4 step 6: verify the x5c chain order and optionally the root.
    verify_x5c_chain(&certs, trust_anchors)
}

/// Verify an Apple attestation statement (W3C WebAuthn §8.8).
///
/// Requires `x5c` in the attStmt. Verifies that:
/// 1. The credential certificate (x5c[0]) contains an Apple nonce extension
///    (OID 1.2.840.113635.100.8.2) whose value equals SHA-256(authData || clientDataHash).
/// 2. The credential certificate's EC P-256 public key equals the registered credential key.
///
/// Then validates the full `x5c` chain order via [`verify_x5c_chain`].
fn verify_apple(
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_public_key: &PublicKey,
    trust_anchors: &[Vec<u8>],
) -> Result<AttestationType> {
    let stmt_map = match att_stmt {
        Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "apple attStmt must be a CBOR map".to_string(),
            ))
        }
    };

    let mut x5c_certs: Option<Vec<Vec<u8>>> = None;

    for (k, v) in stmt_map {
        if let Value::Text(ref key) = k {
            if key == "x5c" {
                x5c_certs = Some(extract_x5c_array(v)?);
            }
        }
    }

    // §8.8 step 1: x5c must be present.
    let certs = x5c_certs.ok_or_else(|| {
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
    let cert_nonce = extract_apple_nonce_from_cert(&certs[0])?;

    // §8.8 step 4: nonce in the cert must equal the expected nonce.
    if cert_nonce != expected_nonce {
        return Err(WebAuthnError::InvalidAttestationObject(
            "apple: certificate nonce does not match SHA-256(authData || clientDataHash)"
                .to_string(),
        ));
    }

    // §8.8 step 5: the cert's public key must equal the registered credential key.
    // This proves the authenticator holds the private key.
    let cert_pk = extract_ec_p256_public_key_from_cert(&certs[0])?;
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

    // §8.8 step 6: verify the x5c chain order and optionally the root.
    verify_x5c_chain(&certs, trust_anchors)
}

/// Verify a TPM attestation statement (W3C WebAuthn §8.3).
///
/// Requires `ver = "2.0"`, `alg` matching the credential key algorithm, and
/// `x5c` with an AIK (attestation identity key) certificate. Parses and
/// validates `certInfo` (TPM2B_ATTEST), verifies that `pubArea` encodes the
/// same public key as the credential, and verifies `sig` over the raw
/// `certInfo` bytes using the attestation certificate's public key. Then
/// validates the full `x5c` chain order via [`verify_x5c_chain`].
fn verify_tpm(
    att_stmt: &Value,
    auth_data_bytes: &[u8],
    client_data_hash: &[u8; 32],
    credential_public_key: &PublicKey,
    trust_anchors: &[Vec<u8>],
) -> Result<AttestationType> {
    let stmt_map = match att_stmt {
        Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "tpm attStmt must be a CBOR map".to_string(),
            ))
        }
    };

    let mut ver: Option<String> = None;
    let mut alg: Option<i64> = None;
    let mut sig: Option<Vec<u8>> = None;
    let mut x5c_certs: Option<Vec<Vec<u8>>> = None;
    let mut cert_info: Option<Vec<u8>> = None;
    let mut pub_area: Option<Vec<u8>> = None;

    for (k, v) in stmt_map {
        match k {
            Value::Text(ref key) if key == "ver" => {
                ver = Some(match v {
                    Value::Text(s) => s.clone(),
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "tpm attStmt ver must be a CBOR text string".to_string(),
                        ))
                    }
                });
            }
            Value::Text(ref key) if key == "alg" => {
                alg = Some(match v {
                    Value::Integer(i) => i64::try_from(*i).map_err(|_| {
                        WebAuthnError::InvalidAttestationObject(
                            "tpm attStmt alg value out of i64 range".to_string(),
                        )
                    })?,
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "tpm attStmt alg must be a CBOR integer".to_string(),
                        ))
                    }
                });
            }
            Value::Text(ref key) if key == "sig" => {
                sig = Some(match v {
                    Value::Bytes(b) => b.clone(),
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "tpm attStmt sig must be CBOR bytes".to_string(),
                        ))
                    }
                });
            }
            Value::Text(ref key) if key == "x5c" => {
                x5c_certs = Some(extract_x5c_array(v)?);
            }
            Value::Text(ref key) if key == "certInfo" => {
                cert_info = Some(match v {
                    Value::Bytes(b) => b.clone(),
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "tpm attStmt certInfo must be CBOR bytes".to_string(),
                        ))
                    }
                });
            }
            Value::Text(ref key) if key == "pubArea" => {
                pub_area = Some(match v {
                    Value::Bytes(b) => b.clone(),
                    _ => {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "tpm attStmt pubArea must be CBOR bytes".to_string(),
                        ))
                    }
                });
            }
            _ => {}
        }
    }

    // §8.3 step 1: ver must be "2.0" — only TPM 2.0 is relevant for WebAuthn.
    let ver = ver.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm attStmt missing required field: ver".to_string(),
        )
    })?;
    if ver != "2.0" {
        return Err(WebAuthnError::InvalidAttestationObject(format!(
            "tpm: ver must be \"2.0\", got \"{ver}\""
        )));
    }

    // §8.3 step 1 (alg): alg must match the credential public key's COSE algorithm.
    let alg = alg.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm attStmt missing required field: alg".to_string(),
        )
    })?;
    let expected_alg = credential_public_key.algorithm();
    if alg != expected_alg {
        return Err(WebAuthnError::InvalidAttestationObject(format!(
            "tpm: attStmt alg ({alg}) does not match credential key algorithm ({expected_alg})"
        )));
    }

    // §8.3 step 1 (x5c): x5c must be present — ECDAA is deprecated and unsupported.
    let certs = x5c_certs.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm attStmt missing required field: x5c (ECDAA is not supported)".to_string(),
        )
    })?;
    let sig = sig.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm attStmt missing required field: sig".to_string(),
        )
    })?;
    let cert_info = cert_info.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm attStmt missing required field: certInfo".to_string(),
        )
    })?;
    let pub_area = pub_area.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm attStmt missing required field: pubArea".to_string(),
        )
    })?;

    // §8.3 step 1: extract the AIK certificate's public key, keyed by alg.
    // The cert key may differ from the credential key but must match alg.
    let cert_key_bytes = match alg {
        COSE_ES256 => extract_ec_p256_public_key_from_cert(&certs[0])?,
        COSE_RS256 => extract_rsa_public_key_der_from_cert(&certs[0])?,
        _ => return Err(WebAuthnError::UnsupportedAlgorithm(alg)),
    };

    // §8.3 step 3: attToBeSigned = authData || clientDataHash.
    // extraData in certInfo must equal SHA-256(attToBeSigned).
    let mut att_to_be_signed = Vec::with_capacity(auth_data_bytes.len() + 32);
    att_to_be_signed.extend_from_slice(auth_data_bytes);
    att_to_be_signed.extend_from_slice(client_data_hash);
    let expected_extra_data = crate::crypto::sha256(&att_to_be_signed);

    // Compute name(pubArea) = nameAlg_bytes || H_nameAlg(pubArea).
    // Used to verify certInfo.attested.name in step 4.d.
    let expected_name = compute_pub_area_name(&pub_area)?;

    // §8.3 step 2: verify that pubArea encodes the same public key as the credential.
    verify_pub_area_matches_credential(&pub_area, credential_public_key)?;

    // §8.3 step 4.a–d: parse and validate certInfo (TPM2B_ATTEST).
    verify_cert_info(&cert_info, &expected_extra_data, &expected_name)?;

    // §8.3 step 5: verify sig over the raw certInfo bytes using the AIK cert key.
    match alg {
        COSE_ES256 => verify_es256(&cert_key_bytes, &cert_info, &sig)?,
        COSE_RS256 => verify_rs256(&cert_key_bytes, &cert_info, &sig)?,
        // SAFETY: alg was already validated to be ES256 or RS256 in the match above.
        _ => unreachable!("alg validated earlier"),
    }

    // §8.3 step 6: verify the x5c chain order and optionally the root.
    verify_x5c_chain(&certs, trust_anchors)
}

/// Compute the TPM name for a raw `pubArea` blob.
///
/// `name = nameAlg_bytes (2 bytes, big-endian) || H_nameAlg(pubArea)`.
/// `nameAlg` is read from bytes 2–3 of `pubArea` (the `TPMT_PUBLIC.nameAlg`
/// field). Supported values: `0x000B` (TPM_ALG_SHA256), `0x000C` (TPM_ALG_SHA384).
fn compute_pub_area_name(pub_area: &[u8]) -> Result<Vec<u8>> {
    if pub_area.len() < 4 {
        return Err(WebAuthnError::InvalidAttestationObject(
            "tpm: pubArea too short to read nameAlg (need at least 4 bytes)".to_string(),
        ));
    }
    let name_alg = u16::from_be_bytes([pub_area[2], pub_area[3]]);
    let hash: Vec<u8> = match name_alg {
        0x000B => crate::crypto::sha256(pub_area).to_vec(),
        0x000C => {
            // TPM_ALG_SHA384 — used when nameAlg selects P-384 or larger curve.
            digest::digest(&digest::SHA384, pub_area).as_ref().to_vec()
        }
        other => {
            return Err(WebAuthnError::InvalidAttestationObject(format!(
                "tpm: unsupported pubArea nameAlg 0x{other:04X} \
                 (expected 0x000B SHA-256 or 0x000C SHA-384)"
            )))
        }
    };
    // name = nameAlg (2 bytes, big-endian) || H_nameAlg(pubArea)
    let mut name = vec![pub_area[2], pub_area[3]];
    name.extend_from_slice(&hash);
    Ok(name)
}

/// Verify that `pubArea` (`TPMT_PUBLIC`) encodes the same public key as `credential_public_key`.
///
/// Parses the binary layout of `TPMT_PUBLIC` to locate the `unique` field
/// (TPMS_ECC_POINT for ECC keys, TPM2B_PUBLIC_KEY_RSA for RSA) and compares
/// the raw key material against the stored credential.
fn verify_pub_area_matches_credential(
    pub_area: &[u8],
    credential_public_key: &PublicKey,
) -> Result<()> {
    if pub_area.len() < 10 {
        return Err(WebAuthnError::InvalidAttestationObject(
            "tpm: pubArea too short (need at least 10 bytes for the fixed header)".to_string(),
        ));
    }

    let key_type = u16::from_be_bytes([pub_area[0], pub_area[1]]);
    // authPolicy is a variable-length blob at offset 8; its 2-byte length prefix determines
    // where the `parameters` field starts.
    let auth_policy_size = u16::from_be_bytes([pub_area[8], pub_area[9]]) as usize;
    let params_start = 10_usize.checked_add(auth_policy_size).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject("tpm: pubArea authPolicy size overflow".to_string())
    })?;

    match key_type {
        // ECC: TPMS_ECC_PARMS = 4 (sym) + 2 (scheme) + 2 (curveID) + 2 (kdf) = 10 bytes.
        // unique = TPMS_ECC_POINT: x (2-byte length-prefixed) || y (2-byte length-prefixed).
        0x0023 => {
            let unique_start = params_start.checked_add(10).ok_or_else(|| {
                WebAuthnError::InvalidAttestationObject(
                    "tpm: pubArea ECC params offset overflow".to_string(),
                )
            })?;
            let mut pos = unique_start;
            let x = tpm_read_blob(pub_area, &mut pos)?;
            let y = tpm_read_blob(pub_area, &mut pos)?;
            match credential_public_key {
                PublicKey::ES256 { x: cx, y: cy } => {
                    if x != cx.as_slice() || y != cy.as_slice() {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "tpm: pubArea ECC point does not match ES256 credential key"
                                .to_string(),
                        ));
                    }
                }
                PublicKey::ES384 { x: cx, y: cy } => {
                    if x != cx.as_slice() || y != cy.as_slice() {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "tpm: pubArea ECC point does not match ES384 credential key"
                                .to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(WebAuthnError::InvalidAttestationObject(
                        "tpm: pubArea type is ECC (0x0023) but credential key is not an EC key"
                            .to_string(),
                    ))
                }
            }
        }
        // RSA: TPMS_RSA_PARMS = 4 (sym) + 2 (scheme) + 2 (keyBits) + 4 (exponent) = 12 bytes.
        // unique = TPM2B_PUBLIC_KEY_RSA: 2-byte-length-prefixed modulus.
        0x0001 => {
            let unique_start = params_start.checked_add(12).ok_or_else(|| {
                WebAuthnError::InvalidAttestationObject(
                    "tpm: pubArea RSA params offset overflow".to_string(),
                )
            })?;
            let mut pos = unique_start;
            let tpm_modulus = tpm_read_blob(pub_area, &mut pos)?;
            match credential_public_key {
                PublicKey::RS256 { n, .. } => {
                    // Strip leading 0x00 bytes from both sides before comparing: the TPM
                    // encodes the modulus without a DER sign-extension byte, but the DER
                    // INTEGER `n` from COSE may carry a leading 0x00 if the high bit is set.
                    fn strip(b: &[u8]) -> &[u8] {
                        let start = b.iter().position(|v| *v != 0).unwrap_or(b.len());
                        &b[start..]
                    }
                    if strip(tpm_modulus) != strip(n) {
                        return Err(WebAuthnError::InvalidAttestationObject(
                            "tpm: pubArea RSA modulus does not match RS256 credential key"
                                .to_string(),
                        ));
                    }
                }
                _ => {
                    return Err(WebAuthnError::InvalidAttestationObject(
                        "tpm: pubArea type is RSA (0x0001) but credential key is not RS256"
                            .to_string(),
                    ))
                }
            }
        }
        other => {
            return Err(WebAuthnError::InvalidAttestationObject(format!(
                "tpm: unsupported pubArea key type: 0x{other:04X}"
            )))
        }
    }

    Ok(())
}

/// Parse and validate a `certInfo` (`TPM2B_ATTEST`) blob (§8.3 step 4).
///
/// Checks magic, type, extraData, and attested.name. The signature over this
/// blob is verified separately in step 5.
fn verify_cert_info(
    cert_info: &[u8],
    expected_extra_data: &[u8; 32],
    expected_name: &[u8],
) -> Result<()> {
    let mut pos = 0usize;

    // §8.3 step 4: TPM2B_ATTEST starts with a 2-byte size field (TPMS_ATTEST length).
    tpm_skip(cert_info, &mut pos, 2)?;

    // §8.3 step 4.a: magic must be TPM_GENERATED_VALUE (0xFF544347).
    let magic = tpm_read_u32_be(cert_info, &mut pos)?;
    if magic != 0xFF544347 {
        return Err(WebAuthnError::InvalidAttestationObject(format!(
            "tpm: certInfo magic must be 0xFF544347 (TPM_GENERATED_VALUE), got 0x{magic:08X}"
        )));
    }

    // §8.3 step 4.b: type must be TPM_ST_ATTEST_CERTIFY (0x8017).
    let attest_type = tpm_read_u16_be(cert_info, &mut pos)?;
    if attest_type != 0x8017 {
        return Err(WebAuthnError::InvalidAttestationObject(format!(
            "tpm: certInfo type must be 0x8017 (TPM_ST_ATTEST_CERTIFY), got 0x{attest_type:04X}"
        )));
    }

    // qualifiedSigner (2-byte length-prefixed blob) — skip without verification.
    let _ = tpm_read_blob(cert_info, &mut pos)?;

    // §8.3 step 4.c: extraData must equal SHA-256(authData || clientDataHash).
    let extra_data = tpm_read_blob(cert_info, &mut pos)?;
    if extra_data != expected_extra_data.as_slice() {
        return Err(WebAuthnError::InvalidAttestationObject(
            "tpm: certInfo extraData does not match SHA-256(authData || clientDataHash)"
                .to_string(),
        ));
    }

    // clockInfo (8 bytes) and firmwareVersion (8 bytes) — skip without verification.
    tpm_skip(cert_info, &mut pos, 16)?;

    // §8.3 step 4.d: attested.name must equal name(pubArea).
    let attested_name = tpm_read_blob(cert_info, &mut pos)?;
    if attested_name != expected_name {
        return Err(WebAuthnError::InvalidAttestationObject(
            "tpm: certInfo attested.name does not match computed name(pubArea)".to_string(),
        ));
    }

    Ok(())
}

/// Read a big-endian `u16` from `data[*pos..*pos+2]` and advance `*pos` by 2.
fn tpm_read_u16_be(data: &[u8], pos: &mut usize) -> Result<u16> {
    let end = pos.checked_add(2).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject("tpm: position overflow reading u16".to_string())
    })?;
    let bytes: [u8; 2] = data
        .get(*pos..end)
        .ok_or_else(|| {
            WebAuthnError::InvalidAttestationObject("tpm: buffer too short reading u16".to_string())
        })?
        // Slice is exactly 2 bytes as guaranteed by the checked_add above.
        .try_into()
        .expect("slice is exactly 2 bytes");
    *pos = end;
    Ok(u16::from_be_bytes(bytes))
}

/// Read a big-endian `u32` from `data[*pos..*pos+4]` and advance `*pos` by 4.
fn tpm_read_u32_be(data: &[u8], pos: &mut usize) -> Result<u32> {
    let end = pos.checked_add(4).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject("tpm: position overflow reading u32".to_string())
    })?;
    let bytes: [u8; 4] = data
        .get(*pos..end)
        .ok_or_else(|| {
            WebAuthnError::InvalidAttestationObject("tpm: buffer too short reading u32".to_string())
        })?
        // Slice is exactly 4 bytes as guaranteed by the checked_add above.
        .try_into()
        .expect("slice is exactly 4 bytes");
    *pos = end;
    Ok(u32::from_be_bytes(bytes))
}

/// Read a 2-byte-length-prefixed blob from `data` at `*pos` and advance `*pos`.
fn tpm_read_blob<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len = tpm_read_u16_be(data, pos)? as usize;
    let end = pos.checked_add(len).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm: position overflow reading length-prefixed blob".to_string(),
        )
    })?;
    let slice = data.get(*pos..end).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm: length-prefixed field extends beyond buffer".to_string(),
        )
    })?;
    *pos = end;
    Ok(slice)
}

/// Skip `n` bytes in `data` at `*pos` and advance `*pos`.
fn tpm_skip(data: &[u8], pos: &mut usize, n: usize) -> Result<()> {
    let end = pos.checked_add(n).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(format!(
            "tpm: position overflow skipping {n} bytes"
        ))
    })?;
    if end > data.len() {
        return Err(WebAuthnError::InvalidAttestationObject(format!(
            "tpm: buffer too short skipping {n} bytes (have {}, need {end})",
            data.len()
        )));
    }
    *pos = end;
    Ok(())
}

/// Extract a DER-encoded `RSAPublicKey` (`SEQUENCE { INTEGER n, INTEGER e }`) from
/// a DER-encoded X.509 certificate by navigating to the SubjectPublicKeyInfo.
///
/// Searches for the rsaEncryption OID (1.2.840.113549.1.1.1), skips the NULL
/// AlgorithmIdentifier parameters, parses the BIT STRING, and returns the
/// `RSAPublicKey` SEQUENCE contents — the format `ring`'s
/// `RSA_PKCS1_2048_8192_SHA256` expects (`RSAPublicKey` per RFC 3447, not
/// SubjectPublicKeyInfo).
fn extract_rsa_public_key_der_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    // OID 1.2.840.113549.1.1.1 (rsaEncryption) in DER.
    const RSA_ENCRYPTION_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];

    let oid_pos = cert_der
        .windows(RSA_ENCRYPTION_OID.len())
        .position(|w| w == RSA_ENCRYPTION_OID)
        .ok_or_else(|| {
            WebAuthnError::InvalidAttestationObject(
                "tpm: attestation cert does not contain rsaEncryption OID".to_string(),
            )
        })?;

    let after_oid = &cert_der[oid_pos + RSA_ENCRYPTION_OID.len()..];

    // Skip AlgorithmIdentifier parameters (typically NULL: 05 00).
    let (_, _, after_params) = der_parse_tlv(after_oid).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm: failed to parse AlgorithmIdentifier params after rsaEncryption OID".to_string(),
        )
    })?;

    // Parse the BIT STRING containing the RSAPublicKey SEQUENCE.
    let (bs_tag, bs_content, _) = der_parse_tlv(after_params).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm: failed to parse SubjectPublicKeyInfo BIT STRING".to_string(),
        )
    })?;
    if bs_tag != 0x03 {
        return Err(WebAuthnError::InvalidAttestationObject(
            "tpm: expected BIT STRING after AlgorithmIdentifier in SubjectPublicKeyInfo"
                .to_string(),
        ));
    }

    // The BIT STRING starts with an unused-bits byte (0x00 for all key types).
    // The RSAPublicKey SEQUENCE { INTEGER n, INTEGER e } follows immediately.
    let rsa_pk = bs_content.get(1..).ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject(
            "tpm: BIT STRING for RSA public key is too short".to_string(),
        )
    })?;

    Ok(rsa_pk.to_vec())
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
        let result = verify(
            "none",
            &none_att_stmt(),
            &[],
            &[0u8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(matches!(result, Ok(AttestationType::None)));
    }

    #[test]
    fn accepts_unknown_format_as_none() {
        let pk = dummy_es256_key();
        let result = verify(
            "unknown-format",
            &none_att_stmt(),
            &[],
            &[0u8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(matches!(result, Ok(AttestationType::None)));
    }

    #[test]
    fn packed_basic_attestation_valid_sig_returns_basic() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
        let att_pub = kp.public_key().as_ref();
        let cert = make_fake_p256_cert(att_pub);

        let pk = dummy_es256_key();
        let auth_data = b"fake-auth-data";
        let client_data_hash = [0xABu8; 32];

        let mut msg = Vec::new();
        msg.extend_from_slice(auth_data);
        msg.extend_from_slice(&client_data_hash);
        let sig = kp.sign(&rng, &msg).expect("test setup");

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
        // Single-cert chain, no trust anchors → Basic (no x509-parser call needed).
        let result = verify(
            "packed",
            &stmt,
            auth_data,
            &client_data_hash,
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    // ── id-fido-gen-ce-aaguid extension tests ────────────────────────────────

    /// Build a self-signed leaf cert carrying the `id-fido-gen-ce-aaguid`
    /// extension (OID 1.3.6.1.4.1.45724.1.1.4) with the given AAGUID value.
    fn make_leaf_with_aaguid_extension(aaguid: &[u8; 16]) -> (rcgen::KeyPair, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("test setup");
        let mut params = rcgen::CertificateParams::default();
        let mut content = vec![0x04, 0x10]; // OCTET STRING, 16 bytes
        content.extend_from_slice(aaguid);
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4],
                content,
            ));
        let cert = params.self_signed(&key).expect("test setup");
        (key, cert.der().to_vec())
    }

    #[test]
    fn cert_aaguid_extension_absent_passes() {
        let (_key, _cert, cert_der) = make_ca();
        assert!(verify_cert_aaguid_extension(&cert_der, &[0x11u8; 16]).is_ok());
    }

    #[test]
    fn cert_aaguid_extension_matching_passes() {
        let aaguid = [0x42u8; 16];
        let (_key, cert_der) = make_leaf_with_aaguid_extension(&aaguid);
        assert!(verify_cert_aaguid_extension(&cert_der, &aaguid).is_ok());
    }

    #[test]
    fn cert_aaguid_extension_mismatch_rejected() {
        let cert_aaguid = [0x42u8; 16];
        let (_key, cert_der) = make_leaf_with_aaguid_extension(&cert_aaguid);
        let auth_data_aaguid = [0x99u8; 16];
        let result = verify_cert_aaguid_extension(&cert_der, &auth_data_aaguid);
        assert!(matches!(
            result,
            Err(WebAuthnError::AttestationAaguidMismatch)
        ));
    }

    #[test]
    fn cert_aaguid_extension_unparseable_cert_passes() {
        // A non-DER cert can't be checked for extension presence; skip rather
        // than fail, matching the fast-path used elsewhere when no chain or
        // trust anchor validation is in play.
        let fake_cert = make_fake_p256_cert(&[0x04u8; 65]);
        assert!(verify_cert_aaguid_extension(&fake_cert, &[0x11u8; 16]).is_ok());
    }

    /// Build a self-signed leaf cert with an explicit Basic Constraints
    /// extension set to `CA:FALSE` (as opposed to `make_ca()`'s `CA:TRUE`, or
    /// the default `NoCa` which omits the extension entirely).
    fn make_leaf_explicit_no_ca() -> Vec<u8> {
        let key = rcgen::KeyPair::generate().expect("test setup");
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.self_signed(&key).expect("test setup").der().to_vec()
    }

    #[test]
    fn cert_is_not_ca_absent_basic_constraints_passes() {
        // Default rcgen leaf certs omit the Basic Constraints extension
        // entirely; that must not be treated as a failure.
        let (_key, cert_der) = make_leaf_with_aaguid_extension(&[0x11u8; 16]);
        assert!(verify_cert_is_not_ca(&cert_der).is_ok());
    }

    #[test]
    fn cert_is_not_ca_explicit_false_passes() {
        let cert_der = make_leaf_explicit_no_ca();
        assert!(verify_cert_is_not_ca(&cert_der).is_ok());
    }

    #[test]
    fn cert_is_not_ca_rejects_ca_cert() {
        let (_key, _cert, cert_der) = make_ca();
        assert!(matches!(
            verify_cert_is_not_ca(&cert_der),
            Err(WebAuthnError::AttestationCertIsCa)
        ));
    }

    #[test]
    fn cert_is_not_ca_unparseable_cert_passes() {
        let fake_cert = make_fake_p256_cert(&[0x04u8; 65]);
        assert!(verify_cert_is_not_ca(&fake_cert).is_ok());
    }

    #[test]
    fn packed_basic_attestation_rejects_ca_leaf_certificate() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let (ca_key, _ca_cert, ca_der) = make_ca();

        let rng = SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            ca_key.serialize_der().as_ref(),
            &rng,
        )
        .expect("test setup");

        let pk = dummy_es256_key();
        let auth_data = b"fake-auth-data";
        let client_data_hash = [0xABu8; 32];
        let mut msg = Vec::new();
        msg.extend_from_slice(auth_data);
        msg.extend_from_slice(&client_data_hash);
        let sig = kp.sign(&rng, &msg).expect("test setup");

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
                Value::Array(vec![Value::Bytes(ca_der)]),
            ),
        ]);
        let result = verify(
            "packed",
            &stmt,
            auth_data,
            &client_data_hash,
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(matches!(result, Err(WebAuthnError::AttestationCertIsCa)));
    }

    #[test]
    fn packed_basic_attestation_aaguid_extension_matches_returns_basic() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let aaguid = [0x77u8; 16];
        let (key, cert_der) = make_leaf_with_aaguid_extension(&aaguid);

        let rng = SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            key.serialize_der().as_ref(),
            &rng,
        )
        .expect("test setup");

        let pk = dummy_es256_key();
        let auth_data = b"fake-auth-data";
        let client_data_hash = [0xABu8; 32];
        let mut msg = Vec::new();
        msg.extend_from_slice(auth_data);
        msg.extend_from_slice(&client_data_hash);
        let sig = kp.sign(&rng, &msg).expect("test setup");

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
                Value::Array(vec![Value::Bytes(cert_der)]),
            ),
        ]);
        let result = verify(
            "packed",
            &stmt,
            auth_data,
            &client_data_hash,
            &pk,
            &[],
            &[],
            &aaguid,
        );
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    #[test]
    fn packed_basic_attestation_aaguid_extension_mismatch_rejected() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let cert_aaguid = [0x77u8; 16];
        let (key, cert_der) = make_leaf_with_aaguid_extension(&cert_aaguid);

        let rng = SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            key.serialize_der().as_ref(),
            &rng,
        )
        .expect("test setup");

        let pk = dummy_es256_key();
        let auth_data = b"fake-auth-data";
        let client_data_hash = [0xABu8; 32];
        let mut msg = Vec::new();
        msg.extend_from_slice(auth_data);
        msg.extend_from_slice(&client_data_hash);
        let sig = kp.sign(&rng, &msg).expect("test setup");

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
                Value::Array(vec![Value::Bytes(cert_der)]),
            ),
        ]);
        // authenticatorData's aaguid differs from the cert extension's aaguid.
        let auth_data_aaguid = [0x99u8; 16];
        let result = verify(
            "packed",
            &stmt,
            auth_data,
            &client_data_hash,
            &pk,
            &[],
            &[],
            &auth_data_aaguid,
        );
        assert!(matches!(
            result,
            Err(WebAuthnError::AttestationAaguidMismatch)
        ));
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
            &[],
            &[0u8; 16],
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
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
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
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
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
        let result = verify("packed", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
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
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
        let pub_bytes = kp.public_key().as_ref(); // 0x04 || x || y

        let x = pub_bytes[1..33].to_vec();
        let y = pub_bytes[33..65].to_vec();
        let pk = PublicKey::ES256 { x, y };

        let auth_data = b"fake-auth-data";
        let client_data_hash = [0xABu8; 32];

        let mut verification_data = Vec::new();
        verification_data.extend_from_slice(auth_data);
        verification_data.extend_from_slice(&client_data_hash);

        let sig = kp.sign(&rng, &verification_data).expect("test setup");

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

        let result = verify(
            "packed",
            &stmt,
            auth_data,
            &client_data_hash,
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(matches!(result, Ok(AttestationType::SelfAttestation)));
    }

    #[test]
    fn packed_self_attestation_es256_bad_signature() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
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

        let result = verify(
            "packed",
            &stmt,
            b"auth",
            &[0u8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
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
        let result = verify(
            "fido-u2f",
            &stmt,
            &[0u8; 37],
            &[0u8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
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
        let result = verify(
            "fido-u2f",
            &stmt,
            &[0u8; 37],
            &[0u8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
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
        let result = verify(
            "fido-u2f",
            &stmt,
            &[0u8; 37],
            &[0u8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
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
        let result = verify(
            "fido-u2f",
            &stmt,
            &[0u8; 37],
            &[0u8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
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
        let att_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let att_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, att_pkcs8.as_ref(), &rng)
                .expect("test setup");
        let att_pub = att_kp.public_key().as_ref(); // 65 bytes: 0x04 || x || y
        let cert = make_fake_p256_cert(att_pub);

        // Credential keypair (separate from attestation key).
        let cred_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let cred_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cred_pkcs8.as_ref(), &rng)
                .expect("test setup");
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

        let sig = att_kp.sign(&rng, &verification_data).expect("test setup");

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
            &[],
            &[0u8; 16],
        );
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    #[test]
    fn fido_u2f_bad_signature_rejected() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let att_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let att_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, att_pkcs8.as_ref(), &rng)
                .expect("test setup");
        let cert = make_fake_p256_cert(att_kp.public_key().as_ref());

        let cred_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let cred_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cred_pkcs8.as_ref(), &rng)
                .expect("test setup");
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
            &[],
            &[0u8; 16],
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
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
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

        let sig = kp.sign(&rng, &verification_data).expect("test setup");

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
            &[],
            &[0u8; 16],
        );
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    #[test]
    fn android_key_bad_signature_rejected() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
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
            &[],
            &[0u8; 16],
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
        let result = verify(
            "android-key",
            &stmt,
            &[],
            &[0u8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
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
        let result = verify(
            "android-key",
            &stmt,
            &[],
            &[0u8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
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
        let cert_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let cert_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cert_pkcs8.as_ref(), &rng)
                .expect("test setup");
        let cert = make_fake_p256_cert(cert_kp.public_key().as_ref());

        let cred_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let cred_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cred_pkcs8.as_ref(), &rng)
                .expect("test setup");
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
            &[],
            &[0u8; 16],
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
        let result = verify(
            "android-key",
            &stmt,
            &[],
            &[0u8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("ES256"))
        );
    }

    // ── apple tests ──────────────────────────────────────────────────────────

    #[test]
    fn apple_rejects_missing_x5c() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![]);
        let result = verify("apple", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("x5c"))
        );
    }

    #[test]
    fn apple_rejects_empty_x5c() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![(Value::Text("x5c".to_string()), Value::Array(vec![]))]);
        let result = verify("apple", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("non-empty"))
        );
    }

    #[test]
    fn apple_rejects_nonce_mismatch() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
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
            &[],
            &[0u8; 16],
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
        let cert_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let cert_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cert_pkcs8.as_ref(), &rng)
                .expect("test setup");
        let cert_pub = cert_kp.public_key().as_ref();

        let cred_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let cred_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cred_pkcs8.as_ref(), &rng)
                .expect("test setup");
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
            &[],
            &[0u8; 16],
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
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
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
            &[],
            &[0u8; 16],
        );
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    // ── tpm tests ────────────────────────────────────────────────────────────

    fn build_tpm_ecc_pub_area(x: &[u8], y: &[u8]) -> Vec<u8> {
        let mut pa = Vec::new();
        pa.extend_from_slice(&[0x00, 0x23]); // type = ECC
        pa.extend_from_slice(&[0x00, 0x0B]); // nameAlg = SHA-256
        pa.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // objectAttributes
        pa.extend_from_slice(&[0x00, 0x00]); // authPolicy size = 0
                                             // TPMS_ECC_PARMS: sym(4) + scheme(2) + curveID P-256(2) + kdf(2) = 10 bytes
        pa.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00]);
        // unique = TPMS_ECC_POINT: x (2-byte length-prefixed) || y (2-byte length-prefixed)
        pa.extend_from_slice(&(x.len() as u16).to_be_bytes());
        pa.extend_from_slice(x);
        pa.extend_from_slice(&(y.len() as u16).to_be_bytes());
        pa.extend_from_slice(y);
        pa
    }

    fn build_tpm_cert_info(extra_data: &[u8; 32], attested_name: &[u8]) -> Vec<u8> {
        let mut attest = Vec::new();
        attest.extend_from_slice(&[0xFF, 0x54, 0x43, 0x47]); // magic = TPM_GENERATED_VALUE
        attest.extend_from_slice(&[0x80, 0x17]); // type = TPM_ST_ATTEST_CERTIFY
        attest.extend_from_slice(&[0x00, 0x00]); // qualifiedSigner (empty)
        attest.extend_from_slice(&(extra_data.len() as u16).to_be_bytes());
        attest.extend_from_slice(extra_data);
        attest.extend_from_slice(&[0u8; 8]); // clockInfo
        attest.extend_from_slice(&[0u8; 8]); // firmwareVersion
        attest.extend_from_slice(&(attested_name.len() as u16).to_be_bytes());
        attest.extend_from_slice(attested_name);

        let mut cert_info = Vec::new();
        cert_info.extend_from_slice(&(attest.len() as u16).to_be_bytes()); // size
        cert_info.extend_from_slice(&attest);
        cert_info
    }

    #[test]
    fn tpm_rejects_missing_ver() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(vec![0u8; 4])]),
            ),
            (
                Value::Text("certInfo".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
            (
                Value::Text("pubArea".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
        ]);
        let result = verify("tpm", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("ver"))
        );
    }

    #[test]
    fn tpm_rejects_wrong_ver() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("1.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(vec![0u8; 4])]),
            ),
            (
                Value::Text("certInfo".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
            (
                Value::Text("pubArea".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
        ]);
        let result = verify("tpm", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("2.0"))
        );
    }

    #[test]
    fn tpm_rejects_missing_alg() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(vec![0u8; 4])]),
            ),
            (
                Value::Text("certInfo".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
            (
                Value::Text("pubArea".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
        ]);
        let result = verify("tpm", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("alg"))
        );
    }

    #[test]
    fn tpm_rejects_alg_mismatch() {
        // Credential is ES256 (-7) but attStmt claims RS256 (-257).
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-257i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(vec![0u8; 4])]),
            ),
            (
                Value::Text("certInfo".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
            (
                Value::Text("pubArea".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
        ]);
        let result = verify("tpm", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("alg"))
        );
    }

    #[test]
    fn tpm_rejects_missing_x5c() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("certInfo".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
            (
                Value::Text("pubArea".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
        ]);
        let result = verify("tpm", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("x5c"))
        );
    }

    #[test]
    fn tpm_rejects_empty_x5c() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (Value::Text("x5c".to_string()), Value::Array(vec![])),
            (
                Value::Text("certInfo".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
            (
                Value::Text("pubArea".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
        ]);
        let result = verify("tpm", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("non-empty"))
        );
    }

    #[test]
    fn tpm_rejects_missing_cert_info() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(vec![0u8; 4])]),
            ),
            (
                Value::Text("pubArea".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
        ]);
        let result = verify("tpm", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("certInfo"))
        );
    }

    #[test]
    fn tpm_rejects_missing_pub_area() {
        let pk = dummy_es256_key();
        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(vec![0u8; 4])]),
            ),
            (
                Value::Text("certInfo".to_string()),
                Value::Bytes(vec![0u8; 4]),
            ),
        ]);
        let result = verify("tpm", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("pubArea"))
        );
    }

    #[test]
    fn tpm_rejects_bad_magic_in_cert_info() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
        let att_pub = kp.public_key().as_ref();
        let cert = make_fake_p256_cert(att_pub);

        let cred_pub = kp.public_key().as_ref();
        let pk = PublicKey::ES256 {
            x: cred_pub[1..33].to_vec(),
            y: cred_pub[33..65].to_vec(),
        };
        let pub_area = build_tpm_ecc_pub_area(&cred_pub[1..33], &cred_pub[33..65]);
        let name = compute_pub_area_name(&pub_area).expect("test setup");

        // Build certInfo with WRONG magic (0xDEADBEEF).
        let mut attest = Vec::new();
        attest.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // wrong magic
        attest.extend_from_slice(&[0x80, 0x17]);
        attest.extend_from_slice(&[0x00, 0x00]); // qualifiedSigner (empty)
        attest.extend_from_slice(&(32u16).to_be_bytes());
        attest.extend_from_slice(&[0u8; 32]); // extraData placeholder
        attest.extend_from_slice(&[0u8; 16]); // clockInfo + firmwareVersion
        attest.extend_from_slice(&(name.len() as u16).to_be_bytes());
        attest.extend_from_slice(&name);
        let mut cert_info = (attest.len() as u16).to_be_bytes().to_vec();
        cert_info.extend_from_slice(&attest);

        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (Value::Text("certInfo".to_string()), Value::Bytes(cert_info)),
            (Value::Text("pubArea".to_string()), Value::Bytes(pub_area)),
        ]);

        let result = verify("tpm", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("magic"))
        );
    }

    #[test]
    fn tpm_rejects_bad_type_in_cert_info() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
        let att_pub = kp.public_key().as_ref();
        let cert = make_fake_p256_cert(att_pub);

        let cred_pub = kp.public_key().as_ref();
        let pk = PublicKey::ES256 {
            x: cred_pub[1..33].to_vec(),
            y: cred_pub[33..65].to_vec(),
        };
        let pub_area = build_tpm_ecc_pub_area(&cred_pub[1..33], &cred_pub[33..65]);
        let name = compute_pub_area_name(&pub_area).expect("test setup");

        // Build certInfo with correct magic but wrong type (0x8001 instead of 0x8017).
        let mut attest = Vec::new();
        attest.extend_from_slice(&[0xFF, 0x54, 0x43, 0x47]); // magic OK
        attest.extend_from_slice(&[0x80, 0x01]); // wrong type
        attest.extend_from_slice(&[0x00, 0x00]);
        attest.extend_from_slice(&(32u16).to_be_bytes());
        attest.extend_from_slice(&[0u8; 32]);
        attest.extend_from_slice(&[0u8; 16]);
        attest.extend_from_slice(&(name.len() as u16).to_be_bytes());
        attest.extend_from_slice(&name);
        let mut cert_info = (attest.len() as u16).to_be_bytes().to_vec();
        cert_info.extend_from_slice(&attest);

        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (Value::Text("certInfo".to_string()), Value::Bytes(cert_info)),
            (Value::Text("pubArea".to_string()), Value::Bytes(pub_area)),
        ]);

        let result = verify("tpm", &stmt, &[], &[0u8; 32], &pk, &[], &[], &[0u8; 16]);
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("type"))
        );
    }

    #[test]
    fn tpm_rejects_extra_data_mismatch() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
        let att_pub = kp.public_key().as_ref();
        let cert = make_fake_p256_cert(att_pub);

        let cred_pub = kp.public_key().as_ref();
        let pk = PublicKey::ES256 {
            x: cred_pub[1..33].to_vec(),
            y: cred_pub[33..65].to_vec(),
        };
        let pub_area = build_tpm_ecc_pub_area(&cred_pub[1..33], &cred_pub[33..65]);
        let name = compute_pub_area_name(&pub_area).expect("test setup");

        // Build certInfo with correct magic+type but wrong extraData (all zeros).
        let cert_info = build_tpm_cert_info(&[0u8; 32], &name);

        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (Value::Text("certInfo".to_string()), Value::Bytes(cert_info)),
            (Value::Text("pubArea".to_string()), Value::Bytes(pub_area)),
        ]);

        // auth_data = [0xAA; 10] so SHA-256(auth_data || client_data_hash) != all-zeros.
        let result = verify(
            "tpm",
            &stmt,
            &[0xAAu8; 10],
            &[0xBBu8; 32],
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("extraData"))
        );
    }

    #[test]
    fn tpm_rejects_attested_name_mismatch() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
        let att_pub = kp.public_key().as_ref();
        let cert = make_fake_p256_cert(att_pub);

        let cred_pub = kp.public_key().as_ref();
        let pk = PublicKey::ES256 {
            x: cred_pub[1..33].to_vec(),
            y: cred_pub[33..65].to_vec(),
        };
        let pub_area = build_tpm_ecc_pub_area(&cred_pub[1..33], &cred_pub[33..65]);

        let auth_data = b"auth-data";
        let client_data_hash = [0xCCu8; 32];
        let mut att_signed = auth_data.to_vec();
        att_signed.extend_from_slice(&client_data_hash);
        let extra_data = crate::crypto::sha256(&att_signed);

        // Use a wrong name (all zeros) so the check in step 4.d fails.
        let wrong_name = vec![0u8; 34];
        let cert_info = build_tpm_cert_info(&extra_data, &wrong_name);

        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (Value::Text("certInfo".to_string()), Value::Bytes(cert_info)),
            (Value::Text("pubArea".to_string()), Value::Bytes(pub_area)),
        ]);

        let result = verify(
            "tpm",
            &stmt,
            auth_data,
            &client_data_hash,
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("attested.name"))
        );
    }

    #[test]
    fn tpm_rejects_pub_area_key_mismatch() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
        let att_pub = kp.public_key().as_ref();
        let cert = make_fake_p256_cert(att_pub);

        // pubArea contains a different key (all zeros) than the credential key.
        let pub_area = build_tpm_ecc_pub_area(&[0u8; 32], &[0u8; 32]);
        let name = compute_pub_area_name(&pub_area).expect("test setup");

        let auth_data = b"auth-data";
        let client_data_hash = [0xCCu8; 32];
        let mut att_signed = auth_data.to_vec();
        att_signed.extend_from_slice(&client_data_hash);
        let extra_data = crate::crypto::sha256(&att_signed);
        let cert_info = build_tpm_cert_info(&extra_data, &name);

        // Credential key uses a non-zero x, y — mismatch with pubArea zeros.
        let cred_pub = kp.public_key().as_ref();
        let pk = PublicKey::ES256 {
            x: cred_pub[1..33].to_vec(),
            y: cred_pub[33..65].to_vec(),
        };

        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
            (Value::Text("sig".to_string()), Value::Bytes(vec![0u8; 64])),
            (Value::Text("certInfo".to_string()), Value::Bytes(cert_info)),
            (Value::Text("pubArea".to_string()), Value::Bytes(pub_area)),
        ]);

        let result = verify(
            "tpm",
            &stmt,
            auth_data,
            &client_data_hash,
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(
            matches!(result, Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("ES256"))
        );
    }

    #[test]
    fn tpm_rejects_bad_signature() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("test setup");
        let att_pub = kp.public_key().as_ref();
        let cert = make_fake_p256_cert(att_pub);

        let cred_pub = kp.public_key().as_ref();
        let pk = PublicKey::ES256 {
            x: cred_pub[1..33].to_vec(),
            y: cred_pub[33..65].to_vec(),
        };
        let pub_area = build_tpm_ecc_pub_area(&cred_pub[1..33], &cred_pub[33..65]);
        let name = compute_pub_area_name(&pub_area).expect("test setup");

        let auth_data = b"auth-data";
        let client_data_hash = [0xCCu8; 32];
        let mut att_signed = auth_data.to_vec();
        att_signed.extend_from_slice(&client_data_hash);
        let extra_data = crate::crypto::sha256(&att_signed);
        let cert_info = build_tpm_cert_info(&extra_data, &name);

        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
            (
                Value::Text("sig".to_string()),
                Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            ), // garbage
            (Value::Text("certInfo".to_string()), Value::Bytes(cert_info)),
            (Value::Text("pubArea".to_string()), Value::Bytes(pub_area)),
        ]);

        let result = verify(
            "tpm",
            &stmt,
            auth_data,
            &client_data_hash,
            &pk,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(matches!(
            result,
            Err(WebAuthnError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn tpm_valid_es256_returns_basic() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();

        // Attestation keypair (signs certInfo).
        let att_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let att_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, att_pkcs8.as_ref(), &rng)
                .expect("test setup");
        let att_pub = att_kp.public_key().as_ref();
        let cert = make_fake_p256_cert(att_pub);

        // Credential keypair (what gets attested — can differ from the AIK cert key).
        let cred_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let cred_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cred_pkcs8.as_ref(), &rng)
                .expect("test setup");
        let cred_pub = cred_kp.public_key().as_ref(); // 65 bytes: 0x04 || x || y
        let cred_x = cred_pub[1..33].to_vec();
        let cred_y = cred_pub[33..65].to_vec();
        let credential_public_key = PublicKey::ES256 {
            x: cred_x.clone(),
            y: cred_y.clone(),
        };

        let auth_data = b"fake-auth-data";
        let client_data_hash = [0xABu8; 32];

        // Build pubArea for the ES256 credential key.
        let pub_area = build_tpm_ecc_pub_area(&cred_x, &cred_y);

        // Compute the TPM name of pubArea: SHA-256 nameAlg → [0x00, 0x0B] || SHA-256(pubArea).
        let name = compute_pub_area_name(&pub_area).expect("test setup");

        // Compute extraData = SHA-256(authData || clientDataHash).
        let mut att_signed = auth_data.to_vec();
        att_signed.extend_from_slice(&client_data_hash);
        let extra_data = crate::crypto::sha256(&att_signed);

        // Build a valid certInfo (TPM2B_ATTEST).
        let cert_info = build_tpm_cert_info(&extra_data, &name);

        // Sign certInfo with the attestation key (not the credential key).
        let sig = att_kp.sign(&rng, &cert_info).expect("test setup");

        let stmt = Value::Map(vec![
            (
                Value::Text("ver".to_string()),
                Value::Text("2.0".to_string()),
            ),
            (
                Value::Text("alg".to_string()),
                Value::Integer((-7i64).into()),
            ),
            (
                Value::Text("x5c".to_string()),
                Value::Array(vec![Value::Bytes(cert)]),
            ),
            (
                Value::Text("sig".to_string()),
                Value::Bytes(sig.as_ref().to_vec()),
            ),
            (Value::Text("certInfo".to_string()), Value::Bytes(cert_info)),
            (Value::Text("pubArea".to_string()), Value::Bytes(pub_area)),
        ]);

        let result = verify(
            "tpm",
            &stmt,
            auth_data,
            &client_data_hash,
            &credential_public_key,
            &[],
            &[],
            &[0u8; 16],
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

    // ── x5c chain verification tests ─────────────────────────────────────────

    /// Build a self-signed CA certificate using rcgen.
    fn make_ca() -> (rcgen::KeyPair, rcgen::Certificate, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("test setup");
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("test setup");
        let der = cert.der().to_vec();
        (key, cert, der)
    }

    /// Build a leaf certificate signed by the given CA.
    fn make_leaf(issuer_cert: &rcgen::Certificate, issuer_key: &rcgen::KeyPair) -> Vec<u8> {
        let leaf_key = rcgen::KeyPair::generate().expect("test setup");
        rcgen::CertificateParams::default()
            .signed_by(&leaf_key, issuer_cert, issuer_key)
            .expect("test setup")
            .der()
            .to_vec()
    }

    /// Build an intermediate CA signed by the given root CA.
    fn make_intermediate(
        issuer_cert: &rcgen::Certificate,
        issuer_key: &rcgen::KeyPair,
    ) -> (rcgen::KeyPair, rcgen::Certificate, Vec<u8>) {
        let inter_key = rcgen::KeyPair::generate().expect("test setup");
        let mut p = rcgen::CertificateParams::default();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let inter_cert = p
            .signed_by(&inter_key, issuer_cert, issuer_key)
            .expect("test setup");
        let inter_der = inter_cert.der().to_vec();
        (inter_key, inter_cert, inter_der)
    }

    #[test]
    fn chain_single_self_signed_no_anchors_returns_basic() {
        let (_key, _cert, root_der) = make_ca();
        let result = verify_x5c_chain(&[root_der], &[]);
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    #[test]
    fn chain_leaf_and_root_no_anchors_returns_basic() {
        let (root_key, root_cert, root_der) = make_ca();
        let leaf_der = make_leaf(&root_cert, &root_key);
        let result = verify_x5c_chain(&[leaf_der, root_der], &[]);
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    #[test]
    fn chain_verified_to_trust_anchor_returns_basic_verified() {
        let (root_key, root_cert, root_der) = make_ca();
        let leaf_der = make_leaf(&root_cert, &root_key);
        let result = verify_x5c_chain(&[leaf_der, root_der.clone()], &[root_der]);
        assert!(matches!(result, Ok(AttestationType::BasicVerified)));
    }

    #[test]
    fn chain_order_failure_swapped_certs_returns_chain_invalid() {
        let (root_key, root_cert, root_der) = make_ca();
        let leaf_der = make_leaf(&root_cert, &root_key);
        // Swap: root first, leaf second — chain order is wrong.
        let result = verify_x5c_chain(&[root_der, leaf_der], &[]);
        assert!(matches!(
            result,
            Err(WebAuthnError::AttestationChainInvalid(_))
        ));
    }

    #[test]
    fn chain_root_not_in_trust_anchors_returns_root_untrusted() {
        let (root_key, root_cert, root_der) = make_ca();
        let leaf_der = make_leaf(&root_cert, &root_key);
        let (_other_key, _other_cert, other_root_der) = make_ca();
        let result = verify_x5c_chain(&[leaf_der, root_der], &[other_root_der]);
        assert!(matches!(
            result,
            Err(WebAuthnError::AttestationRootUntrusted)
        ));
    }

    #[test]
    fn chain_leaf_intermediate_root_no_anchors_returns_basic() {
        let (root_key, root_cert, root_der) = make_ca();
        let (inter_key, inter_cert, inter_der) = make_intermediate(&root_cert, &root_key);
        let leaf_der = make_leaf(&inter_cert, &inter_key);
        let result = verify_x5c_chain(&[leaf_der, inter_der, root_der], &[]);
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }

    #[test]
    fn chain_leaf_intermediate_root_with_anchor_returns_basic_verified() {
        let (root_key, root_cert, root_der) = make_ca();
        let (inter_key, inter_cert, inter_der) = make_intermediate(&root_cert, &root_key);
        let leaf_der = make_leaf(&inter_cert, &inter_key);
        let result = verify_x5c_chain(&[leaf_der, inter_der, root_der.clone()], &[root_der]);
        assert!(matches!(result, Ok(AttestationType::BasicVerified)));
    }

    #[test]
    fn packed_basic_attestation_with_trust_anchor_returns_basic_verified() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();

        // Generate the attestation keypair (signs authData || clientDataHash).
        let att_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let att_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, att_pkcs8.as_ref(), &rng)
                .expect("test setup");
        let att_pub = att_kp.public_key().as_ref();

        // Build a fake cert that has the ring EC P-256 key in its SPKI so our
        // extract_ec_p256_public_key_from_cert helper can find it.
        let fake_cert = make_fake_p256_cert(att_pub);

        let cred_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .expect("test setup");
        let cred_kp =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, cred_pkcs8.as_ref(), &rng)
                .expect("test setup");
        let cred_pub = cred_kp.public_key().as_ref();
        let credential_public_key = PublicKey::ES256 {
            x: cred_pub[1..33].to_vec(),
            y: cred_pub[33..65].to_vec(),
        };

        let auth_data = b"fake-auth-data";
        let client_data_hash = [0xABu8; 32];

        let mut verification_data = Vec::new();
        verification_data.extend_from_slice(auth_data);
        verification_data.extend_from_slice(&client_data_hash);
        let sig = att_kp.sign(&rng, &verification_data).expect("test setup");

        // No trust anchors → chain validated, Basic returned (fake_cert is not
        // parseable by x509-parser so the pair verification will fail; this
        // test only validates the trust-anchor path, so use a single-cert chain).
        let stmt_single = Value::Map(vec![
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
                Value::Array(vec![Value::Bytes(fake_cert)]),
            ),
        ]);

        // Single-cert chain: no pairs to verify, chain order trivially valid.
        // With no anchors → Basic.
        let result = verify(
            "packed",
            &stmt_single,
            auth_data,
            &client_data_hash,
            &credential_public_key,
            &[],
            &[],
            &[0u8; 16],
        );
        assert!(matches!(result, Ok(AttestationType::Basic)));
    }
}
