//! FIDO Alliance Metadata Service (MDS) status consumption.
//!
//! WebAuthn §14.4 ("Metadata Service Considerations") recommends that a
//! relying party consult the [FIDO Metadata Service](https://fidoalliance.org/metadata/)
//! to check whether an authenticator model is known to be compromised before
//! trusting a newly registered credential. `caden` does not fetch the MDS
//! BLOB itself — that requires network access, which would break the
//! library's stateless, I/O-free design (see [`crate::RelyingParty`]). The
//! caller performs the HTTP GET (e.g. from a scheduled job) and passes the
//! raw JWT string to [`verify_and_parse_mds_blob`], which verifies the JWS
//! signature and certificate chain (FIDO MDS3 §3.2) and parses the payload
//! (FIDO MDS3 §3.3) into per-AAGUID [`AuthenticatorStatus`] lists ready for
//! [`crate::RelyingParty::authenticator_metadata`].
//!
//! Only the status values that FIDO Alliance recommends treating as
//! disqualifying are enforced automatically ([`AuthenticatorStatus::is_compromised`]);
//! the caller decides how to source and refresh the underlying MDS data.

use std::collections::HashMap;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use serde::Deserialize;

use crate::attestation::{
    cert_signed_by, extract_ec_p256_public_key_from_cert, verify_chain_order,
};
use crate::crypto::verify_es256_jws;
use crate::error::{Result, WebAuthnError};

/// The status of an authenticator model as reported by the FIDO Metadata
/// Service `StatusReport` structure.
///
/// This mirrors the `AuthenticatorStatus` enum from the [FIDO Metadata
/// Service specification](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#authenticatorstatus-enum).
/// New statuses may be added by FIDO Alliance over time, so this type is
/// `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum AuthenticatorStatus {
    /// The authenticator is not FIDO certified.
    NotFidoCertified,
    /// The authenticator is FIDO certified.
    FidoCertified,
    /// A compromise of the authenticator's user verification method
    /// (fingerprint, PIN, etc.) has been discovered. Attestations from this
    /// model can no longer be trusted to prove the claimed user verification
    /// actually occurred.
    UserVerificationBypass,
    /// The attestation key for this authenticator model is known to be
    /// compromised. Attestation signatures from this model can no longer be
    /// trusted to prove authenticator provenance.
    AttestationKeyCompromise,
    /// A remote (software) compromise of the authenticator's user key has
    /// been discovered — an attacker can extract or use the private key
    /// without physical access to the device.
    UserKeyRemoteCompromise,
    /// A physical compromise of the authenticator's user key has been
    /// discovered — an attacker with physical access can extract or use the
    /// private key.
    UserKeyPhysicalCompromise,
    /// A software or firmware update is available that addresses a known
    /// issue; not itself a compromise.
    UpdateAvailable,
    /// The authenticator model has been revoked by the vendor or FIDO
    /// Alliance and must no longer be trusted.
    Revoked,
    /// The authenticator vendor has self-asserted certification without
    /// completing the FIDO Alliance certification process.
    SelfAssertionSubmitted,
    /// FIDO certified at Authenticator Certification Level 1.
    FidoCertifiedL1,
    /// FIDO certified at Authenticator Certification Level 1+.
    FidoCertifiedL1Plus,
    /// FIDO certified at Authenticator Certification Level 2.
    FidoCertifiedL2,
    /// FIDO certified at Authenticator Certification Level 2+.
    FidoCertifiedL2Plus,
    /// FIDO certified at Authenticator Certification Level 3.
    FidoCertifiedL3,
    /// FIDO certified at Authenticator Certification Level 3+.
    FidoCertifiedL3Plus,
}

impl AuthenticatorStatus {
    /// Whether this status indicates the authenticator model should no
    /// longer be trusted for new registrations.
    ///
    /// This is the set of statuses the FIDO Alliance MDS specification
    /// identifies as evidence of an actual security compromise —
    /// [`Revoked`](Self::Revoked),
    /// [`AttestationKeyCompromise`](Self::AttestationKeyCompromise),
    /// [`UserKeyRemoteCompromise`](Self::UserKeyRemoteCompromise),
    /// [`UserKeyPhysicalCompromise`](Self::UserKeyPhysicalCompromise), and
    /// [`UserVerificationBypass`](Self::UserVerificationBypass). Certification
    /// tier and informational statuses (e.g. `UpdateAvailable`,
    /// `NotFidoCertified`) do not indicate compromise on their own.
    pub fn is_compromised(&self) -> bool {
        matches!(
            self,
            Self::Revoked
                | Self::AttestationKeyCompromise
                | Self::UserKeyRemoteCompromise
                | Self::UserKeyPhysicalCompromise
                | Self::UserVerificationBypass
        )
    }
}

impl std::fmt::Display for AuthenticatorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NotFidoCertified => "NOT_FIDO_CERTIFIED",
            Self::FidoCertified => "FIDO_CERTIFIED",
            Self::UserVerificationBypass => "USER_VERIFICATION_BYPASS",
            Self::AttestationKeyCompromise => "ATTESTATION_KEY_COMPROMISE",
            Self::UserKeyRemoteCompromise => "USER_KEY_REMOTE_COMPROMISE",
            Self::UserKeyPhysicalCompromise => "USER_KEY_PHYSICAL_COMPROMISE",
            Self::UpdateAvailable => "UPDATE_AVAILABLE",
            Self::Revoked => "REVOKED",
            Self::SelfAssertionSubmitted => "SELF_ASSERTION_SUBMITTED",
            Self::FidoCertifiedL1 => "FIDO_CERTIFIED_L1",
            Self::FidoCertifiedL1Plus => "FIDO_CERTIFIED_L1plus",
            Self::FidoCertifiedL2 => "FIDO_CERTIFIED_L2",
            Self::FidoCertifiedL2Plus => "FIDO_CERTIFIED_L2plus",
            Self::FidoCertifiedL3 => "FIDO_CERTIFIED_L3",
            Self::FidoCertifiedL3Plus => "FIDO_CERTIFIED_L3plus",
        };
        f.write_str(s)
    }
}

/// FIDO MDS3 §3.2 — JOSE header of the MDS BLOB's JWT Compact Serialization.
/// Only the fields needed to verify the signature are modeled.
#[derive(Deserialize)]
struct MdsJoseHeader {
    alg: String,
    #[serde(default)]
    x5c: Vec<String>,
}

/// FIDO MDS3 §3.3 — `MetadataBLOBPayload`. Only `entries` is modeled; the
/// large surrounding schema (`legalHeader`, `no`, `nextUpdate`, etc.) is out
/// of scope for this library.
#[derive(Deserialize)]
struct MdsBlobPayload {
    #[serde(default)]
    entries: Vec<MdsEntry>,
}

/// FIDO MDS3 §3.3 — one `MetadataBLOBPayloadEntry`. Only `aaguid` and
/// `statusReports[].status` are modeled; `metadataStatement` and the rest of
/// the entry schema are out of scope.
#[derive(Deserialize)]
struct MdsEntry {
    aaguid: Option<String>,
    #[serde(default, rename = "statusReports")]
    status_reports: Vec<MdsStatusReport>,
}

/// FIDO MDS3 §3.3 — one `StatusReport`. Only `status` is modeled.
#[derive(Deserialize)]
struct MdsStatusReport {
    status: String,
}

/// Verify and parse a FIDO Metadata Service BLOB (FIDO MDS3 §3.2), returning
/// a `{ aaguid → statuses }` map ready to pass to
/// [`crate::RelyingParty::authenticator_metadata`].
///
/// `blob` is the raw JWT Compact Serialization string as served (in
/// production) from <https://mds3.fidoalliance.org/>. `trust_root` is the
/// DER-encoded FIDO Alliance MDS root CA certificate (or a caller-chosen
/// substitute, e.g. in tests) that the BLOB's `x5c` chain must root to. This
/// function does not perform the HTTP fetch — the caller is responsible for
/// that, keeping `caden` stateless and I/O-free (see the module docs).
///
/// # Verification steps
/// 1. Split `blob` into `header.payload.signature` (exactly 3 dot-separated
///    segments).
/// 2. Base64url-decode the header and payload segments.
/// 3. Parse the header JSON; require `alg == "ES256"` and a non-empty `x5c`.
/// 4. Base64-decode (standard alphabet, *not* base64url — RFC 7515 §4.1.6)
///    each `x5c` entry into DER bytes.
/// 5. Verify the `x5c` chain order (leaf-first) and that its root is signed
///    by `trust_root`.
/// 6. Verify the ES256 signature — JWS raw `r || s` encoding per RFC 7518
///    §3.4, *not* the DER/ASN.1 encoding WebAuthn ceremony signatures use —
///    over `b64url(header) || "." || b64url(payload)` using `x5c[0]`'s
///    public key.
/// 7. Parse the payload JSON and map each entry's `aaguid` and
///    `statusReports[].status` into the result.
///
/// # Status parsing policy
/// [`AuthenticatorStatus`] is `#[non_exhaustive]` precisely because MDS may
/// introduce new status strings over time. An entry with an unrecognized
/// status string does **not** fail the whole BLOB, or even drop that AAGUID's
/// entry — only the unrecognized status is skipped, and the AAGUID's other
/// (recognized) statuses are still returned. An entry with a missing or
/// malformed `aaguid` is skipped entirely, since there's nothing to key the
/// result map by.
///
/// # Errors
/// Returns [`WebAuthnError::MdsBlobMalformed`] if the JWT structure, base64
/// encoding, or JSON does not match the expected format.
/// Returns [`WebAuthnError::MdsChainInvalid`] if the `x5c` chain order is
/// broken.
/// Returns [`WebAuthnError::MdsRootUntrusted`] if the chain does not root to
/// `trust_root`.
/// Returns [`WebAuthnError::MdsSignatureInvalid`] if the ES256 signature does
/// not verify.
pub fn verify_and_parse_mds_blob(
    blob: &str,
    trust_root: &[u8],
) -> Result<HashMap<[u8; 16], Vec<AuthenticatorStatus>>> {
    // FIDO MDS3 §3.2 — the BLOB is a JWT in Compact Serialization:
    // b64url(header) "." b64url(payload) "." b64url(signature).
    let segments: Vec<&str> = blob.split('.').collect();
    let [header_b64, payload_b64, sig_b64] = segments[..] else {
        return Err(WebAuthnError::MdsBlobMalformed(format!(
            "expected 3 dot-separated JWT segments, got {}",
            segments.len()
        )));
    };

    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|e| {
        WebAuthnError::MdsBlobMalformed(format!("failed to base64url-decode JOSE header: {e}"))
    })?;
    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|e| {
        WebAuthnError::MdsBlobMalformed(format!("failed to base64url-decode payload: {e}"))
    })?;
    let signature = URL_SAFE_NO_PAD.decode(sig_b64).map_err(|e| {
        WebAuthnError::MdsBlobMalformed(format!("failed to base64url-decode signature: {e}"))
    })?;

    let header: MdsJoseHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
        WebAuthnError::MdsBlobMalformed(format!("failed to parse JOSE header JSON: {e}"))
    })?;

    // FIDO MDS3 §3.2 mandates ES256; this is the only alg this library verifies.
    if header.alg != "ES256" {
        return Err(WebAuthnError::MdsBlobMalformed(format!(
            "unsupported JWS alg \"{}\", expected \"ES256\"",
            header.alg
        )));
    }
    if header.x5c.is_empty() {
        return Err(WebAuthnError::MdsBlobMalformed(
            "JOSE header x5c must be a non-empty certificate chain".to_string(),
        ));
    }

    // RFC 7515 §4.1.6 — x5c entries are standard (padded) base64, NOT
    // base64url, unlike the header/payload/signature segments themselves.
    let certs: Vec<Vec<u8>> = header
        .x5c
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            STANDARD.decode(entry).map_err(|e| {
                WebAuthnError::MdsBlobMalformed(format!("failed to base64-decode x5c[{i}]: {e}"))
            })
        })
        .collect::<Result<_>>()?;

    // FIDO MDS3 §3.2 — verify the x5c chain order and that the root is signed
    // by the caller-supplied trust anchor (mandatory — see MdsRootUntrusted).
    verify_chain_order(&certs, WebAuthnError::MdsChainInvalid)?;
    let root_der = certs
        .last()
        .expect("certs is non-empty: header.x5c was checked non-empty above");
    if !cert_signed_by(root_der, trust_root) {
        return Err(WebAuthnError::MdsRootUntrusted);
    }

    // FIDO MDS3 §3.2 — verify the ES256 signature (JWS raw r||s encoding)
    // over `b64url(header) || "." || b64url(payload)` using x5c[0]'s key.
    let signing_input = format!("{header_b64}.{payload_b64}");
    let leaf_pk = extract_ec_p256_public_key_from_cert(&certs[0])?;
    verify_es256_jws(&leaf_pk, signing_input.as_bytes(), &signature)
        .map_err(|_| WebAuthnError::MdsSignatureInvalid)?;

    // FIDO MDS3 §3.3 — parse the payload; only entries[].aaguid and
    // entries[].statusReports[].status are consumed.
    let payload: MdsBlobPayload = serde_json::from_slice(&payload_bytes).map_err(|e| {
        WebAuthnError::MdsBlobMalformed(format!("failed to parse BLOB payload JSON: {e}"))
    })?;

    let mut result: HashMap<[u8; 16], Vec<AuthenticatorStatus>> = HashMap::new();
    for entry in payload.entries {
        let Some(aaguid_str) = entry.aaguid else {
            continue;
        };
        let Some(aaguid) = parse_aaguid(&aaguid_str) else {
            continue;
        };
        // Unrecognized status strings are skipped individually rather than
        // dropping the entry or failing the BLOB — see the policy note above.
        let statuses = entry
            .status_reports
            .iter()
            .filter_map(|report| status_from_wire(&report.status));
        result.entry(aaguid).or_default().extend(statuses);
    }

    Ok(result)
}

/// Parse a hyphenated UUID string (e.g.
/// `"12345678-1234-1234-1234-123456789abc"`) into 16 raw bytes. Returns
/// `None` on any malformed input; callers skip the containing entry rather
/// than failing the whole BLOB (see [`verify_and_parse_mds_blob`]'s status
/// parsing policy).
fn parse_aaguid(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

/// Map an MDS wire status string (e.g. `"REVOKED"`) to [`AuthenticatorStatus`].
/// Returns `None` for strings this library does not recognize — the inverse
/// of [`AuthenticatorStatus`]'s `Display` impl.
fn status_from_wire(s: &str) -> Option<AuthenticatorStatus> {
    Some(match s {
        "NOT_FIDO_CERTIFIED" => AuthenticatorStatus::NotFidoCertified,
        "FIDO_CERTIFIED" => AuthenticatorStatus::FidoCertified,
        "USER_VERIFICATION_BYPASS" => AuthenticatorStatus::UserVerificationBypass,
        "ATTESTATION_KEY_COMPROMISE" => AuthenticatorStatus::AttestationKeyCompromise,
        "USER_KEY_REMOTE_COMPROMISE" => AuthenticatorStatus::UserKeyRemoteCompromise,
        "USER_KEY_PHYSICAL_COMPROMISE" => AuthenticatorStatus::UserKeyPhysicalCompromise,
        "UPDATE_AVAILABLE" => AuthenticatorStatus::UpdateAvailable,
        "REVOKED" => AuthenticatorStatus::Revoked,
        "SELF_ASSERTION_SUBMITTED" => AuthenticatorStatus::SelfAssertionSubmitted,
        "FIDO_CERTIFIED_L1" => AuthenticatorStatus::FidoCertifiedL1,
        "FIDO_CERTIFIED_L1plus" => AuthenticatorStatus::FidoCertifiedL1Plus,
        "FIDO_CERTIFIED_L2" => AuthenticatorStatus::FidoCertifiedL2,
        "FIDO_CERTIFIED_L2plus" => AuthenticatorStatus::FidoCertifiedL2Plus,
        "FIDO_CERTIFIED_L3" => AuthenticatorStatus::FidoCertifiedL3,
        "FIDO_CERTIFIED_L3plus" => AuthenticatorStatus::FidoCertifiedL3Plus,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compromise_statuses_are_flagged() {
        assert!(AuthenticatorStatus::Revoked.is_compromised());
        assert!(AuthenticatorStatus::AttestationKeyCompromise.is_compromised());
        assert!(AuthenticatorStatus::UserKeyRemoteCompromise.is_compromised());
        assert!(AuthenticatorStatus::UserKeyPhysicalCompromise.is_compromised());
        assert!(AuthenticatorStatus::UserVerificationBypass.is_compromised());
    }

    #[test]
    fn informational_statuses_are_not_flagged() {
        assert!(!AuthenticatorStatus::NotFidoCertified.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertified.is_compromised());
        assert!(!AuthenticatorStatus::UpdateAvailable.is_compromised());
        assert!(!AuthenticatorStatus::SelfAssertionSubmitted.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL1.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL1Plus.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL2.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL2Plus.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL3.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL3Plus.is_compromised());
    }

    #[test]
    fn display_matches_mds_wire_names() {
        assert_eq!(AuthenticatorStatus::Revoked.to_string(), "REVOKED");
        assert_eq!(
            AuthenticatorStatus::FidoCertifiedL1Plus.to_string(),
            "FIDO_CERTIFIED_L1plus"
        );
    }

    // ── verify_and_parse_mds_blob ────────────────────────────────────────────

    /// Build a self-signed CA certificate using rcgen — stands in for the
    /// FIDO Alliance MDS root CA.
    fn make_root() -> (rcgen::KeyPair, rcgen::Certificate, Vec<u8>) {
        let key = rcgen::KeyPair::generate().expect("test setup");
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("test setup");
        let der = cert.der().to_vec();
        (key, cert, der)
    }

    /// Build a leaf certificate signed by the given issuer — stands in for
    /// the MDS BLOB signer certificate (x5c[0]).
    fn make_signing_leaf(
        issuer_cert: &rcgen::Certificate,
        issuer_key: &rcgen::KeyPair,
    ) -> (rcgen::KeyPair, Vec<u8>) {
        let leaf_key = rcgen::KeyPair::generate().expect("test setup");
        let der = rcgen::CertificateParams::default()
            .signed_by(&leaf_key, issuer_cert, issuer_key)
            .expect("test setup")
            .der()
            .to_vec();
        (leaf_key, der)
    }

    /// Sign `message` with `leaf_key`'s private key in JWS "fixed" (raw
    /// r||s) ES256 encoding — matches what `verify_and_parse_mds_blob` expects
    /// per RFC 7518 §3.4. rcgen's default (ring-backed) key pairs generate
    /// their PKCS#8 document via `ring::signature::EcdsaKeyPair::generate_pkcs8`
    /// internally, so it loads directly into a ring `EcdsaKeyPair` here.
    fn jws_sign(leaf_key: &rcgen::KeyPair, message: &[u8]) -> Vec<u8> {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

        let rng = SystemRandom::new();
        let kp = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            leaf_key.serialized_der(),
            &rng,
        )
        .expect("test setup");
        kp.sign(&rng, message)
            .expect("test setup")
            .as_ref()
            .to_vec()
    }

    /// Build a complete, validly-signed MDS BLOB JWT for the given leaf
    /// signing key, leaf-first DER certificate chain, and payload JSON.
    fn build_blob(leaf_key: &rcgen::KeyPair, chain_der: &[Vec<u8>], payload_json: &str) -> String {
        let x5c: Vec<String> = chain_der.iter().map(|c| STANDARD.encode(c)).collect();
        let header_json = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "x5c": x5c,
        })
        .to_string();

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = jws_sign(leaf_key, signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

        format!("{header_b64}.{payload_b64}.{sig_b64}")
    }

    const TEST_AAGUID: &str = "12345678-1234-1234-1234-123456789abc";
    const TEST_AAGUID_BYTES: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc,
    ];

    #[test]
    fn valid_blob_round_trips_into_hashmap() {
        let (root_key, root_cert, root_der) = make_root();
        let (leaf_key, leaf_der) = make_signing_leaf(&root_cert, &root_key);

        let payload = serde_json::json!({
            "entries": [
                {
                    "aaguid": TEST_AAGUID,
                    "statusReports": [{ "status": "REVOKED" }],
                }
            ]
        })
        .to_string();

        let blob = build_blob(&leaf_key, &[leaf_der, root_der.clone()], &payload);

        let result = verify_and_parse_mds_blob(&blob, &root_der).expect("valid blob should parse");
        assert_eq!(
            result.get(&TEST_AAGUID_BYTES),
            Some(&vec![AuthenticatorStatus::Revoked])
        );
    }

    #[test]
    fn bad_signature_rejected() {
        let (root_key, root_cert, root_der) = make_root();
        let (leaf_key, leaf_der) = make_signing_leaf(&root_cert, &root_key);

        let payload = serde_json::json!({ "entries": [] }).to_string();
        let mut blob = build_blob(&leaf_key, &[leaf_der, root_der.clone()], &payload);

        // Tamper with the payload segment after signing so the signature no
        // longer matches — the segments are still valid base64url/JSON.
        let parts: Vec<&str> = blob.split('.').collect();
        let tampered_payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({ "entries": [], "tampered": true })
                .to_string()
                .as_bytes(),
        );
        blob = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let err = verify_and_parse_mds_blob(&blob, &root_der).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::MdsSignatureInvalid));
    }

    #[test]
    fn untrusted_root_rejected() {
        let (root_key, root_cert, root_der) = make_root();
        let (leaf_key, leaf_der) = make_signing_leaf(&root_cert, &root_key);
        let (_other_key, _other_cert, other_root_der) = make_root();

        let payload = serde_json::json!({ "entries": [] }).to_string();
        let blob = build_blob(&leaf_key, &[leaf_der, root_der], &payload);

        let err = verify_and_parse_mds_blob(&blob, &other_root_der).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::MdsRootUntrusted));
    }

    #[test]
    fn malformed_base64_in_header_rejected() {
        let blob = "not-valid-base64!!!.eyJ9.eyJ9";
        let err = verify_and_parse_mds_blob(blob, &[]).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::MdsBlobMalformed(_)));
    }

    #[test]
    fn malformed_json_payload_rejected() {
        let (root_key, root_cert, root_der) = make_root();
        let (leaf_key, leaf_der) = make_signing_leaf(&root_cert, &root_key);

        // Valid base64url but not valid JSON.
        let not_json_b64 = URL_SAFE_NO_PAD.encode(b"not json at all");
        let x5c: Vec<String> = [leaf_der, root_der.clone()]
            .iter()
            .map(|c| STANDARD.encode(c))
            .collect();
        let header_json = serde_json::json!({ "alg": "ES256", "x5c": x5c }).to_string();
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let signing_input = format!("{header_b64}.{not_json_b64}");
        let sig_b64 = URL_SAFE_NO_PAD.encode(jws_sign(&leaf_key, signing_input.as_bytes()));
        let blob = format!("{header_b64}.{not_json_b64}.{sig_b64}");

        let err = verify_and_parse_mds_blob(&blob, &root_der).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::MdsBlobMalformed(_)));
    }

    #[test]
    fn wrong_segment_count_rejected() {
        let err = verify_and_parse_mds_blob("only.two", &[]).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::MdsBlobMalformed(_)));
    }

    #[test]
    fn unrecognized_status_skipped_without_breaking_other_entries() {
        let (root_key, root_cert, root_der) = make_root();
        let (leaf_key, leaf_der) = make_signing_leaf(&root_cert, &root_key);

        const OTHER_AAGUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        const OTHER_AAGUID_BYTES: [u8; 16] = [
            0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xcc, 0xcc, 0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee,
            0xee, 0xee,
        ];

        let payload = serde_json::json!({
            "entries": [
                {
                    "aaguid": TEST_AAGUID,
                    "statusReports": [
                        { "status": "REVOKED" },
                        { "status": "SOME_FUTURE_STATUS_NOT_YET_DEFINED" },
                    ],
                },
                {
                    "aaguid": OTHER_AAGUID,
                    "statusReports": [{ "status": "FIDO_CERTIFIED_L1" }],
                }
            ]
        })
        .to_string();

        let blob = build_blob(&leaf_key, &[leaf_der, root_der.clone()], &payload);
        let result = verify_and_parse_mds_blob(&blob, &root_der).expect("valid blob should parse");

        // The unrecognized status is skipped, but REVOKED (from the same
        // entry) is kept — the entry itself is not dropped.
        assert_eq!(
            result.get(&TEST_AAGUID_BYTES),
            Some(&vec![AuthenticatorStatus::Revoked])
        );
        // The second, unrelated entry is unaffected.
        assert_eq!(
            result.get(&OTHER_AAGUID_BYTES),
            Some(&vec![AuthenticatorStatus::FidoCertifiedL1])
        );
    }

    #[test]
    fn x5c_encoded_as_base64url_instead_of_standard_is_rejected() {
        // RFC 7515 §4.1.6: x5c entries are standard (padded) base64, NOT
        // base64url. Encoding them with the URL-safe alphabet instead is
        // exactly the bug this test guards against — it must not silently
        // verify.
        let (root_key, root_cert, root_der) = make_root();
        let (leaf_key, leaf_der) = make_signing_leaf(&root_cert, &root_key);

        let x5c: Vec<String> = [leaf_der, root_der.clone()]
            .iter()
            .map(|c| URL_SAFE_NO_PAD.encode(c))
            .collect();
        let header_json = serde_json::json!({ "alg": "ES256", "x5c": x5c }).to_string();
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

        let payload_json = serde_json::json!({ "entries": [] }).to_string();
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_b64 = URL_SAFE_NO_PAD.encode(jws_sign(&leaf_key, signing_input.as_bytes()));
        let blob = format!("{header_b64}.{payload_b64}.{sig_b64}");

        let result = verify_and_parse_mds_blob(&blob, &root_der);
        assert!(
            result.is_err(),
            "x5c encoded as base64url must not verify as if it were standard base64"
        );
    }
}
