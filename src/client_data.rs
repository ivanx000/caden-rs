//! Parsing and validation of `clientDataJSON`.
//!
//! `clientDataJSON` is a JSON object produced by the browser that binds a
//! WebAuthn ceremony to a specific type, challenge, and origin. The relying
//! party must verify all three fields before accepting any ceremony.
//!
//! This module separates parsing from validation so that error messages can
//! name the exact failing field (type mismatch vs challenge mismatch vs origin
//! mismatch) rather than a generic "invalid client data".

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;

use crate::error::{WebAuthnError, Result};

// ─── Raw JSON structure ───────────────────────────────────────────────────────

/// The JSON fields we extract from `clientDataJSON`.
///
/// The spec allows additional fields (e.g. `tokenBinding`, extensions). We
/// accept and ignore them; serde's default behaviour handles this correctly.
#[derive(Debug, Deserialize)]
struct RawClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String, // base64url-encoded in the JSON
    origin: String,
    // crossOrigin is accepted but not validated; we ignore its value.
    #[allow(dead_code)]
    #[serde(rename = "crossOrigin")]
    cross_origin: Option<bool>,
}

// ─── Public types ─────────────────────────────────────────────────────────────

/// Decoded and structured `clientDataJSON` ready for validation.
#[derive(Debug)]
pub struct ParsedClientData {
    /// The ceremony type — `"webauthn.create"` or `"webauthn.get"`.
    pub type_: String,

    /// The raw challenge bytes (base64url-decoded from the JSON `challenge` field).
    pub challenge_bytes: Vec<u8>,

    /// The origin the client reports (e.g. `"https://example.com"`).
    pub origin: String,

    /// A copy of the original raw JSON bytes.
    ///
    /// Kept because `clientDataHash = SHA-256(clientDataJSON)` must be computed
    /// over the exact bytes as received — not a re-serialised version.
    pub raw_json: Vec<u8>,
}

// ─── Public functions ─────────────────────────────────────────────────────────

/// Decode and parse raw `clientDataJSON` bytes.
///
/// `raw` must be the UTF-8 JSON bytes — **not** base64url encoded. The caller
/// is responsible for base64url decoding the wire value before calling this.
///
/// Does **not** validate type, challenge, or origin — call [`validate_client_data`]
/// for that, so each check can produce a precise error.
///
/// # Errors
/// - [`WebAuthnError::InvalidClientData`] — JSON parse failure or missing fields.
/// - [`WebAuthnError::Base64DecodeError`] — challenge field is not valid base64url.
pub fn parse_client_data(raw: &[u8]) -> Result<ParsedClientData> {
    let rcd: RawClientData = serde_json::from_slice(raw)
        .map_err(|e| WebAuthnError::InvalidClientData(format!("JSON parse failed: {e}")))?;

    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&rcd.challenge)
        .map_err(|e| WebAuthnError::Base64DecodeError(format!("challenge field: {e}")))?;

    Ok(ParsedClientData {
        type_: rcd.type_,
        challenge_bytes,
        origin: rcd.origin,
        raw_json: raw.to_vec(),
    })
}

/// Validate the parsed client data against the expected ceremony parameters.
///
/// Checks (in order): ceremony type, challenge bytes, origin. Returns the first
/// mismatch found so the caller receives the most specific error available.
///
/// # Arguments
/// * `parsed`             — Output of [`parse_client_data`].
/// * `expected_type`      — `"webauthn.create"` or `"webauthn.get"`.
/// * `expected_challenge` — The raw challenge bytes the relying party issued.
/// * `expected_origin`    — Full origin of your web app, e.g. `"https://example.com"`.
///
/// # Errors
/// - [`WebAuthnError::InvalidClientData`] — type field does not match.
/// - [`WebAuthnError::ChallengeMismatch`] — challenge bytes do not match.
/// - [`WebAuthnError::OriginMismatch`]    — origin does not match.
pub fn validate_client_data(
    parsed: &ParsedClientData,
    expected_type: &str,
    expected_challenge: &[u8],
    expected_origin: &str,
) -> Result<()> {
    // Verify the ceremony type.
    if parsed.type_ != expected_type {
        return Err(WebAuthnError::InvalidClientData(format!(
            "expected type \"{expected_type}\", got \"{}\"",
            parsed.type_
        )));
    }

    // Verify the challenge matches byte-for-byte.
    if parsed.challenge_bytes != expected_challenge {
        return Err(WebAuthnError::ChallengeMismatch);
    }

    // Verify the origin.
    if parsed.origin != expected_origin {
        return Err(WebAuthnError::OriginMismatch {
            expected: expected_origin.to_string(),
            got: parsed.origin.clone(),
        });
    }

    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_raw(type_: &str, challenge_b64: &str, origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"{type_}","challenge":"{challenge_b64}","origin":"{origin}"}}"#
        )
        .into_bytes()
    }

    #[test]
    fn parses_valid_create() {
        let challenge_bytes = vec![1u8; 32];
        let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let raw = make_raw("webauthn.create", &challenge_b64, "https://example.com");

        let parsed = parse_client_data(&raw).unwrap();
        assert_eq!(parsed.type_, "webauthn.create");
        assert_eq!(parsed.challenge_bytes, challenge_bytes);
        assert_eq!(parsed.origin, "https://example.com");
        assert_eq!(parsed.raw_json, raw);
    }

    #[test]
    fn parses_valid_get() {
        let challenge_bytes = vec![2u8; 32];
        let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let raw = make_raw("webauthn.get", &challenge_b64, "https://example.com");

        let parsed = parse_client_data(&raw).unwrap();
        assert_eq!(parsed.type_, "webauthn.get");
    }

    #[test]
    fn rejects_invalid_json() {
        let result = parse_client_data(b"not json at all");
        assert!(matches!(result, Err(WebAuthnError::InvalidClientData(_))));
    }

    #[test]
    fn rejects_bad_challenge_encoding() {
        let raw = br#"{"type":"webauthn.create","challenge":"!!!","origin":"https://x.com"}"#;
        let result = parse_client_data(raw);
        assert!(matches!(result, Err(WebAuthnError::Base64DecodeError(_))));
    }

    #[test]
    fn validate_accepts_correct_fields() {
        let challenge = vec![0xABu8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.create", &b64, "https://example.com");
        let parsed = parse_client_data(&raw).unwrap();

        validate_client_data(&parsed, "webauthn.create", &challenge, "https://example.com")
            .unwrap();
    }

    #[test]
    fn validate_rejects_wrong_type() {
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.get", &b64, "https://example.com");
        let parsed = parse_client_data(&raw).unwrap();

        let err =
            validate_client_data(&parsed, "webauthn.create", &challenge, "https://example.com")
                .unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidClientData(_)));
    }

    #[test]
    fn validate_rejects_challenge_mismatch() {
        let challenge = vec![0xAAu8; 32];
        let wrong = vec![0xBBu8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.create", &b64, "https://example.com");
        let parsed = parse_client_data(&raw).unwrap();

        let err =
            validate_client_data(&parsed, "webauthn.create", &wrong, "https://example.com")
                .unwrap_err();
        assert!(matches!(err, WebAuthnError::ChallengeMismatch));
    }

    #[test]
    fn validate_rejects_origin_mismatch() {
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.create", &b64, "https://evil.com");
        let parsed = parse_client_data(&raw).unwrap();

        let err = validate_client_data(
            &parsed,
            "webauthn.create",
            &challenge,
            "https://example.com",
        )
        .unwrap_err();
        assert!(matches!(
            err,
            WebAuthnError::OriginMismatch { expected, got }
            if expected == "https://example.com" && got == "https://evil.com"
        ));
    }
}
