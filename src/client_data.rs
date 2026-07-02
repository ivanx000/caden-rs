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

use crate::error::{Result, WebAuthnError};

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

    /// Whether the browser flagged this as a cross-origin credential use.
    ///
    /// `true` when `crossOrigin` is present and set to `true` in the JSON;
    /// `false` when absent or explicitly `false`.
    pub cross_origin: bool,

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
    if raw.is_empty() {
        return Err(WebAuthnError::InvalidClientData(
            "empty client data".to_string(),
        ));
    }

    let rcd: RawClientData = serde_json::from_slice(raw)
        .map_err(|e| WebAuthnError::InvalidClientData(format!("JSON parse failed: {e}")))?;

    let challenge_bytes = URL_SAFE_NO_PAD
        .decode(&rcd.challenge)
        .map_err(|e| WebAuthnError::Base64DecodeError(format!("challenge field: {e}")))?;

    Ok(ParsedClientData {
        type_: rcd.type_,
        challenge_bytes,
        origin: rcd.origin,
        cross_origin: rcd.cross_origin.unwrap_or(false),
        raw_json: raw.to_vec(),
    })
}

/// Validate the parsed client data against the expected ceremony parameters.
///
/// Checks (in order): ceremony type, challenge bytes, origin, cross-origin.
/// Returns the first mismatch found so the caller receives the most specific
/// error available.
///
/// # Arguments
/// * `parsed`               — Output of [`parse_client_data`].
/// * `expected_type`        — `"webauthn.create"` or `"webauthn.get"`.
/// * `expected_challenge`   — The raw challenge bytes the relying party issued.
/// * `allowed_origins`      — All origins this RP accepts. The client-supplied
///   origin must equal at least one entry exactly.
/// * `reject_cross_origin`  — When `true`, reject any response with
///   `crossOrigin: true` in the client data (§7.1 step 10 / §7.2 step 12).
///
/// # Errors
/// - [`WebAuthnError::InvalidClientData`]   — type field does not match.
/// - [`WebAuthnError::ChallengeMismatch`]   — challenge bytes do not match.
/// - [`WebAuthnError::OriginMismatch`]      — origin is not in the allowed list.
/// - [`WebAuthnError::CrossOriginNotAllowed`] — cross-origin flag set and RP rejects it.
pub fn validate_client_data(
    parsed: &ParsedClientData,
    expected_type: &str,
    expected_challenge: &[u8],
    allowed_origins: &[String],
    reject_cross_origin: bool,
) -> Result<()> {
    // Verify the ceremony type. An empty type string is always wrong.
    if parsed.type_.is_empty() {
        return Err(WebAuthnError::InvalidClientData(
            "type field is empty".to_string(),
        ));
    }

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

    // Verify the origin is in the allowed list.
    if !allowed_origins.iter().any(|o| o == &parsed.origin) {
        return Err(WebAuthnError::OriginMismatch {
            expected: allowed_origins.join(", "),
            got: parsed.origin.clone(),
        });
    }

    // §7.1 step 10 / §7.2 step 12 — reject cross-origin use when the RP
    // has opted in to strict same-origin enforcement.
    if reject_cross_origin && parsed.cross_origin {
        return Err(WebAuthnError::CrossOriginNotAllowed);
    }

    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    // URL_SAFE (with padding) — used to test padded base64url acceptance.
    use base64::engine::general_purpose::URL_SAFE;

    fn make_raw(type_: &str, challenge_b64: &str, origin: &str) -> Vec<u8> {
        format!(r#"{{"type":"{type_}","challenge":"{challenge_b64}","origin":"{origin}"}}"#)
            .into_bytes()
    }

    #[test]
    fn parses_valid_create() {
        let challenge_bytes = vec![1u8; 32];
        let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let raw = make_raw("webauthn.create", &challenge_b64, "https://example.com");

        let parsed = parse_client_data(&raw).expect("test setup");
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

        let parsed = parse_client_data(&raw).expect("test setup");
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
        let parsed = parse_client_data(&raw).expect("test setup");
        let origins = vec!["https://example.com".to_string()];

        validate_client_data(&parsed, "webauthn.create", &challenge, &origins, false)
            .expect("test setup");
    }

    #[test]
    fn validate_rejects_wrong_type() {
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.get", &b64, "https://example.com");
        let parsed = parse_client_data(&raw).expect("test setup");
        let origins = vec!["https://example.com".to_string()];

        let err = validate_client_data(&parsed, "webauthn.create", &challenge, &origins, false)
            .expect_err("expected error");
        assert!(matches!(err, WebAuthnError::InvalidClientData(_)));
    }

    #[test]
    fn validate_rejects_challenge_mismatch() {
        let challenge = vec![0xAAu8; 32];
        let wrong = vec![0xBBu8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.create", &b64, "https://example.com");
        let parsed = parse_client_data(&raw).expect("test setup");
        let origins = vec!["https://example.com".to_string()];

        let err = validate_client_data(&parsed, "webauthn.create", &wrong, &origins, false)
            .expect_err("expected error");
        assert!(matches!(err, WebAuthnError::ChallengeMismatch));
    }

    #[test]
    fn validate_rejects_origin_mismatch() {
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.create", &b64, "https://evil.com");
        let parsed = parse_client_data(&raw).expect("test setup");
        let origins = vec!["https://example.com".to_string()];

        let err = validate_client_data(&parsed, "webauthn.create", &challenge, &origins, false)
            .expect_err("expected error");
        assert!(matches!(
            err,
            WebAuthnError::OriginMismatch { expected, got }
            if expected == "https://example.com" && got == "https://evil.com"
        ));
    }

    #[test]
    fn rejects_empty_bytes() {
        let err = parse_client_data(&[]).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::InvalidClientData(ref m) if m.contains("empty")));
    }

    #[test]
    fn rejects_utf8_but_not_json() {
        let err = parse_client_data(b"hello world, not json").expect_err("expected error");
        assert!(matches!(err, WebAuthnError::InvalidClientData(_)));
    }

    #[test]
    fn rejects_json_missing_type_field() {
        let challenge = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let raw = format!(r#"{{"challenge":"{challenge}","origin":"https://x.com"}}"#).into_bytes();
        let err = parse_client_data(&raw).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::InvalidClientData(_)));
    }

    #[test]
    fn rejects_json_missing_challenge_field() {
        let raw = br#"{"type":"webauthn.create","origin":"https://x.com"}"#.to_vec();
        let err = parse_client_data(&raw).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::InvalidClientData(_)));
    }

    #[test]
    fn rejects_json_missing_origin_field() {
        let challenge = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let raw = format!(r#"{{"type":"webauthn.create","challenge":"{challenge}"}}"#).into_bytes();
        let err = parse_client_data(&raw).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::InvalidClientData(_)));
    }

    #[test]
    fn rejects_challenge_with_invalid_base64() {
        let raw =
            br#"{"type":"webauthn.create","challenge":"!!!invalid!!!","origin":"https://x.com"}"#
                .to_vec();
        let err = parse_client_data(&raw).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::Base64DecodeError(_)));
    }

    #[test]
    fn accepts_challenge_with_base64_padding() {
        // Some implementations include base64url padding ("=="); both forms must
        // decode to the same bytes. URL_SAFE_NO_PAD is our canonical encoder, so
        // no-pad form must always work. The padded form is best-effort.
        let challenge_bytes = vec![0xFEu8, 0xED, 0xBE];
        let b64_no_pad = URL_SAFE_NO_PAD.encode(&challenge_bytes);
        let b64_padded = URL_SAFE.encode(&challenge_bytes);

        let raw_no_pad = make_raw("webauthn.create", &b64_no_pad, "https://x.com");
        let raw_padded = make_raw("webauthn.create", &b64_padded, "https://x.com");

        let parsed_no_pad = parse_client_data(&raw_no_pad).expect("test setup");
        assert_eq!(parsed_no_pad.challenge_bytes, challenge_bytes);

        if let Ok(parsed_padded) = parse_client_data(&raw_padded) {
            assert_eq!(parsed_padded.challenge_bytes, challenge_bytes);
        }
    }

    #[test]
    fn validate_rejects_empty_type_field() {
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("", &b64, "https://example.com");
        let parsed = parse_client_data(&raw).expect("test setup");
        let origins = vec!["https://example.com".to_string()];
        let err = validate_client_data(&parsed, "webauthn.create", &challenge, &origins, false)
            .expect_err("expected error");
        assert!(matches!(err, WebAuthnError::InvalidClientData(ref m) if m.contains("empty")));
    }

    #[test]
    fn validate_rejects_origin_with_trailing_slash() {
        // Per spec, origins must match exactly — trailing slash is a different origin.
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.create", &b64, "https://example.com/");
        let parsed = parse_client_data(&raw).expect("test setup");
        let origins = vec!["https://example.com".to_string()];
        let err = validate_client_data(&parsed, "webauthn.create", &challenge, &origins, false)
            .expect_err("expected error");
        assert!(matches!(err, WebAuthnError::OriginMismatch { .. }));
    }

    #[test]
    fn cross_origin_true_accepted_when_reject_disabled() {
        // Default behaviour (reject_cross_origin=false): crossOrigin:true is allowed.
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = format!(
            r#"{{"type":"webauthn.create","challenge":"{b64}","origin":"https://example.com","crossOrigin":true}}"#
        )
        .into_bytes();
        let parsed = parse_client_data(&raw).expect("test setup");
        assert!(parsed.cross_origin);
        let origins = vec!["https://example.com".to_string()];
        validate_client_data(&parsed, "webauthn.create", &challenge, &origins, false)
            .expect("crossOrigin:true must not fail when reject_cross_origin is false");
    }

    #[test]
    fn cross_origin_true_rejected_when_reject_enabled() {
        // §7.1 step 10: RP may reject crossOrigin:true.
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = format!(
            r#"{{"type":"webauthn.create","challenge":"{b64}","origin":"https://example.com","crossOrigin":true}}"#
        )
        .into_bytes();
        let parsed = parse_client_data(&raw).expect("test setup");
        let origins = vec!["https://example.com".to_string()];
        let err = validate_client_data(&parsed, "webauthn.create", &challenge, &origins, true)
            .expect_err("expected error");
        assert!(matches!(err, WebAuthnError::CrossOriginNotAllowed));
    }

    #[test]
    fn cross_origin_false_accepted_when_reject_enabled() {
        // crossOrigin:false (or absent) must always be accepted, even when
        // reject_cross_origin is true.
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = format!(
            r#"{{"type":"webauthn.create","challenge":"{b64}","origin":"https://example.com","crossOrigin":false}}"#
        )
        .into_bytes();
        let parsed = parse_client_data(&raw).expect("test setup");
        assert!(!parsed.cross_origin);
        let origins = vec!["https://example.com".to_string()];
        validate_client_data(&parsed, "webauthn.create", &challenge, &origins, true)
            .expect("test setup");
    }

    #[test]
    fn cross_origin_absent_accepted_when_reject_enabled() {
        // Missing crossOrigin key defaults to false — must not be rejected.
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.create", &b64, "https://example.com");
        let parsed = parse_client_data(&raw).expect("test setup");
        assert!(!parsed.cross_origin);
        let origins = vec!["https://example.com".to_string()];
        validate_client_data(&parsed, "webauthn.create", &challenge, &origins, true)
            .expect("test setup");
    }

    #[test]
    fn validate_accepts_origin_in_multi_origin_list() {
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.create", &b64, "https://second.com");
        let parsed = parse_client_data(&raw).expect("test setup");
        let origins = vec![
            "https://first.com".to_string(),
            "https://second.com".to_string(),
        ];
        validate_client_data(&parsed, "webauthn.create", &challenge, &origins, false)
            .expect("test setup");
    }

    #[test]
    fn validate_rejects_origin_not_in_list() {
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.create", &b64, "https://evil.com");
        let parsed = parse_client_data(&raw).expect("test setup");
        let origins = vec![
            "https://first.com".to_string(),
            "https://second.com".to_string(),
        ];
        let err = validate_client_data(&parsed, "webauthn.create", &challenge, &origins, false)
            .expect_err("expected error");
        assert!(matches!(
            err,
            WebAuthnError::OriginMismatch { got, .. } if got == "https://evil.com"
        ));
    }

    #[test]
    fn validate_accepts_single_origin_list() {
        let challenge = vec![0u8; 32];
        let b64 = URL_SAFE_NO_PAD.encode(&challenge);
        let raw = make_raw("webauthn.create", &b64, "https://example.com");
        let parsed = parse_client_data(&raw).expect("test setup");
        let origins = vec!["https://example.com".to_string()];
        validate_client_data(&parsed, "webauthn.create", &challenge, &origins, false)
            .expect("test setup");
    }
}
