//! Registration ceremony — W3C WebAuthn §7.1.
//!
//! The registration ceremony is how a user's authenticator creates a new
//! credential and proves it to the relying party. The relying party verifies:
//!
//! 1. The response was produced for *this* challenge and *this* origin.
//! 2. The authenticator data is bound to *this* RP ID.
//! 3. The public key is valid and can be stored for future authentication.
//!
//! Spec: <https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential>

use ciborium::value::Value;
use std::time::SystemTime;

use crate::algorithm::{COSE_EDDSA, COSE_ES256};
use crate::attestation;
use crate::authenticator_data::{self, CoseKey};
use crate::challenge::CHALLENGE_MAX_AGE_SECS;
use crate::client_data;
use crate::credential::{
    AuthenticatorAttestationResponse, Challenge, Credential, PublicKey, RegistrationResult,
};
use crate::crypto::sha256;
use crate::error::{Result, WebAuthnError};

// ─── RelyingParty ─────────────────────────────────────────────────────────────

/// The relying party — your server application.
///
/// `RelyingParty` is the main entry point for ceremony verification. It is
/// stateless with respect to credentials; callers pass in the data and receive
/// result types back. This keeps the library storage-agnostic.
///
/// Create one instance per application configuration and reuse it across
/// ceremonies. `RelyingParty` is `Clone`, so it can be shared via `Arc` in
/// an async context.
///
/// # Example
///
/// ```rust,no_run
/// use webauthn::RelyingParty;
///
/// // Single origin — typical production setup.
/// let rp = RelyingParty::new("example.com", "https://example.com", "My Service");
///
/// // Multiple origins — e.g. prod + local dev in one instance.
/// let rp = RelyingParty::with_origins(
///     "example.com",
///     ["https://example.com", "http://localhost:8080"],
///     "My Service",
/// );
/// ```
#[derive(Debug, Clone)]
pub struct RelyingParty {
    /// Relying party ID, e.g. `"example.com"`.
    ///
    /// Must match the `rpId` used in the browser's
    /// `navigator.credentials.create()` / `get()` call options.
    pub id: String,

    /// The set of origins this RP accepts, e.g. `["https://example.com"]`.
    ///
    /// Each entry must match `window.location.origin` exactly — scheme, host,
    /// and port all matter. A client-supplied origin is accepted if it equals
    /// any entry in this list.
    pub allowed_origins: Vec<String>,

    /// Human-readable name shown to users, e.g. `"My Service"`.
    pub name: String,

    /// Whether the UV (User Verification) flag must be set in every
    /// authentication assertion. Defaults to `false`.
    ///
    /// Set to `true` when your threat model requires the authenticator to
    /// verify the user's identity (PIN, biometric, pattern) on every sign-in.
    /// See [`RelyingParty::require_user_verification`] to enable this at
    /// construction time using the builder pattern.
    pub require_user_verification: bool,
}

impl RelyingParty {
    /// Create a new `RelyingParty` that accepts a single origin.
    ///
    /// # Arguments
    /// * `id`     — Relying party ID, e.g. `"example.com"`.
    /// * `origin` — Full app origin, e.g. `"https://example.com"`.
    /// * `name`   — Human-readable service name.
    pub fn new(id: &str, origin: &str, name: &str) -> Self {
        Self {
            id: id.to_string(),
            allowed_origins: vec![origin.to_string()],
            name: name.to_string(),
            require_user_verification: false,
        }
    }

    /// Create a new `RelyingParty` that accepts multiple origins.
    ///
    /// Use this when your app is served from more than one origin — for example,
    /// `https://example.com` in production and `http://localhost:8080` in
    /// development — and you want a single `RelyingParty` instance to handle
    /// both environments.
    ///
    /// # Arguments
    /// * `id`      — Relying party ID, e.g. `"example.com"`.
    /// * `origins` — Iterator of accepted origins.
    /// * `name`    — Human-readable service name.
    pub fn with_origins(
        id: &str,
        origins: impl IntoIterator<Item = impl Into<String>>,
        name: &str,
    ) -> Self {
        Self {
            id: id.to_string(),
            allowed_origins: origins.into_iter().map(Into::into).collect(),
            name: name.to_string(),
            require_user_verification: false,
        }
    }

    /// Require the UV (User Verification) flag on every authentication assertion.
    ///
    /// When `true`, `verify_authentication` returns
    /// [`crate::error::WebAuthnError::UserNotVerified`] if the authenticator's
    /// `UV` bit is not set — meaning the user was not verified via PIN,
    /// biometric, or another local gesture.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use webauthn::RelyingParty;
    ///
    /// let rp = RelyingParty::new("example.com", "https://example.com", "My Service")
    ///     .require_user_verification(true);
    /// ```
    pub fn require_user_verification(mut self, required: bool) -> Self {
        self.require_user_verification = required;
        self
    }

    /// Verify a registration ceremony response (W3C WebAuthn §7.1).
    ///
    /// Call this after the client returns an `AuthenticatorAttestationResponse`.
    /// On `Ok`, persist `result.credential` in your database. On `Err`, reject
    /// the registration and return an appropriate error to the client.
    ///
    /// # Arguments
    /// * `challenge` — The challenge you issued for this ceremony.
    /// * `response`  — The raw attestation response from the authenticator.
    /// * `user_id`   — Your application's identifier for this user.
    ///
    /// # Errors
    /// Returns a [`WebAuthnError`] variant indicating exactly which
    /// verification step failed.
    pub fn verify_registration(
        &self,
        challenge: &Challenge,
        response: &AuthenticatorAttestationResponse,
        user_id: &[u8],
    ) -> Result<RegistrationResult> {
        verify_registration_inner(self, challenge, response, user_id)
    }
}

// ─── Ceremony implementation ──────────────────────────────────────────────────

fn verify_registration_inner(
    rp: &RelyingParty,
    challenge: &Challenge,
    response: &AuthenticatorAttestationResponse,
    user_id: &[u8],
) -> Result<RegistrationResult> {
    // ── Pre-check: challenge expiry ───────────────────────────────────────────
    // The spec does not specify where to check this, but rejecting an expired
    // challenge before doing any crypto is the most efficient ordering.
    if challenge.is_expired(CHALLENGE_MAX_AGE_SECS) {
        return Err(WebAuthnError::ChallengeExpired);
    }

    // ── §7.1 step 5 ───────────────────────────────────────────────────────────
    // Let JSONtext be the UTF-8 decoding of response.clientDataJSON.
    // response.client_data_json already holds the raw bytes; validate UTF-8.
    let _ = std::str::from_utf8(&response.client_data_json).map_err(|_| {
        WebAuthnError::InvalidClientData("clientDataJSON is not valid UTF-8".to_string())
    })?;

    // ── §7.1 step 6 ───────────────────────────────────────────────────────────
    // Parse clientDataJSON bytes into a CollectedClientData structure.
    let parsed_cd = client_data::parse_client_data(&response.client_data_json)?;

    // ── §7.1 step 7 ───────────────────────────────────────────────────────────
    // Verify that C.type equals "webauthn.create".
    // ── §7.1 step 8 ───────────────────────────────────────────────────────────
    // Verify that C.challenge equals the issued challenge.
    // ── §7.1 step 9 ───────────────────────────────────────────────────────────
    // Verify that C.origin matches the relying party's origin.
    client_data::validate_client_data(
        &parsed_cd,
        "webauthn.create",
        &challenge.bytes,
        &rp.allowed_origins,
    )?;

    // ── §7.1 step 11 ──────────────────────────────────────────────────────────
    // Let hash be SHA-256(clientDataJSON bytes).
    let client_data_hash = sha256(&parsed_cd.raw_json);

    // ── §7.1 step 12 ──────────────────────────────────────────────────────────
    // Perform CBOR decoding on the attestationObject.
    let (fmt, auth_data_bytes, att_stmt) = parse_attestation_object(&response.attestation_object)?;

    // ── §7.1 step 9 (authData) ────────────────────────────────────────────────
    // Parse the raw authenticator data bytes into a typed structure.
    let auth_data = authenticator_data::parse_authenticator_data(&auth_data_bytes)?;

    // ── §7.1 step 13 ──────────────────────────────────────────────────────────
    // Verify that the rpIdHash in authData is SHA-256(rp.id).
    let expected_rp_id_hash = sha256(rp.id.as_bytes());
    if auth_data.rp_id_hash != expected_rp_id_hash {
        return Err(WebAuthnError::RpIdHashMismatch);
    }

    // ── §7.1 step 14 ──────────────────────────────────────────────────────────
    // Verify that the User Present (UP) flag is set.
    // A registration without UP is invalid — the user must have been present.
    if !auth_data.flags.user_present {
        return Err(WebAuthnError::UserNotPresent);
    }

    // ── §7.1 step 16 ──────────────────────────────────────────────────────────
    // Verify that the AT (Attested Credential Data) flag is set.
    // If absent, the authenticator did not include a public key — unusable.
    let cred_data = auth_data.attested_credential_data.ok_or_else(|| {
        WebAuthnError::InvalidAuthenticatorData(
            "attested credential data (AT flag) is required for registration".to_string(),
        )
    })?;

    // ── §7.1 step 17 ──────────────────────────────────────────────────────────
    // Extract the COSE public key and convert it to a typed PublicKey.
    // The parser already validated kty, crv (for EC2), and alg (for RSA).
    // Here we additionally check that EC2 keys use ES256 (the only EC2 algorithm
    // we support), and reject any combination we cannot verify.
    let public_key = match cred_data.public_key {
        CoseKey::EC2 { alg, x, y, .. } if alg == COSE_ES256 => PublicKey::ES256 { x, y },
        CoseKey::EC2 { alg, .. } => return Err(WebAuthnError::UnsupportedAlgorithm(alg)),
        CoseKey::OKP { alg, x, .. } if alg == COSE_EDDSA => PublicKey::EdDSA(x),
        CoseKey::OKP { alg, .. } => return Err(WebAuthnError::UnsupportedAlgorithm(alg)),
        CoseKey::RSA { n, e, .. } => PublicKey::RS256 { n, e },
    };

    // ── §7.1 step 19 ──────────────────────────────────────────────────────────
    // Verify the attestation statement. Pass the public key so packed
    // self-attestation can verify the signature with the credential key.
    // Pass credential_id for fido-u2f verificationData construction.
    let attestation_type = attestation::verify(
        &fmt,
        &att_stmt,
        &auth_data_bytes,
        &client_data_hash,
        &public_key,
        &cred_data.credential_id,
    )?;

    // ── §7.1 step 25 ──────────────────────────────────────────────────────────
    // Build the Credential. The caller must persist this object.
    let credential = Credential {
        id: cred_data.credential_id,
        public_key,
        sign_count: auth_data.sign_count,
        user_id: user_id.to_vec(),
        rp_id: rp.id.clone(),
        created_at: SystemTime::now(),
    };

    Ok(RegistrationResult {
        credential,
        attestation_type,
    })
}

// ─── CBOR attestation object ──────────────────────────────────────────────────

/// Decode the CBOR attestation object and return `(fmt, authData bytes, attStmt)`.
///
/// The attestation object is a CBOR map with at least:
/// - `"fmt"`      (text): attestation format
/// - `"attStmt"`  (map):  attestation statement (forwarded to `attestation::verify`)
/// - `"authData"` (bytes): raw authenticator data
fn parse_attestation_object(data: &[u8]) -> Result<(String, Vec<u8>, Value)> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| WebAuthnError::CborDecodeError(format!("attestation object: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidAttestationObject(
                "attestation object must be a CBOR map".to_string(),
            ))
        }
    };

    let mut fmt: Option<String> = None;
    let mut auth_data: Option<Result<Vec<u8>>> = None;
    let mut att_stmt: Option<Value> = None;

    for (k, v) in map {
        match k {
            Value::Text(ref key) if key == "fmt" => {
                if let Value::Text(s) = v {
                    fmt = Some(s);
                }
            }
            Value::Text(ref key) if key == "authData" => {
                auth_data = Some(match v {
                    Value::Bytes(b) => Ok(b),
                    _ => Err(WebAuthnError::InvalidAttestationObject(
                        "authData must be CBOR bytes, not another type".to_string(),
                    )),
                });
            }
            Value::Text(ref key) if key == "attStmt" => {
                att_stmt = Some(v);
            }
            _ => {}
        }
    }

    let fmt = fmt.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject("missing required field: fmt".to_string())
    })?;

    let auth_data = auth_data.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject("missing required field: authData".to_string())
    })??; // first ? unwraps Option, second ? propagates the inner Result

    let att_stmt = att_stmt.ok_or_else(|| {
        WebAuthnError::InvalidAttestationObject("missing required field: attStmt".to_string())
    })?;

    Ok((fmt, auth_data, att_stmt))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_attestation_object_cbor() {
        let bad_bytes = &[0xFF, 0x00, 0x00];
        let result = parse_attestation_object(bad_bytes);
        assert!(matches!(result, Err(WebAuthnError::CborDecodeError(_))));
    }

    #[test]
    fn rejects_attestation_object_that_is_not_a_map() {
        let integer_cbor = &[0x00u8]; // CBOR integer 0
        let result = parse_attestation_object(integer_cbor);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(_))
        ));
    }

    #[test]
    fn rejects_attestation_object_missing_fmt() {
        let mut buf = Vec::new();
        let v = Value::Map(vec![(
            Value::Text("authData".to_string()),
            Value::Bytes(vec![0u8; 37]),
        )]);
        ciborium::into_writer(&v, &mut buf).unwrap();
        let result = parse_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(_))
        ));
    }

    #[test]
    fn rejects_attestation_object_missing_auth_data() {
        let mut buf = Vec::new();
        let v = Value::Map(vec![
            (
                Value::Text("fmt".to_string()),
                Value::Text("none".to_string()),
            ),
            (Value::Text("attStmt".to_string()), Value::Map(vec![])),
        ]);
        ciborium::into_writer(&v, &mut buf).unwrap();
        let result = parse_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("authData")
        ));
    }

    #[test]
    fn rejects_attestation_object_missing_att_stmt() {
        let mut buf = Vec::new();
        let v = Value::Map(vec![
            (
                Value::Text("fmt".to_string()),
                Value::Text("none".to_string()),
            ),
            (
                Value::Text("authData".to_string()),
                Value::Bytes(vec![0u8; 37]),
            ),
        ]);
        ciborium::into_writer(&v, &mut buf).unwrap();
        let result = parse_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("attStmt")
        ));
    }

    #[test]
    fn rejects_auth_data_not_bytes() {
        // authData is present but is a text string, not bytes.
        let mut buf = Vec::new();
        let v = Value::Map(vec![
            (
                Value::Text("fmt".to_string()),
                Value::Text("none".to_string()),
            ),
            (Value::Text("attStmt".to_string()), Value::Map(vec![])),
            (
                Value::Text("authData".to_string()),
                Value::Text("not bytes".to_string()),
            ),
        ]);
        ciborium::into_writer(&v, &mut buf).unwrap();
        let result = parse_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("bytes")
        ));
    }
}
