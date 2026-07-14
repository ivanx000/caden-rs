//! Authentication ceremony — W3C WebAuthn §7.2.
//!
//! The authentication ceremony is how a user proves possession of a previously
//! registered credential. The relying party's job:
//!
//! 1. Verify the response was produced for *this* challenge and *this* origin.
//! 2. Verify the authenticator data is bound to *this* RP ID.
//! 3. Verify the ECDSA signature over `authData || SHA-256(clientDataJSON)`.
//! 4. Check the sign count to detect cloned authenticators.
//!
//! Spec: <https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion>

use crate::authenticator_data;
use crate::challenge::CHALLENGE_MAX_AGE_SECS;
use crate::client_data;
use crate::credential::{AuthenticationResult, Challenge, Credential, PublicKey};
use crate::crypto::{
    rsa_components_to_der, sha256, verify_eddsa, verify_es256, verify_es384, verify_rs256,
};
use crate::error::{Result, WebAuthnError};
use crate::options::{
    AuthenticationOptions, PublicKeyCredentialDescriptor, UserVerificationRequirement,
};
use crate::registration::RelyingParty;

/// The browser's response after a `navigator.credentials.get()` call.
///
/// All fields carry **raw decoded bytes** — base64url decoding must happen
/// outside the library before constructing this struct.
#[derive(Debug, Clone)]
pub struct AuthenticatorAssertionResponse {
    /// Raw UTF-8 bytes of the `clientDataJSON` object.
    pub client_data_json: Vec<u8>,

    /// Raw bytes of the `authenticatorData` structure.
    pub authenticator_data: Vec<u8>,

    /// DER-encoded ECDSA signature bytes.
    pub signature: Vec<u8>,

    /// Optional raw user handle bytes (some authenticators omit it).
    pub user_handle: Option<Vec<u8>>,

    /// The credential ID returned by the authenticator as `rawId` in the
    /// `PublicKeyCredential` object.
    ///
    /// In the discoverable credential (passkey) flow, `allowCredentials` is
    /// empty and the authenticator picks a credential; call
    /// [`crate::RelyingParty::begin_authentication`] to extract this value
    /// and look up the [`crate::Credential`] before calling
    /// [`crate::RelyingParty::verify_authentication`].
    ///
    /// In the non-discoverable flow, this equals the ID the server placed in
    /// `allowCredentials`. In both cases, set this to the raw bytes of
    /// `PublicKeyCredential.rawId` returned by the browser.
    pub credential_id: Vec<u8>,
}

impl RelyingParty {
    /// Begin an authentication ceremony by generating options for the browser.
    ///
    /// Returns an [`AuthenticationOptions`] value ready to serialize and send
    /// to the client as `PublicKeyCredentialRequestOptions`. Before responding,
    /// persist `options.challenge` in your session store — you must pass it to
    /// [`RelyingParty::verify_authentication`] when the browser returns.
    ///
    /// Pass the stored credential ID(s) to restrict which credential the
    /// browser presents. Pass an empty iterator for the passkey / discoverable
    /// credential flow where the authenticator picks any matching credential.
    ///
    /// # Arguments
    /// * `allow_credentials` — Credential IDs to restrict the assertion to.
    ///   An empty iterator produces an empty `allowCredentials` array, signaling
    ///   the passkey / discoverable credential flow to the browser.
    ///
    /// # Errors
    /// Returns a [`WebAuthnError`] only if the system random number generator
    /// fails to generate a challenge (extremely unlikely).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use webauthn::RelyingParty;
    ///
    /// let rp = RelyingParty::new("example.com", "https://example.com", "My Service");
    ///
    /// // Non-discoverable flow: hint at a specific credential.
    /// let cred_id: Vec<u8> = vec![ /* bytes from DB */ ];
    /// let opts = rp.authentication_options([cred_id.as_slice()]).expect("RNG failure");
    /// // Persist opts.challenge, serialize opts to JSON, send to browser.
    ///
    /// // Passkey / discoverable flow: empty allowCredentials.
    /// let passkey_opts = rp.authentication_options(std::iter::empty::<Vec<u8>>())
    ///     .expect("RNG failure");
    /// ```
    pub fn authentication_options(
        &self,
        allow_credentials: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<AuthenticationOptions> {
        let challenge = Challenge::new()?;
        let user_verification = if self.require_user_verification {
            UserVerificationRequirement::Required
        } else {
            UserVerificationRequirement::Preferred
        };
        let allow_credentials = allow_credentials
            .into_iter()
            .map(|id| PublicKeyCredentialDescriptor {
                id: id.as_ref().to_vec(),
                transports: None,
            })
            .collect();
        Ok(AuthenticationOptions {
            challenge,
            timeout_ms: 300_000,
            rp_id: self.id.clone(),
            allow_credentials,
            user_verification,
        })
    }

    /// Extract the credential ID and user handle from a passkey assertion response.
    ///
    /// In the discoverable credential (passkey) flow, the browser sends
    /// `allowCredentials: []` — the authenticator picks a credential and returns
    /// its ID as `rawId` in the `PublicKeyCredential`. Call this method to
    /// extract the ID, look up the stored [`crate::Credential`] in your
    /// database, then pass it to [`RelyingParty::verify_authentication`].
    ///
    /// The library holds no credential state; the lookup step is the caller's
    /// responsibility, keeping the library storage-agnostic.
    ///
    /// # Arguments
    /// * `response` — The assertion response from the authenticator.
    ///
    /// # Returns
    /// `(credential_id, user_handle)` — use `credential_id` to look up the
    /// [`crate::Credential`] in your store. `user_handle` identifies the user
    /// account when the authenticator includes it; not all authenticators do.
    ///
    /// # Errors
    /// Returns [`crate::error::WebAuthnError::MissingCredentialId`] if
    /// `response.credential_id` is empty.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use webauthn::{AuthenticatorAssertionResponse, Challenge, RelyingParty};
    /// # let rp = RelyingParty::new("example.com", "https://example.com", "Demo");
    /// # let response = AuthenticatorAssertionResponse {
    /// #     client_data_json: vec![], authenticator_data: vec![],
    /// #     signature: vec![], user_handle: None, credential_id: vec![1, 2, 3],
    /// # };
    /// # let challenge = Challenge::new().unwrap();
    /// // 1. Extract the credential ID from the assertion.
    /// let (cred_id, _user_handle) = rp.begin_authentication(&response).unwrap();
    ///
    /// // 2. Look up the credential in your database.
    /// # let stored_credential = rp.begin_authentication(&response).map(|_| todo!()).unwrap();
    /// // let stored_credential = db.find_credential(&cred_id).unwrap();
    ///
    /// // 3. Verify the full assertion.
    /// // let result = rp.verify_authentication(&stored_credential, &challenge, &response).unwrap();
    /// ```
    pub fn begin_authentication(
        &self,
        response: &AuthenticatorAssertionResponse,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        if response.credential_id.is_empty() {
            return Err(WebAuthnError::MissingCredentialId);
        }
        Ok((response.credential_id.clone(), response.user_handle.clone()))
    }

    /// Verify an authentication ceremony response (W3C WebAuthn §7.2).
    ///
    /// Call this after the client returns an `AuthenticatorAssertionResponse`.
    /// On `Ok`, update the stored credential's `sign_count` to
    /// `result.new_sign_count` before responding to the client.
    ///
    /// # Arguments
    /// * `stored_credential` — Retrieved from your database by credential ID.
    /// * `challenge`         — The challenge you issued for this ceremony.
    /// * `response`          — The assertion response from the authenticator.
    ///
    /// # Errors
    /// Returns a [`crate::error::WebAuthnError`] variant indicating exactly which
    /// verification step failed, including `SignCountInvalid` for suspected
    /// authenticator clones.
    pub fn verify_authentication(
        &self,
        stored_credential: &Credential,
        challenge: &Challenge,
        response: &AuthenticatorAssertionResponse,
    ) -> Result<AuthenticationResult> {
        verify_authentication_inner(self, stored_credential, challenge, response)
    }
}

// ─── Ceremony implementation ──────────────────────────────────────────────────

fn verify_authentication_inner(
    rp: &RelyingParty,
    stored_credential: &Credential,
    challenge: &Challenge,
    response: &AuthenticatorAssertionResponse,
) -> Result<AuthenticationResult> {
    // ── Pre-check: challenge expiry ───────────────────────────────────────────
    if challenge.is_expired(CHALLENGE_MAX_AGE_SECS) {
        return Err(WebAuthnError::ChallengeExpired);
    }

    // ── §7.2 step 11 ─────────────────────────────────────────────────────────
    // Parse clientDataJSON bytes (already raw UTF-8).
    let parsed_cd = client_data::parse_client_data(&response.client_data_json)?;

    // ── §7.2 step 13 ─────────────────────────────────────────────────────────
    // Verify type == "webauthn.get".
    // ── §7.2 step 14 ─────────────────────────────────────────────────────────
    // Verify the challenge matches.
    // ── §7.2 step 15 ─────────────────────────────────────────────────────────
    // Verify the origin matches rp.origin.
    // ── §7.2 step 12 ─────────────────────────────────────────────────────────
    // If reject_cross_origin is set, reject crossOrigin: true.
    client_data::validate_client_data(
        &parsed_cd,
        "webauthn.get",
        &challenge.bytes,
        &rp.allowed_origins,
        rp.reject_cross_origin,
    )?;

    // ── Single-use challenge enforcement (opt-in) ─────────────────────────────
    // Mirror the registration check: consume the challenge after it passes
    // expiry and binding, before any further crypto work.
    if let Some(ref used) = rp.used_challenges {
        let mut set = used
            .lock()
            .expect("used_challenges mutex is poisoned — a previous ceremony panicked");
        if set.contains(&challenge.bytes) {
            return Err(WebAuthnError::ChallengePreviouslyUsed);
        }
        set.insert(challenge.bytes.clone());
    }

    // ── §7.2 step 17 ─────────────────────────────────────────────────────────
    // Let hash be SHA-256(clientDataJSON bytes).
    let client_data_hash = sha256(&parsed_cd.raw_json);

    // ── §7.2 step 18 ─────────────────────────────────────────────────────────
    // Parse the authenticator data binary structure.
    let auth_data = authenticator_data::parse_authenticator_data(&response.authenticator_data)?;

    // ── §7.2 step 19 ─────────────────────────────────────────────────────────
    // Verify rpIdHash = SHA-256(stored credential's rp_id).
    let expected_rp_id_hash = sha256(stored_credential.rp_id.as_bytes());
    if auth_data.rp_id_hash != expected_rp_id_hash {
        return Err(WebAuthnError::RpIdHashMismatch);
    }

    // ── §7.2 step 20 ─────────────────────────────────────────────────────────
    // Verify the User Present (UP) flag.
    if !auth_data.flags.user_present {
        return Err(WebAuthnError::UserNotPresent);
    }

    // ── §7.2 step 21 ─────────────────────────────────────────────────────────
    // If the RP requires user verification, the UV flag must be set.
    if rp.require_user_verification && !auth_data.flags.user_verified {
        return Err(WebAuthnError::UserNotVerified);
    }

    // ── §7.2 step 21 — Backup Eligibility policy ──────────────────────────────
    if rp.reject_backup_eligible && auth_data.flags.backup_eligible {
        return Err(WebAuthnError::BackupEligibleNotAllowed);
    }
    if rp.require_backup_eligible && !auth_data.flags.backup_eligible {
        return Err(WebAuthnError::BackupEligibilityRequired);
    }

    // ── §7.2 step 21 — Backup Eligibility consistency ─────────────────────────
    // BE is immutable per spec — a mismatch between the stored registration value
    // and the current assertion signals a credential substitution attempt.
    if auth_data.flags.backup_eligible != stored_credential.backup_eligible {
        return Err(WebAuthnError::BackupEligibilityChanged);
    }

    // ── §7.2 step 24 ─────────────────────────────────────────────────────────
    // Verify the signature over: authData || SHA-256(clientDataJSON).
    //
    // ES256 is ECDSA-P256-SHA256: ring hashes the *message* internally.
    // The message is `authData_bytes || clientDataHash` (not pre-hashed again).
    let mut signed_data = auth_data.raw.clone();
    signed_data.extend_from_slice(&client_data_hash);

    // §7.2 step 24
    match &stored_credential.public_key {
        PublicKey::ES256 { x, y } => {
            // Reconstruct the 65-byte uncompressed point ring expects.
            let mut pk = Vec::with_capacity(65);
            pk.push(0x04);
            pk.extend_from_slice(x);
            pk.extend_from_slice(y);
            verify_es256(&pk, &signed_data, &response.signature)?;
        }
        PublicKey::ES384 { x, y } => {
            // Reconstruct the 97-byte uncompressed P-384 point ring expects.
            let mut pk = Vec::with_capacity(97);
            pk.push(0x04);
            pk.extend_from_slice(x);
            pk.extend_from_slice(y);
            verify_es384(&pk, &signed_data, &response.signature)?;
        }
        PublicKey::EdDSA(pk) => {
            // Ed25519 signature is raw 64 bytes; ring processes the message directly.
            verify_eddsa(pk, &signed_data, &response.signature)?;
        }
        PublicKey::RS256 { n, e } => {
            let der = rsa_components_to_der(n, e)?;
            verify_rs256(&der, &signed_data, &response.signature)?;
        }
    }

    // ── §7.2 step 25 ─────────────────────────────────────────────────────────
    // Verify the sign count is strictly greater than the stored value.
    //
    // Per spec: if either counter is non-zero, the received counter must exceed
    // the stored one. Both being 0 indicates a counter-less authenticator, which
    // is accepted. A stored non-zero counter with received=0 is rejected: it
    // could indicate a wrap-around (overflow) or a counter-less authenticator
    // being substituted for a counter-bearing one — both are suspicious.
    let received = auth_data.sign_count;
    let stored = stored_credential.sign_count;

    if (stored > 0 || received > 0) && received <= stored {
        return Err(WebAuthnError::SignCountInvalid { stored, received });
    }

    Ok(AuthenticationResult {
        credential_id: stored_credential.id.clone(),
        new_sign_count: received,
        user_present: auth_data.flags.user_present,
        user_verified: auth_data.flags.user_verified,
        backup_eligible: auth_data.flags.backup_eligible,
        backup_state: auth_data.flags.backup_state,
        extensions: auth_data.extensions,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rp() -> RelyingParty {
        RelyingParty::new("example.com", "https://example.com", "Test Service")
    }

    #[test]
    fn authentication_options_challenge_is_32_bytes() {
        let opts = make_rp()
            .authentication_options(std::iter::empty::<Vec<u8>>())
            .expect("authentication_options failed");
        assert_eq!(opts.challenge.bytes.len(), 32);
    }

    #[test]
    fn authentication_options_rp_id_matches() {
        let opts = make_rp()
            .authentication_options(std::iter::empty::<Vec<u8>>())
            .expect("authentication_options failed");
        assert_eq!(opts.rp_id, "example.com");
    }

    #[test]
    fn authentication_options_allow_credentials_round_trips() {
        let cred_id = vec![1u8, 2, 3, 4];
        let opts = make_rp()
            .authentication_options(std::iter::once(cred_id.as_slice()))
            .expect("authentication_options failed");
        assert_eq!(opts.allow_credentials.len(), 1);
        assert_eq!(opts.allow_credentials[0].id, cred_id);
        assert!(opts.allow_credentials[0].transports.is_none());
    }

    #[test]
    fn authentication_options_json_shape() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let cred_id = vec![1u8, 2, 3, 4];
        let opts = make_rp()
            .authentication_options(std::iter::once(cred_id.as_slice()))
            .expect("authentication_options failed");
        let json = serde_json::to_value(&opts).expect("serialization failed");

        // "challenge" is a valid base64url string (no padding)
        let challenge_str = json["challenge"]
            .as_str()
            .expect("challenge must be a string");
        URL_SAFE_NO_PAD
            .decode(challenge_str)
            .expect("challenge must be valid base64url");

        // "timeout" defaults to 5 minutes
        assert_eq!(json["timeout"], 300_000u32);

        // "rpId"
        assert_eq!(json["rpId"], "example.com");

        // "allowCredentials[0]" has the right shape
        assert_eq!(json["allowCredentials"][0]["type"], "public-key");
        let id_str = json["allowCredentials"][0]["id"]
            .as_str()
            .expect("id must be a string");
        let decoded = URL_SAFE_NO_PAD
            .decode(id_str)
            .expect("id must be valid base64url");
        assert_eq!(decoded, cred_id);

        // "userVerification" defaults to "preferred"
        assert_eq!(json["userVerification"], "preferred");
    }

    #[test]
    fn authentication_options_empty_allow_credentials_serializes_to_empty_array() {
        let opts = make_rp()
            .authentication_options(std::iter::empty::<Vec<u8>>())
            .expect("authentication_options failed");
        let json = serde_json::to_value(&opts).expect("serialization failed");
        assert_eq!(json["allowCredentials"], serde_json::json!([]));
    }

    #[test]
    fn authentication_options_uv_required_when_configured() {
        let rp = make_rp().require_user_verification(true);
        let opts = rp
            .authentication_options(std::iter::empty::<Vec<u8>>())
            .expect("authentication_options failed");
        let json = serde_json::to_value(&opts).expect("serialization failed");
        assert_eq!(json["userVerification"], "required");
    }
}
