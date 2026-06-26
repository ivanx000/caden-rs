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
use crate::crypto::{rsa_components_to_der, sha256, verify_eddsa, verify_es256, verify_rs256};
use crate::error::{Result, WebAuthnError};
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
}

impl RelyingParty {
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

    // ── §7.2 step 24 ─────────────────────────────────────────────────────────
    // Verify the signature over: authData || SHA-256(clientDataJSON).
    //
    // ES256 is ECDSA-P256-SHA256: ring hashes the *message* internally.
    // The message is `authData_bytes || clientDataHash` (not pre-hashed again).
    let mut signed_data = auth_data.raw.clone();
    signed_data.extend_from_slice(&client_data_hash);

    match &stored_credential.public_key {
        PublicKey::ES256 { x, y } => {
            // Reconstruct the 65-byte uncompressed point ring expects.
            let mut pk = Vec::with_capacity(65);
            pk.push(0x04);
            pk.extend_from_slice(x);
            pk.extend_from_slice(y);
            verify_es256(&pk, &signed_data, &response.signature)?;
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
    })
}
