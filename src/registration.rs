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
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::algorithm::{COSE_EDDSA, COSE_ES256, COSE_ES384, COSE_RS256};
use crate::attestation;
use crate::authenticator_data::{self, CoseKey};
use crate::challenge::CHALLENGE_MAX_AGE_SECS;
use crate::client_data;
use crate::credential::{
    AuthenticatorAttestationResponse, Challenge, Credential, PublicKey, RegistrationResult,
};
use crate::crypto::sha256;
use crate::error::{Result, WebAuthnError};
use crate::options::{
    AttestationPreference, AuthenticatorSelection, PublicKeyCredentialDescriptor,
    RegistrationOptions, UserEntity,
};

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

    /// Whether to reject `clientDataJSON` that contains `crossOrigin: true`.
    /// Defaults to `false`.
    ///
    /// A cross-origin credential use occurs when the WebAuthn call is made
    /// from an iframe whose origin differs from the top-level page. When your
    /// application never embeds WebAuthn in an iframe, set this to `true` to
    /// close that attack surface (§7.1 step 10 / §7.2 step 12).
    /// See [`RelyingParty::reject_cross_origin`] to enable this using the
    /// builder pattern.
    pub reject_cross_origin: bool,

    /// COSE algorithm identifiers this RP accepts at registration time.
    ///
    /// When non-empty, `verify_registration` returns
    /// [`crate::error::WebAuthnError::UnsupportedAlgorithm`] if the credential's
    /// algorithm is not in this list. An empty list (the default) accepts any
    /// algorithm the library supports (ES256, EdDSA, RS256).
    ///
    /// Use [`RelyingParty::allowed_algorithms`] to set this at construction time.
    pub allowed_algorithms: Vec<i64>,

    /// Whether to reject credentials that are not backup-eligible (BE flag not set).
    /// Defaults to `false`.
    ///
    /// Set to `true` for consumer passkey deployments that require cross-device
    /// sign-in via platform sync services (iCloud Keychain, Google Password Manager).
    /// See [`RelyingParty::require_backup_eligible`] to enable via the builder.
    pub require_backup_eligible: bool,

    /// Whether to reject credentials that are backup-eligible (BE flag is set).
    /// Defaults to `false`.
    ///
    /// Set to `true` for high-security environments (banking, SSH) that require
    /// hardware-bound keys that cannot leave the device.
    /// See [`RelyingParty::reject_backup_eligible`] to enable via the builder.
    pub reject_backup_eligible: bool,

    /// DER-encoded root CA certificates used to verify the `x5c` attestation
    /// chain returned by the authenticator.
    ///
    /// When non-empty, `verify_registration` walks the chain returned in `x5c`
    /// and checks that its root is signed by one of these anchors. A successful
    /// check upgrades the result to [`crate::credential::AttestationType::BasicVerified`].
    ///
    /// When empty (the default), the chain order is still validated (each
    /// certificate must be signed by the next), but the root is not checked
    /// against any CA set and `AttestationType::Basic` is returned instead.
    ///
    /// Use [`RelyingParty::trust_anchors`] to set this at construction time.
    pub trust_anchors: Vec<Vec<u8>>,

    /// Opt-in set of challenge bytes already consumed by a completed ceremony.
    ///
    /// `None` when single-use enforcement is disabled (the default). Enable
    /// via [`RelyingParty::enforce_single_use_challenges`].
    ///
    /// The `Arc` lets `Clone`d instances share the same tracking set so all
    /// ceremony paths that use copies of the same `RelyingParty` (e.g. behind
    /// an `Arc<RelyingParty>` in an async web handler) enforce the policy
    /// collectively rather than independently.
    pub used_challenges: Option<Arc<Mutex<HashSet<Vec<u8>>>>>,

    /// Default authenticator selection criteria copied into every
    /// [`RegistrationOptions`] produced by [`RelyingParty::begin_registration`].
    ///
    /// `None` (the default) omits the `authenticatorSelection` field from the
    /// JSON sent to the browser. Set via
    /// [`RelyingParty::default_authenticator_selection`].
    pub default_authenticator_selection: Option<AuthenticatorSelection>,
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
            reject_cross_origin: false,
            allowed_algorithms: vec![],
            require_backup_eligible: false,
            reject_backup_eligible: false,
            trust_anchors: vec![],
            used_challenges: None,
            default_authenticator_selection: None,
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
            reject_cross_origin: false,
            allowed_algorithms: vec![],
            require_backup_eligible: false,
            reject_backup_eligible: false,
            trust_anchors: vec![],
            used_challenges: None,
            default_authenticator_selection: None,
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

    /// Reject `clientDataJSON` that contains `crossOrigin: true` (§7.1 step 10).
    ///
    /// When `true`, any registration or authentication response from a
    /// cross-origin iframe is rejected with
    /// [`crate::error::WebAuthnError::CrossOriginNotAllowed`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use webauthn::RelyingParty;
    ///
    /// let rp = RelyingParty::new("example.com", "https://example.com", "My Service")
    ///     .reject_cross_origin(true);
    /// ```
    pub fn reject_cross_origin(mut self, reject: bool) -> Self {
        self.reject_cross_origin = reject;
        self
    }

    /// Restrict which COSE algorithms this RP accepts at registration time.
    ///
    /// When the list is non-empty, `verify_registration` rejects any credential
    /// whose algorithm is not in this list with
    /// [`crate::error::WebAuthnError::UnsupportedAlgorithm`].
    /// An empty list (the default) accepts ES256, EdDSA, and RS256.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use webauthn::{RelyingParty, COSE_ES256};
    ///
    /// let rp = RelyingParty::new("example.com", "https://example.com", "My Service")
    ///     .allowed_algorithms([COSE_ES256]);
    /// ```
    pub fn allowed_algorithms(mut self, algs: impl IntoIterator<Item = i64>) -> Self {
        self.allowed_algorithms = algs.into_iter().collect();
        self
    }

    /// Require that credentials are backup-eligible (BE flag must be set).
    ///
    /// When `true`, `verify_registration` and `verify_authentication` return
    /// [`crate::error::WebAuthnError::BackupEligibilityRequired`] for any
    /// credential whose BE flag is not set.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use webauthn::RelyingParty;
    ///
    /// let rp = RelyingParty::new("example.com", "https://example.com", "My Service")
    ///     .require_backup_eligible(true);
    /// ```
    pub fn require_backup_eligible(mut self, required: bool) -> Self {
        self.require_backup_eligible = required;
        self
    }

    /// Reject credentials that are backup-eligible (BE flag must not be set).
    ///
    /// When `true`, `verify_registration` and `verify_authentication` return
    /// [`crate::error::WebAuthnError::BackupEligibleNotAllowed`] for any
    /// credential whose BE flag is set.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use webauthn::RelyingParty;
    ///
    /// let rp = RelyingParty::new("example.com", "https://example.com", "My Service")
    ///     .reject_backup_eligible(true);
    /// ```
    pub fn reject_backup_eligible(mut self, reject: bool) -> Self {
        self.reject_backup_eligible = reject;
        self
    }

    /// Provide DER-encoded root CA certificates used to verify the `x5c` chain.
    ///
    /// When a non-empty set is supplied, `verify_registration` verifies that
    /// the root of the attestation certificate chain is signed by one of these
    /// anchors and returns [`crate::credential::AttestationType::BasicVerified`]
    /// on success, or [`crate::error::WebAuthnError::AttestationRootUntrusted`]
    /// on failure. Chain structure (each cert signed by the next) is always
    /// checked regardless of this setting.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use webauthn::RelyingParty;
    ///
    /// let fido_root_der: Vec<u8> = std::fs::read("fido-root.der").unwrap();
    /// let rp = RelyingParty::new("example.com", "https://example.com", "My Service")
    ///     .trust_anchors([fido_root_der]);
    /// ```
    pub fn trust_anchors(mut self, roots: impl IntoIterator<Item = Vec<u8>>) -> Self {
        self.trust_anchors = roots.into_iter().collect();
        self
    }

    /// Opt in to server-side single-use challenge enforcement.
    ///
    /// When `true`, the library maintains an internal set of challenge bytes
    /// that have already been processed. After the challenge passes the normal
    /// expiry and binding checks, it is looked up in this set:
    ///
    /// - If already present → the ceremony fails with
    ///   [`crate::error::WebAuthnError::ChallengePreviouslyUsed`].
    /// - If absent → it is inserted and the ceremony continues.
    ///
    /// A challenge is consumed even if later verification steps (e.g.
    /// signature check) fail, so a failed ceremony with a valid challenge
    /// cannot be retried with the same challenge bytes.
    ///
    /// The tracking set is shared across `Clone`d instances of this
    /// `RelyingParty` via `Arc`, so all ceremony paths using copies of the
    /// same instance enforce the policy collectively.
    ///
    /// When `false` (the default), single-use enforcement is the caller's
    /// responsibility — track issued challenges in your session store and
    /// delete each one after it is presented to a ceremony.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use webauthn::RelyingParty;
    ///
    /// let rp = RelyingParty::new("example.com", "https://example.com", "My Service")
    ///     .enforce_single_use_challenges(true);
    /// ```
    pub fn enforce_single_use_challenges(mut self, enforce: bool) -> Self {
        self.used_challenges = if enforce {
            Some(Arc::new(Mutex::new(HashSet::new())))
        } else {
            None
        };
        self
    }

    /// Set the default `authenticatorSelection` criteria for every registration.
    ///
    /// When set, the value is copied into every [`RegistrationOptions`] returned
    /// by [`RelyingParty::begin_registration`]. When `None` (the default), the
    /// `authenticatorSelection` field is omitted from the JSON sent to the
    /// browser, which lets the browser choose any available authenticator.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use webauthn::{
    ///     RelyingParty,
    ///     AuthenticatorSelection, ResidentKeyRequirement, UserVerificationRequirement,
    /// };
    ///
    /// let rp = RelyingParty::new("example.com", "https://example.com", "My Service")
    ///     .default_authenticator_selection(AuthenticatorSelection {
    ///         authenticator_attachment: None,
    ///         resident_key: Some(ResidentKeyRequirement::Required),
    ///         require_resident_key: false,
    ///         user_verification: UserVerificationRequirement::Required,
    ///     });
    /// ```
    pub fn default_authenticator_selection(mut self, sel: AuthenticatorSelection) -> Self {
        self.default_authenticator_selection = Some(sel);
        self
    }

    /// Begin a registration ceremony by generating options for the browser.
    ///
    /// Returns a [`RegistrationOptions`] value ready to serialize and send to
    /// the client as `PublicKeyCredentialCreationOptions`. Before responding,
    /// persist `options.challenge` in your session store — you must pass it
    /// to [`RelyingParty::verify_registration`] when the browser returns.
    ///
    /// `pub_key_cred_params` is populated from this RP's configured
    /// [`RelyingParty::allowed_algorithms`]. If no algorithms are configured,
    /// all four supported algorithms are included: ES256, ES384, EdDSA, RS256.
    ///
    /// # Arguments
    /// * `user` — The account information to embed in the options.
    /// * `exclude_credentials` — Iterator of raw credential ID bytes already
    ///   registered for this user. The browser will instruct the authenticator
    ///   to refuse re-registering any credential whose ID is in this list.
    ///   Pass an empty iterator when no credentials exist yet.
    ///
    /// # Errors
    /// Returns a [`WebAuthnError`] only if the system random number generator
    /// fails to generate a challenge (extremely unlikely).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use webauthn::{RelyingParty, UserEntity};
    ///
    /// let rp = RelyingParty::new("example.com", "https://example.com", "My Service");
    /// let user = UserEntity {
    ///     id: b"user-42".to_vec(),
    ///     name: "alice@example.com".to_string(),
    ///     display_name: "Alice".to_string(),
    /// };
    /// // Pass existing credential IDs to prevent the authenticator from
    /// // re-registering an already-stored credential.
    /// let existing_ids: Vec<Vec<u8>> = vec![/* from DB */];
    /// let opts = rp.begin_registration(user, existing_ids.iter().map(|v| v.as_slice()))
    ///     .expect("RNG failure");
    /// // Persist opts.challenge, serialize opts to JSON, send to browser.
    /// ```
    pub fn begin_registration(
        &self,
        user: UserEntity,
        exclude_credentials: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<RegistrationOptions> {
        let challenge = Challenge::new()?;
        let pub_key_cred_params = if self.allowed_algorithms.is_empty() {
            vec![COSE_ES256, COSE_ES384, COSE_EDDSA, COSE_RS256]
        } else {
            self.allowed_algorithms.clone()
        };
        let exclude_credentials: Vec<PublicKeyCredentialDescriptor> = exclude_credentials
            .into_iter()
            .map(|id| PublicKeyCredentialDescriptor {
                id: id.as_ref().to_vec(),
                transports: None,
            })
            .collect();
        Ok(RegistrationOptions {
            challenge,
            rp_id: self.id.clone(),
            rp_name: self.name.clone(),
            user,
            pub_key_cred_params,
            timeout_ms: 300_000,
            attestation: AttestationPreference::None,
            exclude_credentials,
            authenticator_selection: self.default_authenticator_selection.clone(),
        })
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
    // ── §7.1 step 10 ──────────────────────────────────────────────────────────
    // If reject_cross_origin is set, reject crossOrigin: true.
    client_data::validate_client_data(
        &parsed_cd,
        "webauthn.create",
        &challenge.bytes,
        &rp.allowed_origins,
        rp.reject_cross_origin,
    )?;

    // ── Single-use challenge enforcement (opt-in) ─────────────────────────────
    // After the challenge has passed the expiry and binding checks above,
    // record it in the used-challenge set if enforcement is enabled. A
    // challenge is consumed even if subsequent steps fail — this prevents
    // retrying the same challenge with a corrected payload.
    if let Some(ref used) = rp.used_challenges {
        let mut set = used
            .lock()
            .expect("used_challenges mutex is poisoned — a previous ceremony panicked");
        if set.contains(&challenge.bytes) {
            return Err(WebAuthnError::ChallengePreviouslyUsed);
        }
        set.insert(challenge.bytes.clone());
    }

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

    // ── §7.1 step 18 ──────────────────────────────────────────────────────────
    // Apply the RP's backup eligibility policy.
    if rp.reject_backup_eligible && auth_data.flags.backup_eligible {
        return Err(WebAuthnError::BackupEligibleNotAllowed);
    }
    if rp.require_backup_eligible && !auth_data.flags.backup_eligible {
        return Err(WebAuthnError::BackupEligibilityRequired);
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
    //
    // Read the algorithm integer first (by reference) so we can check the RP's
    // allowlist before consuming the CoseKey.
    let cose_alg: i64 = match &cred_data.public_key {
        CoseKey::EC2 { alg, .. } => *alg,
        CoseKey::OKP { alg, .. } => *alg,
        CoseKey::RSA { .. } => COSE_RS256,
    };

    // §7.1 step 17 — reject the credential algorithm if not in the RP's allowlist.
    if !rp.allowed_algorithms.is_empty() && !rp.allowed_algorithms.contains(&cose_alg) {
        return Err(WebAuthnError::UnsupportedAlgorithm(cose_alg));
    }

    let public_key = match cred_data.public_key {
        CoseKey::EC2 { alg, x, y, .. } if alg == COSE_ES256 => PublicKey::ES256 { x, y },
        CoseKey::EC2 { alg, x, y, .. } if alg == COSE_ES384 => PublicKey::ES384 { x, y },
        CoseKey::EC2 { alg, .. } => return Err(WebAuthnError::UnsupportedAlgorithm(alg)),
        CoseKey::OKP { alg, x, .. } if alg == COSE_EDDSA => PublicKey::EdDSA(x),
        CoseKey::OKP { alg, .. } => return Err(WebAuthnError::UnsupportedAlgorithm(alg)),
        CoseKey::RSA { n, e, .. } => PublicKey::RS256 { n, e },
    };

    // ── §7.1 step 19 ──────────────────────────────────────────────────────────
    // Verify the attestation statement. Pass the public key so packed
    // self-attestation can verify the signature with the credential key.
    // Pass credential_id for fido-u2f verificationData construction.
    // Pass trust_anchors for x5c chain root verification (§7.1 step 22).
    let attestation_type = attestation::verify(
        &fmt,
        &att_stmt,
        &auth_data_bytes,
        &client_data_hash,
        &public_key,
        &cred_data.credential_id,
        &rp.trust_anchors,
    )?;

    let backup_eligible = auth_data.flags.backup_eligible;
    let backup_state = auth_data.flags.backup_state;
    let extensions = auth_data.extensions;

    // ── §7.1 step 25 ──────────────────────────────────────────────────────────
    // Build the Credential. The caller must persist this object.
    // backup_eligible is stored so authentication can enforce BE immutability.
    // backup_state reflects the credential's sync state at registration time;
    // callers must update it after each successful authentication.
    let credential = Credential {
        id: cred_data.credential_id,
        public_key,
        sign_count: auth_data.sign_count,
        user_id: user_id.to_vec(),
        rp_id: rp.id.clone(),
        created_at: SystemTime::now(),
        backup_eligible,
        backup_state,
    };

    Ok(RegistrationResult {
        credential,
        attestation_type,
        backup_eligible,
        backup_state,
        extensions,
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
        ciborium::into_writer(&v, &mut buf).expect("test setup");
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
        ciborium::into_writer(&v, &mut buf).expect("test setup");
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
        ciborium::into_writer(&v, &mut buf).expect("test setup");
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
        ciborium::into_writer(&v, &mut buf).expect("test setup");
        let result = parse_attestation_object(&buf);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(ref m)) if m.contains("bytes")
        ));
    }

    // ── begin_registration tests ─────────────────────────────────────────────

    fn make_user() -> UserEntity {
        UserEntity {
            id: vec![1, 2, 3, 4],
            name: "alice@example.com".to_string(),
            display_name: "Alice".to_string(),
        }
    }

    fn make_rp() -> RelyingParty {
        RelyingParty::new("example.com", "https://example.com", "Test Service")
    }

    #[test]
    fn begin_registration_challenge_is_32_bytes() {
        let opts = make_rp()
            .begin_registration(make_user(), std::iter::empty::<Vec<u8>>())
            .expect("begin_registration failed");
        assert_eq!(opts.challenge.bytes.len(), 32);
    }

    #[test]
    fn begin_registration_rp_fields_match() {
        let opts = make_rp()
            .begin_registration(make_user(), std::iter::empty::<Vec<u8>>())
            .expect("begin_registration failed");
        assert_eq!(opts.rp_id, "example.com");
        assert_eq!(opts.rp_name, "Test Service");
    }

    #[test]
    fn begin_registration_includes_es256_by_default() {
        let opts = make_rp()
            .begin_registration(make_user(), std::iter::empty::<Vec<u8>>())
            .expect("begin_registration failed");
        assert!(opts.pub_key_cred_params.contains(&COSE_ES256));
    }

    #[test]
    fn begin_registration_respects_allowed_algorithms() {
        let rp = make_rp().allowed_algorithms([COSE_ES256]);
        let opts = rp
            .begin_registration(make_user(), std::iter::empty::<Vec<u8>>())
            .expect("begin_registration failed");
        assert_eq!(opts.pub_key_cred_params, vec![COSE_ES256]);
    }

    #[test]
    fn begin_registration_json_shape() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let opts = make_rp()
            .begin_registration(make_user(), std::iter::empty::<Vec<u8>>())
            .expect("begin_registration failed");
        let json = serde_json::to_value(&opts).expect("serialization failed");

        // rp.id and rp.name
        assert_eq!(json["rp"]["id"], "example.com");
        assert_eq!(json["rp"]["name"], "Test Service");

        // user.id encoded as base64url (no padding)
        let expected_id = URL_SAFE_NO_PAD.encode(&[1u8, 2, 3, 4]);
        assert_eq!(json["user"]["id"], expected_id);

        // pubKeyCredParams[0] shape
        assert_eq!(json["pubKeyCredParams"][0]["type"], "public-key");

        // attestation defaults to "none"
        assert_eq!(json["attestation"], "none");

        // timeout defaults to 5 minutes
        assert_eq!(json["timeout"], 300_000u32);

        // authenticatorSelection is absent when None
        assert!(
            json.get("authenticatorSelection").is_none()
                || json["authenticatorSelection"].is_null()
        );
    }
}
