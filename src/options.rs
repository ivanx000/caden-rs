//! Options types for WebAuthn registration and authentication ceremonies.
//!
//! These types represent `PublicKeyCredentialCreationOptions`, the JSON object
//! sent to the browser before `navigator.credentials.create()`. Construct them
//! via [`crate::RelyingParty::begin_registration`] and serialize directly with
//! `serde_json::to_string`.
//!
//! Spec: <https://www.w3.org/TR/webauthn-3/#dictionary-makecredentialoptions>

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::ser::SerializeMap;

use crate::credential::Challenge;

// ─── UserEntity ───────────────────────────────────────────────────────────────

/// The user account information sent to the authenticator during registration.
///
/// Corresponds to `PublicKeyCredentialUserEntity` in the W3C spec.
/// Spec: <https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity>
#[derive(Debug, Clone)]
pub struct UserEntity {
    /// Opaque byte string that uniquely identifies this user account.
    ///
    /// The authenticator stores this alongside the credential and returns it
    /// as `userHandle` during a discoverable credential (passkey) authentication.
    /// Must not contain personally identifiable information — use an internal
    /// user ID, not an email address.
    pub id: Vec<u8>,

    /// Human-readable account identifier, e.g. an email address or username.
    ///
    /// Displayed to the user when selecting a credential. May contain PII.
    pub name: String,

    /// Human-friendly display name for the account, e.g. `"Alice Smith"`.
    pub display_name: String,
}

// ─── AttestationPreference ────────────────────────────────────────────────────

/// The relying party's preference for attestation conveyance.
///
/// Sent to the browser as the `attestation` field of
/// `PublicKeyCredentialCreationOptions`. Defaults to `None` when constructed
/// via [`crate::RelyingParty::begin_registration`].
///
/// Spec: <https://www.w3.org/TR/webauthn-3/#enumdef-attestationconveyancepreference>
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationPreference {
    /// Do not request attestation. The authenticator may still produce one.
    None,
    /// Allow the browser or platform to proxy the attestation statement.
    Indirect,
    /// The authenticator must produce a direct attestation statement.
    Direct,
}

// ─── AuthenticatorAttachment ──────────────────────────────────────────────────

/// Authenticator attachment modality.
///
/// When `Some`, the browser will only consider authenticators of the specified
/// type. Omit to allow both platform and roaming authenticators.
///
/// Spec: <https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment>
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    /// A built-in platform authenticator, e.g. Touch ID or Windows Hello.
    Platform,
    /// A roaming authenticator, e.g. a USB or NFC security key.
    CrossPlatform,
}

// ─── ResidentKeyRequirement ───────────────────────────────────────────────────

/// Whether a client-side discoverable credential (passkey) is required.
///
/// `Required` is the right choice for passwordless flows where the user selects
/// their account from the authenticator. `Preferred` allows the authenticator
/// to store the credential if it can but does not require it.
///
/// Spec: <https://www.w3.org/TR/webauthn-3/#enumdef-residentkeyrequirement>
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKeyRequirement {
    /// The RP prefers a server-side (non-discoverable) credential.
    Discouraged,
    /// The RP prefers a discoverable credential but can work without it.
    Preferred,
    /// The RP requires a discoverable credential (passkey).
    Required,
}

// ─── UserVerificationRequirement ─────────────────────────────────────────────

/// Whether the authenticator must verify the user's identity.
///
/// User verification includes PIN entry, biometric checks, and similar gestures
/// that confirm the person is the legitimate owner of the authenticator.
///
/// Spec: <https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement>
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationRequirement {
    /// The RP requires the authenticator to verify the user.
    Required,
    /// The RP prefers user verification but will accept a result without it.
    Preferred,
    /// The RP does not want user verification.
    Discouraged,
}

// ─── AuthenticatorSelection ───────────────────────────────────────────────────

/// Criteria for authenticator selection during registration.
///
/// Passed as the `authenticatorSelection` field in
/// `PublicKeyCredentialCreationOptions`.
///
/// Spec: <https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorselectioncriteria>
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelection {
    /// Preferred authenticator attachment modality.
    ///
    /// `None` (the default) allows both platform and roaming authenticators.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    /// Whether a discoverable credential (passkey) is required.
    ///
    /// `None` means no preference. Use `Required` for passwordless flows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<ResidentKeyRequirement>,

    /// Legacy fallback for browsers that predate WebAuthn Level 2.
    ///
    /// Set to `true` only when you need to support older browsers that do not
    /// implement `residentKey`. Modern deployments should use `resident_key`.
    pub require_resident_key: bool,

    /// Whether the authenticator must verify the user's identity.
    pub user_verification: UserVerificationRequirement,
}

// ─── RegistrationOptions ─────────────────────────────────────────────────────

/// Options for a registration ceremony, serialized as
/// `PublicKeyCredentialCreationOptions` and sent to the browser.
///
/// Construct via [`crate::RelyingParty::begin_registration`]. Before responding
/// to the client, persist `challenge` in your session store — you will need it
/// when the browser sends the attestation response.
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
/// let opts = rp.begin_registration(user).expect("challenge generation failed");
/// // Persist opts.challenge, then serialize opts to JSON and send to browser.
/// let json = serde_json::to_string(&opts).expect("serialization failed");
/// ```
///
/// Spec: <https://www.w3.org/TR/webauthn-3/#dictionary-makecredentialoptions>
#[derive(Debug, Clone)]
pub struct RegistrationOptions {
    /// The challenge issued for this ceremony.
    ///
    /// Persist this before responding — you must pass it to
    /// [`crate::RelyingParty::verify_registration`] when the browser returns.
    pub challenge: Challenge,

    /// Relying party ID (e.g. `"example.com"`). Serialized under `"rp"`.
    pub rp_id: String,

    /// Human-readable relying party name. Serialized under `"rp"`.
    pub rp_name: String,

    /// User account information sent to the authenticator.
    pub user: UserEntity,

    /// COSE algorithm identifiers this RP accepts, in preference order.
    ///
    /// Serialized as `"pubKeyCredParams"`: an array of
    /// `{"type": "public-key", "alg": <id>}` objects. Populated from
    /// [`crate::RelyingParty::allowed_algorithms`] (or all four supported
    /// algorithms if none are configured).
    pub pub_key_cred_params: Vec<i64>,

    /// How long (in milliseconds) the client may wait for the user before
    /// timing out. Defaults to `300_000` (5 minutes).
    pub timeout_ms: u32,

    /// The RP's preference for attestation. Defaults to `AttestationPreference::None`.
    pub attestation: AttestationPreference,

    /// Optional criteria for selecting an authenticator.
    pub authenticator_selection: Option<AuthenticatorSelection>,
}

// ─── W3C-compliant Serialize impl for RegistrationOptions ────────────────────

// Private: "rp" JSON object.
#[derive(serde::Serialize)]
struct RpInfoSer<'a> {
    id: &'a str,
    name: &'a str,
}

// Private: one entry in "pubKeyCredParams".
#[derive(serde::Serialize)]
struct PubKeyCredParamSer {
    #[serde(rename = "type")]
    credential_type: &'static str,
    alg: i64,
}

// Private: "user" JSON object with id as base64url.
struct UserEntitySer<'a>(&'a UserEntity);

impl serde::Serialize for UserEntitySer<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(3))?;
        map.serialize_entry("id", &URL_SAFE_NO_PAD.encode(&self.0.id))?;
        map.serialize_entry("name", &self.0.name)?;
        map.serialize_entry("displayName", &self.0.display_name)?;
        map.end()
    }
}

impl serde::Serialize for RegistrationOptions {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = if self.authenticator_selection.is_some() {
            7
        } else {
            6
        };
        let mut map = serializer.serialize_map(Some(field_count))?;

        // "rp": { "id": "...", "name": "..." }
        map.serialize_entry(
            "rp",
            &RpInfoSer {
                id: &self.rp_id,
                name: &self.rp_name,
            },
        )?;

        // "user": { "id": "<base64url>", "name": "...", "displayName": "..." }
        map.serialize_entry("user", &UserEntitySer(&self.user))?;

        // "challenge": "<base64url, no padding>"
        map.serialize_entry("challenge", &URL_SAFE_NO_PAD.encode(&self.challenge.bytes))?;

        // "pubKeyCredParams": [{ "type": "public-key", "alg": <n> }, ...]
        let params: Vec<PubKeyCredParamSer> = self
            .pub_key_cred_params
            .iter()
            .map(|&alg| PubKeyCredParamSer {
                credential_type: "public-key",
                alg,
            })
            .collect();
        map.serialize_entry("pubKeyCredParams", &params)?;

        // "timeout": <milliseconds>
        map.serialize_entry("timeout", &self.timeout_ms)?;

        // "attestation": "none" | "indirect" | "direct"
        map.serialize_entry("attestation", &self.attestation)?;

        // "authenticatorSelection": { ... } — omitted when None
        if let Some(ref sel) = self.authenticator_selection {
            map.serialize_entry("authenticatorSelection", sel)?;
        }

        map.end()
    }
}
