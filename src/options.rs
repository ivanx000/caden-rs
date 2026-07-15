//! Options types for WebAuthn registration and authentication ceremonies.
//!
//! These types represent the JSON objects sent to the browser before
//! `navigator.credentials.create()` and `navigator.credentials.get()`.
//! Construct them via [`crate::RelyingParty::begin_registration`] and
//! [`crate::RelyingParty::authentication_options`] and serialize directly
//! with `serde_json::to_string`.
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
/// // Pass the credential IDs already registered for this user so the browser
/// // can tell the authenticator to skip re-registering them.
/// let existing: Vec<Vec<u8>> = vec![/* credential IDs from DB */];
/// let opts = rp.begin_registration(user, existing.iter().map(|v| v.as_slice()))
///     .expect("challenge generation failed");
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

    /// Credentials to exclude from this registration.
    ///
    /// The authenticator will refuse to create a new credential if one of the
    /// listed IDs is already stored on it, preventing duplicate registrations.
    /// An empty list (the default) places no restriction.
    ///
    /// Serialized as `"excludeCredentials"`:
    /// `[{"type": "public-key", "id": "<base64url>"}, ...]`.
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,

    /// Optional criteria for selecting an authenticator.
    pub authenticator_selection: Option<AuthenticatorSelection>,
}

// ─── AuthenticatorTransport ───────────────────────────────────────────────────

/// Transport channels a credential may use to communicate with the client.
///
/// Used in [`PublicKeyCredentialDescriptor::transports`] to hint to the
/// browser which transports a credential was registered with, allowing the
/// platform to present a more targeted authenticator picker.
///
/// Spec: <https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport>
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorTransport {
    /// USB connection (e.g. a YubiKey plugged into a USB port).
    Usb,
    /// Near-field communication (e.g. tap-to-authenticate security keys).
    Nfc,
    /// Bluetooth Low Energy.
    Ble,
    /// Built-in platform authenticator (Touch ID, Windows Hello, etc.).
    Internal,
    /// Cross-device authentication via a phone or tablet (FIDO2 hybrid transport).
    Hybrid,
}

// ─── PublicKeyCredentialDescriptor ───────────────────────────────────────────

/// A reference to a previously registered credential.
///
/// Placed in `allowCredentials` when constructing [`AuthenticationOptions`].
/// An empty `allowCredentials` list signals the passkey / discoverable
/// credential flow — the browser prompts the user to pick any matching
/// credential rather than restricting to a specific one.
///
/// Spec: <https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptor>
#[derive(Debug, Clone)]
pub struct PublicKeyCredentialDescriptor {
    /// Raw credential ID bytes, as stored in your database.
    pub id: Vec<u8>,

    /// Optional transport hints for the credential.
    ///
    /// When `None`, no transport hint is sent and the platform uses all
    /// available transports. Only set this if you recorded the transports
    /// during registration (available via the authenticator extensions).
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

// ─── AuthenticationOptions ────────────────────────────────────────────────────

/// Options for an authentication ceremony, serialized as
/// `PublicKeyCredentialRequestOptions` and sent to the browser.
///
/// Construct via [`crate::RelyingParty::authentication_options`]. Before
/// responding to the client, persist `challenge` in your session store —
/// you will need it when the browser sends the assertion response.
///
/// ```rust,no_run
/// use webauthn::RelyingParty;
///
/// let rp = RelyingParty::new("example.com", "https://example.com", "My Service");
/// // Non-discoverable flow: pass the credential ID to restrict which credential
/// // the browser shows.
/// let stored_cred_id: Vec<u8> = vec![ /* bytes from DB */ ];
/// let opts = rp.authentication_options([stored_cred_id.as_slice()])
///     .expect("challenge generation failed");
/// // Persist opts.challenge, then serialize opts to JSON and send to browser.
/// let json = serde_json::to_string(&opts).expect("serialization failed");
/// ```
///
/// Spec: <https://www.w3.org/TR/webauthn-3/#dictionary-assertion-options>
#[derive(Debug, Clone)]
pub struct AuthenticationOptions {
    /// The challenge issued for this ceremony.
    ///
    /// Persist this before responding — you must pass it to
    /// [`crate::RelyingParty::verify_authentication`] when the browser returns.
    pub challenge: Challenge,

    /// How long (in milliseconds) the client may wait before timing out.
    ///
    /// Defaults to `300_000` (5 minutes). Serialized as `"timeout"`.
    pub timeout_ms: u32,

    /// The relying party ID. Must match the `rpId` used at registration.
    ///
    /// Serialized as `"rpId"`.
    pub rp_id: String,

    /// Credentials the authenticator may use for this assertion.
    ///
    /// An empty list (the default for the passkey flow) lets the authenticator
    /// choose any discoverable credential matching this RP. Serialized as
    /// `"allowCredentials"`.
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,

    /// Whether the authenticator must verify the user's identity.
    ///
    /// Set from [`crate::RelyingParty::require_user_verification`]:
    /// `Required` when `true`, `Preferred` otherwise. Serialized as
    /// `"userVerification"`.
    pub user_verification: UserVerificationRequirement,
}

// ─── W3C-compliant Serialize impl for AuthenticationOptions ──────────────────

// Private: one entry in "allowCredentials".
struct CredentialDescriptorSer<'a>(&'a PublicKeyCredentialDescriptor);

impl serde::Serialize for CredentialDescriptorSer<'_> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let size = if self.0.transports.is_some() { 3 } else { 2 };
        let mut map = s.serialize_map(Some(size))?;
        map.serialize_entry("type", "public-key")?;
        map.serialize_entry("id", &URL_SAFE_NO_PAD.encode(&self.0.id))?;
        if let Some(ref transports) = self.0.transports {
            map.serialize_entry("transports", transports)?;
        }
        map.end()
    }
}

impl serde::Serialize for AuthenticationOptions {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(5))?;

        // "challenge": "<base64url, no padding>"
        map.serialize_entry("challenge", &URL_SAFE_NO_PAD.encode(&self.challenge.bytes))?;

        // "timeout": <milliseconds>
        map.serialize_entry("timeout", &self.timeout_ms)?;

        // "rpId": "example.com"
        map.serialize_entry("rpId", &self.rp_id)?;

        // "allowCredentials": [{"type": "public-key", "id": "<base64url>"}, ...]
        let descriptors: Vec<CredentialDescriptorSer> = self
            .allow_credentials
            .iter()
            .map(CredentialDescriptorSer)
            .collect();
        map.serialize_entry("allowCredentials", &descriptors)?;

        // "userVerification": "required" | "preferred" | "discouraged"
        map.serialize_entry("userVerification", &self.user_verification)?;

        map.end()
    }
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
        let field_count = 7 + if self.authenticator_selection.is_some() {
            1
        } else {
            0
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

        // "excludeCredentials": [{"type": "public-key", "id": "<base64url>"}, ...]
        let excluded: Vec<CredentialDescriptorSer> = self
            .exclude_credentials
            .iter()
            .map(CredentialDescriptorSer)
            .collect();
        map.serialize_entry("excludeCredentials", &excluded)?;

        // "attestation": "none" | "indirect" | "direct"
        map.serialize_entry("attestation", &self.attestation)?;

        // "authenticatorSelection": { ... } — omitted when None
        if let Some(ref sel) = self.authenticator_selection {
            map.serialize_entry("authenticatorSelection", sel)?;
        }

        map.end()
    }
}
