//! Core domain types for stored credentials, challenges, and ceremony results.

use std::time::{Duration, SystemTime};

use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{WebAuthnError, Result};

// ─── Public key ───────────────────────────────────────────────────────────────

/// The public key extracted from a COSE key structure during registration.
///
/// ES256 (P-256 ECDSA with SHA-256) is the algorithm implemented and by far
/// the most common used by passkey authenticators. RS256 is present as a
/// placeholder; signature verification for it is not yet implemented.
#[derive(Debug, Clone)]
pub enum PublicKey {
    /// P-256 ECDSA public key.
    ///
    /// `x` and `y` are the 32-byte affine coordinates of the public point.
    /// To obtain the 65-byte uncompressed point for ring, prepend `0x04`:
    /// `0x04 || x (32 bytes) || y (32 bytes)`.
    ES256 { x: Vec<u8>, y: Vec<u8> },

    /// RSA-PKCS1v15 SHA-256 public key. (Not yet implemented — Phase 2.)
    RS256(Vec<u8>),
}

// ─── Stored credential ────────────────────────────────────────────────────────

/// A registered credential persisted on the relying-party side after a
/// successful registration ceremony.
///
/// The caller is responsible for storing this in a durable, server-side store
/// keyed by `id` (the credential ID) and associated with `user_id`.
#[derive(Debug, Clone)]
pub struct Credential {
    /// Opaque byte string that uniquely identifies this credential.
    /// Produced by the authenticator during registration.
    pub id: Vec<u8>,

    /// The authenticator's public key in the format signalled during registration.
    pub public_key: PublicKey,

    /// Monotonically increasing counter maintained by the authenticator.
    /// Used to detect cloned authenticators.
    pub sign_count: u32,

    /// Application-defined identifier for the user this credential belongs to.
    pub user_id: Vec<u8>,

    /// Relying party ID (e.g. `"example.com"`).
    /// Stored so authentication can verify the credential is bound to this RP.
    pub rp_id: String,

    /// When this credential was first registered.
    pub created_at: SystemTime,
}

// ─── Wire-format input types ──────────────────────────────────────────────────

/// The response produced by the authenticator after `navigator.credentials.create()`.
///
/// Both fields carry the **raw decoded bytes** — base64url decoding happens
/// outside the library before constructing this struct. This matches the
/// ArrayBuffer values you get after calling `response.clientDataJSON` in JS.
#[derive(Debug, Clone)]
pub struct AuthenticatorAttestationResponse {
    /// Raw UTF-8 bytes of the `clientDataJSON` object.
    pub client_data_json: Vec<u8>,

    /// Raw CBOR bytes of the `attestationObject`.
    pub attestation_object: Vec<u8>,
}

// ─── Challenge ────────────────────────────────────────────────────────────────

/// A single-use challenge issued by the relying party before a ceremony.
///
/// **Security contract**: each `Challenge` must be used at most once and must
/// expire after a short window (typically 60–300 seconds). The caller is
/// responsible for enforcing both properties.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// 32 cryptographically random bytes.
    pub bytes: Vec<u8>,

    /// When this challenge was generated — used for expiry checks.
    pub created_at: SystemTime,
}

impl Challenge {
    /// Generate a fresh 32-byte challenge using the OS cryptographic RNG.
    ///
    /// 32 bytes provides 256 bits of entropy — far beyond any brute-force threat.
    ///
    /// # Errors
    /// Returns [`WebAuthnError::InvalidClientData`] if the system RNG fails
    /// (extremely unlikely; would indicate a kernel-level failure).
    pub fn new() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut bytes = vec![0u8; 32];
        rng.fill(&mut bytes).map_err(|_| {
            WebAuthnError::InvalidClientData(
                "system random number generator failed to produce bytes".to_string(),
            )
        })?;
        Ok(Self {
            bytes,
            created_at: SystemTime::now(),
        })
    }

    /// Returns `true` if this challenge is older than `ttl_secs` seconds.
    ///
    /// Returns `true` if the system clock has gone backwards since the challenge
    /// was created — treating an unverifiable age as expired is the safe default.
    pub fn is_expired(&self, ttl_secs: u64) -> bool {
        self.created_at
            .elapsed()
            .map(|age| age > Duration::from_secs(ttl_secs))
            .unwrap_or(true)
    }
}

// ─── Ceremony result types ────────────────────────────────────────────────────

/// Successful outcome of a registration ceremony.
#[derive(Debug)]
pub struct RegistrationResult {
    /// The newly registered credential — persist this in your database.
    pub credential: Credential,

    /// What kind of attestation the authenticator provided.
    pub attestation_type: AttestationType,
}

/// Successful outcome of an authentication ceremony.
#[derive(Debug)]
pub struct AuthenticationResult {
    /// The credential ID used to authenticate.
    pub credential_id: Vec<u8>,

    /// The sign count returned by the authenticator this ceremony.
    /// Update the stored credential's `sign_count` to this value after success.
    pub new_sign_count: u32,

    /// Whether the User Present (UP) flag was set — the authenticator confirmed
    /// that a human was at the device (button press, touch, etc.).
    pub user_present: bool,

    /// Whether the authenticator signalled that the user was verified
    /// (biometric check, PIN, etc.) — corresponds to the UV flag.
    pub user_verified: bool,
}

/// The level of attestation the authenticator provided.
#[derive(Debug, PartialEq, Eq)]
pub enum AttestationType {
    /// The authenticator explicitly provided no attestation (`"fmt": "none"`).
    /// The credential is still usable, but device provenance cannot be verified.
    None,

    /// The attestation was signed by the same key used for authentication
    /// (self-attestation). Proves the credential is fresh but not the device model.
    SelfAttestation,
}
