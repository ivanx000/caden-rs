//! Core domain types for stored credentials, challenges, and ceremony results.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use ciborium::value::Value;

use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{Result, WebAuthnError};

// ─── Public key ───────────────────────────────────────────────────────────────

/// The public key extracted from a COSE key structure during registration.
///
/// Four algorithms are supported:
/// - **ES256** — ECDSA P-256 with SHA-256 (COSE alg `-7`). Most common.
/// - **ES384** — ECDSA P-384 with SHA-384 (COSE alg `-35`).
/// - **EdDSA** — Ed25519 (COSE alg `-8`). Used by newer FIDO2 authenticators.
/// - **RS256** — RSA PKCS#1 v1.5 with SHA-256 (COSE alg `-257`). Used by
///   older YubiKey 4-series devices and Windows Hello.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PublicKey {
    /// P-256 ECDSA public key (COSE alg `-7`, kty `2`).
    ///
    /// `x` and `y` are the 32-byte affine coordinates of the public point.
    /// To obtain the 65-byte uncompressed point for ring, prepend `0x04`:
    /// `0x04 || x (32 bytes) || y (32 bytes)`.
    ES256 {
        #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
        x: Vec<u8>,
        #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
        y: Vec<u8>,
    },

    /// P-384 ECDSA public key (COSE alg `-35`, kty `2`).
    ///
    /// `x` and `y` are the 48-byte affine coordinates of the public point.
    /// To obtain the 97-byte uncompressed point for ring, prepend `0x04`:
    /// `0x04 || x (48 bytes) || y (48 bytes)`.
    ES384 {
        #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
        x: Vec<u8>,
        #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
        y: Vec<u8>,
    },

    /// Ed25519 EdDSA public key (COSE alg `-8`, kty `1` OKP).
    ///
    /// The inner `Vec<u8>` is the raw 32-byte Ed25519 public key,
    /// as encoded in COSE OKP key parameter `-2` (`x`).
    EdDSA(#[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] Vec<u8>),

    /// RSA PKCS#1 v1.5 SHA-256 public key (COSE alg `-257`, kty `3`).
    ///
    /// `n` is the big-endian modulus (256 bytes for a 2048-bit key).
    /// `e` is the big-endian public exponent (typically `[0x01, 0x00, 0x01]`).
    RS256 {
        #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
        n: Vec<u8>,
        #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
        e: Vec<u8>,
    },
}

impl PublicKey {
    /// Return the COSE algorithm identifier for this key.
    pub fn algorithm(&self) -> i64 {
        match self {
            PublicKey::ES256 { .. } => crate::algorithm::COSE_ES256,
            PublicKey::ES384 { .. } => crate::algorithm::COSE_ES384,
            PublicKey::EdDSA(_) => crate::algorithm::COSE_EDDSA,
            PublicKey::RS256 { .. } => crate::algorithm::COSE_RS256,
        }
    }

    /// Return a human-readable description of the key type.
    pub fn key_type(&self) -> &'static str {
        match self {
            PublicKey::ES256 { .. } => "EC2 P-256",
            PublicKey::ES384 { .. } => "EC2 P-384",
            PublicKey::EdDSA(_) => "OKP Ed25519",
            PublicKey::RS256 { .. } => "RSA 2048",
        }
    }
}

// ─── Stored credential ────────────────────────────────────────────────────────

/// A registered credential persisted on the relying-party side after a
/// successful registration ceremony.
///
/// The caller is responsible for storing this in a durable, server-side store
/// keyed by `id` (the credential ID) and associated with `user_id`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Credential {
    /// Opaque byte string that uniquely identifies this credential.
    /// Produced by the authenticator during registration.
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub id: Vec<u8>,

    /// The authenticator's public key in the format signalled during registration.
    pub public_key: PublicKey,

    /// Monotonically increasing counter maintained by the authenticator.
    /// Used to detect cloned authenticators.
    pub sign_count: u32,

    /// Application-defined identifier for the user this credential belongs to.
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub user_id: Vec<u8>,

    /// Relying party ID (e.g. `"example.com"`).
    /// Stored so authentication can verify the credential is bound to this RP.
    pub rp_id: String,

    /// When this credential was first registered.
    pub created_at: SystemTime,

    /// Whether this credential is eligible for backup to a platform sync
    /// service (BE flag, §6.1 bit 3).
    ///
    /// This value is immutable per spec — the authenticator sets it once at
    /// registration and it must not change in subsequent ceremonies. A change
    /// in `backup_eligible` between registration and authentication is treated
    /// as a credential substitution attempt and rejected with
    /// [`crate::error::WebAuthnError::BackupEligibilityChanged`].
    pub backup_eligible: bool,
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Challenge {
    /// 32 cryptographically random bytes.
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
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
            .map(|age| age >= Duration::from_secs(ttl_secs))
            .unwrap_or(true)
    }
}

// ─── Ceremony result types ────────────────────────────────────────────────────

/// Successful outcome of a registration ceremony.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RegistrationResult {
    /// The newly registered credential — persist this in your database.
    pub credential: Credential,

    /// What kind of attestation the authenticator provided.
    pub attestation_type: AttestationType,

    /// Whether the registered credential is eligible for backup to a platform
    /// sync service (BE flag). This value is set by the authenticator and is
    /// immutable — it will not change in future ceremonies for this credential.
    pub backup_eligible: bool,

    /// Whether the credential was backed up at the time of registration (BS flag).
    pub backup_state: bool,

    /// Authenticator extension data from registration (§6.1 / §10.5), or `None` if the
    /// ED flag was not set. Keys are extension identifiers (e.g. `"credProps"`); values
    /// are raw CBOR that callers inspect themselves.
    ///
    /// Excluded from serde serialization: `ciborium::value::Value` has no portable JSON
    /// encoding. Extract the values you need and convert them before serializing.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub extensions: Option<HashMap<String, Value>>,
}

/// Successful outcome of an authentication ceremony.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthenticationResult {
    /// The credential ID used to authenticate.
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
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

    /// Whether the credential is eligible for backup (BE flag).
    /// Should remain constant across authentications for a given credential.
    pub backup_eligible: bool,

    /// Whether the credential is currently backed up (BS flag).
    /// May change between ceremonies as backup state varies.
    pub backup_state: bool,

    /// Authenticator extension data from authentication (§6.1 / §10.5), or `None` if the
    /// ED flag was not set. Keys are extension identifiers (e.g. `"appid"`); values are
    /// raw CBOR that callers inspect themselves.
    ///
    /// Excluded from serde serialization: `ciborium::value::Value` has no portable JSON
    /// encoding. Extract the values you need and convert them before serializing.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub extensions: Option<HashMap<String, Value>>,
}

/// The level of attestation the authenticator provided.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AttestationType {
    /// The authenticator explicitly provided no attestation (`"fmt": "none"`).
    /// The credential is still usable, but device provenance cannot be verified.
    None,

    /// The attestation was signed by the same key used for authentication
    /// (self-attestation). Proves the credential is fresh but not the device model.
    SelfAttestation,

    /// The attestation was signed by a separate attestation key with an `x5c`
    /// certificate chain present. The chain order has been verified (each cert is
    /// signed by the next), but the root has **not** been checked against a trust
    /// anchor because none were configured on [`crate::RelyingParty`]. Device
    /// provenance is structurally plausible but not cryptographically anchored.
    Basic,

    /// Same as [`Basic`](AttestationType::Basic) but the root certificate was
    /// additionally verified to be signed by one of the trust anchors configured
    /// via [`crate::RelyingParty::trust_anchors`]. Device provenance is
    /// cryptographically anchored to the configured CA set.
    BasicVerified,
}

// ─── Serde round-trip tests ───────────────────────────────────────────────────

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    fn epoch_plus(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn challenge_round_trips() {
        let c = Challenge {
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
            created_at: epoch_plus(1_700_000_000),
        };
        let json = serde_json::to_string(&c).expect("test setup");
        let back: Challenge = serde_json::from_str(&json).expect("test setup");
        assert_eq!(back.bytes, c.bytes);
        assert_eq!(back.created_at, c.created_at);
    }

    #[test]
    fn public_key_es256_round_trips() {
        let key = PublicKey::ES256 {
            x: vec![0x01u8; 32],
            y: vec![0x02u8; 32],
        };
        let json = serde_json::to_string(&key).expect("test setup");
        let back: PublicKey = serde_json::from_str(&json).expect("test setup");
        match back {
            PublicKey::ES256 { x, y } => {
                assert_eq!(x, vec![0x01u8; 32]);
                assert_eq!(y, vec![0x02u8; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn public_key_eddsa_round_trips() {
        let key = PublicKey::EdDSA(vec![0x03u8; 32]);
        let json = serde_json::to_string(&key).expect("test setup");
        let back: PublicKey = serde_json::from_str(&json).expect("test setup");
        match back {
            PublicKey::EdDSA(bytes) => assert_eq!(bytes, vec![0x03u8; 32]),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn public_key_rs256_round_trips() {
        let key = PublicKey::RS256 {
            n: vec![0x04u8; 256],
            e: vec![0x01, 0x00, 0x01],
        };
        let json = serde_json::to_string(&key).expect("test setup");
        let back: PublicKey = serde_json::from_str(&json).expect("test setup");
        match back {
            PublicKey::RS256 { n, e } => {
                assert_eq!(n, vec![0x04u8; 256]);
                assert_eq!(e, vec![0x01, 0x00, 0x01]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn credential_round_trips() {
        let cred = Credential {
            id: vec![0xAAu8; 16],
            public_key: PublicKey::ES256 {
                x: vec![0x01u8; 32],
                y: vec![0x02u8; 32],
            },
            sign_count: 42,
            user_id: vec![0xBBu8; 8],
            rp_id: "example.com".to_string(),
            created_at: epoch_plus(1_700_000_000),
            backup_eligible: true,
        };
        let json = serde_json::to_string(&cred).expect("test setup");
        let back: Credential = serde_json::from_str(&json).expect("test setup");
        assert_eq!(back.id, cred.id);
        assert_eq!(back.sign_count, cred.sign_count);
        assert_eq!(back.user_id, cred.user_id);
        assert_eq!(back.rp_id, cred.rp_id);
        assert_eq!(back.created_at, cred.created_at);
        assert_eq!(back.backup_eligible, cred.backup_eligible);
    }
}
