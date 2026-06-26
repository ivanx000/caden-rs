//! Error types for the webauthn library.
//!
//! Every variant produces a message that aids debugging without leaking
//! security-sensitive material (key bytes, challenge values, etc.).

use thiserror::Error;

/// All errors that can be returned by WebAuthn ceremony verification.
#[derive(Debug, Error)]
pub enum WebAuthnError {
    /// The client data JSON could not be decoded or is structurally invalid.
    #[error("Invalid client data: {0}")]
    InvalidClientData(String),

    /// The challenge inside the client data does not match the issued challenge.
    ///
    /// Security-critical: a mismatch means the response was not produced for
    /// this ceremony instance.
    #[error("Challenge mismatch: expected challenge does not match response")]
    ChallengeMismatch,

    /// The `origin` field in the client data does not match the expected origin.
    ///
    /// Prevents a credential from one origin being replayed at another.
    #[error("Origin mismatch: expected {expected}, got {got}")]
    OriginMismatch { expected: String, got: String },

    /// The RP ID hash in authenticator data does not equal SHA-256(rp_id).
    ///
    /// Ensures the authenticator bound the credential to the correct relying party.
    #[error("RP ID hash mismatch")]
    RpIdHashMismatch,

    /// The User Present (UP) flag is not set in the authenticator data flags byte.
    #[error("User Present flag not set")]
    UserNotPresent,

    /// The User Verification (UV) flag is not set, but the relying party has
    /// `require_user_verification` enabled.
    ///
    /// The authenticator must perform user verification (PIN, biometric, etc.)
    /// before the assertion is accepted.
    #[error("User Verification flag not set")]
    UserNotVerified,

    /// The attestation object could not be decoded or is missing required fields.
    #[error("Invalid attestation object: {0}")]
    InvalidAttestationObject(String),

    /// The authenticator data bytes are malformed or too short.
    #[error("Invalid authenticator data: {0}")]
    InvalidAuthenticatorData(String),

    /// The COSE public key inside the credential data is invalid.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// ECDSA signature verification returned a failure.
    ///
    /// The message was either tampered with or signed by the wrong key.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// The sign count in the assertion is not greater than the stored sign count.
    ///
    /// Indicates a possible authenticator clone or replay attack.
    #[error("Sign count invalid: stored {stored}, received {received}")]
    SignCountInvalid { stored: u32, received: u32 },

    /// A CBOR decoding step failed.
    #[error("CBOR decode error: {0}")]
    CborDecodeError(String),

    /// A base64url decoding step failed.
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),

    /// The challenge was issued too long ago and is no longer valid.
    ///
    /// Callers should generate a new challenge and restart the ceremony.
    #[error("Challenge expired")]
    ChallengeExpired,

    /// The COSE algorithm identifier is not supported by this library.
    ///
    /// The `i64` is the raw COSE algorithm integer (e.g. `-7` = ES256, `-257` = RS256).
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(i64),

    /// `clientDataJSON` contains `crossOrigin: true` but the relying party has
    /// `reject_cross_origin` enabled.
    ///
    /// Cross-origin credentials allow assertions from an iframe whose origin
    /// differs from the top-level origin. When the RP does not expect embedded
    /// usage, `crossOrigin: true` may indicate credential abuse.
    #[error("Cross-origin credential use is not permitted by this relying party")]
    CrossOriginNotAllowed,

    /// The credential has the Backup Eligibility (BE) flag set, but this relying
    /// party has `reject_backup_eligible` enabled.
    ///
    /// Use this policy when your threat model requires hardware-bound keys that
    /// cannot be synced to a cloud or platform account.
    #[error("Credential is backup-eligible but this relying party does not permit backed-up credentials")]
    BackupEligibleNotAllowed,

    /// The credential does not have the Backup Eligibility (BE) flag set, but
    /// this relying party has `require_backup_eligible` enabled.
    ///
    /// Use this policy for consumer passkey deployments that depend on credential
    /// sync (e.g. cross-device sign-in via iCloud Keychain or Google Password Manager).
    #[error("Credential is not backup-eligible but this relying party requires backup-eligible credentials")]
    BackupEligibilityRequired,
}

/// Convenience alias so callers write `webauthn::Result<T>`.
pub type Result<T> = std::result::Result<T, WebAuthnError>;
