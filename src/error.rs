//! Error types for the webauthn library.
//!
//! Every variant produces a message that aids debugging without leaking
//! security-sensitive material (key bytes, challenge values, etc.).

use thiserror::Error;

use crate::metadata::AuthenticatorStatus;

/// All errors that can be returned by WebAuthn ceremony verification.
#[derive(Debug, Error)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
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

    /// The challenge has already been consumed by a previous ceremony.
    ///
    /// This error is only returned when the relying party has opted in to
    /// single-use challenge enforcement via
    /// [`crate::RelyingParty::enforce_single_use_challenges`]. Issue a fresh
    /// challenge and restart the ceremony.
    #[error("Challenge was already used in a previous ceremony")]
    ChallengePreviouslyUsed,

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

    /// The Backup Eligibility (BE) flag in the authenticator data differs from
    /// the value recorded at registration time.
    ///
    /// BE is immutable per spec — a mismatch indicates a possible credential
    /// substitution attack (a different authenticator presenting the same credential ID).
    #[error(
        "Backup Eligibility flag changed since registration — credential may have been substituted"
    )]
    BackupEligibilityChanged,

    /// The `x5c` certificate chain in an attestation statement is structurally
    /// invalid: a certificate in the chain is not signed by the next certificate,
    /// or the DER encoding is malformed.
    ///
    /// The inner string identifies which link in the chain failed and why.
    #[error("Attestation certificate chain invalid: {0}")]
    AttestationChainInvalid(String),

    /// The `x5c` chain is structurally valid but its root certificate is not
    /// signed by any of the configured trust anchors.
    ///
    /// This error is only returned when the relying party has configured at least
    /// one trust anchor via [`crate::RelyingParty::trust_anchors`]. When no
    /// trust anchors are configured the chain structure is still verified but
    /// the root is accepted unconditionally.
    #[error("Attestation root certificate is not trusted by any configured trust anchor")]
    AttestationRootUntrusted,

    /// The attestation certificate carries the `id-fido-gen-ce-aaguid`
    /// extension (OID 1.3.6.1.4.1.45724.1.1.4) but its value does not match
    /// the AAGUID reported in `authenticatorData`.
    ///
    /// Per WebAuthn §8.2.1, when present this extension binds the certificate
    /// to a specific authenticator model. A mismatch means the certificate was
    /// issued for a different model than the one that produced this response —
    /// a signal of a forged or misused attestation certificate.
    #[error("Attestation certificate AAGUID extension does not match authenticatorData AAGUID")]
    AttestationAaguidMismatch,

    /// The packed attestation certificate's Basic Constraints extension has
    /// the CA component set to `true`.
    ///
    /// Per WebAuthn §8.2.1 (Certificate Requirements for Packed Attestation
    /// Statements), an attestation certificate MUST have Basic Constraints
    /// `CA:FALSE` — it must be an end-entity certificate, not one capable of
    /// signing other certificates. A `CA:TRUE` leaf is a signal that a CA
    /// certificate is being substituted for a genuine attestation leaf.
    #[error("Attestation certificate is marked as a CA (Basic Constraints CA:TRUE)")]
    AttestationCertIsCa,

    /// The authenticator's AAGUID is flagged with a compromised
    /// [`AuthenticatorStatus`] in the relying party's configured
    /// [`crate::RelyingParty::authenticator_metadata`].
    ///
    /// Per WebAuthn §14.4 (Metadata Service Considerations), a relying party
    /// should consult the FIDO Metadata Service and refuse new registrations
    /// from authenticator models known to be compromised, revoked, or capable
    /// of bypassing user verification.
    #[error("Authenticator model is untrusted: FIDO MDS status {0}")]
    AuthenticatorStatusUntrusted(AuthenticatorStatus),

    /// The `credential_id` field of an [`crate::AuthenticatorAssertionResponse`] is empty.
    ///
    /// Both discoverable and non-discoverable flows require the authenticator to
    /// return the selected credential ID as `rawId` in the `PublicKeyCredential`.
    /// An empty `credential_id` means the field was not populated before calling
    /// [`crate::RelyingParty::begin_authentication`].
    #[error("Missing credential ID: response.credential_id must not be empty")]
    MissingCredentialId,

    /// The FIDO MDS BLOB passed to
    /// [`crate::metadata::verify_and_parse_mds_blob`] is not well-formed: it
    /// does not have the 3-segment JWT Compact Serialization structure, a
    /// segment is not valid base64(url), the JOSE header or payload is not
    /// valid JSON, or a required field (`alg`, `x5c`) is missing or wrong.
    ///
    /// The inner string identifies which part of the BLOB failed to parse,
    /// without echoing untrusted BLOB content back verbatim.
    #[error("Malformed FIDO MDS BLOB: {0}")]
    MdsBlobMalformed(String),

    /// The `x5c` certificate chain in the FIDO MDS BLOB's JOSE header is
    /// structurally invalid: a certificate in the chain is not signed by the
    /// next certificate, or the DER encoding is malformed.
    ///
    /// The inner string identifies which link in the chain failed and why.
    #[error("FIDO MDS BLOB signer certificate chain invalid: {0}")]
    MdsChainInvalid(String),

    /// The FIDO MDS BLOB's `x5c` chain is structurally valid, but its root
    /// certificate is not signed by the caller-supplied trust anchor.
    ///
    /// Unlike attestation trust anchors (which are optional — an unanchored
    /// chain still yields [`AttestationType::Basic`](crate::credential::AttestationType::Basic)),
    /// the MDS trust root is mandatory: an unrooted MDS BLOB cannot be
    /// trusted to report accurate authenticator status, so there is no
    /// unverified fallback.
    #[error("FIDO MDS BLOB signer root certificate is not trusted by the supplied trust anchor")]
    MdsRootUntrusted,

    /// The ES256 signature over the FIDO MDS BLOB's `header.payload` does not
    /// verify against the `x5c[0]` leaf certificate's public key.
    ///
    /// The BLOB was either tampered with or signed by a key that does not
    /// correspond to the presented certificate chain.
    #[error("FIDO MDS BLOB signature verification failed")]
    MdsSignatureInvalid,
}

/// Convenience alias so callers write `webauthn::Result<T>`.
pub type Result<T> = std::result::Result<T, WebAuthnError>;
