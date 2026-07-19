//! FIDO Alliance Metadata Service (MDS) status consumption.
//!
//! WebAuthn §14.4 ("Metadata Service Considerations") recommends that a
//! relying party consult the [FIDO Metadata Service](https://fidoalliance.org/metadata/)
//! to check whether an authenticator model is known to be compromised before
//! trusting a newly registered credential. `caden` does not fetch or parse the
//! MDS BLOB itself — that requires network access and JWS verification, which
//! would break the library's stateless, I/O-free design (see
//! [`crate::RelyingParty`]). Instead, the caller fetches and verifies the MDS
//! BLOB out-of-band (e.g. with a scheduled job) and supplies the resulting
//! per-AAGUID [`AuthenticatorStatus`] lists to
//! [`crate::RelyingParty::authenticator_metadata`].
//!
//! Only the status values that FIDO Alliance recommends treating as
//! disqualifying are enforced automatically ([`AuthenticatorStatus::is_compromised`]);
//! the caller decides how to source and refresh the underlying MDS data.

/// The status of an authenticator model as reported by the FIDO Metadata
/// Service `StatusReport` structure.
///
/// This mirrors the `AuthenticatorStatus` enum from the [FIDO Metadata
/// Service specification](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#authenticatorstatus-enum).
/// New statuses may be added by FIDO Alliance over time, so this type is
/// `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum AuthenticatorStatus {
    /// The authenticator is not FIDO certified.
    NotFidoCertified,
    /// The authenticator is FIDO certified.
    FidoCertified,
    /// A compromise of the authenticator's user verification method
    /// (fingerprint, PIN, etc.) has been discovered. Attestations from this
    /// model can no longer be trusted to prove the claimed user verification
    /// actually occurred.
    UserVerificationBypass,
    /// The attestation key for this authenticator model is known to be
    /// compromised. Attestation signatures from this model can no longer be
    /// trusted to prove authenticator provenance.
    AttestationKeyCompromise,
    /// A remote (software) compromise of the authenticator's user key has
    /// been discovered — an attacker can extract or use the private key
    /// without physical access to the device.
    UserKeyRemoteCompromise,
    /// A physical compromise of the authenticator's user key has been
    /// discovered — an attacker with physical access can extract or use the
    /// private key.
    UserKeyPhysicalCompromise,
    /// A software or firmware update is available that addresses a known
    /// issue; not itself a compromise.
    UpdateAvailable,
    /// The authenticator model has been revoked by the vendor or FIDO
    /// Alliance and must no longer be trusted.
    Revoked,
    /// The authenticator vendor has self-asserted certification without
    /// completing the FIDO Alliance certification process.
    SelfAssertionSubmitted,
    /// FIDO certified at Authenticator Certification Level 1.
    FidoCertifiedL1,
    /// FIDO certified at Authenticator Certification Level 1+.
    FidoCertifiedL1Plus,
    /// FIDO certified at Authenticator Certification Level 2.
    FidoCertifiedL2,
    /// FIDO certified at Authenticator Certification Level 2+.
    FidoCertifiedL2Plus,
    /// FIDO certified at Authenticator Certification Level 3.
    FidoCertifiedL3,
    /// FIDO certified at Authenticator Certification Level 3+.
    FidoCertifiedL3Plus,
}

impl AuthenticatorStatus {
    /// Whether this status indicates the authenticator model should no
    /// longer be trusted for new registrations.
    ///
    /// This is the set of statuses the FIDO Alliance MDS specification
    /// identifies as evidence of an actual security compromise —
    /// [`Revoked`](Self::Revoked),
    /// [`AttestationKeyCompromise`](Self::AttestationKeyCompromise),
    /// [`UserKeyRemoteCompromise`](Self::UserKeyRemoteCompromise),
    /// [`UserKeyPhysicalCompromise`](Self::UserKeyPhysicalCompromise), and
    /// [`UserVerificationBypass`](Self::UserVerificationBypass). Certification
    /// tier and informational statuses (e.g. `UpdateAvailable`,
    /// `NotFidoCertified`) do not indicate compromise on their own.
    pub fn is_compromised(&self) -> bool {
        matches!(
            self,
            Self::Revoked
                | Self::AttestationKeyCompromise
                | Self::UserKeyRemoteCompromise
                | Self::UserKeyPhysicalCompromise
                | Self::UserVerificationBypass
        )
    }
}

impl std::fmt::Display for AuthenticatorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NotFidoCertified => "NOT_FIDO_CERTIFIED",
            Self::FidoCertified => "FIDO_CERTIFIED",
            Self::UserVerificationBypass => "USER_VERIFICATION_BYPASS",
            Self::AttestationKeyCompromise => "ATTESTATION_KEY_COMPROMISE",
            Self::UserKeyRemoteCompromise => "USER_KEY_REMOTE_COMPROMISE",
            Self::UserKeyPhysicalCompromise => "USER_KEY_PHYSICAL_COMPROMISE",
            Self::UpdateAvailable => "UPDATE_AVAILABLE",
            Self::Revoked => "REVOKED",
            Self::SelfAssertionSubmitted => "SELF_ASSERTION_SUBMITTED",
            Self::FidoCertifiedL1 => "FIDO_CERTIFIED_L1",
            Self::FidoCertifiedL1Plus => "FIDO_CERTIFIED_L1plus",
            Self::FidoCertifiedL2 => "FIDO_CERTIFIED_L2",
            Self::FidoCertifiedL2Plus => "FIDO_CERTIFIED_L2plus",
            Self::FidoCertifiedL3 => "FIDO_CERTIFIED_L3",
            Self::FidoCertifiedL3Plus => "FIDO_CERTIFIED_L3plus",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compromise_statuses_are_flagged() {
        assert!(AuthenticatorStatus::Revoked.is_compromised());
        assert!(AuthenticatorStatus::AttestationKeyCompromise.is_compromised());
        assert!(AuthenticatorStatus::UserKeyRemoteCompromise.is_compromised());
        assert!(AuthenticatorStatus::UserKeyPhysicalCompromise.is_compromised());
        assert!(AuthenticatorStatus::UserVerificationBypass.is_compromised());
    }

    #[test]
    fn informational_statuses_are_not_flagged() {
        assert!(!AuthenticatorStatus::NotFidoCertified.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertified.is_compromised());
        assert!(!AuthenticatorStatus::UpdateAvailable.is_compromised());
        assert!(!AuthenticatorStatus::SelfAssertionSubmitted.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL1.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL1Plus.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL2.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL2Plus.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL3.is_compromised());
        assert!(!AuthenticatorStatus::FidoCertifiedL3Plus.is_compromised());
    }

    #[test]
    fn display_matches_mds_wire_names() {
        assert_eq!(AuthenticatorStatus::Revoked.to_string(), "REVOKED");
        assert_eq!(
            AuthenticatorStatus::FidoCertifiedL1Plus.to_string(),
            "FIDO_CERTIFIED_L1plus"
        );
    }
}
