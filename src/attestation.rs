//! Attestation statement verification.
//!
//! An attestation statement lets the relying party verify the provenance of an
//! authenticator — specifically, that it is a genuine device from a known
//! manufacturer and model. This library supports only the `"none"` format.
//!
//! ## Supported formats
//!
//! | Format      | Status           | Notes                                      |
//! |-------------|------------------|--------------------------------------------|
//! | `"none"`    | Supported        | No cryptographic attestation provided      |
//! | `"packed"`  | Not supported    | Requires CA chain validation               |
//! | `"fido-u2f"`| Not supported    | Legacy U2F devices                         |
//! | `"tpm"`     | Not supported    | Requires TPM certificate chain             |
//! | `"apple"`   | Not supported    | Requires Apple's root certificate          |
//!
//! For a portfolio / learning project, `"none"` is sufficient.  Production
//! relying parties that require verified device provenance should implement
//! `"packed"` or use a FIDO Metadata Service (MDS) integration.

use crate::credential::AttestationType;
use crate::error::{WebAuthnError, Result};

/// Verify the attestation statement and return the [`AttestationType`].
///
/// # Arguments
/// * `fmt`              — Attestation format string from the attestation object.
/// * `_auth_data`       — Raw authenticator data bytes (reserved for future use).
/// * `_client_data_hash`— SHA-256(clientDataJSON) (reserved for packed/tpm formats).
///
/// # Errors
/// Returns [`WebAuthnError::InvalidAttestationObject`] for any format other
/// than `"none"`, since this library cannot verify their statements.
pub fn verify(
    fmt: &str,
    _auth_data: &[u8],
    _client_data_hash: &[u8],
) -> Result<AttestationType> {
    match fmt {
        // §8.7 — "none" attestation: the authenticator is not attested.
        // The attStmt must be an empty CBOR map, but since we receive it
        // already decoded we simply return AttestationType::None.
        "none" => Ok(AttestationType::None),

        // Any other format would require certificate chain validation against
        // the FIDO Metadata Service — out of scope for this library.
        other => Err(WebAuthnError::InvalidAttestationObject(format!(
            "attestation format \"{other}\" is not supported by this library; \
             only \"none\" is accepted"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_none_format() {
        let result = verify("none", &[], &[]);
        assert!(matches!(result, Ok(AttestationType::None)));
    }

    #[test]
    fn rejects_packed_format() {
        let result = verify("packed", &[], &[]);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(_))
        ));
    }

    #[test]
    fn rejects_fido_u2f_format() {
        let result = verify("fido-u2f", &[], &[]);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(_))
        ));
    }

    #[test]
    fn rejects_unknown_format() {
        let result = verify("not-a-real-format", &[], &[]);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAttestationObject(_))
        ));
    }
}
