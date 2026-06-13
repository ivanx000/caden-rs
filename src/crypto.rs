//! Low-level cryptographic primitives used throughout WebAuthn ceremony verification.
//!
//! All cryptographic operations are delegated to [`ring`], which is a carefully
//! audited, FIPS-aligned library descended from BoringSSL. No custom crypto is
//! implemented here.

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, UnparsedPublicKey};

use crate::credential::Challenge;
use crate::error::{WebAuthnError, Result};

/// Compute SHA-256 of `data` and return the 32-byte digest.
///
/// Used to hash `clientDataJSON` (→ clientDataHash) and to compute the
/// RP ID hash for comparison against authenticator data.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = digest::digest(&digest::SHA256, data);
    // SHA256 always produces exactly 32 bytes; the unwrap cannot fail.
    digest
        .as_ref()
        .try_into()
        .expect("SHA-256 digest is always 32 bytes")
}

/// Generate `len` cryptographically random bytes using the OS RNG.
///
/// # Errors
/// Returns [`WebAuthnError::InvalidClientData`] if the system RNG fails
/// (extremely unlikely in practice).
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes).map_err(|_| {
        WebAuthnError::InvalidClientData(
            "system random number generator failed to produce bytes".to_string(),
        )
    })?;
    Ok(bytes)
}

/// Verify an ES256 (ECDSA P-256 + SHA-256) signature.
///
/// # Arguments
/// * `public_key_uncompressed` — 65-byte uncompressed P-256 point:
///   `0x04 || x (32 bytes) || y (32 bytes)`.
/// * `message`   — The raw message that was signed (ring hashes internally via SHA-256).
/// * `signature` — DER-encoded ASN.1 ECDSA signature, as produced by authenticators.
///
/// # Errors
/// Returns [`WebAuthnError::SignatureVerificationFailed`] if the signature is
/// invalid, the key is malformed, or the public key does not match.
pub fn verify_es256(
    public_key_uncompressed: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key_uncompressed);
    key.verify(message, signature)
        .map_err(|_| WebAuthnError::SignatureVerificationFailed)
}

/// Generate a fresh 32-byte [`Challenge`] using the OS cryptographic RNG.
///
/// Convenience wrapper around [`Challenge::new`]; prefer that method in new code.
pub fn generate_challenge() -> Result<Challenge> {
    Challenge::new()
}
