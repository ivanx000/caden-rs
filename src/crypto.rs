//! Low-level cryptographic primitives used throughout WebAuthn ceremony verification.
//!
//! All cryptographic operations are delegated to [`ring`], which is a carefully
//! audited, FIPS-aligned library descended from BoringSSL. No custom crypto is
//! implemented here.

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, UnparsedPublicKey};

use crate::credential::Challenge;
use crate::error::{Result, WebAuthnError};

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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── sha256 ───────────────────────────────────────────────────────────────

    #[test]
    fn sha256_known_answer_empty_input() {
        // RFC-specified SHA-256 of the empty string.
        let digest = sha256(b"");
        let expected = hex_to_bytes(
            "e3b0c44298fc1c149afbf4c8996fb924\
                                     27ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(digest, expected.as_slice());
    }

    #[test]
    fn sha256_returns_32_bytes() {
        assert_eq!(sha256(b"anything").len(), 32);
    }

    #[test]
    fn sha256_is_deterministic() {
        assert_eq!(sha256(b"abc"), sha256(b"abc"));
    }

    #[test]
    fn sha256_different_inputs_differ() {
        assert_ne!(sha256(b"abc"), sha256(b"abd"));
        assert_ne!(sha256(b"abc"), sha256(b""));
    }

    // ── random_bytes ─────────────────────────────────────────────────────────

    #[test]
    fn random_bytes_zero_len_returns_empty() {
        let result = random_bytes(0).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn random_bytes_returns_exact_len() {
        let result = random_bytes(32).unwrap();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn random_bytes_two_calls_differ() {
        let a = random_bytes(32).unwrap();
        let b = random_bytes(32).unwrap();
        assert_ne!(a, b, "two random 32-byte draws should not match");
    }

    // ── verify_es256 ─────────────────────────────────────────────────────────

    #[test]
    fn verify_es256_rejects_key_missing_prefix() {
        // A 64-byte key (missing the 0x04 uncompressed-point prefix) is invalid.
        let key_64 = vec![0x01u8; 64];
        let err = verify_es256(&key_64, b"msg", b"sig").unwrap_err();
        assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_es256_rejects_empty_key() {
        let err = verify_es256(&[], b"msg", b"sig").unwrap_err();
        assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_es256_rejects_empty_signature() {
        let key = vec![0x04u8; 65];
        let err = verify_es256(&key, b"hello", &[]).unwrap_err();
        assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_es256_rejects_wrong_signature() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pk = kp.public_key().as_ref();

        // Sign "message A" but verify against "message B".
        let sig = kp.sign(&rng, b"message A").unwrap();
        let err = verify_es256(pk, b"message B", sig.as_ref()).unwrap_err();
        assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
    }

    #[test]
    fn verify_es256_rejects_garbage_der_signature() {
        use ring::rand::SystemRandom;
        use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let pk = kp.public_key().as_ref();

        let err = verify_es256(pk, b"hello", &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap_err();
        assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
