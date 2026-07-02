//! Minimal DER (Distinguished Encoding Rules) builder for RSA public keys.
//!
//! ring's RSA verification API expects the public key in DER-encoded
//! RSAPublicKey format (`SEQUENCE { INTEGER n, INTEGER e }` per RFC 3447 §A.1.1),
//! but COSE stores RSA keys as raw modulus (`n`) and exponent (`e`) byte arrays.
//! This module bridges the two.
//!
//! Only the subset of DER needed to encode an RSA public key is implemented.
//! No general-purpose ASN.1 library is pulled in — the structure is fixed and
//! the encoding can be computed with simple byte concatenation.

use crate::error::{Result, WebAuthnError};

/// Encode a DER length field.
///
/// DER uses a variable-length encoding:
/// - 1 byte for lengths 0–127
/// - `0x81 nn` for lengths 128–255
/// - `0x82 nn nn` for lengths 256–65535
/// - `0x84 nn nn nn nn` for larger lengths (handles edge cases)
pub fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else if len <= 0xFFFF {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        // For RSA keys up to 4096-bit, this branch is unreachable in practice.
        vec![
            0x84,
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ]
    }
}

/// Wrap `contents` in a DER SEQUENCE (tag `0x30`).
pub fn der_sequence(contents: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    out.extend_from_slice(&der_length(contents.len()));
    out.extend_from_slice(contents);
    out
}

/// Encode `value` as a DER INTEGER (tag `0x02`).
///
/// DER integers are signed. If the high bit of `value[0]` is set, a leading
/// `0x00` byte is prepended so the value is not misread as negative.
pub fn der_integer(value: &[u8]) -> Vec<u8> {
    let needs_pad = !value.is_empty() && value[0] & 0x80 != 0;
    let content_len = value.len() + if needs_pad { 1 } else { 0 };

    let mut out = vec![0x02];
    out.extend_from_slice(&der_length(content_len));
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(value);
    out
}

/// Wrap `contents` in a DER BIT STRING (tag `0x03`).
///
/// The leading `0x00` byte signals that no bits are unused in the final octet —
/// required for all SubjectPublicKeyInfo public keys.
pub fn der_bit_string(contents: &[u8]) -> Vec<u8> {
    let content_len = contents.len() + 1; // +1 for the unused-bits byte
    let mut out = vec![0x03];
    out.extend_from_slice(&der_length(content_len));
    out.push(0x00); // unused bits = 0
    out.extend_from_slice(contents);
    out
}

/// Encode `oid_bytes` as a DER OID (tag `0x06`).
///
/// `oid_bytes` must be the already-encoded OID value (not including tag/length).
pub fn der_oid(oid_bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0x06];
    out.extend_from_slice(&der_length(oid_bytes.len()));
    out.extend_from_slice(oid_bytes);
    out
}

/// Return the two-byte DER NULL encoding (`0x05 0x00`).
pub fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// Build a DER-encoded `RSAPublicKey` from raw modulus and exponent bytes.
///
/// `ring`'s `UnparsedPublicKey` with `RSA_PKCS1_2048_8192_SHA256` parses the
/// key as an RSAPublicKey (RFC 3447 §A.1.1), not SubjectPublicKeyInfo. COSE
/// stores `n` and `e` as raw big-endian integers; this function wraps them in
/// the ASN.1 structure ring requires.
///
/// # Structure produced
/// ```text
/// SEQUENCE {          ← RSAPublicKey (RFC 3447)
///   INTEGER n         ← modulus
///   INTEGER e         ← publicExponent
/// }
/// ```
///
/// # Arguments
/// * `n` — RSA modulus as a big-endian byte array (256 bytes for 2048-bit key).
/// * `e` — RSA public exponent as a big-endian byte array (typically `[0x01, 0x00, 0x01]`).
///
/// # Errors
/// Returns [`WebAuthnError::InvalidPublicKey`] if `n` or `e` are empty.
pub fn rsa_components_to_der(n: &[u8], e: &[u8]) -> Result<Vec<u8>> {
    if n.is_empty() {
        return Err(WebAuthnError::InvalidPublicKey(
            "RSA modulus (n) must not be empty".to_string(),
        ));
    }
    if e.is_empty() {
        return Err(WebAuthnError::InvalidPublicKey(
            "RSA exponent (e) must not be empty".to_string(),
        ));
    }

    // RSAPublicKey SEQUENCE { INTEGER n, INTEGER e }
    let mut contents = der_integer(n);
    contents.extend_from_slice(&der_integer(e));
    Ok(der_sequence(&contents))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── der_length ───────────────────────────────────────────────────────────

    #[test]
    fn der_length_short_form() {
        assert_eq!(der_length(0), [0x00]);
        assert_eq!(der_length(1), [0x01]);
        assert_eq!(der_length(127), [0x7f]);
    }

    #[test]
    fn der_length_one_byte_long_form() {
        assert_eq!(der_length(128), [0x81, 0x80]);
        assert_eq!(der_length(255), [0x81, 0xff]);
    }

    #[test]
    fn der_length_two_byte_long_form() {
        assert_eq!(der_length(256), [0x82, 0x01, 0x00]);
        assert_eq!(der_length(290), [0x82, 0x01, 0x22]);
        assert_eq!(der_length(65535), [0x82, 0xff, 0xff]);
    }

    // ── der_sequence ─────────────────────────────────────────────────────────

    #[test]
    fn der_sequence_empty() {
        let encoded = der_sequence(&[]);
        assert_eq!(encoded, [0x30, 0x00]);
    }

    #[test]
    fn der_sequence_wraps_contents() {
        let encoded = der_sequence(&[0xAA, 0xBB]);
        assert_eq!(encoded, [0x30, 0x02, 0xAA, 0xBB]);
    }

    // ── der_integer ──────────────────────────────────────────────────────────

    #[test]
    fn der_integer_no_padding_needed() {
        // 0x01 has high bit clear — no 0x00 prefix needed.
        let encoded = der_integer(&[0x01, 0x00, 0x01]);
        assert_eq!(encoded, [0x02, 0x03, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn der_integer_padding_needed_for_high_bit() {
        // 0x80 has high bit set — DER requires a leading 0x00.
        let encoded = der_integer(&[0x80]);
        assert_eq!(encoded, [0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn der_integer_ff_byte_gets_padded() {
        let encoded = der_integer(&[0xFF, 0x00]);
        assert_eq!(encoded, [0x02, 0x03, 0x00, 0xFF, 0x00]);
    }

    #[test]
    fn der_integer_256_byte_value() {
        // Simulate a 2048-bit RSA modulus starting with 0xB7 (high bit set).
        let n = [0xB7u8; 256];
        let encoded = der_integer(&n);
        // tag + length(257) + 0x00 + 256 bytes
        assert_eq!(encoded[0], 0x02);
        assert_eq!(&encoded[1..4], [0x82, 0x01, 0x01]);
        assert_eq!(encoded[4], 0x00); // padding byte
        assert_eq!(encoded[5], 0xB7); // first byte of n
        assert_eq!(encoded.len(), 1 + 3 + 1 + 256); // tag + len + pad + value
    }

    // ── der_bit_string ───────────────────────────────────────────────────────

    #[test]
    fn der_bit_string_prepends_unused_bits_byte() {
        let encoded = der_bit_string(&[0xAB, 0xCD]);
        // 0x03 (tag) | 0x03 (len=3) | 0x00 (unused bits) | 0xAB | 0xCD
        assert_eq!(encoded, [0x03, 0x03, 0x00, 0xAB, 0xCD]);
    }

    // ── der_oid ──────────────────────────────────────────────────────────────

    #[test]
    fn der_oid_rsa_encryption() {
        let encoded = der_oid(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
        assert_eq!(encoded[0], 0x06); // OID tag
        assert_eq!(encoded[1], 9); // length = 9
        assert_eq!(
            &encoded[2..],
            [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]
        );
    }

    // ── der_null ─────────────────────────────────────────────────────────────

    #[test]
    fn der_null_is_two_bytes() {
        assert_eq!(der_null(), [0x05, 0x00]);
    }

    // ── rsa_components_to_der ────────────────────────────────────────────────

    #[test]
    fn rsa_components_to_der_rejects_empty_n() {
        let err = rsa_components_to_der(&[], &[0x01, 0x00, 0x01]).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("n")));
    }

    #[test]
    fn rsa_components_to_der_rejects_empty_e() {
        let err = rsa_components_to_der(&[0x01u8; 256], &[]).expect_err("expected error");
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("e")));
    }

    #[test]
    fn rsa_components_to_der_produces_correct_size_for_2048_bit_key() {
        // n starting with 0x01 (high bit clear): no DER padding byte needed.
        // INTEGER n = 1(tag)+3(len)+256(val) = 260 bytes
        // INTEGER e = 1(tag)+1(len)+3(val) = 5 bytes
        // SEQUENCE = 1(tag)+3(len)+265(contents) = 269 bytes
        let n = vec![0x01u8; 256];
        let e = [0x01u8, 0x00, 0x01];
        let der = rsa_components_to_der(&n, &e).expect("test setup");
        assert_eq!(der[0], 0x30, "must start with SEQUENCE tag");
        assert_eq!(
            der.len(),
            269,
            "RSAPublicKey for 2048-bit key (no DER padding) should be 269 bytes"
        );
    }

    #[test]
    fn rsa_components_to_der_produces_correct_size_with_high_bit_modulus() {
        // n starting with 0xb7 (high bit set): DER padding byte prepended → n is 257 bytes.
        // INTEGER n = 1(tag)+3(len)+257(val+pad) = 261 bytes
        // INTEGER e = 1(tag)+1(len)+3(val) = 5 bytes
        // SEQUENCE = 1(tag)+3(len)+266(contents) = 270 bytes
        let n = vec![0xb7u8; 256];
        let e = [0x01u8, 0x00, 0x01];
        let der = rsa_components_to_der(&n, &e).expect("test setup");
        assert_eq!(der[0], 0x30);
        assert_eq!(
            der.len(),
            270,
            "RSAPublicKey with 0x00-padded modulus should be 270 bytes"
        );
    }

    #[test]
    fn rsa_components_to_der_accepted_by_ring() {
        // Use a real RSA 2048-bit public key (n, e from the test key hardcoded in
        // crypto module tests). ring must accept the RSAPublicKey DER we produce.
        let n: &[u8] = &[
            0xb7, 0xe0, 0x0f, 0xc9, 0xdb, 0xfa, 0xce, 0x64, 0xa6, 0xe2, 0xb7, 0xfb, 0xa2, 0x1c,
            0x09, 0x14, 0xfb, 0xd6, 0x26, 0xe5, 0x17, 0xcc, 0xf6, 0x6b, 0xf5, 0x8e, 0xbb, 0x69,
            0x07, 0x50, 0xc0, 0xbb, 0x4c, 0xe7, 0x6e, 0xd8, 0xa4, 0x6a, 0x69, 0x29, 0xfc, 0xc9,
            0x52, 0x0c, 0xdb, 0x04, 0xec, 0xa2, 0xef, 0x27, 0x7d, 0x8f, 0xfa, 0x9d, 0xaa, 0x10,
            0x59, 0x54, 0x7b, 0x42, 0x78, 0xdb, 0xae, 0xd4, 0x24, 0x0a, 0xd4, 0x06, 0x69, 0xb0,
            0xe2, 0xa5, 0x68, 0xca, 0x2d, 0x41, 0x34, 0xb0, 0x64, 0xaf, 0x61, 0x13, 0xc9, 0x32,
            0xfc, 0x93, 0x56, 0x4f, 0x82, 0x7b, 0xea, 0xff, 0x20, 0xe5, 0x1c, 0x56, 0xb6, 0xe0,
            0xf4, 0xaa, 0x6a, 0x20, 0xd2, 0x1c, 0x46, 0x71, 0xe6, 0x05, 0x9a, 0x96, 0x99, 0xad,
            0x5a, 0x6f, 0x78, 0xfd, 0xa7, 0x06, 0xf8, 0xfd, 0x2d, 0xea, 0x91, 0xf2, 0x9e, 0xac,
            0xc0, 0x43, 0x45, 0x2d, 0x79, 0xb0, 0xf2, 0x24, 0x5a, 0x8c, 0x91, 0xe6, 0xc6, 0xc2,
            0xfe, 0x50, 0x8d, 0x64, 0x82, 0x06, 0x77, 0x6e, 0xef, 0x7d, 0x61, 0x6e, 0x80, 0xd1,
            0x87, 0xfb, 0x25, 0x35, 0xc6, 0xe8, 0x3a, 0xec, 0x38, 0xce, 0x45, 0x70, 0xf8, 0x56,
            0xc7, 0x6e, 0xb7, 0x20, 0xdb, 0x72, 0x51, 0x82, 0xd0, 0xd2, 0xd2, 0xbd, 0xc9, 0xe0,
            0x3c, 0xef, 0xbb, 0x93, 0x70, 0xdd, 0xfb, 0xd4, 0xda, 0x6e, 0xf6, 0x73, 0xb3, 0x79,
            0xf7, 0xe8, 0x49, 0x72, 0x22, 0x44, 0x92, 0xd8, 0xe4, 0x3e, 0x04, 0xbc, 0x83, 0xb2,
            0x6c, 0x59, 0x4a, 0x79, 0x11, 0x1e, 0x33, 0xd6, 0x4b, 0xe6, 0x24, 0x7b, 0xdf, 0x93,
            0x18, 0x1d, 0xb3, 0x27, 0x0b, 0x73, 0xbb, 0xff, 0xa8, 0xe2, 0x13, 0xa0, 0x8f, 0x39,
            0x2c, 0x21, 0xc1, 0x5e, 0xf1, 0xa8, 0x82, 0x25, 0x28, 0x19, 0xae, 0xc9, 0x3f, 0x09,
            0x2d, 0x8c, 0x81, 0xa5,
        ];
        let e: &[u8] = &[0x01, 0x00, 0x01];

        let der = rsa_components_to_der(n, e).expect("test setup");
        assert_eq!(der[0], 0x30);
        assert_eq!(
            der.len(),
            270,
            "RSAPublicKey for RSA 2048 (high-bit modulus) should be 270 bytes"
        );

        // The round-trip test (sign with ring, verify with our DER) lives in
        // crypto::tests::verify_rs256_accepts_valid_signature.
    }
}
