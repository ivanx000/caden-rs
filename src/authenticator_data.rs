//! Authenticator data parsing.
//!
//! The authenticator data (`authData`) is a binary structure defined in
//! [WebAuthn §6.1](https://www.w3.org/TR/webauthn-2/#authenticator-data).
//! It is produced by the authenticator hardware and carries the RP ID binding,
//! user-presence/verification flags, a sign counter, and (during registration)
//! the new credential's public key encoded as a COSE_Key.
//!
//! ## Binary layout
//!
//! ```text
//! Offset   Len   Field
//! ──────   ───   ─────────────────────────────────────────────────
//!      0    32   rpIdHash   — SHA-256 of the RP ID
//!     32     1   flags      — bitmask (UP / UV / AT / ED)
//!     33     4   signCount  — big-endian u32
//!     37     *   attestedCredentialData (present iff AT flag is set)
//!              16   aaguid
//!               2   credentialIdLength  (big-endian u16)
//!               *   credentialId
//!               *   credentialPublicKey (CBOR-encoded COSE_Key)
//! ```

use ciborium::value::Value;

use crate::error::{WebAuthnError, Result};

// ─── Flags bitmask constants ──────────────────────────────────────────────────

/// Bit 0: User Present — the authenticator confirmed physical user presence.
const FLAG_UP: u8 = 0x01;
/// Bit 2: User Verified — biometric / PIN check passed.
const FLAG_UV: u8 = 0x04;
/// Bit 6: Attested Credential Data — `attestedCredentialData` is present.
const FLAG_AT: u8 = 0x40;
/// Bit 7: Extension Data — CBOR extensions follow the credential data.
const FLAG_ED: u8 = 0x80;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Decoded flags byte from authenticator data.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatorFlags {
    /// UP: the authenticator confirmed physical user presence.
    pub user_present: bool,
    /// UV: biometric or PIN check passed.
    pub user_verified: bool,
    /// AT: attested credential data is included (registration only).
    pub attested_credential_data: bool,
    /// ED: a CBOR extension map follows the credential data.
    pub extension_data: bool,
}

/// A decoded COSE_Key from the credential's authenticator data.
///
/// This struct represents an EC2 key (kty = 2). The `alg` field carries the
/// COSE algorithm identifier; the caller is responsible for checking it is
/// the expected value (e.g. `-7` for ES256) before using the key.
#[derive(Debug, Clone)]
pub struct CoseKey {
    /// Key type (COSE map key `1`). Value `2` = EC2 (elliptic-curve).
    pub kty: i64,
    /// Algorithm (COSE map key `3`). Value `-7` = ES256.
    pub alg: i64,
    /// Curve (COSE map key `-1`). Value `1` = P-256.
    pub crv: i64,
    /// X coordinate (COSE map key `-2`). 32 bytes for P-256.
    pub x: Vec<u8>,
    /// Y coordinate (COSE map key `-3`). 32 bytes for P-256.
    pub y: Vec<u8>,
}

/// Credential data embedded in the authenticator data during registration.
#[derive(Debug)]
pub struct AttestedCredentialData {
    /// Authenticator Attestation GUID — identifies the authenticator model.
    /// All-zeros is common for platform authenticators.
    pub aaguid: [u8; 16],

    /// Opaque credential identifier chosen by the authenticator.
    pub credential_id: Vec<u8>,

    /// The new credential's public key as a decoded COSE_Key.
    pub public_key: CoseKey,
}

/// Fully parsed authenticator data.
#[derive(Debug)]
pub struct AuthenticatorData {
    /// SHA-256 hash of the RP ID. Verified against `SHA-256(rp_id)` by the caller.
    pub rp_id_hash: [u8; 32],

    /// Decoded flags byte.
    pub flags: AuthenticatorFlags,

    /// Authenticator-maintained signature counter.
    pub sign_count: u32,

    /// Present only during registration (when the AT flag is set).
    pub attested_credential_data: Option<AttestedCredentialData>,

    /// The original raw bytes of this authenticator data structure.
    ///
    /// Kept because the signed payload for authentication is
    /// `authData || SHA-256(clientDataJSON)` — the exact bytes matter.
    pub raw: Vec<u8>,
}

// ─── Public parsing functions ─────────────────────────────────────────────────

/// Parse the raw authenticator data bytes into an [`AuthenticatorData`].
///
/// # Errors
/// - [`WebAuthnError::InvalidAuthenticatorData`] — bytes too short or malformed.
/// - [`WebAuthnError::InvalidPublicKey`] / [`WebAuthnError::CborDecodeError`]
///   — the embedded COSE key cannot be decoded.
pub fn parse_authenticator_data(data: &[u8]) -> Result<AuthenticatorData> {
    // Minimum: 32 (rpIdHash) + 1 (flags) + 4 (signCount) = 37 bytes.
    if data.len() < 37 {
        return Err(WebAuthnError::InvalidAuthenticatorData(format!(
            "too short: {} bytes (need at least 37)",
            data.len()
        )));
    }

    // §6.1: Parse rpIdHash (32 bytes).
    let rp_id_hash: [u8; 32] = data[0..32]
        .try_into()
        .expect("slice of exactly 32 bytes always converts");

    // §6.1: Parse flags byte.
    let flags_byte = data[32];
    let flags = AuthenticatorFlags {
        user_present: flags_byte & FLAG_UP != 0,
        user_verified: flags_byte & FLAG_UV != 0,
        attested_credential_data: flags_byte & FLAG_AT != 0,
        extension_data: flags_byte & FLAG_ED != 0,
    };

    // §6.1: Parse sign count (big-endian u32).
    let sign_count = u32::from_be_bytes(
        data[33..37]
            .try_into()
            .expect("slice of exactly 4 bytes always converts"),
    );

    // §6.1: Conditionally parse attested credential data.
    let attested_credential_data = if flags.attested_credential_data {
        Some(parse_attested_credential_data(&data[37..])?)
    } else {
        None
    };

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested_credential_data,
        raw: data.to_vec(),
    })
}

/// Decode a CBOR-encoded COSE_Key and return it as a [`CoseKey`].
///
/// Only EC2 keys (kty = 2) are supported. The x and y coordinates are
/// required; passing a non-EC2 key will return [`WebAuthnError::InvalidPublicKey`].
/// Algorithm validation (e.g. checking `alg == -7`) is the caller's responsibility.
///
/// # Errors
/// - [`WebAuthnError::CborDecodeError`] — input is not valid CBOR.
/// - [`WebAuthnError::InvalidPublicKey`] — missing required fields or unsupported key type.
pub fn parse_cose_key(data: &[u8]) -> Result<CoseKey> {
    let value: Value = ciborium::from_reader(data)
        .map_err(|e| WebAuthnError::CborDecodeError(format!("COSE key: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidPublicKey(
                "COSE key must be a CBOR map".to_string(),
            ))
        }
    };

    let get_int = |key: i64| -> Option<i64> {
        map.iter().find_map(|(k, v)| {
            if let (Value::Integer(ki), Value::Integer(vi)) = (k, v) {
                if i64::try_from(*ki).ok()? == key {
                    return i64::try_from(*vi).ok();
                }
            }
            None
        })
    };

    let get_bytes = |key: i64| -> Option<Vec<u8>> {
        map.iter().find_map(|(k, v)| {
            if let Value::Integer(ki) = k {
                if i64::try_from(*ki).ok()? == key {
                    if let Value::Bytes(b) = v {
                        return Some(b.clone());
                    }
                }
            }
            None
        })
    };

    // COSE map key 1 = kty. kty = 2 means EC2 (elliptic curve).
    let kty = get_int(1)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing or non-integer kty".to_string()))?;

    if kty != 2 {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "unsupported key type: {kty} (only EC2 / kty=2 is supported)"
        )));
    }

    // COSE map key 3 = alg. Not validated here — caller checks the algorithm.
    let alg = get_int(3)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing or non-integer alg".to_string()))?;

    // COSE map key -1 = crv. crv = 1 means P-256.
    let crv = get_int(-1)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing or non-integer crv".to_string()))?;

    // COSE map key -2 = x coordinate.
    let x = get_bytes(-2)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing x coordinate".to_string()))?;

    // COSE map key -3 = y coordinate.
    let y = get_bytes(-3)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing y coordinate".to_string()))?;

    if x.len() != 32 || y.len() != 32 {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "P-256 coordinates must be 32 bytes each; got x={}, y={}",
            x.len(),
            y.len()
        )));
    }

    Ok(CoseKey { kty, alg, crv, x, y })
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn parse_attested_credential_data(data: &[u8]) -> Result<AttestedCredentialData> {
    if data.len() < 18 {
        return Err(WebAuthnError::InvalidAuthenticatorData(
            "attested credential data too short (need at least 18 bytes after flags/counter)"
                .to_string(),
        ));
    }

    let mut offset = 0;

    // aaguid: 16 bytes.
    let aaguid: [u8; 16] = data[offset..offset + 16]
        .try_into()
        .expect("slice of exactly 16 bytes always converts");
    offset += 16;

    // credentialIdLength: big-endian u16.
    let cred_id_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if data.len() < offset + cred_id_len {
        return Err(WebAuthnError::InvalidAuthenticatorData(format!(
            "credential ID length ({cred_id_len}) exceeds remaining data"
        )));
    }

    // credentialId: cred_id_len bytes.
    let credential_id = data[offset..offset + cred_id_len].to_vec();
    offset += cred_id_len;

    // credentialPublicKey: remaining bytes are a CBOR-encoded COSE_Key.
    // ciborium::from_reader reads exactly one item; any trailing extension data
    // is not consumed — correct per spec.
    let public_key = parse_cose_key(&data[offset..])?;

    Ok(AttestedCredentialData {
        aaguid,
        credential_id,
        public_key,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;

    /// Build a minimal authenticator data buffer for testing.
    pub fn make_auth_data(
        rp_id_hash: &[u8; 32],
        flags: u8,
        sign_count: u32,
        cred_data: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(rp_id_hash);
        out.push(flags);
        out.extend_from_slice(&sign_count.to_be_bytes());
        if let Some(cd) = cred_data {
            out.extend_from_slice(cd);
        }
        out
    }

    fn make_cose_key_cbor(x: &[u8], y: &[u8]) -> Vec<u8> {
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            (Value::Integer((-2i64).into()), Value::Bytes(x.to_vec())),
            (Value::Integer((-3i64).into()), Value::Bytes(y.to_vec())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        buf
    }

    #[test]
    fn rejects_too_short() {
        let result = parse_authenticator_data(&[0u8; 10]);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAuthenticatorData(_))
        ));
    }

    #[test]
    fn parses_minimal_auth_data() {
        let rp_hash = [0xABu8; 32];
        let data = make_auth_data(&rp_hash, FLAG_UP, 42, None);
        let parsed = parse_authenticator_data(&data).unwrap();

        assert_eq!(parsed.rp_id_hash, rp_hash);
        assert!(parsed.flags.user_present);
        assert!(!parsed.flags.user_verified);
        assert_eq!(parsed.sign_count, 42);
        assert!(parsed.attested_credential_data.is_none());
        assert_eq!(parsed.raw, data);
    }

    #[test]
    fn parses_up_and_uv_flags() {
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_UV, 0, None);
        let parsed = parse_authenticator_data(&data).unwrap();
        assert!(parsed.flags.user_present);
        assert!(parsed.flags.user_verified);
    }

    #[test]
    fn raw_field_equals_input_bytes() {
        let data = make_auth_data(&[0u8; 32], FLAG_UP, 7, None);
        let parsed = parse_authenticator_data(&data).unwrap();
        assert_eq!(parsed.raw, data);
    }

    #[test]
    fn parse_cose_key_valid_es256() {
        let x = vec![0x01u8; 32];
        let y = vec![0x02u8; 32];
        let cbor = make_cose_key_cbor(&x, &y);
        let key = parse_cose_key(&cbor).unwrap();
        assert_eq!(key.kty, 2);
        assert_eq!(key.alg, -7);
        assert_eq!(key.crv, 1);
        assert_eq!(key.x, x);
        assert_eq!(key.y, y);
    }

    #[test]
    fn parse_cose_key_rejects_missing_x() {
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            // x intentionally omitted
            (
                Value::Integer((-3i64).into()),
                Value::Bytes(vec![0u8; 32]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let result = parse_cose_key(&buf);
        assert!(matches!(result, Err(WebAuthnError::InvalidPublicKey(_))));
    }

    #[test]
    fn parse_cose_key_rejects_wrong_kty() {
        let cose = Value::Map(vec![
            // kty = 3 (RSA) — not supported
            (Value::Integer(1i64.into()), Value::Integer(3i64.into())),
            (Value::Integer(3i64.into()), Value::Integer((-257i64).into())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let result = parse_cose_key(&buf);
        assert!(matches!(result, Err(WebAuthnError::InvalidPublicKey(_))));
    }
}
