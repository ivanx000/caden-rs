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

use crate::error::{Result, WebAuthnError};

// ─── Flags bitmask constants ──────────────────────────────────────────────────

/// Bit 0: User Present — the authenticator confirmed physical user presence.
const FLAG_UP: u8 = 0x01;
/// Bit 2: User Verified — biometric / PIN check passed.
const FLAG_UV: u8 = 0x04;
/// Bit 6: Attested Credential Data — `attestedCredentialData` is present.
const FLAG_AT: u8 = 0x40;
/// Bit 7: Extension Data — CBOR extensions follow the credential data.
const FLAG_ED: u8 = 0x80;

/// Maximum sane credential ID length. Values above this indicate corrupt data.
const MAX_CREDENTIAL_ID_LEN: usize = 1023;

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
            "too short: expected at least 37 bytes, got {}",
            data.len()
        )));
    }

    // §6.1: Parse rpIdHash (32 bytes). The bounds check above guarantees this.
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

    // §6.1: Parse sign count (big-endian u32). Bytes 33–36 are within the 37-byte minimum.
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
/// Only EC2 keys (kty = 2, crv = 1 / P-256) are supported. The x and y
/// coordinates must each be exactly 32 bytes. Algorithm validation (e.g.
/// checking `alg == -7` for ES256) is the caller's responsibility.
///
/// # Errors
/// - [`WebAuthnError::CborDecodeError`] — input is not valid CBOR.
/// - [`WebAuthnError::InvalidPublicKey`] — missing required fields, wrong key type, or bad curve.
/// - [`WebAuthnError::UnsupportedAlgorithm`] — `alg` is present but not a recognised value.
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

    // Check for duplicate integer keys — ambiguous and likely corrupt input.
    {
        let mut seen: Vec<i64> = Vec::new();
        for (k, _) in &map {
            if let Value::Integer(ki) = k {
                if let Ok(n) = i64::try_from(*ki) {
                    if seen.contains(&n) {
                        return Err(WebAuthnError::InvalidPublicKey(format!(
                            "duplicate COSE key: {n}"
                        )));
                    }
                    seen.push(n);
                }
            }
        }
    }

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
    let kty = get_int(1).ok_or_else(|| {
        WebAuthnError::InvalidPublicKey("missing required field: kty".to_string())
    })?;

    if kty != 2 {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "unsupported key type: {kty} (only EC2 / kty=2 is supported)"
        )));
    }

    // COSE map key 3 = alg. Caller checks the specific algorithm value.
    let alg = get_int(3).ok_or_else(|| {
        WebAuthnError::InvalidPublicKey("missing required field: alg".to_string())
    })?;

    // COSE map key -1 = crv. crv = 1 means P-256.
    let crv = get_int(-1).ok_or_else(|| {
        WebAuthnError::InvalidPublicKey("missing required field: crv".to_string())
    })?;

    if crv != 1 {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "unsupported curve: {crv} (only P-256 / crv=1 is supported)"
        )));
    }

    // COSE map key -2 = x coordinate.
    let x = get_bytes(-2)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing required field: x".to_string()))?;

    // COSE map key -3 = y coordinate.
    let y = get_bytes(-3)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing required field: y".to_string()))?;

    if x.len() != 32 {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "x coordinate must be 32 bytes, got {}",
            x.len()
        )));
    }
    if y.len() != 32 {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "y coordinate must be 32 bytes, got {}",
            y.len()
        )));
    }

    Ok(CoseKey {
        kty,
        alg,
        crv,
        x,
        y,
    })
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn parse_attested_credential_data(data: &[u8]) -> Result<AttestedCredentialData> {
    // Need at least: 16 (aaguid) + 2 (credentialIdLength) = 18 bytes.
    if data.len() < 18 {
        return Err(WebAuthnError::InvalidAuthenticatorData(format!(
            "attested credential data too short: expected at least 18 bytes after flags/counter, got {}",
            data.len()
        )));
    }

    let mut offset = 0usize;

    // aaguid: 16 bytes.
    let aaguid: [u8; 16] = data
        .get(offset..offset + 16)
        .ok_or_else(|| {
            WebAuthnError::InvalidAuthenticatorData("truncated before aaguid".to_string())
        })?
        .try_into()
        .expect("slice of exactly 16 bytes always converts");
    offset += 16;

    // credentialIdLength: big-endian u16. Bytes 16 and 17 are within the 18-byte minimum.
    let cred_id_len = u16::from_be_bytes([
        *data.get(offset).ok_or_else(|| {
            WebAuthnError::InvalidAuthenticatorData(
                "truncated before credentialIdLength high byte".to_string(),
            )
        })?,
        *data.get(offset + 1).ok_or_else(|| {
            WebAuthnError::InvalidAuthenticatorData(
                "truncated before credentialIdLength low byte".to_string(),
            )
        })?,
    ]) as usize;
    offset += 2;

    if cred_id_len == 0 {
        return Err(WebAuthnError::InvalidAuthenticatorData(
            "credentialIdLength is 0 — empty credential ID is not valid".to_string(),
        ));
    }

    if cred_id_len > MAX_CREDENTIAL_ID_LEN {
        return Err(WebAuthnError::InvalidAuthenticatorData(format!(
            "credentialIdLength {cred_id_len} exceeds maximum {MAX_CREDENTIAL_ID_LEN} — likely corrupt data"
        )));
    }

    let credential_id = data
        .get(offset..offset + cred_id_len)
        .ok_or_else(|| {
            WebAuthnError::InvalidAuthenticatorData(format!(
                "credentialIdLength ({cred_id_len}) extends past end of buffer"
            ))
        })?
        .to_vec();
    offset += cred_id_len;

    // credentialPublicKey: remaining bytes are a CBOR-encoded COSE_Key.
    // ciborium::from_reader reads exactly one item; any trailing extension data
    // is not consumed — correct per spec.
    let remaining = data.get(offset..).ok_or_else(|| {
        WebAuthnError::InvalidAuthenticatorData("truncated before public key CBOR".to_string())
    })?;

    if remaining.is_empty() {
        return Err(WebAuthnError::InvalidAuthenticatorData(
            "no bytes remaining for credentialPublicKey CBOR".to_string(),
        ));
    }

    let public_key = parse_cose_key(remaining)?;

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
        make_cose_key_cbor_with_alg_crv(x, y, -7, 1)
    }

    fn make_cose_key_cbor_with_alg_crv(x: &[u8], y: &[u8], alg: i64, crv: i64) -> Vec<u8> {
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            (Value::Integer(3i64.into()), Value::Integer(alg.into())),
            (Value::Integer((-1i64).into()), Value::Integer(crv.into())),
            (Value::Integer((-2i64).into()), Value::Bytes(x.to_vec())),
            (Value::Integer((-3i64).into()), Value::Bytes(y.to_vec())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        buf
    }

    fn make_attested_cred_data(cred_id: &[u8], pk_cbor: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 16]; // aaguid
        out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        out.extend_from_slice(cred_id);
        out.extend_from_slice(pk_cbor);
        out
    }

    // ── parse_authenticator_data ─────────────────────────────────────────────

    #[test]
    fn rejects_too_short() {
        let result = parse_authenticator_data(&[0u8; 10]);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAuthenticatorData(_))
        ));
    }

    #[test]
    fn rejects_exactly_36_bytes() {
        let result = parse_authenticator_data(&[0u8; 36]);
        assert!(matches!(
            result,
            Err(WebAuthnError::InvalidAuthenticatorData(_))
        ));
    }

    #[test]
    fn rejects_empty() {
        let result = parse_authenticator_data(&[]);
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
    fn all_flags_set_parses_without_panic() {
        // All flags 0xFF — AT is set so it tries to parse attested cred data;
        // since there's none, it returns an error (not a panic).
        let data = make_auth_data(&[0u8; 32], 0xFF, 0, None);
        let result = parse_authenticator_data(&data);
        assert!(result.is_err());
    }

    #[test]
    fn at_flag_set_but_no_data_returns_error() {
        // AT flag set but no bytes after the 37-byte header.
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_AT, 0, None);
        let err = parse_authenticator_data(&data).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidAuthenticatorData(_)));
    }

    // ── attested credential data ─────────────────────────────────────────────

    #[test]
    fn rejects_zero_length_credential_id() {
        let pk = make_cose_key_cbor(&[0x01u8; 32], &[0x02u8; 32]);
        let cred_data = make_attested_cred_data(&[], &pk); // empty cred ID
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_AT, 0, Some(&cred_data));
        let err = parse_authenticator_data(&data).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidAuthenticatorData(_)));
        // Verify the message is specific.
        assert!(err.to_string().contains("0"));
    }

    #[test]
    fn rejects_credential_id_too_large() {
        // credentialIdLength = 1024 — above MAX_CREDENTIAL_ID_LEN.
        let mut cred_data = vec![0u8; 16]; // aaguid
        let oversized_len: u16 = 1024;
        cred_data.extend_from_slice(&oversized_len.to_be_bytes());
        // Don't append any bytes — the length check fires before the buffer read.
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_AT, 0, Some(&cred_data));
        let err = parse_authenticator_data(&data).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidAuthenticatorData(_)));
        assert!(err.to_string().contains("1024"));
    }

    #[test]
    fn rejects_credential_id_extends_past_buffer() {
        let mut cred_data = vec![0u8; 16]; // aaguid
        cred_data.extend_from_slice(&50u16.to_be_bytes()); // claims 50-byte ID
        cred_data.extend_from_slice(&[0xABu8; 10]); // only 10 bytes present
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_AT, 0, Some(&cred_data));
        let err = parse_authenticator_data(&data).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidAuthenticatorData(_)));
    }

    #[test]
    fn rejects_empty_cbor_after_credential_id() {
        let mut cred_data = vec![0u8; 16]; // aaguid
        cred_data.extend_from_slice(&1u16.to_be_bytes());
        cred_data.push(0xAB); // credential ID (1 byte)
                              // No CBOR bytes follow.
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_AT, 0, Some(&cred_data));
        let err = parse_authenticator_data(&data).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidAuthenticatorData(_)));
    }

    // ── parse_cose_key ───────────────────────────────────────────────────────

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
    fn parse_cose_key_rejects_missing_kty() {
        let cose = Value::Map(vec![
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            (Value::Integer((-2i64).into()), Value::Bytes(vec![0u8; 32])),
            (Value::Integer((-3i64).into()), Value::Bytes(vec![0u8; 32])),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(_)));
        assert!(err.to_string().contains("kty"));
    }

    #[test]
    fn parse_cose_key_rejects_missing_alg() {
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            (Value::Integer((-2i64).into()), Value::Bytes(vec![0u8; 32])),
            (Value::Integer((-3i64).into()), Value::Bytes(vec![0u8; 32])),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(_)));
        assert!(err.to_string().contains("alg"));
    }

    #[test]
    fn parse_cose_key_rejects_missing_crv() {
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            (Value::Integer((-2i64).into()), Value::Bytes(vec![0u8; 32])),
            (Value::Integer((-3i64).into()), Value::Bytes(vec![0u8; 32])),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(_)));
        assert!(err.to_string().contains("crv"));
    }

    #[test]
    fn parse_cose_key_rejects_missing_x() {
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            (Value::Integer((-3i64).into()), Value::Bytes(vec![0u8; 32])),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(_)));
        assert!(err.to_string().contains("x"));
    }

    #[test]
    fn parse_cose_key_rejects_missing_y() {
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            (Value::Integer((-2i64).into()), Value::Bytes(vec![0u8; 32])),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(_)));
        assert!(err.to_string().contains("y"));
    }

    #[test]
    fn parse_cose_key_rejects_wrong_kty() {
        // kty = 3 (RSA) — not supported
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(3i64.into())),
            (
                Value::Integer(3i64.into()),
                Value::Integer((-257i64).into()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("3")));
    }

    #[test]
    fn parse_cose_key_rejects_unsupported_crv() {
        // crv = 2 (P-384) — not supported
        let cbor = make_cose_key_cbor_with_alg_crv(&[0x01u8; 32], &[0x02u8; 32], -7, 2);
        let err = parse_cose_key(&cbor).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("2")));
    }

    #[test]
    fn parse_cose_key_rejects_short_x_coordinate() {
        let cbor = make_cose_key_cbor(&[0x01u8; 31], &[0x02u8; 32]);
        let err = parse_cose_key(&cbor).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("31")));
    }

    #[test]
    fn parse_cose_key_rejects_short_y_coordinate() {
        let cbor = make_cose_key_cbor(&[0x01u8; 32], &[0x02u8; 10]);
        let err = parse_cose_key(&cbor).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("10")));
    }

    #[test]
    fn parse_cose_key_rejects_long_x_coordinate() {
        let cbor = make_cose_key_cbor(&[0x01u8; 33], &[0x02u8; 32]);
        let err = parse_cose_key(&cbor).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("33")));
    }

    #[test]
    fn parse_cose_key_rejects_duplicate_key() {
        // Two entries with the same CBOR integer key (1 = kty).
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
            (Value::Integer(1i64.into()), Value::Integer(3i64.into())), // duplicate kty
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
            (Value::Integer((-2i64).into()), Value::Bytes(vec![0u8; 32])),
            (Value::Integer((-3i64).into()), Value::Bytes(vec![0u8; 32])),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("duplicate")));
    }

    #[test]
    fn parse_cose_key_rejects_not_a_map() {
        // A CBOR integer instead of a map.
        let cose = Value::Integer(42i64.into());
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(_)));
    }

    #[test]
    fn parse_cose_key_rejects_empty_input() {
        let err = parse_cose_key(&[]).unwrap_err();
        assert!(matches!(err, WebAuthnError::CborDecodeError(_)));
    }
}
