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
//!      *     *   extensions (CBOR map, present iff ED flag is set)
//! ```

use std::collections::HashMap;
use std::io::Cursor;

use ciborium::value::Value;

use crate::algorithm::{
    COSE_CRV_ED25519, COSE_CRV_P256, COSE_CRV_P384, COSE_EDDSA, COSE_ES256, COSE_ES384,
    COSE_KTY_EC2, COSE_KTY_OKP, COSE_KTY_RSA, COSE_RS256,
};
use crate::error::{Result, WebAuthnError};

// ─── Flags bitmask constants ──────────────────────────────────────────────────

/// Bit 0: User Present — the authenticator confirmed physical user presence.
const FLAG_UP: u8 = 0x01;
/// Bit 2: User Verified — biometric / PIN check passed.
const FLAG_UV: u8 = 0x04;
/// Bit 3: Backup Eligibility — the credential may be synced to a platform account.
const FLAG_BE: u8 = 0x08;
/// Bit 4: Backup State — the credential is currently backed up.
const FLAG_BS: u8 = 0x10;
/// Bit 6: Attested Credential Data — `attestedCredentialData` is present.
const FLAG_AT: u8 = 0x40;
/// Bit 7: Extension Data — CBOR extensions follow the credential data.
const FLAG_ED: u8 = 0x80;

/// Maximum sane credential ID length. Values above this indicate corrupt data.
const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// Minimum RSA modulus length in bytes (2048-bit key = 256 bytes).
const MIN_RSA_N_LEN: usize = 256;

// ─── Types ───────────────────────────────────────────────────────────────────

/// Decoded flags byte from authenticator data.
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatorFlags {
    /// UP: the authenticator confirmed physical user presence.
    pub user_present: bool,
    /// UV: biometric or PIN check passed.
    pub user_verified: bool,
    /// BE: the credential is eligible for backup to a platform sync service.
    /// Immutable — set at registration and cannot change across ceremonies.
    pub backup_eligible: bool,
    /// BS: the credential is currently backed up. May change between ceremonies.
    pub backup_state: bool,
    /// AT: attested credential data is included (registration only).
    pub attested_credential_data: bool,
    /// ED: a CBOR extension map follows the credential data.
    pub extension_data: bool,
}

/// A decoded COSE_Key from the credential's authenticator data.
///
/// Three key types are supported:
/// - `EC2`: elliptic-curve (kty = 2). Carries `crv`, `x`, and `y`.
/// - `OKP`: octet key pair (kty = 1). Carries the raw 32-byte Ed25519 key in `x`.
/// - `RSA`: RSA public key (kty = 3). Carries `n` and `e`.
///
/// The `alg` field in each variant holds the COSE algorithm identifier;
/// the registration ceremony validates it against the expected value.
#[derive(Debug, Clone)]
pub enum CoseKey {
    /// EC2 key — P-256 with ES256 (alg = -7) or P-384 with ES384 (alg = -35).
    EC2 {
        /// Algorithm (COSE map key `3`). `-7` = ES256, `-35` = ES384.
        alg: i64,
        /// Curve (COSE map key `-1`). `1` = P-256, `2` = P-384.
        crv: i64,
        /// X coordinate (COSE map key `-2`). 32 bytes for P-256, 48 bytes for P-384.
        x: Vec<u8>,
        /// Y coordinate (COSE map key `-3`). 32 bytes for P-256, 48 bytes for P-384.
        y: Vec<u8>,
    },
    /// OKP key — EdDSA with Ed25519 (alg = -8, crv = 6).
    OKP {
        /// Algorithm (COSE map key `3`). Value `-8` = EdDSA.
        alg: i64,
        /// Raw 32-byte Ed25519 public key (COSE map key `-2`).
        x: Vec<u8>,
    },
    /// RSA key — RS256 (alg = -257).
    RSA {
        /// Algorithm (COSE map key `3`). Value `-257` = RS256.
        alg: i64,
        /// Modulus (COSE map key `-1`). At least 256 bytes for a 2048-bit key.
        n: Vec<u8>,
        /// Public exponent (COSE map key `-2`). Typically `[0x01, 0x00, 0x01]`.
        e: Vec<u8>,
    },
}

impl CoseKey {
    /// Return the COSE algorithm identifier for this key.
    pub fn alg(&self) -> i64 {
        match self {
            CoseKey::EC2 { alg, .. } => *alg,
            CoseKey::OKP { alg, .. } => *alg,
            CoseKey::RSA { alg, .. } => *alg,
        }
    }
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

    /// Extension data from the authenticator (§6.1 / §10.5), present when the ED flag is set.
    ///
    /// Keys are extension identifiers (e.g. `"credProps"`, `"appid"`); values are raw CBOR.
    /// Unknown extensions are stored as-is — the library never rejects an unrecognised key.
    pub extensions: Option<HashMap<String, Value>>,

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
        backup_eligible: flags_byte & FLAG_BE != 0,
        backup_state: flags_byte & FLAG_BS != 0,
        attested_credential_data: flags_byte & FLAG_AT != 0,
        extension_data: flags_byte & FLAG_ED != 0,
    };

    // §6.1: BS can only be set when BE is also set — a credential cannot be backed
    // up without first being backup-eligible.
    if flags.backup_state && !flags.backup_eligible {
        return Err(WebAuthnError::InvalidAuthenticatorData(
            "BS flag (backup state) is set but BE flag (backup eligibility) is not — invalid per §6.1".to_string(),
        ));
    }

    // §6.1: Parse sign count (big-endian u32). Bytes 33–36 are within the 37-byte minimum.
    let sign_count = u32::from_be_bytes(
        data[33..37]
            .try_into()
            .expect("slice of exactly 4 bytes always converts"),
    );

    // §6.1: Conditionally parse attested credential data.
    let (attested_credential_data, at_bytes_consumed) = if flags.attested_credential_data {
        let (cred_data, n) = parse_attested_credential_data(&data[37..])?;
        (Some(cred_data), n)
    } else {
        (None, 0)
    };

    // §6.1: Conditionally parse the extensions CBOR map (ED flag = bit 7).
    // Extensions follow AT data when present, otherwise they start immediately after
    // the 37-byte fixed header.
    let extensions = if flags.extension_data {
        let ext_start = 37 + at_bytes_consumed;
        Some(parse_extension_map(&data[ext_start..])?)
    } else {
        None
    };

    Ok(AuthenticatorData {
        rp_id_hash,
        flags,
        sign_count,
        attested_credential_data,
        extensions,
        raw: data.to_vec(),
    })
}

/// Decode a CBOR-encoded COSE_Key and return it as a [`CoseKey`].
///
/// Both EC2 (kty = 2) and RSA (kty = 3) keys are supported.
/// For EC2: dispatches on `alg` to validate crv and coordinate length —
///   ES256 (alg = -7) requires crv = 1 and 32-byte x/y coordinates;
///   ES384 (alg = -35) requires crv = 2 and 48-byte x/y coordinates.
/// For RSA: validates alg == -257 and that n is at least 256 bytes.
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

    // COSE map key 1 = kty. Dispatch on key type.
    let kty = get_int(1).ok_or_else(|| {
        WebAuthnError::InvalidPublicKey("missing required field: kty".to_string())
    })?;

    if kty == COSE_KTY_OKP {
        parse_okp_key(&get_int, &get_bytes)
    } else if kty == COSE_KTY_EC2 {
        parse_ec2_key(&get_int, &get_bytes)
    } else if kty == COSE_KTY_RSA {
        parse_rsa_key(&get_int, &get_bytes)
    } else {
        Err(WebAuthnError::InvalidPublicKey(format!(
            "unsupported key type: {kty} (supported: OKP=1, EC2=2, RSA=3)"
        )))
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn parse_okp_key(
    get_int: &impl Fn(i64) -> Option<i64>,
    get_bytes: &impl Fn(i64) -> Option<Vec<u8>>,
) -> Result<CoseKey> {
    // COSE map key 3 = alg. For OKP keys we require EdDSA = -8.
    let alg = get_int(3).ok_or_else(|| {
        WebAuthnError::InvalidPublicKey("missing required field: alg".to_string())
    })?;

    if alg != COSE_EDDSA {
        return Err(WebAuthnError::UnsupportedAlgorithm(alg));
    }

    // COSE map key -1 = crv. Value 6 = Ed25519.
    let crv = get_int(-1).ok_or_else(|| {
        WebAuthnError::InvalidPublicKey("missing required field: crv".to_string())
    })?;

    if crv != COSE_CRV_ED25519 {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "unsupported OKP curve: {crv} (only Ed25519 / crv=6 is supported)"
        )));
    }

    // COSE map key -2 = x (raw public key bytes). Ed25519 keys are always 32 bytes.
    let x = get_bytes(-2)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing required field: x".to_string()))?;

    if x.len() != 32 {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            x.len()
        )));
    }

    Ok(CoseKey::OKP { alg, x })
}

fn parse_ec2_key(
    get_int: &impl Fn(i64) -> Option<i64>,
    get_bytes: &impl Fn(i64) -> Option<Vec<u8>>,
) -> Result<CoseKey> {
    // COSE map key 3 = alg. Dispatch on algorithm to determine expected curve and
    // coordinate size. Mixing alg and crv (e.g. ES256 with P-384) is rejected.
    let alg = get_int(3).ok_or_else(|| {
        WebAuthnError::InvalidPublicKey("missing required field: alg".to_string())
    })?;

    // COSE map key -1 = crv.
    let crv = get_int(-1).ok_or_else(|| {
        WebAuthnError::InvalidPublicKey("missing required field: crv".to_string())
    })?;

    let coord_size: usize = match alg {
        COSE_ES256 => {
            // ES256 (ECDSA P-256 SHA-256) requires crv=1 (P-256) and 32-byte coordinates.
            if crv != COSE_CRV_P256 {
                return Err(WebAuthnError::InvalidPublicKey(format!(
                    "ES256 requires curve P-256 (crv=1), got {crv}"
                )));
            }
            32
        }
        COSE_ES384 => {
            // ES384 (ECDSA P-384 SHA-384) requires crv=2 (P-384) and 48-byte coordinates.
            if crv != COSE_CRV_P384 {
                return Err(WebAuthnError::InvalidPublicKey(format!(
                    "ES384 requires curve P-384 (crv=2), got {crv}"
                )));
            }
            48
        }
        _ => return Err(WebAuthnError::UnsupportedAlgorithm(alg)),
    };

    // COSE map key -2 = x coordinate.
    let x = get_bytes(-2)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing required field: x".to_string()))?;

    // COSE map key -3 = y coordinate.
    let y = get_bytes(-3)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing required field: y".to_string()))?;

    if x.len() != coord_size {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "x coordinate must be {coord_size} bytes, got {}",
            x.len()
        )));
    }
    if y.len() != coord_size {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "y coordinate must be {coord_size} bytes, got {}",
            y.len()
        )));
    }

    Ok(CoseKey::EC2 { alg, crv, x, y })
}

fn parse_rsa_key(
    get_int: &impl Fn(i64) -> Option<i64>,
    get_bytes: &impl Fn(i64) -> Option<Vec<u8>>,
) -> Result<CoseKey> {
    // COSE map key 3 = alg. For RSA keys we require RS256 = -257.
    let alg = get_int(3).ok_or_else(|| {
        WebAuthnError::InvalidPublicKey("missing required field: alg".to_string())
    })?;

    if alg != COSE_RS256 {
        return Err(WebAuthnError::UnsupportedAlgorithm(alg));
    }

    // COSE map key -1 = n (modulus).
    let n = get_bytes(-1)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing required field: n".to_string()))?;

    if n.len() < MIN_RSA_N_LEN {
        return Err(WebAuthnError::InvalidPublicKey(format!(
            "RSA modulus must be at least {} bytes (2048-bit), got {}",
            MIN_RSA_N_LEN,
            n.len()
        )));
    }

    // COSE map key -2 = e (public exponent).
    let e = get_bytes(-2)
        .ok_or_else(|| WebAuthnError::InvalidPublicKey("missing required field: e".to_string()))?;

    if e.is_empty() {
        return Err(WebAuthnError::InvalidPublicKey(
            "RSA exponent (e) must not be empty".to_string(),
        ));
    }

    Ok(CoseKey::RSA { alg, n, e })
}

/// Returns `(AttestedCredentialData, bytes_consumed)` where `bytes_consumed` is the number of
/// bytes read from `data`. Used by the caller to locate the extension map that may follow.
fn parse_attested_credential_data(data: &[u8]) -> Result<(AttestedCredentialData, usize)> {
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

    // credentialPublicKey: a CBOR-encoded COSE_Key that may be followed by extension bytes.
    // Use a Cursor to determine exactly how many bytes the COSE key occupies so the caller
    // can locate the extension map that may immediately follow.
    let remaining = data.get(offset..).ok_or_else(|| {
        WebAuthnError::InvalidAuthenticatorData("truncated before public key CBOR".to_string())
    })?;

    if remaining.is_empty() {
        return Err(WebAuthnError::InvalidAuthenticatorData(
            "no bytes remaining for credentialPublicKey CBOR".to_string(),
        ));
    }

    // §6.1: Probe CBOR size with a cursor so we can report bytes_consumed accurately.
    // parse_cose_key does the real validation; this call is only for the byte count.
    let mut cursor = Cursor::new(remaining);
    let _: Value = ciborium::from_reader(&mut cursor)
        .map_err(|e| WebAuthnError::CborDecodeError(format!("COSE key: {e}")))?;
    let cbor_len = cursor.position() as usize;

    let public_key = parse_cose_key(&remaining[..cbor_len])?;

    Ok((
        AttestedCredentialData {
            aaguid,
            credential_id,
            public_key,
        },
        offset + cbor_len,
    ))
}

/// Decode the CBOR extension map from `data` (§6.1 / §10.5).
///
/// The extensions section is a CBOR map whose keys are extension identifier strings
/// (e.g. `"credProps"`, `"appid"`) and whose values are extension-specific CBOR.
/// Unknown extensions are stored as raw [`Value`] — the library never rejects an
/// unrecognised extension key.
fn parse_extension_map(data: &[u8]) -> Result<HashMap<String, Value>> {
    if data.is_empty() {
        return Err(WebAuthnError::InvalidAuthenticatorData(
            "ED flag is set but no extension bytes are present".to_string(),
        ));
    }

    let value: Value = ciborium::from_reader(data)
        .map_err(|e| WebAuthnError::CborDecodeError(format!("extension map: {e}")))?;

    let map = match value {
        Value::Map(m) => m,
        _ => {
            return Err(WebAuthnError::InvalidAuthenticatorData(
                "extension data must be a CBOR map".to_string(),
            ))
        }
    };

    let mut extensions = HashMap::new();
    for (k, v) in map {
        // §10.5: extension identifiers are strings. Non-text keys are skipped silently.
        if let Value::Text(key) = k {
            extensions.insert(key, v);
        }
    }

    Ok(extensions)
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

    fn make_rsa_cose_key_cbor(n: &[u8], e: &[u8]) -> Vec<u8> {
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(3i64.into())), // kty: RSA
            (
                Value::Integer(3i64.into()),
                Value::Integer((-257i64).into()),
            ), // alg: RS256
            (Value::Integer((-1i64).into()), Value::Bytes(n.to_vec())), // n
            (Value::Integer((-2i64).into()), Value::Bytes(e.to_vec())), // e
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

    // ── BE / BS flag parsing ─────────────────────────────────────────────────

    #[test]
    fn parses_be_flag() {
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_BE, 0, None);
        let parsed = parse_authenticator_data(&data).unwrap();
        assert!(parsed.flags.backup_eligible);
        assert!(!parsed.flags.backup_state);
    }

    #[test]
    fn parses_be_and_bs_flags() {
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_BE | FLAG_BS, 0, None);
        let parsed = parse_authenticator_data(&data).unwrap();
        assert!(parsed.flags.backup_eligible);
        assert!(parsed.flags.backup_state);
    }

    #[test]
    fn rejects_bs_without_be() {
        // §6.1: BS set without BE is an invalid combination.
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_BS, 0, None);
        let err = parse_authenticator_data(&data).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidAuthenticatorData(_)));
        assert!(err.to_string().contains("BS"));
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

    // ── extension parsing (§6.1 / §10.5) ────────────────────────────────────

    fn make_extension_cbor(entries: &[(&str, Value)]) -> Vec<u8> {
        let map = Value::Map(
            entries
                .iter()
                .map(|(k, v)| (Value::Text(k.to_string()), v.clone()))
                .collect(),
        );
        let mut buf = Vec::new();
        ciborium::into_writer(&map, &mut buf).unwrap();
        buf
    }

    #[test]
    fn ed_flag_not_set_produces_none_extensions() {
        let data = make_auth_data(&[0u8; 32], FLAG_UP, 1, None);
        let parsed = parse_authenticator_data(&data).unwrap();
        assert!(parsed.extensions.is_none());
    }

    #[test]
    fn ed_flag_set_with_valid_map_populates_extensions() {
        let ext_cbor = make_extension_cbor(&[("appid", Value::Bool(true))]);
        let mut data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_ED, 0, None);
        data.extend_from_slice(&ext_cbor);
        let parsed = parse_authenticator_data(&data).unwrap();
        let exts = parsed.extensions.unwrap();
        assert_eq!(exts.get("appid"), Some(&Value::Bool(true)));
    }

    #[test]
    fn ed_flag_set_with_multiple_extensions() {
        let cred_props = Value::Map(vec![(Value::Text("rk".to_string()), Value::Bool(true))]);
        let ext_cbor = make_extension_cbor(&[
            ("credProps", cred_props.clone()),
            ("appid", Value::Bool(false)),
        ]);
        let mut data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_ED, 0, None);
        data.extend_from_slice(&ext_cbor);
        let parsed = parse_authenticator_data(&data).unwrap();
        let exts = parsed.extensions.unwrap();
        assert_eq!(exts.get("credProps"), Some(&cred_props));
        assert_eq!(exts.get("appid"), Some(&Value::Bool(false)));
    }

    #[test]
    fn ed_flag_set_with_at_flag_parses_extensions_after_cose_key() {
        // AT + ED: extensions must appear after the attested credential data (COSE key).
        let pk_cbor = make_cose_key_cbor(&[0x01u8; 32], &[0x02u8; 32]);
        let cred_data = make_attested_cred_data(&[0xAAu8; 8], &pk_cbor);
        let ext_cbor = make_extension_cbor(&[("appid", Value::Bool(true))]);
        let mut combined = cred_data;
        combined.extend_from_slice(&ext_cbor);
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_AT | FLAG_ED, 0, Some(&combined));
        let parsed = parse_authenticator_data(&data).unwrap();
        assert!(parsed.attested_credential_data.is_some());
        let exts = parsed.extensions.unwrap();
        assert_eq!(exts.get("appid"), Some(&Value::Bool(true)));
    }

    #[test]
    fn ed_flag_set_with_no_bytes_returns_error() {
        // ED set but buffer ends at the 37-byte fixed header — no extension bytes present.
        let data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_ED, 0, None);
        let err = parse_authenticator_data(&data).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidAuthenticatorData(_)));
        assert!(err.to_string().contains("ED"));
    }

    #[test]
    fn ed_flag_set_with_malformed_cbor_returns_error() {
        let mut data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_ED, 0, None);
        data.extend_from_slice(&[0xFF, 0xFF]); // not valid CBOR
        let err = parse_authenticator_data(&data).unwrap_err();
        assert!(matches!(err, WebAuthnError::CborDecodeError(_)));
    }

    #[test]
    fn ed_flag_set_with_non_map_cbor_returns_error() {
        let mut data = make_auth_data(&[0u8; 32], FLAG_UP | FLAG_ED, 0, None);
        // Encode a CBOR integer instead of a map.
        let not_a_map = Value::Integer(42i64.into());
        let mut cbor_buf = Vec::new();
        ciborium::into_writer(&not_a_map, &mut cbor_buf).unwrap();
        data.extend_from_slice(&cbor_buf);
        let err = parse_authenticator_data(&data).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidAuthenticatorData(_)));
        assert!(err.to_string().contains("map"));
    }

    // ── parse_cose_key — EC2 ─────────────────────────────────────────────────

    #[test]
    fn parse_cose_key_valid_es256() {
        let x = vec![0x01u8; 32];
        let y = vec![0x02u8; 32];
        let cbor = make_cose_key_cbor(&x, &y);
        let key = parse_cose_key(&cbor).unwrap();
        match key {
            CoseKey::EC2 {
                alg,
                crv,
                x: kx,
                y: ky,
            } => {
                assert_eq!(alg, -7);
                assert_eq!(crv, 1);
                assert_eq!(kx, x);
                assert_eq!(ky, y);
            }
            _ => panic!("expected EC2 key"),
        }
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
    fn parse_cose_key_rejects_unsupported_kty() {
        // kty = 4 (symmetric) — not supported at all
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(4i64.into())),
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("4")));
    }

    #[test]
    fn parse_cose_key_rejects_unsupported_crv() {
        // alg=-7 (ES256) with crv=2 (P-384) is an alg/curve mismatch — ES256 requires crv=1.
        let cbor = make_cose_key_cbor_with_alg_crv(&[0x01u8; 32], &[0x02u8; 32], -7, 2);
        let err = parse_cose_key(&cbor).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("2")));
    }

    #[test]
    fn parse_cose_key_valid_es384() {
        let x = vec![0x01u8; 48];
        let y = vec![0x02u8; 48];
        let cbor = make_cose_key_cbor_with_alg_crv(&x, &y, -35, 2);
        let key = parse_cose_key(&cbor).unwrap();
        match key {
            CoseKey::EC2 {
                alg,
                crv,
                x: kx,
                y: ky,
            } => {
                assert_eq!(alg, -35);
                assert_eq!(crv, 2);
                assert_eq!(kx, x);
                assert_eq!(ky, y);
            }
            _ => panic!("expected EC2 key"),
        }
    }

    #[test]
    fn parse_cose_key_es384_rejects_short_x_coordinate() {
        let cbor = make_cose_key_cbor_with_alg_crv(&[0x01u8; 32], &[0x02u8; 48], -35, 2);
        let err = parse_cose_key(&cbor).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("32")));
    }

    #[test]
    fn parse_cose_key_es384_rejects_short_y_coordinate() {
        let cbor = make_cose_key_cbor_with_alg_crv(&[0x01u8; 48], &[0x02u8; 32], -35, 2);
        let err = parse_cose_key(&cbor).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("32")));
    }

    #[test]
    fn parse_cose_key_es384_rejects_wrong_crv() {
        // alg=-35 (ES384) with crv=1 (P-256) is an alg/curve mismatch — ES384 requires crv=2.
        let cbor = make_cose_key_cbor_with_alg_crv(&[0x01u8; 48], &[0x02u8; 48], -35, 1);
        let err = parse_cose_key(&cbor).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("1")));
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

    // ── parse_cose_key — RS256 ───────────────────────────────────────────────

    #[test]
    fn parse_cose_key_valid_rs256() {
        let n = vec![0x01u8; 256]; // 2048-bit modulus (high bit clear — no DER pad needed here)
        let e = vec![0x01u8, 0x00, 0x01];
        let cbor = make_rsa_cose_key_cbor(&n, &e);
        let key = parse_cose_key(&cbor).unwrap();
        match key {
            CoseKey::RSA { alg, n: kn, e: ke } => {
                assert_eq!(alg, -257);
                assert_eq!(kn, n);
                assert_eq!(ke, e);
            }
            _ => panic!("expected RSA key"),
        }
    }

    #[test]
    fn parse_cose_key_rs256_rejects_short_modulus() {
        // n = 255 bytes — below the 256-byte (2048-bit) minimum.
        let n = vec![0x01u8; 255];
        let e = vec![0x01u8, 0x00, 0x01];
        let cbor = make_rsa_cose_key_cbor(&n, &e);
        let err = parse_cose_key(&cbor).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("255")));
    }

    #[test]
    fn parse_cose_key_rs256_rejects_missing_n() {
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(3i64.into())),
            (
                Value::Integer(3i64.into()),
                Value::Integer((-257i64).into()),
            ),
            // -1 (n) absent
            (
                Value::Integer((-2i64).into()),
                Value::Bytes(vec![0x01, 0x00, 0x01]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("n")));
    }

    #[test]
    fn parse_cose_key_rs256_rejects_missing_e() {
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(3i64.into())),
            (
                Value::Integer(3i64.into()),
                Value::Integer((-257i64).into()),
            ),
            (
                Value::Integer((-1i64).into()),
                Value::Bytes(vec![0x01u8; 256]),
            ),
            // -2 (e) absent
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::InvalidPublicKey(ref m) if m.contains("e")));
    }

    #[test]
    fn parse_cose_key_rsa_with_wrong_alg_returns_unsupported() {
        // kty=3 (RSA) but alg=-7 (ES256) — algorithm mismatch
        let cose = Value::Map(vec![
            (Value::Integer(1i64.into()), Value::Integer(3i64.into())),
            (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
            (
                Value::Integer((-1i64).into()),
                Value::Bytes(vec![0x01u8; 256]),
            ),
            (
                Value::Integer((-2i64).into()),
                Value::Bytes(vec![0x01, 0x00, 0x01]),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&cose, &mut buf).unwrap();
        let err = parse_cose_key(&buf).unwrap_err();
        assert!(matches!(err, WebAuthnError::UnsupportedAlgorithm(-7)));
    }
}
