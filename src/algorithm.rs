//! COSE algorithm and key-type constants.
//!
//! These integer identifiers come from two registries:
//! - COSE Algorithms: <https://www.iana.org/assignments/cose/cose.xhtml>
//! - WebAuthn algorithms: <https://www.w3.org/TR/webauthn-2/#sctn-alg-identifier>
//!
//! COSE uses negative integers for algorithm identifiers (a CBOR convention
//! for frequently-used values) and small positive integers for key type parameters.

/// COSE algorithm: ECDSA P-256 with SHA-256. The most common WebAuthn algorithm.
pub const COSE_ES256: i64 = -7;

/// COSE algorithm: RSA PKCS#1 v1.5 with SHA-256. Used by older YubiKeys and Windows Hello.
pub const COSE_RS256: i64 = -257;

/// COSE key type: EC2 (elliptic-curve, two-coordinate representation).
pub const COSE_KTY_EC2: i64 = 2;

/// COSE key type: RSA.
pub const COSE_KTY_RSA: i64 = 3;

/// COSE EC2 curve: P-256 (NIST curve secp256r1).
pub const COSE_CRV_P256: i64 = 1;
