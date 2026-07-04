//! End-to-end WebAuthn simulation without a browser.
//!
//! This demo simulates both sides of the WebAuthn protocol in software:
//! - **Relying party**: uses the webauthn library (the code under test)
//! - **Authenticator**: simulated using ring's ECDSA (ES256) and RSA (RS256) primitives
//!
//! Run with: `cargo run --example demo`
//!
//! The demo exercises:
//!  1. ES256 Registration   — generate P-256 keypair, build authenticator data, verify
//!  2. ES256 Authentication — sign a challenge, verify signature and sign count
//!  3. ES256 Replay attack  — demonstrate that reusing a sign count is rejected
//!  4. RS256 Registration   — simulate RSA authenticator, verify RSA public key
//!  5. RS256 Authentication — sign with RSA PKCS#1 v1.5, verify RS256 signature
//!  6. RS256 Replay attack  — demonstrate that replay is rejected for RS256 too
//!  7. ES384 Registration   — generate P-384 keypair, build authenticator data, verify
//!  8. ES384 Authentication — sign a challenge, verify ES384 signature and sign count
//!  9. ES384 Replay attack  — demonstrate that replay is rejected for ES384 too
//! 10. EdDSA Registration   — generate Ed25519 keypair, build authenticator data, verify
//! 11. EdDSA Authentication — sign a challenge, verify EdDSA signature and sign count
//! 12. EdDSA Replay attack  — demonstrate that replay is rejected for EdDSA too

use anyhow::{Context, Result};
use ciborium::value::Value;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING,
};

use webauthn::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, Challenge, RelyingParty,
};

// ─── Demo configuration ───────────────────────────────────────────────────────

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost";
const USER_ID: &[u8] = b"demo-user-001";

// RSA 2048-bit test key in PKCS#8 DER format.
// Generated once for testing — never use this key in production.
const RSA_PKCS8_DER: &[u8] = &[
    0x30, 0x82, 0x04, 0xbc, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xa6, 0x30, 0x82, 0x04, 0xa2, 0x02, 0x01,
    0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0xb7, 0xe0, 0x0f, 0xc9, 0xdb, 0xfa, 0xce, 0x64, 0xa6, 0xe2,
    0xb7, 0xfb, 0xa2, 0x1c, 0x09, 0x14, 0xfb, 0xd6, 0x26, 0xe5, 0x17, 0xcc, 0xf6, 0x6b, 0xf5, 0x8e,
    0xbb, 0x69, 0x07, 0x50, 0xc0, 0xbb, 0x4c, 0xe7, 0x6e, 0xd8, 0xa4, 0x6a, 0x69, 0x29, 0xfc, 0xc9,
    0x52, 0x0c, 0xdb, 0x04, 0xec, 0xa2, 0xef, 0x27, 0x7d, 0x8f, 0xfa, 0x9d, 0xaa, 0x10, 0x59, 0x54,
    0x7b, 0x42, 0x78, 0xdb, 0xae, 0xd4, 0x24, 0x0a, 0xd4, 0x06, 0x69, 0xb0, 0xe2, 0xa5, 0x68, 0xca,
    0x2d, 0x41, 0x34, 0xb0, 0x64, 0xaf, 0x61, 0x13, 0xc9, 0x32, 0xfc, 0x93, 0x56, 0x4f, 0x82, 0x7b,
    0xea, 0xff, 0x20, 0xe5, 0x1c, 0x56, 0xb6, 0xe0, 0xf4, 0xaa, 0x6a, 0x20, 0xd2, 0x1c, 0x46, 0x71,
    0xe6, 0x05, 0x9a, 0x96, 0x99, 0xad, 0x5a, 0x6f, 0x78, 0xfd, 0xa7, 0x06, 0xf8, 0xfd, 0x2d, 0xea,
    0x91, 0xf2, 0x9e, 0xac, 0xc0, 0x43, 0x45, 0x2d, 0x79, 0xb0, 0xf2, 0x24, 0x5a, 0x8c, 0x91, 0xe6,
    0xc6, 0xc2, 0xfe, 0x50, 0x8d, 0x64, 0x82, 0x06, 0x77, 0x6e, 0xef, 0x7d, 0x61, 0x6e, 0x80, 0xd1,
    0x87, 0xfb, 0x25, 0x35, 0xc6, 0xe8, 0x3a, 0xec, 0x38, 0xce, 0x45, 0x70, 0xf8, 0x56, 0xc7, 0x6e,
    0xb7, 0x20, 0xdb, 0x72, 0x51, 0x82, 0xd0, 0xd2, 0xd2, 0xbd, 0xc9, 0xe0, 0x3c, 0xef, 0xbb, 0x93,
    0x70, 0xdd, 0xfb, 0xd4, 0xda, 0x6e, 0xf6, 0x73, 0xb3, 0x79, 0xf7, 0xe8, 0x49, 0x72, 0x22, 0x44,
    0x92, 0xd8, 0xe4, 0x3e, 0x04, 0xbc, 0x83, 0xb2, 0x6c, 0x59, 0x4a, 0x79, 0x11, 0x1e, 0x33, 0xd6,
    0x4b, 0xe6, 0x24, 0x7b, 0xdf, 0x93, 0x18, 0x1d, 0xb3, 0x27, 0x0b, 0x73, 0xbb, 0xff, 0xa8, 0xe2,
    0x13, 0xa0, 0x8f, 0x39, 0x2c, 0x21, 0xc1, 0x5e, 0xf1, 0xa8, 0x82, 0x25, 0x28, 0x19, 0xae, 0xc9,
    0x3f, 0x09, 0x2d, 0x8c, 0x81, 0xa5, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01, 0x00, 0x1b,
    0x31, 0xd5, 0x8b, 0xf4, 0x8f, 0xbb, 0xca, 0x49, 0x9f, 0x62, 0xf8, 0x21, 0xb1, 0xf5, 0x4a, 0xe7,
    0xf3, 0x34, 0x95, 0xf1, 0xe6, 0xf3, 0xb4, 0x24, 0x61, 0x7b, 0x88, 0xcd, 0x56, 0xed, 0x66, 0x56,
    0x39, 0xad, 0x5c, 0x77, 0xb6, 0xb0, 0x3e, 0x90, 0x3f, 0x43, 0x36, 0x19, 0x07, 0x79, 0xab, 0x20,
    0x65, 0x4e, 0x0e, 0x07, 0x12, 0x1d, 0xf6, 0xa4, 0x8b, 0x98, 0xde, 0x4c, 0x2b, 0x2b, 0x88, 0x7f,
    0x1b, 0x25, 0xe0, 0x1b, 0xee, 0x18, 0x1b, 0x40, 0x2c, 0x14, 0xb4, 0xdd, 0xe2, 0xcf, 0xc5, 0x5b,
    0x7d, 0x76, 0x66, 0xa6, 0xd1, 0xf0, 0xb4, 0x3a, 0x37, 0x73, 0x1a, 0x50, 0x26, 0x6a, 0x82, 0x4d,
    0xb2, 0x68, 0x25, 0x33, 0x24, 0x8f, 0x06, 0xb5, 0x09, 0x7f, 0xec, 0x68, 0xc0, 0x68, 0xd2, 0xa9,
    0x7b, 0x2e, 0xa1, 0x0f, 0x3c, 0xba, 0x03, 0x11, 0xf1, 0x2d, 0x2c, 0x3d, 0xb9, 0x0d, 0x87, 0x34,
    0x84, 0x62, 0x65, 0xe4, 0xe3, 0x32, 0x0d, 0xbd, 0x90, 0xad, 0x2c, 0x57, 0x74, 0x39, 0xd8, 0x25,
    0x42, 0x46, 0x3c, 0xc9, 0x0b, 0x26, 0xc9, 0x99, 0x75, 0xc2, 0x6e, 0x56, 0x82, 0x41, 0xfb, 0xeb,
    0xd9, 0x80, 0x3d, 0x6e, 0x0e, 0x8b, 0x0b, 0xa3, 0xaf, 0x6c, 0x1d, 0x39, 0x79, 0xf8, 0xa5, 0xae,
    0x6c, 0x9e, 0xdf, 0x1b, 0xd3, 0x7a, 0x16, 0x35, 0xf4, 0x14, 0x6d, 0x1e, 0x4d, 0x7b, 0x6f, 0xbb,
    0xfb, 0xe9, 0x2c, 0x9e, 0xad, 0xf9, 0x0a, 0x53, 0x29, 0x2a, 0xd8, 0xff, 0x9d, 0xb3, 0xac, 0x9e,
    0x2d, 0x86, 0x77, 0x67, 0x4c, 0xa8, 0x74, 0xe3, 0xb2, 0x94, 0xf8, 0xfb, 0xe8, 0x33, 0xf2, 0x3c,
    0x5d, 0x57, 0x79, 0x89, 0x87, 0xd0, 0x9b, 0x52, 0x4b, 0xc9, 0xbc, 0x48, 0x68, 0xbe, 0x85, 0x1f,
    0x25, 0x61, 0x44, 0x7e, 0xa6, 0x40, 0x54, 0x70, 0xaf, 0x65, 0x11, 0x3a, 0x58, 0xd1, 0x81, 0x02,
    0x81, 0x81, 0x00, 0xfd, 0x9e, 0x1a, 0x50, 0x85, 0xd7, 0xa8, 0x9c, 0x36, 0x6a, 0x8f, 0x1c, 0x9f,
    0x2d, 0x6d, 0xdf, 0xb4, 0xe6, 0xc4, 0xd2, 0xcf, 0x99, 0x6f, 0x5d, 0xc5, 0x71, 0x01, 0xe6, 0x1d,
    0x5f, 0xd5, 0x6d, 0x52, 0x86, 0x7c, 0xb6, 0xc2, 0xc2, 0x1b, 0xcd, 0x4a, 0xd1, 0x0c, 0x79, 0x15,
    0x2d, 0x4e, 0x93, 0xe2, 0xc0, 0x7d, 0xe6, 0xa4, 0xc4, 0x71, 0x41, 0xa3, 0x49, 0x93, 0x2c, 0xf9,
    0xe7, 0xc8, 0xe6, 0x79, 0x52, 0x19, 0xf7, 0xe0, 0x2a, 0xd9, 0xc0, 0x0f, 0x3e, 0xad, 0xdf, 0xf4,
    0x96, 0xbd, 0xb9, 0x54, 0x5a, 0x5a, 0xe8, 0x70, 0x2d, 0xad, 0xf0, 0x5d, 0x63, 0x80, 0xb4, 0x8f,
    0x3c, 0x1b, 0xad, 0xd9, 0x2b, 0x63, 0x16, 0x80, 0xe1, 0x52, 0x8d, 0xd7, 0x8e, 0x2c, 0x37, 0x99,
    0x6e, 0x1e, 0x8e, 0x64, 0xcf, 0x0e, 0x79, 0x32, 0xdd, 0x1a, 0xc1, 0x43, 0x7e, 0x4c, 0x0c, 0xab,
    0x29, 0x5b, 0x25, 0x02, 0x81, 0x81, 0x00, 0xb9, 0x9a, 0x3e, 0x3e, 0x20, 0x74, 0xe5, 0x19, 0x82,
    0x8b, 0x1d, 0x20, 0x2b, 0xe5, 0xa9, 0x8c, 0x71, 0xd5, 0xa8, 0xe6, 0xed, 0x7e, 0x0a, 0x91, 0x8f,
    0x87, 0xf5, 0x80, 0xc8, 0xd4, 0x1d, 0x4e, 0x25, 0x0b, 0xfe, 0x22, 0xb6, 0xdd, 0xc3, 0xfd, 0x46,
    0x78, 0x7f, 0x6c, 0x27, 0x9d, 0xfe, 0xbf, 0xea, 0x66, 0x27, 0x57, 0x2e, 0xc2, 0x7c, 0xca, 0x63,
    0x1a, 0xc8, 0xb8, 0xda, 0x2f, 0xf3, 0x03, 0xfc, 0x03, 0xcb, 0xf4, 0x0c, 0x8a, 0x00, 0x2f, 0x5d,
    0x78, 0x7a, 0xff, 0x9e, 0x84, 0xc5, 0x0b, 0xd6, 0xae, 0xf6, 0xf8, 0xc7, 0x6f, 0x5f, 0x77, 0x8c,
    0x4f, 0xe6, 0x4f, 0x58, 0x67, 0xbf, 0xde, 0x8e, 0x39, 0xa5, 0xd8, 0x82, 0x59, 0x40, 0xf8, 0xd4,
    0x46, 0xbe, 0x5b, 0xaa, 0x2b, 0x74, 0xf4, 0x29, 0x72, 0xfd, 0x2b, 0xa0, 0xa2, 0xb4, 0x1a, 0x3d,
    0x4d, 0x2f, 0xfe, 0x61, 0x55, 0x04, 0x81, 0x02, 0x81, 0x80, 0x58, 0x92, 0xa6, 0xce, 0x08, 0x70,
    0x50, 0xca, 0x7d, 0x96, 0xa9, 0x74, 0x6d, 0x83, 0x08, 0x24, 0x60, 0xa1, 0x57, 0x8b, 0xe8, 0x44,
    0xc5, 0xc8, 0x11, 0xf4, 0x6d, 0x9d, 0x58, 0x14, 0xe8, 0x0c, 0xce, 0x0d, 0x79, 0xf0, 0xba, 0x03,
    0xe0, 0x81, 0xc9, 0xe7, 0x48, 0x5b, 0xe1, 0x31, 0x79, 0x87, 0xdc, 0x61, 0x2d, 0x97, 0x27, 0x64,
    0x13, 0xc9, 0xc0, 0xa5, 0x29, 0x69, 0x43, 0xbd, 0xd7, 0x43, 0xe6, 0x8a, 0xed, 0xd6, 0xcb, 0xcb,
    0x2b, 0x51, 0x10, 0x01, 0xeb, 0xe7, 0x93, 0x1c, 0x32, 0x16, 0x4f, 0x87, 0x5e, 0xc8, 0x5e, 0xa5,
    0x15, 0x62, 0x24, 0xbb, 0x63, 0x6f, 0xab, 0xb6, 0x6a, 0x54, 0x44, 0xcc, 0x0a, 0x47, 0x09, 0xab,
    0xa7, 0x91, 0x31, 0xfe, 0xcd, 0x22, 0x7d, 0xcb, 0x1f, 0x90, 0xcb, 0x54, 0x24, 0xd1, 0xdf, 0x19,
    0xa9, 0x06, 0x65, 0xf3, 0xed, 0xcb, 0x5e, 0xdb, 0x8a, 0xa1, 0x02, 0x81, 0x80, 0x0b, 0x53, 0x45,
    0x1f, 0x07, 0x5d, 0xfa, 0xa8, 0xce, 0xd5, 0x6c, 0x46, 0x8d, 0x47, 0x2b, 0x4c, 0x5d, 0x99, 0xda,
    0xff, 0x94, 0x58, 0x4f, 0x8e, 0xc8, 0x42, 0x54, 0x91, 0xb2, 0x2f, 0x77, 0x46, 0x50, 0x6e, 0x65,
    0xe8, 0x7a, 0x5e, 0x17, 0xda, 0x79, 0x95, 0x5a, 0xb9, 0x1f, 0xc5, 0xbd, 0x48, 0xba, 0xa5, 0xd7,
    0x1a, 0xb3, 0xc8, 0xbc, 0x52, 0xa1, 0x2f, 0x7e, 0x36, 0x01, 0x62, 0x51, 0xa2, 0xd9, 0x9a, 0xe5,
    0xb4, 0x13, 0x9b, 0xcc, 0x1d, 0x17, 0xc8, 0x05, 0x41, 0x59, 0xcb, 0xe2, 0x36, 0x31, 0xb8, 0x65,
    0x6b, 0x92, 0xc7, 0xd1, 0xfc, 0x7a, 0x7c, 0x59, 0xa2, 0x57, 0xd3, 0xa4, 0xda, 0x90, 0xb5, 0x25,
    0xd0, 0x8b, 0x4b, 0xa4, 0xf2, 0x4a, 0x09, 0xb3, 0x0d, 0xe6, 0xd9, 0x55, 0xfe, 0x9c, 0x14, 0xdf,
    0x2b, 0xed, 0x56, 0x60, 0x45, 0x05, 0x9e, 0x93, 0x22, 0x23, 0x90, 0x4b, 0x81, 0x02, 0x81, 0x80,
    0x71, 0x49, 0x07, 0xff, 0x86, 0xc5, 0xf7, 0xe4, 0xbd, 0xa8, 0xbc, 0xa4, 0xbe, 0x1f, 0x8e, 0x73,
    0xb0, 0xea, 0x71, 0x85, 0x61, 0xb1, 0x8d, 0x30, 0xe3, 0xac, 0x67, 0xfc, 0x2c, 0x5a, 0x36, 0xcc,
    0x66, 0xe7, 0x2f, 0x32, 0x97, 0x54, 0x97, 0xe9, 0xd6, 0x5d, 0xd9, 0xe5, 0xbb, 0x1a, 0x06, 0x15,
    0x95, 0x2d, 0x8e, 0xca, 0x27, 0x8e, 0x2e, 0x39, 0xab, 0x45, 0x2d, 0x94, 0x26, 0x93, 0xd0, 0x7b,
    0xda, 0x62, 0x02, 0xba, 0xe6, 0xd9, 0x87, 0xad, 0xf7, 0x2a, 0x33, 0x1d, 0x5a, 0xd9, 0xa8, 0xf3,
    0x38, 0x0e, 0x0f, 0xd1, 0x24, 0x25, 0x69, 0x2a, 0x2c, 0x99, 0xf7, 0xea, 0x0d, 0x3b, 0x51, 0x8b,
    0x2a, 0x72, 0xb0, 0x51, 0xd3, 0x07, 0x63, 0x9e, 0x9d, 0x15, 0xe6, 0xa8, 0xf5, 0xce, 0x69, 0x74,
    0x53, 0xd3, 0xb1, 0x26, 0x77, 0xfa, 0x0e, 0x8f, 0xdd, 0x1f, 0x0e, 0x76, 0x51, 0x56, 0x85, 0xb7,
];

fn main() -> Result<()> {
    println!("🔑 Caden demo");
    println!("─────────────────────────────────────");

    let rng = SystemRandom::new();

    let rp = RelyingParty::new(RP_ID, ORIGIN, "Caden Demo");

    // ── ES256: Step 1: Generate authenticator keypair ─────────────────────────
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|e| anyhow::anyhow!("failed to generate PKCS8 keypair: {e}"))?;
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|e| anyhow::anyhow!("failed to load key pair: {e}"))?;

    let public_key_bytes = key_pair.public_key().as_ref().to_vec();

    let mut cred_id = vec![0u8; 16];
    ring::rand::SecureRandom::fill(&rng, &mut cred_id)
        .map_err(|e| anyhow::anyhow!("failed to generate credential ID: {e}"))?;

    // ── ES256: Step 2: Registration ceremony ─────────────────────────────────
    println!("\n[ES256 Registration]");

    let reg_challenge = Challenge::new().context("failed to generate challenge")?;

    let client_data_json_bytes =
        make_client_data_json_bytes("webauthn.create", &reg_challenge.bytes, ORIGIN);

    let auth_data_bytes = make_authenticator_data(
        RP_ID,
        0x41, // flags: UP=1 (bit 0), AT=1 (bit 6)
        0,    // sign count 0 — initial registration
        Some((&cred_id, &encode_es256_cose_key(&public_key_bytes))),
    );

    let attestation_object_bytes = make_attestation_object(&auth_data_bytes);

    let reg_response = AuthenticatorAttestationResponse {
        client_data_json: client_data_json_bytes,
        attestation_object: attestation_object_bytes,
    };

    let reg_result = rp
        .verify_registration(&reg_challenge, &reg_response, USER_ID)
        .context("ES256 registration verification failed")?;

    let cred_id_hex: String = reg_result
        .credential
        .id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    println!("  Registration successful");
    println!("  Credential ID: {cred_id_hex}");
    println!("  Algorithm:     ES256");
    println!("  Sign count:    {}", reg_result.credential.sign_count);

    let mut stored_es256 = reg_result.credential;

    // ── ES256: Step 3: Authentication ceremony ────────────────────────────────
    println!("\n[ES256 Authentication]");

    let auth_challenge = Challenge::new().context("failed to generate challenge")?;

    let auth_response = make_es256_auth_response(
        &key_pair,
        &rng,
        &auth_challenge.bytes,
        RP_ID,
        ORIGIN,
        1, // sign count incremented from 0 to 1
        &cred_id,
    )?;

    let auth_result = rp
        .verify_authentication(&stored_es256, &auth_challenge, &auth_response)
        .context("ES256 authentication failed")?;

    println!("  Authentication successful");
    println!(
        "  Sign count:    {} → updated to {}",
        stored_es256.sign_count, auth_result.new_sign_count
    );
    println!("  User present:  {}", auth_result.user_present);

    stored_es256.sign_count = auth_result.new_sign_count;

    // ── ES256: Step 4: Replay attack demonstration ────────────────────────────
    println!("\n[ES256 Replay Attack Prevention]");

    let replay_challenge = Challenge::new().context("failed to generate challenge")?;
    let replay_response = make_es256_auth_response(
        &key_pair,
        &rng,
        &replay_challenge.bytes,
        RP_ID,
        ORIGIN,
        1, // same sign count — replay
        &cred_id,
    )?;

    match rp.verify_authentication(&stored_es256, &replay_challenge, &replay_response) {
        Err(webauthn::WebAuthnError::SignCountInvalid { stored, received }) => {
            println!("  Replay attack correctly rejected");
            println!("  Error: Sign count invalid: stored {stored}, received {received}");
        }
        Ok(_) => panic!("BUG: ES256 replay attack should have been rejected!"),
        Err(e) => return Err(e.into()),
    }

    // ── RS256: Step 5: Registration ceremony ──────────────────────────────────
    println!("\n[RS256 Registration]");

    let rsa_key_pair = ring::rsa::KeyPair::from_pkcs8(RSA_PKCS8_DER)
        .map_err(|e| anyhow::anyhow!("failed to load RSA key: {e}"))?;
    let (rsa_n, rsa_e) = extract_rsa_components(rsa_key_pair.public().as_ref());

    let mut rsa_cred_id = vec![0u8; 16];
    ring::rand::SecureRandom::fill(&rng, &mut rsa_cred_id)
        .map_err(|e| anyhow::anyhow!("failed to generate RSA credential ID: {e}"))?;

    let rsa_reg_challenge = Challenge::new().context("failed to generate RSA challenge")?;
    let rsa_client_data_json =
        make_client_data_json_bytes("webauthn.create", &rsa_reg_challenge.bytes, ORIGIN);
    let rsa_cose_key = encode_rs256_cose_key(&rsa_n, &rsa_e);
    let rsa_reg_auth_data =
        make_authenticator_data(RP_ID, 0x41, 0, Some((&rsa_cred_id, &rsa_cose_key)));
    let rsa_att_obj = make_attestation_object(&rsa_reg_auth_data);

    let rsa_reg_response = AuthenticatorAttestationResponse {
        client_data_json: rsa_client_data_json,
        attestation_object: rsa_att_obj,
    };

    let rsa_reg_result = rp
        .verify_registration(&rsa_reg_challenge, &rsa_reg_response, USER_ID)
        .context("RS256 registration verification failed")?;

    let rsa_cred_id_hex: String = rsa_reg_result
        .credential
        .id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    println!("  Registration successful");
    println!("  Credential ID: {rsa_cred_id_hex}");
    println!("  Algorithm:     RS256");
    println!("  Sign count:    {}", rsa_reg_result.credential.sign_count);

    let mut stored_rs256 = rsa_reg_result.credential;

    // ── RS256: Step 6: Authentication ceremony ────────────────────────────────
    println!("\n[RS256 Authentication]");

    let rsa_auth_challenge = Challenge::new().context("failed to generate challenge")?;
    let rsa_auth_response = make_rs256_auth_response(
        &rsa_key_pair,
        &rng,
        &rsa_auth_challenge.bytes,
        RP_ID,
        ORIGIN,
        1,
        &rsa_cred_id,
    )?;

    let rsa_auth_result = rp
        .verify_authentication(&stored_rs256, &rsa_auth_challenge, &rsa_auth_response)
        .context("RS256 authentication failed")?;

    println!("  Authentication successful");
    println!(
        "  Sign count:    {} → updated to {}",
        stored_rs256.sign_count, rsa_auth_result.new_sign_count
    );
    println!("  User present:  {}", rsa_auth_result.user_present);

    stored_rs256.sign_count = rsa_auth_result.new_sign_count;

    // ── RS256: Step 7: Replay attack demonstration ────────────────────────────
    println!("\n[RS256 Replay Attack Prevention]");

    let rsa_replay_challenge = Challenge::new().context("failed to generate challenge")?;
    let rsa_replay_response = make_rs256_auth_response(
        &rsa_key_pair,
        &rng,
        &rsa_replay_challenge.bytes,
        RP_ID,
        ORIGIN,
        1, // same sign count — replay
        &rsa_cred_id,
    )?;

    match rp.verify_authentication(&stored_rs256, &rsa_replay_challenge, &rsa_replay_response) {
        Err(webauthn::WebAuthnError::SignCountInvalid { stored, received }) => {
            println!("  Replay attack correctly rejected");
            println!("  Error: Sign count invalid: stored {stored}, received {received}");
        }
        Ok(_) => panic!("BUG: RS256 replay attack should have been rejected!"),
        Err(e) => return Err(e.into()),
    }

    // ── ES384: Step 8: Registration ceremony ─────────────────────────────────
    println!("\n[ES384 Registration]");

    let p384_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
        .map_err(|e| anyhow::anyhow!("failed to generate P-384 PKCS8 keypair: {e}"))?;
    let p384_key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, p384_pkcs8.as_ref(), &rng)
            .map_err(|e| anyhow::anyhow!("failed to load P-384 key pair: {e}"))?;

    let p384_public_key_bytes = p384_key_pair.public_key().as_ref().to_vec(); // 97 bytes

    let mut p384_cred_id = vec![0u8; 16];
    ring::rand::SecureRandom::fill(&rng, &mut p384_cred_id)
        .map_err(|e| anyhow::anyhow!("failed to generate ES384 credential ID: {e}"))?;

    let p384_reg_challenge = Challenge::new().context("failed to generate ES384 challenge")?;
    let p384_client_data_json =
        make_client_data_json_bytes("webauthn.create", &p384_reg_challenge.bytes, ORIGIN);
    let p384_cose_key = encode_es384_cose_key(&p384_public_key_bytes);
    let p384_reg_auth_data =
        make_authenticator_data(RP_ID, 0x41, 0, Some((&p384_cred_id, &p384_cose_key)));
    let p384_att_obj = make_attestation_object(&p384_reg_auth_data);

    let p384_reg_response = AuthenticatorAttestationResponse {
        client_data_json: p384_client_data_json,
        attestation_object: p384_att_obj,
    };

    let p384_reg_result = rp
        .verify_registration(&p384_reg_challenge, &p384_reg_response, USER_ID)
        .context("ES384 registration verification failed")?;

    let p384_cred_id_hex: String = p384_reg_result
        .credential
        .id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    println!("  Registration successful");
    println!("  Credential ID: {p384_cred_id_hex}");
    println!("  Algorithm:     ES384");
    println!("  Sign count:    {}", p384_reg_result.credential.sign_count);

    let mut stored_es384 = p384_reg_result.credential;

    // ── ES384: Step 9: Authentication ceremony ────────────────────────────────
    println!("\n[ES384 Authentication]");

    let p384_auth_challenge = Challenge::new().context("failed to generate challenge")?;
    let p384_auth_response = make_es384_auth_response(
        &p384_key_pair,
        &rng,
        &p384_auth_challenge.bytes,
        RP_ID,
        ORIGIN,
        1,
        &p384_cred_id,
    )?;

    let p384_auth_result = rp
        .verify_authentication(&stored_es384, &p384_auth_challenge, &p384_auth_response)
        .context("ES384 authentication failed")?;

    println!("  Authentication successful");
    println!(
        "  Sign count:    {} → updated to {}",
        stored_es384.sign_count, p384_auth_result.new_sign_count
    );
    println!("  User present:  {}", p384_auth_result.user_present);

    stored_es384.sign_count = p384_auth_result.new_sign_count;

    // ── ES384: Step 10: Replay attack demonstration ───────────────────────────
    println!("\n[ES384 Replay Attack Prevention]");

    let p384_replay_challenge = Challenge::new().context("failed to generate challenge")?;
    let p384_replay_response = make_es384_auth_response(
        &p384_key_pair,
        &rng,
        &p384_replay_challenge.bytes,
        RP_ID,
        ORIGIN,
        1, // same sign count — replay
        &p384_cred_id,
    )?;

    match rp.verify_authentication(&stored_es384, &p384_replay_challenge, &p384_replay_response) {
        Err(webauthn::WebAuthnError::SignCountInvalid { stored, received }) => {
            println!("  Replay attack correctly rejected");
            println!("  Error: Sign count invalid: stored {stored}, received {received}");
        }
        Ok(_) => panic!("BUG: ES384 replay attack should have been rejected!"),
        Err(e) => return Err(e.into()),
    }

    // ── EdDSA: Step 10: Registration ceremony ────────────────────────────────
    println!("\n[EdDSA Registration]");

    let ed_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| anyhow::anyhow!("failed to generate Ed25519 PKCS8 keypair: {e}"))?;
    let ed_key_pair = Ed25519KeyPair::from_pkcs8(ed_pkcs8.as_ref())
        .map_err(|e| anyhow::anyhow!("failed to load Ed25519 key pair: {e}"))?;

    let ed_public_key_bytes = ed_key_pair.public_key().as_ref().to_vec(); // 32 bytes

    let mut ed_cred_id = vec![0u8; 16];
    ring::rand::SecureRandom::fill(&rng, &mut ed_cred_id)
        .map_err(|e| anyhow::anyhow!("failed to generate EdDSA credential ID: {e}"))?;

    let ed_reg_challenge = Challenge::new().context("failed to generate EdDSA challenge")?;
    let ed_client_data_json =
        make_client_data_json_bytes("webauthn.create", &ed_reg_challenge.bytes, ORIGIN);
    let ed_cose_key = encode_eddsa_cose_key(&ed_public_key_bytes);
    let ed_reg_auth_data =
        make_authenticator_data(RP_ID, 0x41, 0, Some((&ed_cred_id, &ed_cose_key)));
    let ed_att_obj = make_attestation_object(&ed_reg_auth_data);

    let ed_reg_response = AuthenticatorAttestationResponse {
        client_data_json: ed_client_data_json,
        attestation_object: ed_att_obj,
    };

    let ed_reg_result = rp
        .verify_registration(&ed_reg_challenge, &ed_reg_response, USER_ID)
        .context("EdDSA registration verification failed")?;

    let ed_cred_id_hex: String = ed_reg_result
        .credential
        .id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    println!("  Registration successful");
    println!("  Credential ID: {ed_cred_id_hex}");
    println!("  Algorithm:     EdDSA");
    println!("  Sign count:    {}", ed_reg_result.credential.sign_count);

    let mut stored_eddsa = ed_reg_result.credential;

    // ── EdDSA: Step 11: Authentication ceremony ───────────────────────────────
    println!("\n[EdDSA Authentication]");

    let ed_auth_challenge = Challenge::new().context("failed to generate challenge")?;
    let ed_auth_response = make_eddsa_auth_response(
        &ed_key_pair,
        &ed_auth_challenge.bytes,
        RP_ID,
        ORIGIN,
        1,
        &ed_cred_id,
    )?;

    let ed_auth_result = rp
        .verify_authentication(&stored_eddsa, &ed_auth_challenge, &ed_auth_response)
        .context("EdDSA authentication failed")?;

    println!("  Authentication successful");
    println!(
        "  Sign count:    {} → updated to {}",
        stored_eddsa.sign_count, ed_auth_result.new_sign_count
    );
    println!("  User present:  {}", ed_auth_result.user_present);

    stored_eddsa.sign_count = ed_auth_result.new_sign_count;

    // ── EdDSA: Step 12: Replay attack demonstration ───────────────────────────
    println!("\n[EdDSA Replay Attack Prevention]");

    let ed_replay_challenge = Challenge::new().context("failed to generate challenge")?;
    let ed_replay_response = make_eddsa_auth_response(
        &ed_key_pair,
        &ed_replay_challenge.bytes,
        RP_ID,
        ORIGIN,
        1, // same sign count — replay
        &ed_cred_id,
    )?;

    match rp.verify_authentication(&stored_eddsa, &ed_replay_challenge, &ed_replay_response) {
        Err(webauthn::WebAuthnError::SignCountInvalid { stored, received }) => {
            println!("  Replay attack correctly rejected");
            println!("  Error: Sign count invalid: stored {stored}, received {received}");
        }
        Ok(_) => panic!("BUG: EdDSA replay attack should have been rejected!"),
        Err(e) => return Err(e.into()),
    }

    // ── Passkey flow: discoverable credential (begin_authentication) ──────────
    println!("\n[Passkey / Discoverable Credential Flow]");

    // The server issues a challenge with no allowCredentials hint.
    // The authenticator picks a credential and returns its ID as rawId.
    let passkey_challenge = Challenge::new().context("failed to generate passkey challenge")?;

    // Simulated authenticator assertion — credential_id is the rawId the
    // authenticator sends back alongside the assertion.
    let passkey_assertion = make_es256_auth_response(
        &key_pair,
        &rng,
        &passkey_challenge.bytes,
        RP_ID,
        ORIGIN,
        2, // stored_es256 is at sign_count=1 after the previous auth
        &cred_id,
    )?;

    // Step 1: Extract the credential ID from the response — no allowCredentials
    // was sent, so the server must read rawId to know which credential to load.
    let (returned_cred_id, _user_handle) = rp
        .begin_authentication(&passkey_assertion)
        .context("begin_authentication failed")?;

    // Step 2: Look up the credential (trivially simulated here).
    let looked_up = if returned_cred_id == stored_es256.id {
        &stored_es256
    } else {
        anyhow::bail!("BUG: returned credential ID does not match stored ES256 credential");
    };

    // Step 3: Verify the full assertion.
    let passkey_result = rp
        .verify_authentication(looked_up, &passkey_challenge, &passkey_assertion)
        .context("passkey verify_authentication failed")?;

    println!("  Passkey authentication successful");
    println!(
        "  Credential ID (hex): {}",
        looked_up
            .id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!(
        "  Sign count: {} → {}",
        looked_up.sign_count, passkey_result.new_sign_count
    );

    println!("\n─────────────────────────────────────");
    println!("All checks passed.");
    Ok(())
}

// ─── Authenticator simulation helpers ─────────────────────────────────────────

fn make_client_data_json_bytes(type_: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
    format!(
        r#"{{"type":"{type_}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
    )
    .into_bytes()
}

/// Build a raw authenticator data buffer.
///
/// Layout: rpIdHash (32) | flags (1) | signCount (4) | attestedCredentialData (if AT set)
fn make_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    cred_data: Option<(&[u8], &[u8])>, // (cred_id, cose_key_cbor)
) -> Vec<u8> {
    let rp_id_hash = webauthn::crypto::sha256(rp_id.as_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((cred_id, cose_key_cbor)) = cred_data {
        out.extend_from_slice(&[0u8; 16]); // aaguid: all-zeros
        let id_len = cred_id.len() as u16;
        out.extend_from_slice(&id_len.to_be_bytes());
        out.extend_from_slice(cred_id);
        out.extend_from_slice(cose_key_cbor);
    }

    out
}

fn encode_es256_cose_key(uncompressed_point: &[u8]) -> Vec<u8> {
    assert_eq!(
        uncompressed_point.len(),
        65,
        "expected 0x04 || x(32) || y(32)"
    );
    let x = uncompressed_point[1..33].to_vec();
    let y = uncompressed_point[33..65].to_vec();

    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())), // alg: ES256
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())), // crv: P-256
        (Value::Integer((-2i64).into()), Value::Bytes(x)),          // x
        (Value::Integer((-3i64).into()), Value::Bytes(y)),          // y
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&cose_key, &mut buf).expect("CBOR encoding should not fail");
    buf
}

fn encode_rs256_cose_key(n: &[u8], e: &[u8]) -> Vec<u8> {
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(3i64.into())), // kty: RSA
        (
            Value::Integer(3i64.into()),
            Value::Integer((-257i64).into()),
        ), // alg: RS256
        (Value::Integer((-1i64).into()), Value::Bytes(n.to_vec())), // n: modulus
        (Value::Integer((-2i64).into()), Value::Bytes(e.to_vec())), // e: exponent
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&cose_key, &mut buf).expect("CBOR encoding should not fail");
    buf
}

/// Extract RSA modulus (n) and exponent (e) from ring's RSAPublicKey DER bytes.
///
/// ring serialises the RSA public key as `SEQUENCE { INTEGER n, INTEGER e }`.
/// We strip the leading 0x00 padding byte from n when present (DER adds it when
/// the high bit is set to prevent sign misinterpretation).
fn extract_rsa_components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pos = 0;
    // Skip outer SEQUENCE tag
    assert_eq!(der[pos], 0x30);
    pos += 1;
    // Skip SEQUENCE length (long form: 0x82 hi lo)
    if der[pos] < 0x80 {
        pos += 1;
    } else {
        let extra = (der[pos] & 0x7f) as usize;
        pos += 1 + extra;
    }

    // Parse INTEGER n
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let n_len = if der[pos] < 0x80 {
        let l = der[pos] as usize;
        pos += 1;
        l
    } else {
        let extra = (der[pos] & 0x7f) as usize;
        pos += 1;
        let mut l = 0usize;
        for _ in 0..extra {
            l = (l << 8) | der[pos] as usize;
            pos += 1;
        }
        l
    };
    // Strip the leading 0x00 padding byte that DER adds when the high bit is set.
    let n_start = if der[pos] == 0x00 { pos + 1 } else { pos };
    let n = der[n_start..pos + n_len].to_vec();
    pos += n_len;

    // Parse INTEGER e
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let e_len = der[pos] as usize;
    pos += 1;
    let e = der[pos..pos + e_len].to_vec();

    (n, e)
}

fn encode_es384_cose_key(uncompressed_point: &[u8]) -> Vec<u8> {
    assert_eq!(
        uncompressed_point.len(),
        97,
        "expected 0x04 || x(48) || y(48)"
    );
    let x = uncompressed_point[1..49].to_vec();
    let y = uncompressed_point[49..97].to_vec();

    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer(3i64.into()), Value::Integer((-35i64).into())), // alg: ES384
        (Value::Integer((-1i64).into()), Value::Integer(2i64.into())), // crv: P-384
        (Value::Integer((-2i64).into()), Value::Bytes(x)),          // x
        (Value::Integer((-3i64).into()), Value::Bytes(y)),          // y
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&cose_key, &mut buf).expect("CBOR encoding should not fail");
    buf
}

fn make_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let att_obj = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        ),
        (Value::Text("attStmt".to_string()), Value::Map(vec![])),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&att_obj, &mut buf).expect("CBOR encoding should not fail");
    buf
}

fn make_es256_auth_response(
    key_pair: &EcdsaKeyPair,
    rng: &SystemRandom,
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
    sign_count: u32,
    cred_id: &[u8],
) -> Result<AuthenticatorAssertionResponse> {
    let client_data_bytes = make_client_data_json_bytes("webauthn.get", challenge, origin);
    let auth_data_bytes = make_authenticator_data(rp_id, 0x01, sign_count, None);

    let client_data_hash = webauthn::crypto::sha256(&client_data_bytes);
    let mut signed_data = auth_data_bytes.clone();
    signed_data.extend_from_slice(&client_data_hash);

    let sig = key_pair
        .sign(rng, &signed_data)
        .map_err(|e| anyhow::anyhow!("ECDSA signing failed: {e}"))?;

    Ok(AuthenticatorAssertionResponse {
        client_data_json: client_data_bytes,
        authenticator_data: auth_data_bytes,
        signature: sig.as_ref().to_vec(),
        user_handle: None,
        credential_id: cred_id.to_vec(),
    })
}

fn make_es384_auth_response(
    key_pair: &EcdsaKeyPair,
    rng: &ring::rand::SystemRandom,
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
    sign_count: u32,
    cred_id: &[u8],
) -> Result<AuthenticatorAssertionResponse> {
    let client_data_bytes = make_client_data_json_bytes("webauthn.get", challenge, origin);
    let auth_data_bytes = make_authenticator_data(rp_id, 0x01, sign_count, None);

    let client_data_hash = webauthn::crypto::sha256(&client_data_bytes);
    let mut signed_data = auth_data_bytes.clone();
    signed_data.extend_from_slice(&client_data_hash);

    let sig = key_pair
        .sign(rng, &signed_data)
        .map_err(|e| anyhow::anyhow!("ECDSA P-384 signing failed: {e}"))?;

    Ok(AuthenticatorAssertionResponse {
        client_data_json: client_data_bytes,
        authenticator_data: auth_data_bytes,
        signature: sig.as_ref().to_vec(),
        user_handle: None,
        credential_id: cred_id.to_vec(),
    })
}

fn make_rs256_auth_response(
    key_pair: &ring::rsa::KeyPair,
    rng: &SystemRandom,
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
    sign_count: u32,
    cred_id: &[u8],
) -> Result<AuthenticatorAssertionResponse> {
    use ring::signature::RSA_PKCS1_SHA256;

    let client_data_bytes = make_client_data_json_bytes("webauthn.get", challenge, origin);
    let auth_data_bytes = make_authenticator_data(rp_id, 0x01, sign_count, None);

    let client_data_hash = webauthn::crypto::sha256(&client_data_bytes);
    let mut signed_data = auth_data_bytes.clone();
    signed_data.extend_from_slice(&client_data_hash);

    let mut sig = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(&RSA_PKCS1_SHA256, rng, &signed_data, &mut sig)
        .map_err(|e| anyhow::anyhow!("RSA signing failed: {e}"))?;

    Ok(AuthenticatorAssertionResponse {
        client_data_json: client_data_bytes,
        authenticator_data: auth_data_bytes,
        signature: sig,
        user_handle: None,
        credential_id: cred_id.to_vec(),
    })
}

fn encode_eddsa_cose_key(public_key: &[u8]) -> Vec<u8> {
    assert_eq!(public_key.len(), 32, "expected 32-byte Ed25519 public key");
    let cose_key = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(1i64.into())), // kty: OKP
        (Value::Integer(3i64.into()), Value::Integer((-8i64).into())), // alg: EdDSA
        (Value::Integer((-1i64).into()), Value::Integer(6i64.into())), // crv: Ed25519
        (
            Value::Integer((-2i64).into()),
            Value::Bytes(public_key.to_vec()),
        ), // x: raw public key
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&cose_key, &mut buf).expect("CBOR encoding should not fail");
    buf
}

fn make_eddsa_auth_response(
    key_pair: &Ed25519KeyPair,
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
    sign_count: u32,
    cred_id: &[u8],
) -> Result<AuthenticatorAssertionResponse> {
    let client_data_bytes = make_client_data_json_bytes("webauthn.get", challenge, origin);
    let auth_data_bytes = make_authenticator_data(rp_id, 0x01, sign_count, None);

    let client_data_hash = webauthn::crypto::sha256(&client_data_bytes);
    let mut signed_data = auth_data_bytes.clone();
    signed_data.extend_from_slice(&client_data_hash);

    let sig = key_pair.sign(&signed_data);

    Ok(AuthenticatorAssertionResponse {
        client_data_json: client_data_bytes,
        authenticator_data: auth_data_bytes,
        signature: sig.as_ref().to_vec(),
        user_handle: None,
        credential_id: cred_id.to_vec(),
    })
}
