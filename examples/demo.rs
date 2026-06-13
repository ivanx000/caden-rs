//! End-to-end WebAuthn simulation without a browser.
//!
//! This demo simulates both sides of the WebAuthn protocol in software:
//! - **Relying party**: uses the webauthn library (the code under test)
//! - **Authenticator**: simulated using ring's P-256 ECDSA primitives
//!
//! Run with: `cargo run --example demo`
//!
//! The demo exercises:
//! 1. Registration  — generate a keypair, build authenticator data, verify
//! 2. Authentication — sign a challenge, verify signature and sign count
//! 3. Replay attack  — demonstrate that reusing a sign count is rejected

use anyhow::{Context, Result};
use ciborium::value::Value;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use webauthn::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, Challenge, RelyingParty,
};

// ─── Demo configuration ───────────────────────────────────────────────────────

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost";
const USER_ID: &[u8] = b"demo-user-001";

fn main() -> Result<()> {
    println!("🔑 WebAuthn demo");
    println!("─────────────────────────────────────");

    let rng = SystemRandom::new();

    let rp = RelyingParty::new(RP_ID, ORIGIN, "WebAuthn Demo");

    // ── Step 1: Generate authenticator keypair ────────────────────────────────
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|e| anyhow::anyhow!("failed to generate PKCS8 keypair: {e}"))?;
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|e| anyhow::anyhow!("failed to load key pair: {e}"))?;

    let public_key_bytes = key_pair.public_key().as_ref().to_vec();

    let mut cred_id = vec![0u8; 16];
    ring::rand::SecureRandom::fill(&rng, &mut cred_id)
        .map_err(|e| anyhow::anyhow!("failed to generate credential ID: {e}"))?;

    // ── Step 2: Registration ceremony ────────────────────────────────────────
    println!("\n[Registration]");

    let reg_challenge = Challenge::new().context("failed to generate challenge")?;

    let client_data_json_bytes =
        make_client_data_json_bytes("webauthn.create", &reg_challenge.bytes, ORIGIN);

    let auth_data_bytes = make_authenticator_data(
        RP_ID,
        0x41, // flags: UP=1 (bit 0), AT=1 (bit 6)
        0,    // sign count 0 — initial registration
        Some((&cred_id, &public_key_bytes)),
    );

    let attestation_object_bytes = make_attestation_object(&auth_data_bytes);

    let reg_response = AuthenticatorAttestationResponse {
        client_data_json: client_data_json_bytes,
        attestation_object: attestation_object_bytes,
    };

    let reg_result = rp
        .verify_registration(&reg_challenge, &reg_response, USER_ID)
        .context("registration verification failed")?;

    let cred_id_hex: String = reg_result
        .credential
        .id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    println!("✅ Registration successful");
    println!("   Credential ID: {cred_id_hex}");
    println!("   Algorithm:     ES256");
    println!("   Sign count:    {}", reg_result.credential.sign_count);

    let mut stored_credential = reg_result.credential;

    // ── Step 3: Authentication ceremony ──────────────────────────────────────
    println!("\n[Authentication]");

    let auth_challenge = Challenge::new().context("failed to generate challenge")?;

    let auth_response = make_auth_response(
        &key_pair,
        &rng,
        &auth_challenge.bytes,
        RP_ID,
        ORIGIN,
        1, // sign count incremented from 0 to 1
    )?;

    let auth_result = rp
        .verify_authentication(&stored_credential, &auth_challenge, &auth_response)
        .context("authentication failed")?;

    println!("✅ Authentication successful");
    println!(
        "   Sign count:    {} → updated to {}",
        stored_credential.sign_count, auth_result.new_sign_count
    );
    println!("   User present:  {}", auth_result.user_present);
    println!("   User verified: {}", auth_result.user_verified);

    stored_credential.sign_count = auth_result.new_sign_count;

    // ── Step 4: Replay attack demonstration ───────────────────────────────────
    println!("\n[Replay Attack Prevention]");

    // Replay the same sign count (1) — should fail because stored is now 1
    let replay_challenge = Challenge::new().context("failed to generate challenge")?;
    let replay_response = make_auth_response(
        &key_pair,
        &rng,
        &replay_challenge.bytes,
        RP_ID,
        ORIGIN,
        1, // same sign count — replay attack
    )?;

    match rp.verify_authentication(&stored_credential, &replay_challenge, &replay_response) {
        Err(webauthn::WebAuthnError::SignCountInvalid { stored, received }) => {
            println!("✅ Replay attack correctly rejected");
            println!("   Error: Sign count invalid: stored {stored}, received {received}");
        }
        Ok(_) => panic!("BUG: replay attack should have been rejected!"),
        Err(e) => return Err(e.into()),
    }

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
    cred_data: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let rp_id_hash = webauthn::crypto::sha256(rp_id.as_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((cred_id, pk_bytes)) = cred_data {
        out.extend_from_slice(&[0u8; 16]); // aaguid: all-zeros
        let id_len = cred_id.len() as u16;
        out.extend_from_slice(&id_len.to_be_bytes());
        out.extend_from_slice(cred_id);
        out.extend_from_slice(&encode_cose_key(pk_bytes));
    }

    out
}

fn encode_cose_key(uncompressed_point: &[u8]) -> Vec<u8> {
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

fn make_auth_response(
    key_pair: &EcdsaKeyPair,
    rng: &SystemRandom,
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
    sign_count: u32,
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
    })
}
