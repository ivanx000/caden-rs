//! End-to-end WebAuthn simulation without a browser.
//!
//! This demo simulates both sides of the WebAuthn protocol:
//! - **Relying party**: uses the passforge library (the code we're demonstrating)
//! - **Authenticator**: simulated in software using ring's P-256 ECDSA primitives
//!
//! Run with: `cargo run --example demo`
//!
//! The demo exercises:
//! 1. Registration — generate a keypair, build authenticator data, verify
//! 2. Authentication — sign a challenge, verify signature and sign count
//! 3. Replay attack — demonstrate that reusing a sign count is rejected

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::value::Value;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use passforge::{
    generate_challenge, AuthenticatorAssertionResponse, AuthenticatorAttestationResponse,
    RelyingParty,
};

// ─── Demo configuration ───────────────────────────────────────────────────────

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8080";
const USER_ID: &[u8] = b"demo-user-001";

fn main() -> Result<()> {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║          passforge — WebAuthn Demo (ES256 / P-256)       ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let rng = SystemRandom::new();
    let rp = RelyingParty::new();

    // ── Step 1: Generate authenticator keypair ────────────────────────────────
    println!("── Authenticator: Generating P-256 keypair ─────────────────");
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|e| anyhow::anyhow!("failed to generate PKCS8 keypair: {e}"))?;
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|e| anyhow::anyhow!("failed to load key pair: {e}"))?;

    // The public key is an uncompressed P-256 point: 0x04 || x (32) || y (32)
    let public_key_bytes = key_pair.public_key().as_ref().to_vec();
    println!(
        "   Public key ({} bytes): {}…",
        public_key_bytes.len(),
        URL_SAFE_NO_PAD.encode(&public_key_bytes[..8])
    );

    // Credential ID: 16 random bytes (authenticator-chosen opaque identifier)
    let mut cred_id = vec![0u8; 16];
    ring::rand::SecureRandom::fill(&rng, &mut cred_id)
        .map_err(|e| anyhow::anyhow!("failed to generate credential ID: {e}"))?;
    println!(
        "   Credential ID: {}\n",
        URL_SAFE_NO_PAD.encode(&cred_id)
    );

    // ── Step 2: Registration ceremony ────────────────────────────────────────
    println!("── Registration Ceremony ───────────────────────────────────");

    let reg_challenge = generate_challenge().context("failed to generate challenge")?;
    println!(
        "   RP issues challenge: {}",
        URL_SAFE_NO_PAD.encode(&reg_challenge.bytes)
    );

    // Simulate authenticator building clientDataJSON
    let client_data_json_str = make_client_data_json(
        "webauthn.create",
        &reg_challenge.bytes,
        ORIGIN,
    );
    let client_data_json_b64 = URL_SAFE_NO_PAD.encode(client_data_json_str.as_bytes());

    // Simulate authenticator building authenticatorData
    let auth_data_bytes = make_authenticator_data(
        RP_ID,
        0x41, // flags: UP=1 (bit 0), AT=1 (bit 6)
        1,    // initial sign count
        Some((&cred_id, &public_key_bytes)),
    );

    // Build the CBOR attestation object: { fmt: "none", attStmt: {}, authData: ... }
    let attestation_object_bytes = make_attestation_object(&auth_data_bytes);
    let attestation_object_b64 = URL_SAFE_NO_PAD.encode(&attestation_object_bytes);

    let reg_response = AuthenticatorAttestationResponse {
        client_data_json: client_data_json_b64,
        attestation_object: attestation_object_b64,
    };

    let reg_result = rp
        .verify_registration(RP_ID, ORIGIN, &reg_challenge, &reg_response, USER_ID.to_vec())
        .context("registration verification failed")?;

    println!("   Registration PASSED");
    println!(
        "   Stored credential ID: {}",
        URL_SAFE_NO_PAD.encode(&reg_result.credential.id)
    );
    println!(
        "   Attestation type: {:?}",
        reg_result.attestation_type
    );
    println!(
        "   Initial sign count: {}\n",
        reg_result.credential.sign_count
    );

    let mut stored_credential = reg_result.credential;

    // ── Step 3: Authentication ceremony (first, valid) ────────────────────────
    println!("── Authentication Ceremony (sign count 1 → 2) ──────────────");

    let auth_challenge = generate_challenge().context("failed to generate challenge")?;
    println!(
        "   RP issues challenge: {}",
        URL_SAFE_NO_PAD.encode(&auth_challenge.bytes)
    );

    let auth_response = make_auth_response(
        &key_pair,
        &rng,
        &auth_challenge.bytes,
        RP_ID,
        ORIGIN,
        2, // sign count incremented from 1 to 2
    )?;

    let auth_result = rp
        .verify_authentication(
            &stored_credential,
            ORIGIN,
            &auth_challenge,
            &auth_response,
        )
        .context("first authentication failed")?;

    println!("   Authentication PASSED");
    println!("   User verified flag: {}", auth_result.user_verified);
    println!("   New sign count: {}", auth_result.new_sign_count);

    // Update stored sign count — caller's responsibility in a real system
    stored_credential.sign_count = auth_result.new_sign_count;
    println!("   Updated stored sign count to {}\n", stored_credential.sign_count);

    // ── Step 4: Replay attack demonstration ───────────────────────────────────
    println!("── Replay Attack Demonstration ─────────────────────────────");
    println!("   Attacker replays the previous sign count (2) — should be rejected.");

    let replay_challenge = generate_challenge().context("failed to generate challenge")?;
    let replay_response = make_auth_response(
        &key_pair,
        &rng,
        &replay_challenge.bytes,
        RP_ID,
        ORIGIN,
        2, // same sign count — this is the attack
    )?;

    match rp.verify_authentication(
        &stored_credential,
        ORIGIN,
        &replay_challenge,
        &replay_response,
    ) {
        Err(passforge::PassforgeError::SignCountInvalid { stored, received }) => {
            println!(
                "   Replay attack REJECTED (stored={stored}, received={received})"
            );
            println!("   The authenticator might be cloned — revoke the credential.");
        }
        Ok(_) => panic!("BUG: replay attack should have been rejected!"),
        Err(e) => return Err(e.into()),
    }

    println!("\n── All checks passed. Demo complete. ───────────────────────");
    Ok(())
}

// ─── Authenticator simulation helpers ─────────────────────────────────────────

/// Build a `clientDataJSON` string as a real browser would produce it.
fn make_client_data_json(type_: &str, challenge: &[u8], origin: &str) -> String {
    let challenge_b64 = URL_SAFE_NO_PAD.encode(challenge);
    format!(
        r#"{{"type":"{type_}","challenge":"{challenge_b64}","origin":"{origin}","crossOrigin":false}}"#
    )
}

/// Build a raw authenticator data buffer.
///
/// Layout: rpIdHash (32) | flags (1) | signCount (4) | attestedCredentialData (if AT set)
fn make_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    // (credential_id, public_key_uncompressed_point) — present when AT flag is set
    cred_data: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let rp_id_hash = passforge::crypto::sha256(rp_id.as_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(&rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((cred_id, pk_bytes)) = cred_data {
        // aaguid: 16 zero bytes (no AAGUID for this simulated authenticator)
        out.extend_from_slice(&[0u8; 16]);

        // credentialIdLength: big-endian u16
        let id_len = cred_id.len() as u16;
        out.extend_from_slice(&id_len.to_be_bytes());

        // credentialId
        out.extend_from_slice(cred_id);

        // credentialPublicKey: COSE_Key encoded as CBOR
        let cose_bytes = encode_cose_key(pk_bytes);
        out.extend_from_slice(&cose_bytes);
    }

    out
}

/// Encode a P-256 uncompressed point (0x04 || x || y) as a COSE_Key CBOR map.
fn encode_cose_key(uncompressed_point: &[u8]) -> Vec<u8> {
    assert_eq!(uncompressed_point.len(), 65, "expected 0x04 || x(32) || y(32)");
    assert_eq!(uncompressed_point[0], 0x04, "expected uncompressed point");

    let x = uncompressed_point[1..33].to_vec();
    let y = uncompressed_point[33..65].to_vec();

    let cose_key = Value::Map(vec![
        // kty: 2 (EC2)
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        // alg: -7 (ES256)
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
        // crv: 1 (P-256)
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        // x coordinate
        (Value::Integer((-2i64).into()), Value::Bytes(x)),
        // y coordinate
        (Value::Integer((-3i64).into()), Value::Bytes(y)),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&cose_key, &mut buf).expect("CBOR encoding should not fail");
    buf
}

/// Build a CBOR attestation object with "none" attestation.
fn make_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let att_obj = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("none".to_string()),
        ),
        (
            Value::Text("attStmt".to_string()),
            Value::Map(vec![]),
        ),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);

    let mut buf = Vec::new();
    ciborium::into_writer(&att_obj, &mut buf).expect("CBOR encoding should not fail");
    buf
}

/// Build a complete `AuthenticatorAssertionResponse` using the given keypair.
fn make_auth_response(
    key_pair: &EcdsaKeyPair,
    rng: &SystemRandom,
    challenge: &[u8],
    rp_id: &str,
    origin: &str,
    sign_count: u32,
) -> Result<AuthenticatorAssertionResponse> {
    // clientDataJSON
    let client_data_str = make_client_data_json("webauthn.get", challenge, origin);
    let client_data_bytes = client_data_str.as_bytes();
    let client_data_json_b64 = URL_SAFE_NO_PAD.encode(client_data_bytes);

    // authenticatorData (no attested credential data during authentication)
    let auth_data_bytes = make_authenticator_data(
        rp_id,
        0x01, // flags: UP=1 only
        sign_count,
        None,
    );
    let authenticator_data_b64 = URL_SAFE_NO_PAD.encode(&auth_data_bytes);

    // Compute clientDataHash = SHA-256(clientDataJSON)
    let client_data_hash = passforge::crypto::sha256(client_data_bytes);

    // The signed message is: authenticatorData || clientDataHash
    let mut signed_data = auth_data_bytes.clone();
    signed_data.extend_from_slice(&client_data_hash);

    // Sign with the private key (ring internally hashes with SHA-256)
    let sig = key_pair
        .sign(rng, &signed_data)
        .map_err(|e| anyhow::anyhow!("ECDSA signing failed: {e}"))?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    Ok(AuthenticatorAssertionResponse {
        client_data_json: client_data_json_b64,
        authenticator_data: authenticator_data_b64,
        signature: signature_b64,
        user_handle: None,
    })
}
