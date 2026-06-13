//! One-shot test-vector generator.
//!
//! Run with: `cargo run --example generate_vectors`
//!
//! Writes deterministic test fixtures to tests/vectors/. The files are checked
//! in to git; this binary only needs to be re-run if the fixture format changes.
//! The simulation approach mirrors examples/demo.rs but captures every
//! intermediate base64url value for use in integration tests.

use std::fs;
use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::value::Value;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::json;

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost";
const USER_ID: &[u8] = b"test-user-vector";

fn main() {
    let out_dir = Path::new("tests/vectors");
    fs::create_dir_all(out_dir).expect("create tests/vectors/");

    let rng = SystemRandom::new();

    // Generate a P-256 keypair (simulated authenticator).
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .expect("generate pkcs8");
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .expect("load key pair");
    let public_key_bytes = key_pair.public_key().as_ref().to_vec(); // 65-byte uncompressed

    // Random credential ID.
    let mut cred_id = vec![0u8; 16];
    rng.fill(&mut cred_id).expect("fill cred_id");

    // Fixed challenge bytes (stable across runs).
    let reg_challenge = vec![
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let auth_challenge = vec![
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
        0xbf, 0xc0,
    ];

    // ── Registration vector ───────────────────────────────────────────────────

    let reg_client_data_json =
        make_client_data_json_bytes("webauthn.create", &reg_challenge, ORIGIN);
    let reg_auth_data = make_authenticator_data(
        RP_ID,
        0x41, // UP + AT
        0,
        Some((&cred_id, &public_key_bytes)),
    );
    let attestation_object = make_attestation_object(&reg_auth_data);

    let cred_id_hex: String = cred_id.iter().map(|b| format!("{b:02x}")).collect();

    let reg_vec = json!({
        "description": "Simulated P-256 authenticator, localhost, registration",
        "rp_id": RP_ID,
        "origin": ORIGIN,
        "user_id_hex": hex(&USER_ID.to_vec()),
        "challenge_b64": URL_SAFE_NO_PAD.encode(&reg_challenge),
        "client_data_json_b64": URL_SAFE_NO_PAD.encode(&reg_client_data_json),
        "attestation_object_b64": URL_SAFE_NO_PAD.encode(&attestation_object),
        "expected_credential_id_hex": cred_id_hex,
        "expected_sign_count": 0
    });

    let reg_path = out_dir.join("registration.json");
    fs::write(
        &reg_path,
        serde_json::to_string_pretty(&reg_vec).unwrap() + "\n",
    )
    .expect("write registration.json");
    println!("Wrote {}", reg_path.display());

    // ── Authentication vector ─────────────────────────────────────────────────

    let auth_client_data_json =
        make_client_data_json_bytes("webauthn.get", &auth_challenge, ORIGIN);
    let auth_auth_data = make_authenticator_data(RP_ID, 0x01, 1, None);

    let client_data_hash = webauthn::crypto::sha256(&auth_client_data_json);
    let mut signed_data = auth_auth_data.clone();
    signed_data.extend_from_slice(&client_data_hash);
    let sig = key_pair.sign(&rng, &signed_data).expect("sign");

    // Derive the stored public key coordinates from the 65-byte uncompressed point.
    let pk_x = public_key_bytes[1..33].to_vec();
    let pk_y = public_key_bytes[33..65].to_vec();

    let auth_vec = json!({
        "description": "Simulated P-256 authenticator, localhost, authentication",
        "rp_id": RP_ID,
        "origin": ORIGIN,
        "challenge_b64": URL_SAFE_NO_PAD.encode(&auth_challenge),
        "client_data_json_b64": URL_SAFE_NO_PAD.encode(&auth_client_data_json),
        "authenticator_data_b64": URL_SAFE_NO_PAD.encode(&auth_auth_data),
        "signature_b64": URL_SAFE_NO_PAD.encode(sig.as_ref()),
        "credential_id_hex": cred_id_hex,
        "public_key_x_b64": URL_SAFE_NO_PAD.encode(&pk_x),
        "public_key_y_b64": URL_SAFE_NO_PAD.encode(&pk_y),
        "stored_sign_count": 0,
        "expected_sign_count": 1
    });

    let auth_path = out_dir.join("authentication.json");
    fs::write(
        &auth_path,
        serde_json::to_string_pretty(&auth_vec).unwrap() + "\n",
    )
    .expect("write authentication.json");
    println!("Wrote {}", auth_path.display());

    println!("Done.");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn make_client_data_json_bytes(type_: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    let b64 = URL_SAFE_NO_PAD.encode(challenge);
    format!(r#"{{"type":"{type_}","challenge":"{b64}","origin":"{origin}","crossOrigin":false}}"#)
        .into_bytes()
}

fn make_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    cred_data: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let rp_hash = webauthn::crypto::sha256(rp_id.as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&rp_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    if let Some((cred_id, pk)) = cred_data {
        out.extend_from_slice(&[0u8; 16]); // aaguid
        out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        out.extend_from_slice(cred_id);
        out.extend_from_slice(&encode_cose_key(pk));
    }
    out
}

fn encode_cose_key(uncompressed: &[u8]) -> Vec<u8> {
    let x = uncompressed[1..33].to_vec();
    let y = uncompressed[33..65].to_vec();
    let cose = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())),
        (Value::Integer(3i64.into()), Value::Integer((-7i64).into())),
        (Value::Integer((-1i64).into()), Value::Integer(1i64.into())),
        (Value::Integer((-2i64).into()), Value::Bytes(x)),
        (Value::Integer((-3i64).into()), Value::Bytes(y)),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&cose, &mut buf).expect("cbor encode");
    buf
}

fn make_attestation_object(auth_data: &[u8]) -> Vec<u8> {
    let obj = Value::Map(vec![
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
    ciborium::into_writer(&obj, &mut buf).expect("cbor encode");
    buf
}
