//! Shared test helpers for vector-based integration tests.

#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::fs;
use std::path::Path;

use webauthn::{Credential, PublicKey};

// ─── Vector structs ───────────────────────────────────────────────────────────

pub struct RegistrationVector {
    pub rp_id: String,
    pub origin: String,
    pub user_id: Vec<u8>,
    pub challenge: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub expected_credential_id: Vec<u8>,
    pub expected_sign_count: u32,
}

pub struct AuthenticationVector {
    pub rp_id: String,
    pub origin: String,
    pub challenge: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub public_key_x: Vec<u8>,
    pub public_key_y: Vec<u8>,
    pub stored_sign_count: u32,
    pub expected_sign_count: u32,
}

// ─── Loaders ─────────────────────────────────────────────────────────────────

pub fn load_registration_vector() -> RegistrationVector {
    let path = Path::new("tests/vectors/registration.json");
    let raw = fs::read_to_string(path).expect("tests/vectors/registration.json must exist");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

    RegistrationVector {
        rp_id: v["rp_id"].as_str().unwrap().to_string(),
        origin: v["origin"].as_str().unwrap().to_string(),
        user_id: hex_to_bytes(v["user_id_hex"].as_str().unwrap()),
        challenge: b64_decode(v["challenge_b64"].as_str().unwrap()),
        client_data_json: b64_decode(v["client_data_json_b64"].as_str().unwrap()),
        attestation_object: b64_decode(v["attestation_object_b64"].as_str().unwrap()),
        expected_credential_id: hex_to_bytes(v["expected_credential_id_hex"].as_str().unwrap()),
        expected_sign_count: v["expected_sign_count"].as_u64().unwrap() as u32,
    }
}

pub fn load_authentication_vector() -> AuthenticationVector {
    let path = Path::new("tests/vectors/authentication.json");
    let raw = fs::read_to_string(path).expect("tests/vectors/authentication.json must exist");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

    AuthenticationVector {
        rp_id: v["rp_id"].as_str().unwrap().to_string(),
        origin: v["origin"].as_str().unwrap().to_string(),
        challenge: b64_decode(v["challenge_b64"].as_str().unwrap()),
        client_data_json: b64_decode(v["client_data_json_b64"].as_str().unwrap()),
        authenticator_data: b64_decode(v["authenticator_data_b64"].as_str().unwrap()),
        signature: b64_decode(v["signature_b64"].as_str().unwrap()),
        credential_id: hex_to_bytes(v["credential_id_hex"].as_str().unwrap()),
        public_key_x: b64_decode(v["public_key_x_b64"].as_str().unwrap()),
        public_key_y: b64_decode(v["public_key_y_b64"].as_str().unwrap()),
        stored_sign_count: v["stored_sign_count"].as_u64().unwrap() as u32,
        expected_sign_count: v["expected_sign_count"].as_u64().unwrap() as u32,
    }
}

// ─── Utilities ────────────────────────────────────────────────────────────────

pub fn hex_to_bytes(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

pub fn b64_decode(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("valid base64url")
}

pub fn build_credential_from_auth_vector(v: &AuthenticationVector) -> Credential {
    use std::time::SystemTime;
    Credential {
        id: v.credential_id.clone(),
        public_key: PublicKey::ES256 {
            x: v.public_key_x.clone(),
            y: v.public_key_y.clone(),
        },
        sign_count: v.stored_sign_count,
        user_id: b"vector-user".to_vec(),
        rp_id: v.rp_id.clone(),
        created_at: SystemTime::now(),
        backup_eligible: false,
    }
}
