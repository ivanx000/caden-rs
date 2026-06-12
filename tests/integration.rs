//! Integration tests for the full WebAuthn registration + authentication pipeline.
//!
//! These tests simulate both the authenticator (key generation, signing) and the
//! relying party (passforge library) to exercise the complete ceremony flows.
//!
//! ## On test vectors
//!
//! The credential data here is generated programmatically using real cryptographic
//! primitives (ring's P-256 ECDSA). This is equivalent to using browser-captured
//! vectors in terms of cryptographic correctness — the paths through the code are
//! identical. The values are not hardcoded because they depend on keys generated
//! fresh per test run; see `make_test_fixture` for the generation logic.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::value::Value;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use passforge::{
    generate_challenge, AuthenticatorAssertionResponse, AuthenticatorAttestationResponse,
    PassforgeError, RelyingParty,
};

// ─── Shared constants ─────────────────────────────────────────────────────────

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

// ─── Test fixture builder ─────────────────────────────────────────────────────

/// Everything needed to run a ceremony pair.
struct Fixture {
    rng: SystemRandom,
    key_pair: EcdsaKeyPair,
    cred_id: Vec<u8>,
    public_key_bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        let cred_id = vec![0xAB; 16];
        Self {
            rng,
            key_pair,
            cred_id,
            public_key_bytes,
        }
    }

    fn make_registration_response(
        &self,
        challenge: &[u8],
        type_str: &str,
        origin: &str,
        rp_id: &str,
        flags: u8,
        sign_count: u32,
        fmt: &str,
    ) -> AuthenticatorAttestationResponse {
        let client_data_json = make_client_data_json(type_str, challenge, origin);
        let client_data_json_b64 = URL_SAFE_NO_PAD.encode(client_data_json.as_bytes());

        let auth_data = make_authenticator_data(
            rp_id,
            flags,
            sign_count,
            Some((&self.cred_id, &self.public_key_bytes)),
        );
        let att_obj = make_attestation_object(&auth_data, fmt);

        AuthenticatorAttestationResponse {
            client_data_json: client_data_json_b64,
            attestation_object: URL_SAFE_NO_PAD.encode(&att_obj),
        }
    }

    fn make_auth_response(
        &self,
        challenge: &[u8],
        origin: &str,
        rp_id: &str,
        sign_count: u32,
    ) -> AuthenticatorAssertionResponse {
        let client_data_str = make_client_data_json("webauthn.get", challenge, origin);
        let client_data_b64 = URL_SAFE_NO_PAD.encode(client_data_str.as_bytes());

        let auth_data = make_authenticator_data(rp_id, 0x01, sign_count, None);
        let auth_data_b64 = URL_SAFE_NO_PAD.encode(&auth_data);

        let client_data_hash = passforge::crypto::sha256(client_data_str.as_bytes());
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&client_data_hash);

        let sig = self.key_pair.sign(&self.rng, &signed_data).unwrap();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

        AuthenticatorAssertionResponse {
            client_data_json: client_data_b64,
            authenticator_data: auth_data_b64,
            signature: sig_b64,
            user_handle: None,
        }
    }
}

// ─── Happy-path integration tests ─────────────────────────────────────────────

#[test]
fn full_registration_and_authentication_flow() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();

    // Registration
    let reg_challenge = generate_challenge().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41, // UP + AT
        1,
        "none",
    );
    let reg_result = rp
        .verify_registration(RP_ID, ORIGIN, &reg_challenge, &response, b"uid".to_vec())
        .expect("registration should succeed");

    assert_eq!(reg_result.credential.sign_count, 1);
    assert_eq!(reg_result.credential.rp_id, RP_ID);
    assert!(matches!(
        reg_result.attestation_type,
        passforge::AttestationType::None
    ));

    // Authentication
    let mut credential = reg_result.credential;
    let auth_challenge = generate_challenge().unwrap();
    let auth_response = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 2);

    let auth_result = rp
        .verify_authentication(&credential, ORIGIN, &auth_challenge, &auth_response)
        .expect("authentication should succeed");

    assert_eq!(auth_result.new_sign_count, 2);
    assert!(!auth_result.user_verified); // UV was not set in flags
    credential.sign_count = auth_result.new_sign_count;
    assert_eq!(credential.sign_count, 2);
}

#[test]
fn authentication_with_uv_flag() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();

    let reg_challenge = generate_challenge().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x45, // UP + UV + AT
        0,
        "none",
    );
    let credential = rp
        .verify_registration(RP_ID, ORIGIN, &reg_challenge, &response, b"uid".to_vec())
        .unwrap()
        .credential;

    let auth_challenge = generate_challenge().unwrap();
    // Build an assertion with UV flag set
    let client_data_str = make_client_data_json("webauthn.get", &auth_challenge.bytes, ORIGIN);
    let auth_data = make_authenticator_data(RP_ID, 0x05, 1, None); // UP + UV
    let client_data_hash = passforge::crypto::sha256(client_data_str.as_bytes());
    let mut signed_data = auth_data.clone();
    signed_data.extend_from_slice(&client_data_hash);
    let sig = fixture.key_pair.sign(&fixture.rng, &signed_data).unwrap();

    let auth_response = AuthenticatorAssertionResponse {
        client_data_json: URL_SAFE_NO_PAD.encode(client_data_str.as_bytes()),
        authenticator_data: URL_SAFE_NO_PAD.encode(&auth_data),
        signature: URL_SAFE_NO_PAD.encode(sig.as_ref()),
        user_handle: None,
    };

    let result = rp
        .verify_authentication(&credential, ORIGIN, &auth_challenge, &auth_response)
        .unwrap();
    assert!(result.user_verified);
}

// ─── Error case tests — every PassforgeError variant ─────────────────────────

#[test]
fn rejects_wrong_type_in_registration() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let challenge = generate_challenge().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.get", // wrong type
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(RP_ID, ORIGIN, &challenge, &response, vec![])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::InvalidClientData(_)));
}

#[test]
fn rejects_challenge_mismatch_on_registration() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let challenge = generate_challenge().unwrap();
    let wrong_challenge = generate_challenge().unwrap();

    // Response is built for `wrong_challenge`, but we verify against `challenge`
    let response = fixture.make_registration_response(
        &wrong_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(RP_ID, ORIGIN, &challenge, &response, vec![])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::ChallengeMismatch));
}

#[test]
fn rejects_origin_mismatch_on_registration() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let challenge = generate_challenge().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        "https://evil.com", // wrong origin in clientDataJSON
        RP_ID,
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(RP_ID, ORIGIN, &challenge, &response, vec![])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::OriginMismatch));
}

#[test]
fn rejects_rp_id_hash_mismatch_on_registration() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let challenge = generate_challenge().unwrap();
    // authenticatorData is built for a DIFFERENT rp_id
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        "evil.com", // wrong RP ID used to build auth data
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(RP_ID, ORIGIN, &challenge, &response, vec![])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::RpIdHashMismatch));
}

#[test]
fn rejects_missing_user_present_flag() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let challenge = generate_challenge().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x40, // AT set, UP NOT set
        1,
        "none",
    );
    let err = rp
        .verify_registration(RP_ID, ORIGIN, &challenge, &response, vec![])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::UserNotPresent));
}

#[test]
fn rejects_unsupported_attestation_format() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let challenge = generate_challenge().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "packed", // not supported
    );
    let err = rp
        .verify_registration(RP_ID, ORIGIN, &challenge, &response, vec![])
        .unwrap_err();
    assert!(matches!(
        err,
        PassforgeError::InvalidAttestationObject(_)
    ));
}

#[test]
fn rejects_invalid_client_data_json() {
    let rp = RelyingParty::new();
    let challenge = generate_challenge().unwrap();
    let response = AuthenticatorAttestationResponse {
        client_data_json: URL_SAFE_NO_PAD.encode(b"not json at all"),
        attestation_object: String::new(),
    };
    let err = rp
        .verify_registration(RP_ID, ORIGIN, &challenge, &response, vec![])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::InvalidClientData(_)));
}

#[test]
fn rejects_invalid_attestation_object_cbor() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let challenge = generate_challenge().unwrap();

    let client_data_json = make_client_data_json("webauthn.create", &challenge.bytes, ORIGIN);
    // 0xFF is a CBOR break code — invalid at the start of a data item.
    let response = AuthenticatorAttestationResponse {
        client_data_json: URL_SAFE_NO_PAD.encode(client_data_json.as_bytes()),
        attestation_object: URL_SAFE_NO_PAD.encode(&[0xFF_u8, 0x00, 0x00]),
    };
    let _ = fixture;
    let err = rp
        .verify_registration(RP_ID, ORIGIN, &challenge, &response, vec![])
        .unwrap_err();
    assert!(matches!(err, PassforgeError::CborDecodeError(_)));
}

#[test]
fn rejects_challenge_mismatch_on_authentication() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();

    let credential = register_credential(&rp, &fixture);

    let real_challenge = generate_challenge().unwrap();
    let wrong_challenge = generate_challenge().unwrap();
    let response = fixture.make_auth_response(&wrong_challenge.bytes, ORIGIN, RP_ID, 2);

    let err = rp
        .verify_authentication(&credential, ORIGIN, &real_challenge, &response)
        .unwrap_err();
    assert!(matches!(err, PassforgeError::ChallengeMismatch));
}

#[test]
fn rejects_origin_mismatch_on_authentication() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = generate_challenge().unwrap();
    let response = fixture.make_auth_response(&challenge.bytes, "https://phishing.com", RP_ID, 2);

    let err = rp
        .verify_authentication(&credential, ORIGIN, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, PassforgeError::OriginMismatch));
}

#[test]
fn rejects_rp_id_hash_mismatch_on_authentication() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = generate_challenge().unwrap();
    // Build authData bound to a different RP ID
    let response = fixture.make_auth_response(&challenge.bytes, ORIGIN, "evil.com", 2);

    let err = rp
        .verify_authentication(&credential, ORIGIN, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, PassforgeError::RpIdHashMismatch));
}

#[test]
fn rejects_signature_verification_failed() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = generate_challenge().unwrap();
    let mut response = fixture.make_auth_response(&challenge.bytes, ORIGIN, RP_ID, 2);

    // Corrupt the signature
    let mut bad_sig = URL_SAFE_NO_PAD.decode(&response.signature).unwrap();
    bad_sig[10] ^= 0xFF;
    response.signature = URL_SAFE_NO_PAD.encode(&bad_sig);

    let err = rp
        .verify_authentication(&credential, ORIGIN, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, PassforgeError::SignatureVerificationFailed));
}

#[test]
fn rejects_replay_attack_same_sign_count() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);

    // First successful authentication
    let ch1 = generate_challenge().unwrap();
    let r1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 2);
    let result = rp.verify_authentication(&credential, ORIGIN, &ch1, &r1).unwrap();
    credential.sign_count = result.new_sign_count;

    // Replay: same sign count (2) that was already consumed
    let ch2 = generate_challenge().unwrap();
    let r2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 2);

    let err = rp
        .verify_authentication(&credential, ORIGIN, &ch2, &r2)
        .unwrap_err();
    assert!(matches!(
        err,
        PassforgeError::SignCountInvalid {
            stored: 2,
            received: 2
        }
    ));
}

#[test]
fn rejects_replay_attack_lower_sign_count() {
    let rp = RelyingParty::new();
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);

    let ch1 = generate_challenge().unwrap();
    let r1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 5);
    credential.sign_count = rp
        .verify_authentication(&credential, ORIGIN, &ch1, &r1)
        .unwrap()
        .new_sign_count;

    // Replay with a lower count
    let ch2 = generate_challenge().unwrap();
    let r2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 3);
    let err = rp
        .verify_authentication(&credential, ORIGIN, &ch2, &r2)
        .unwrap_err();
    assert!(matches!(
        err,
        PassforgeError::SignCountInvalid {
            stored: 5,
            received: 3
        }
    ));
}

#[test]
fn accepts_zero_sign_count_passthrough() {
    // Authenticators that don't implement counters always send 0.
    // The spec says to accept this case (cannot detect clones, but it's allowed).
    let rp = RelyingParty::new();
    let fixture = Fixture::new();

    let reg_challenge = generate_challenge().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        0, // counter-less authenticator
        "none",
    );
    let credential = rp
        .verify_registration(RP_ID, ORIGIN, &reg_challenge, &response, vec![])
        .unwrap()
        .credential;

    let auth_challenge = generate_challenge().unwrap();
    let auth_response = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 0);
    rp.verify_authentication(&credential, ORIGIN, &auth_challenge, &auth_response)
        .expect("zero sign count should be accepted");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Register a credential and return it (convenience for auth-only tests).
fn register_credential(rp: &RelyingParty, fixture: &Fixture) -> passforge::Credential {
    let challenge = generate_challenge().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "none",
    );
    rp.verify_registration(RP_ID, ORIGIN, &challenge, &response, b"uid".to_vec())
        .unwrap()
        .credential
}

fn make_client_data_json(type_: &str, challenge: &[u8], origin: &str) -> String {
    let b64 = URL_SAFE_NO_PAD.encode(challenge);
    format!(r#"{{"type":"{type_}","challenge":"{b64}","origin":"{origin}","crossOrigin":false}}"#)
}

fn make_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    cred_data: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let rp_hash = passforge::crypto::sha256(rp_id.as_bytes());
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
    ciborium::into_writer(&cose, &mut buf).unwrap();
    buf
}

fn make_attestation_object(auth_data: &[u8], fmt: &str) -> Vec<u8> {
    let obj = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text(fmt.to_string()),
        ),
        (Value::Text("attStmt".to_string()), Value::Map(vec![])),
        (
            Value::Text("authData".to_string()),
            Value::Bytes(auth_data.to_vec()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&obj, &mut buf).unwrap();
    buf
}
