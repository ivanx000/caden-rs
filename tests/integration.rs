//! Integration tests for the full WebAuthn registration + authentication pipeline.
//!
//! These tests simulate both the authenticator (key generation, signing) and the
//! relying party (webauthn library) to exercise the complete ceremony flows.
//!
//! All wire-type fields use raw bytes (not base64url), matching the updated API
//! where base64url decoding is the caller's responsibility.

use ciborium::value::Value;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use webauthn::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, Challenge, WebAuthnError,
    RelyingParty,
};

// ─── Shared constants ─────────────────────────────────────────────────────────

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

// ─── Test fixture ─────────────────────────────────────────────────────────────

struct Fixture {
    rng: SystemRandom,
    key_pair: EcdsaKeyPair,
    cred_id: Vec<u8>,
    public_key_bytes: Vec<u8>, // 65-byte uncompressed point
}

impl Fixture {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        Self {
            rng,
            key_pair,
            cred_id: vec![0xABu8; 16],
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
        let client_data_json = make_client_data_json_bytes(type_str, challenge, origin);
        let auth_data = make_authenticator_data(
            rp_id,
            flags,
            sign_count,
            Some((&self.cred_id, &self.public_key_bytes)),
        );
        let att_obj = make_attestation_object(&auth_data, fmt);

        AuthenticatorAttestationResponse {
            client_data_json,
            attestation_object: att_obj,
        }
    }

    fn make_auth_response(
        &self,
        challenge: &[u8],
        origin: &str,
        rp_id: &str,
        sign_count: u32,
    ) -> AuthenticatorAssertionResponse {
        self.make_auth_response_flags(challenge, origin, rp_id, sign_count, 0x01)
    }

    fn make_auth_response_flags(
        &self,
        challenge: &[u8],
        origin: &str,
        rp_id: &str,
        sign_count: u32,
        flags: u8,
    ) -> AuthenticatorAssertionResponse {
        let client_data_bytes = make_client_data_json_bytes("webauthn.get", challenge, origin);
        let auth_data = make_authenticator_data(rp_id, flags, sign_count, None);

        let client_data_hash = webauthn::crypto::sha256(&client_data_bytes);
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&client_data_hash);

        let sig = self.key_pair.sign(&self.rng, &signed_data).unwrap();

        AuthenticatorAssertionResponse {
            client_data_json: client_data_bytes,
            authenticator_data: auth_data,
            signature: sig.as_ref().to_vec(),
            user_handle: None,
        }
    }
}

// ─── Happy-path tests — registration ─────────────────────────────────────────

#[test]
fn full_registration_and_authentication_flow() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    // Registration
    let reg_challenge = Challenge::new().unwrap();
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
        .verify_registration(&reg_challenge, &response, b"uid")
        .expect("registration should succeed");

    assert_eq!(reg_result.credential.sign_count, 1);
    assert_eq!(reg_result.credential.rp_id, RP_ID);
    assert!(matches!(
        reg_result.attestation_type,
        webauthn::AttestationType::None
    ));

    // Authentication
    let mut credential = reg_result.credential;
    let auth_challenge = Challenge::new().unwrap();
    let auth_response = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 2);

    let auth_result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("authentication should succeed");

    assert_eq!(auth_result.new_sign_count, 2);
    assert!(auth_result.user_present);
    assert!(!auth_result.user_verified);
    credential.sign_count = auth_result.new_sign_count;
    assert_eq!(credential.sign_count, 2);
}

#[test]
fn authentication_with_uv_flag() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let reg_challenge = Challenge::new().unwrap();
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
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let auth_challenge = Challenge::new().unwrap();
    let auth_response =
        fixture.make_auth_response_flags(&auth_challenge.bytes, ORIGIN, RP_ID, 1, 0x05); // UP + UV

    let result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .unwrap();
    assert!(result.user_present);
    assert!(result.user_verified);
}

// ─── Sign count edge cases ────────────────────────────────────────────────────

#[test]
fn sign_count_both_zero_succeeds() {
    // stored=0, received=0 — authenticator without counter support
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        0, // counter-less authenticator registered with 0
        "none",
    );
    let credential = rp
        .verify_registration(&reg_challenge, &response, &[])
        .unwrap()
        .credential;
    assert_eq!(credential.sign_count, 0);

    let auth_challenge = Challenge::new().unwrap();
    let auth_response = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 0);
    rp.verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("both-zero sign count should be accepted");
}

#[test]
fn sign_count_stored_zero_received_nonzero_succeeds() {
    // stored=0, received=1 — first authentication on a counter-bearing authenticator
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        0,
        "none",
    );
    let credential = rp
        .verify_registration(&reg_challenge, &response, &[])
        .unwrap()
        .credential;

    let auth_challenge = Challenge::new().unwrap();
    let auth_response = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 1);
    let result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("stored=0, received=1 should succeed");
    assert_eq!(result.new_sign_count, 1);
}

#[test]
fn sign_count_strictly_greater_succeeds() {
    // stored=5, received=6 — normal increment
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);
    credential.sign_count = 5;

    let ch = Challenge::new().unwrap();
    let r = fixture.make_auth_response(&ch.bytes, ORIGIN, RP_ID, 6);
    let result = rp
        .verify_authentication(&credential, &ch, &r)
        .expect("stored=5, received=6 should succeed");
    assert_eq!(result.new_sign_count, 6);
}

#[test]
fn sign_count_equal_fails() {
    // stored=5, received=5 — replay / clone indicator
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);
    credential.sign_count = 5;

    let ch = Challenge::new().unwrap();
    let r = fixture.make_auth_response(&ch.bytes, ORIGIN, RP_ID, 5);
    let err = rp
        .verify_authentication(&credential, &ch, &r)
        .unwrap_err();
    assert!(matches!(
        err,
        WebAuthnError::SignCountInvalid {
            stored: 5,
            received: 5
        }
    ));
}

#[test]
fn sign_count_lower_fails() {
    // stored=5, received=4 — clear replay
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);
    credential.sign_count = 5;

    let ch = Challenge::new().unwrap();
    let r = fixture.make_auth_response(&ch.bytes, ORIGIN, RP_ID, 4);
    let err = rp
        .verify_authentication(&credential, &ch, &r)
        .unwrap_err();
    assert!(matches!(
        err,
        WebAuthnError::SignCountInvalid {
            stored: 5,
            received: 4
        }
    ));
}

// ─── Error cases — registration ───────────────────────────────────────────────

#[test]
fn rejects_wrong_type_in_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
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
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::InvalidClientData(_)));
}

#[test]
fn rejects_challenge_mismatch_on_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let wrong_challenge = Challenge::new().unwrap();
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
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::ChallengeMismatch));
}

#[test]
fn rejects_origin_mismatch_on_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        "https://evil.com",
        RP_ID,
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(
        err,
        WebAuthnError::OriginMismatch { expected, got }
        if expected == ORIGIN && got == "https://evil.com"
    ));
}

#[test]
fn rejects_rp_id_hash_mismatch_on_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        "evil.com",
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::RpIdHashMismatch));
}

#[test]
fn rejects_missing_user_present_flag_on_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
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
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::UserNotPresent));
}

#[test]
fn rejects_unsupported_attestation_format() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "packed",
    );
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::InvalidAttestationObject(_)));
}

#[test]
fn rejects_invalid_client_data_json() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let challenge = Challenge::new().unwrap();
    let response = AuthenticatorAttestationResponse {
        client_data_json: b"not json at all".to_vec(),
        attestation_object: vec![],
    };
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::InvalidClientData(_)));
}

#[test]
fn rejects_invalid_attestation_object_cbor() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let challenge = Challenge::new().unwrap();
    let client_data_json =
        make_client_data_json_bytes("webauthn.create", &challenge.bytes, ORIGIN);
    let response = AuthenticatorAttestationResponse {
        client_data_json,
        attestation_object: vec![0xFF, 0x00, 0x00],
    };
    let err = rp
        .verify_registration(&challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::CborDecodeError(_)));
}

#[test]
fn rejects_expired_challenge() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let expired_challenge = Challenge {
        bytes: vec![0u8; 32],
        created_at: std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(600))
            .unwrap(),
    };

    let response = fixture.make_registration_response(
        &expired_challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "none",
    );
    let err = rp
        .verify_registration(&expired_challenge, &response, &[])
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::ChallengeExpired));
}

// ─── Error cases — authentication ─────────────────────────────────────────────

#[test]
fn rejects_challenge_mismatch_on_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let real_challenge = Challenge::new().unwrap();
    let wrong_challenge = Challenge::new().unwrap();
    let response = fixture.make_auth_response(&wrong_challenge.bytes, ORIGIN, RP_ID, 2);

    let err = rp
        .verify_authentication(&credential, &real_challenge, &response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::ChallengeMismatch));
}

#[test]
fn rejects_origin_mismatch_on_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = Challenge::new().unwrap();
    let response = fixture.make_auth_response(&challenge.bytes, "https://phishing.com", RP_ID, 2);

    let err = rp
        .verify_authentication(&credential, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::OriginMismatch { .. }));
}

#[test]
fn rejects_rp_id_hash_mismatch_on_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = Challenge::new().unwrap();
    let response = fixture.make_auth_response(&challenge.bytes, ORIGIN, "evil.com", 2);

    let err = rp
        .verify_authentication(&credential, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::RpIdHashMismatch));
}

#[test]
fn rejects_missing_user_present_flag_on_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = Challenge::new().unwrap();
    // flags=0x00: UP not set
    let response =
        fixture.make_auth_response_flags(&challenge.bytes, ORIGIN, RP_ID, 2, 0x00);

    let err = rp
        .verify_authentication(&credential, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::UserNotPresent));
}

#[test]
fn rejects_tampered_signature() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = Challenge::new().unwrap();
    let mut response = fixture.make_auth_response(&challenge.bytes, ORIGIN, RP_ID, 2);

    response.signature[10] ^= 0xFF;

    let err = rp
        .verify_authentication(&credential, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
}

#[test]
fn rejects_completely_invalid_signature_bytes() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let challenge = Challenge::new().unwrap();
    let mut response = fixture.make_auth_response(&challenge.bytes, ORIGIN, RP_ID, 2);

    response.signature = vec![0xDE, 0xAD, 0xBE, 0xEF]; // not a valid DER signature

    let err = rp
        .verify_authentication(&credential, &challenge, &response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
}

#[test]
fn rejects_signature_over_wrong_data() {
    // A valid signature, but over a different message — simulates a cross-ceremony replay.
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let ch1 = Challenge::new().unwrap();
    let ch2 = Challenge::new().unwrap();

    // Sign challenge 1, present with challenge 2 verification context.
    let response_for_ch1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 2);
    let mut response_for_ch2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 2);

    // Swap in the signature from the ch1 response — wrong message.
    response_for_ch2.signature = response_for_ch1.signature;

    let err = rp
        .verify_authentication(&credential, &ch2, &response_for_ch2)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
}

#[test]
fn rejects_replay_attack_same_sign_count() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);

    let ch1 = Challenge::new().unwrap();
    let r1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 2);
    let result = rp.verify_authentication(&credential, &ch1, &r1).unwrap();
    credential.sign_count = result.new_sign_count;

    let ch2 = Challenge::new().unwrap();
    let r2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 2); // same count

    let err = rp
        .verify_authentication(&credential, &ch2, &r2)
        .unwrap_err();
    assert!(matches!(
        err,
        WebAuthnError::SignCountInvalid {
            stored: 2,
            received: 2
        }
    ));
}

#[test]
fn rejects_replay_attack_lower_sign_count() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);

    let ch1 = Challenge::new().unwrap();
    let r1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 5);
    credential.sign_count = rp
        .verify_authentication(&credential, &ch1, &r1)
        .unwrap()
        .new_sign_count;

    let ch2 = Challenge::new().unwrap();
    let r2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 3);
    let err = rp
        .verify_authentication(&credential, &ch2, &r2)
        .unwrap_err();
    assert!(matches!(
        err,
        WebAuthnError::SignCountInvalid {
            stored: 5,
            received: 3
        }
    ));
}

// ─── Convenience helpers ──────────────────────────────────────────────────────

fn register_credential(rp: &RelyingParty, fixture: &Fixture) -> webauthn::Credential {
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "webauthn.create",
        ORIGIN,
        RP_ID,
        0x41,
        1,
        "none",
    );
    rp.verify_registration(&challenge, &response, b"uid")
        .unwrap()
        .credential
}

fn make_client_data_json_bytes(type_: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let b64 = URL_SAFE_NO_PAD.encode(challenge);
    format!(
        r#"{{"type":"{type_}","challenge":"{b64}","origin":"{origin}","crossOrigin":false}}"#
    )
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
    ciborium::into_writer(&cose, &mut buf).unwrap();
    buf
}

fn make_attestation_object(auth_data: &[u8], fmt: &str) -> Vec<u8> {
    let obj = Value::Map(vec![
        (Value::Text("fmt".to_string()), Value::Text(fmt.to_string())),
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
