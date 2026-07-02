//! Integration tests for the full WebAuthn registration + authentication pipeline.
//!
//! These tests simulate both the authenticator (key generation, signing) and the
//! relying party (webauthn library) to exercise the complete ceremony flows.
//!
//! All wire-type fields use raw bytes (not base64url), matching the updated API
//! where base64url decoding is the caller's responsibility.

mod helpers;

use ciborium::value::Value;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use webauthn::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, Challenge, RelyingParty,
    WebAuthnError,
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
        origin: &str,
        rp_id: &str,
        flags: u8,
        sign_count: u32,
    ) -> AuthenticatorAttestationResponse {
        let client_data_json = make_client_data_json_bytes("webauthn.create", challenge, origin);
        let auth_data = make_authenticator_data(
            rp_id,
            flags,
            sign_count,
            Some((&self.cred_id, &self.public_key_bytes)),
        );
        let att_obj = make_attestation_object(&auth_data, "none");

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
        ORIGIN,
        RP_ID,
        0x41, // UP + AT
        1,
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
        ORIGIN,
        RP_ID,
        0x45, // UP + UV + AT
        0,
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
        ORIGIN,
        RP_ID,
        0x41,
        0, // counter-less authenticator registered with 0
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
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
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
    let err = rp.verify_authentication(&credential, &ch, &r).unwrap_err();
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
    let err = rp.verify_authentication(&credential, &ch, &r).unwrap_err();
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
    // Use "webauthn.get" (wrong type for registration) — constructed inline so
    // the normal helper (which always uses "webauthn.create") stays narrow.
    let client_data_json = make_client_data_json_bytes("webauthn.get", &challenge.bytes, ORIGIN);
    let auth_data = make_authenticator_data(
        RP_ID,
        0x41,
        1,
        Some((&fixture.cred_id, &fixture.public_key_bytes)),
    );
    let response = AuthenticatorAttestationResponse {
        client_data_json,
        attestation_object: make_attestation_object(&auth_data, "none"),
    };
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
    let response =
        fixture.make_registration_response(&wrong_challenge.bytes, ORIGIN, RP_ID, 0x41, 1);
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
    let response =
        fixture.make_registration_response(&challenge.bytes, "https://evil.com", RP_ID, 0x41, 1);
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
    let response =
        fixture.make_registration_response(&challenge.bytes, ORIGIN, "evil.com", 0x41, 1);
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
        ORIGIN,
        RP_ID,
        0x40, // AT set, UP NOT set
        1,
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
    // Use fmt="packed" with an empty attStmt — constructed inline so the
    // normal helper (which always uses fmt="none") stays narrow.
    let client_data_json = make_client_data_json_bytes("webauthn.create", &challenge.bytes, ORIGIN);
    let auth_data = make_authenticator_data(
        RP_ID,
        0x41,
        1,
        Some((&fixture.cred_id, &fixture.public_key_bytes)),
    );
    let response = AuthenticatorAttestationResponse {
        client_data_json,
        attestation_object: make_attestation_object(&auth_data, "packed"),
    };
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
    let client_data_json = make_client_data_json_bytes("webauthn.create", &challenge.bytes, ORIGIN);
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

    let response =
        fixture.make_registration_response(&expired_challenge.bytes, ORIGIN, RP_ID, 0x41, 1);
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
    let response = fixture.make_auth_response_flags(&challenge.bytes, ORIGIN, RP_ID, 2, 0x00);

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

// ─── Backup Eligibility / Backup State (BE / BS) flag tests ──────────────────

#[test]
fn default_rp_accepts_backup_eligible_credential() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let ch = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &ch.bytes, ORIGIN, RP_ID, 0x49, // UP + AT + BE
        1,
    );
    let result = rp.verify_registration(&ch, &response, b"uid").unwrap();
    assert!(result.backup_eligible);
    assert!(!result.backup_state);
}

#[test]
fn default_rp_accepts_non_backup_eligible_credential() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let ch = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &ch.bytes, ORIGIN, RP_ID, 0x41, // UP + AT (no BE)
        1,
    );
    let result = rp.verify_registration(&ch, &response, b"uid").unwrap();
    assert!(!result.backup_eligible);
    assert!(!result.backup_state);
}

#[test]
fn require_backup_eligible_rejects_non_be_at_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").require_backup_eligible(true);
    let fixture = Fixture::new();

    let ch = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &ch.bytes, ORIGIN, RP_ID, 0x41, // UP + AT — no BE
        1,
    );
    let err = rp.verify_registration(&ch, &response, b"uid").unwrap_err();
    assert!(matches!(err, WebAuthnError::BackupEligibilityRequired));
}

#[test]
fn require_backup_eligible_accepts_be_at_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").require_backup_eligible(true);
    let fixture = Fixture::new();

    let ch = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &ch.bytes, ORIGIN, RP_ID, 0x49, // UP + AT + BE
        1,
    );
    rp.verify_registration(&ch, &response, b"uid").unwrap();
}

#[test]
fn reject_backup_eligible_rejects_be_at_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").reject_backup_eligible(true);
    let fixture = Fixture::new();

    let ch = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &ch.bytes, ORIGIN, RP_ID, 0x49, // UP + AT + BE
        1,
    );
    let err = rp.verify_registration(&ch, &response, b"uid").unwrap_err();
    assert!(matches!(err, WebAuthnError::BackupEligibleNotAllowed));
}

#[test]
fn reject_backup_eligible_accepts_non_be_at_registration() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").reject_backup_eligible(true);
    let fixture = Fixture::new();

    let ch = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &ch.bytes, ORIGIN, RP_ID, 0x41, // UP + AT — no BE
        1,
    );
    rp.verify_registration(&ch, &response, b"uid").unwrap();
}

#[test]
fn require_backup_eligible_rejects_non_be_at_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").require_backup_eligible(true);
    let fixture = Fixture::new();
    // Register succeeds because we use BE flags.
    let credential = {
        let ch = Challenge::new().unwrap();
        let r = fixture.make_registration_response(&ch.bytes, ORIGIN, RP_ID, 0x49, 1);
        rp.verify_registration(&ch, &r, b"uid").unwrap().credential
    };

    // Authenticate without BE — policy should reject it.
    let ch = Challenge::new().unwrap();
    let response = fixture.make_auth_response_flags(&ch.bytes, ORIGIN, RP_ID, 2, 0x01); // UP only
    let err = rp
        .verify_authentication(&credential, &ch, &response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::BackupEligibilityRequired));
}

#[test]
fn require_backup_eligible_accepts_be_at_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").require_backup_eligible(true);
    let fixture = Fixture::new();
    let credential = {
        let ch = Challenge::new().unwrap();
        let r = fixture.make_registration_response(&ch.bytes, ORIGIN, RP_ID, 0x49, 1);
        rp.verify_registration(&ch, &r, b"uid").unwrap().credential
    };

    let ch = Challenge::new().unwrap();
    let response = fixture.make_auth_response_flags(&ch.bytes, ORIGIN, RP_ID, 2, 0x09); // UP + BE
    rp.verify_authentication(&credential, &ch, &response)
        .unwrap();
}

#[test]
fn reject_backup_eligible_rejects_be_at_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").reject_backup_eligible(true);
    let fixture = Fixture::new();
    let credential = {
        let ch = Challenge::new().unwrap();
        let r = fixture.make_registration_response(&ch.bytes, ORIGIN, RP_ID, 0x41, 1);
        rp.verify_registration(&ch, &r, b"uid").unwrap().credential
    };

    let ch = Challenge::new().unwrap();
    let response = fixture.make_auth_response_flags(&ch.bytes, ORIGIN, RP_ID, 2, 0x09); // UP + BE
    let err = rp
        .verify_authentication(&credential, &ch, &response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::BackupEligibleNotAllowed));
}

#[test]
fn reject_backup_eligible_accepts_non_be_at_authentication() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").reject_backup_eligible(true);
    let fixture = Fixture::new();
    let credential = {
        let ch = Challenge::new().unwrap();
        let r = fixture.make_registration_response(&ch.bytes, ORIGIN, RP_ID, 0x41, 1);
        rp.verify_registration(&ch, &r, b"uid").unwrap().credential
    };

    let ch = Challenge::new().unwrap();
    let response = fixture.make_auth_response_flags(&ch.bytes, ORIGIN, RP_ID, 2, 0x01); // UP only
    rp.verify_authentication(&credential, &ch, &response)
        .unwrap();
}

#[test]
fn authentication_result_exposes_backup_state() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = {
        let ch = Challenge::new().unwrap();
        let r = fixture.make_registration_response(
            &ch.bytes, ORIGIN, RP_ID, 0x49, // UP + AT + BE
            1,
        );
        rp.verify_registration(&ch, &r, b"uid").unwrap().credential
    };

    let ch = Challenge::new().unwrap();
    // 0x19 = UP (0x01) + BE (0x08) + BS (0x10)
    let response = fixture.make_auth_response_flags(&ch.bytes, ORIGIN, RP_ID, 2, 0x19);
    let result = rp
        .verify_authentication(&credential, &ch, &response)
        .unwrap();
    assert!(result.backup_eligible);
    assert!(result.backup_state);
}

#[test]
fn rejects_backup_eligibility_change_at_authentication() {
    // Register with BE=false. Authenticate with BE=true.
    // BE is immutable — the mismatch must be detected and rejected.
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let reg_ch = Challenge::new().unwrap();
    let reg_response = fixture.make_registration_response(
        &reg_ch.bytes,
        ORIGIN,
        RP_ID,
        0x41, // UP + AT — BE not set → backup_eligible: false stored
        1,
    );
    let credential = rp
        .verify_registration(&reg_ch, &reg_response, b"uid")
        .unwrap()
        .credential;
    assert!(!credential.backup_eligible);

    let auth_ch = Challenge::new().unwrap();
    // flags 0x09 = UP (0x01) + BE (0x08) — authenticator now claims BE=true
    let auth_response = fixture.make_auth_response_flags(&auth_ch.bytes, ORIGIN, RP_ID, 2, 0x09);
    let err = rp
        .verify_authentication(&credential, &auth_ch, &auth_response)
        .unwrap_err();
    assert!(
        matches!(err, WebAuthnError::BackupEligibilityChanged),
        "expected BackupEligibilityChanged, got {err:?}"
    );
}

// ─── Convenience helpers ──────────────────────────────────────────────────────

fn register_credential(rp: &RelyingParty, fixture: &Fixture) -> webauthn::Credential {
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&challenge.bytes, ORIGIN, RP_ID, 0x41, 1);
    rp.verify_registration(&challenge, &response, b"uid")
        .unwrap()
        .credential
}

fn make_client_data_json_bytes(type_: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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

// ─── Test vector tests ────────────────────────────────────────────────────────

#[test]
fn test_registration_vector() {
    let v = helpers::load_registration_vector();
    let rp = RelyingParty::new(&v.rp_id, &v.origin, "Vector RP");

    let challenge = webauthn::Challenge {
        bytes: v.challenge.clone(),
        created_at: std::time::SystemTime::now(),
    };
    let response = webauthn::AuthenticatorAttestationResponse {
        client_data_json: v.client_data_json.clone(),
        attestation_object: v.attestation_object.clone(),
    };

    let result = rp
        .verify_registration(&challenge, &response, &v.user_id)
        .expect("vector registration should verify");

    assert_eq!(
        result.credential.id, v.expected_credential_id,
        "credential ID must match vector"
    );
    assert_eq!(result.credential.sign_count, v.expected_sign_count);
    assert_eq!(result.credential.rp_id, v.rp_id);
}

#[test]
fn test_authentication_vector() {
    let v = helpers::load_authentication_vector();
    let rp = RelyingParty::new(&v.rp_id, &v.origin, "Vector RP");

    let credential = helpers::build_credential_from_auth_vector(&v);
    let challenge = webauthn::Challenge {
        bytes: v.challenge.clone(),
        created_at: std::time::SystemTime::now(),
    };
    let response = webauthn::AuthenticatorAssertionResponse {
        client_data_json: v.client_data_json.clone(),
        authenticator_data: v.authenticator_data.clone(),
        signature: v.signature.clone(),
        user_handle: None,
    };

    let result = rp
        .verify_authentication(&credential, &challenge, &response)
        .expect("vector authentication should verify");

    assert_eq!(result.new_sign_count, v.expected_sign_count);
    assert!(result.user_present);
}

#[test]
fn test_vectors_are_stable() {
    // Run both vector loaders twice and confirm identical output.
    let rv1 = helpers::load_registration_vector();
    let rv2 = helpers::load_registration_vector();
    assert_eq!(rv1.challenge, rv2.challenge);
    assert_eq!(rv1.attestation_object, rv2.attestation_object);
    assert_eq!(rv1.expected_credential_id, rv2.expected_credential_id);

    let av1 = helpers::load_authentication_vector();
    let av2 = helpers::load_authentication_vector();
    assert_eq!(av1.challenge, av2.challenge);
    assert_eq!(av1.authenticator_data, av2.authenticator_data);
    assert_eq!(av1.signature, av2.signature);
    assert_eq!(av1.expected_sign_count, av2.expected_sign_count);
}

// ─── Registration hardening ───────────────────────────────────────────────────

#[test]
fn rejects_registration_with_missing_att_stmt() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let challenge = Challenge::new().unwrap();

    // Build an attestation object that is missing "attStmt".
    let fixture = Fixture::new();
    let auth_data = make_authenticator_data(
        RP_ID,
        0x41,
        0,
        Some((&fixture.cred_id, &fixture.public_key_bytes)),
    );
    let att_obj = {
        let obj = Value::Map(vec![
            (
                Value::Text("fmt".to_string()),
                Value::Text("none".to_string()),
            ),
            (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
            // "attStmt" intentionally absent
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&obj, &mut buf).unwrap();
        buf
    };
    let client_data_json = make_client_data_json_bytes("webauthn.create", &challenge.bytes, ORIGIN);

    let response = webauthn::AuthenticatorAttestationResponse {
        client_data_json,
        attestation_object: att_obj,
    };
    let err = rp
        .verify_registration(&challenge, &response, b"uid")
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::InvalidAttestationObject(ref m) if m.contains("attStmt")));
}

#[test]
fn rejects_registration_auth_data_not_bytes() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let challenge = Challenge::new().unwrap();

    let att_obj = {
        let obj = Value::Map(vec![
            (
                Value::Text("fmt".to_string()),
                Value::Text("none".to_string()),
            ),
            (Value::Text("attStmt".to_string()), Value::Map(vec![])),
            (
                Value::Text("authData".to_string()),
                Value::Text("not bytes".to_string()),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&obj, &mut buf).unwrap();
        buf
    };
    let client_data_json = make_client_data_json_bytes("webauthn.create", &challenge.bytes, ORIGIN);

    let response = webauthn::AuthenticatorAttestationResponse {
        client_data_json,
        attestation_object: att_obj,
    };
    let err = rp
        .verify_registration(&challenge, &response, b"uid")
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::InvalidAttestationObject(_)));
}

#[test]
fn rejects_registration_truncated_auth_data() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();

    // authData with only 10 bytes — too short to contain the required header.
    let short_auth_data = vec![0u8; 10];
    let att_obj = {
        let obj = Value::Map(vec![
            (
                Value::Text("fmt".to_string()),
                Value::Text("none".to_string()),
            ),
            (Value::Text("attStmt".to_string()), Value::Map(vec![])),
            (
                Value::Text("authData".to_string()),
                Value::Bytes(short_auth_data),
            ),
        ]);
        let mut buf = Vec::new();
        ciborium::into_writer(&obj, &mut buf).unwrap();
        buf
    };
    let client_data_json = make_client_data_json_bytes("webauthn.create", &challenge.bytes, ORIGIN);
    let response = webauthn::AuthenticatorAttestationResponse {
        client_data_json,
        attestation_object: att_obj,
    };
    let _ = fixture; // suppress unused warning
    let err = rp
        .verify_registration(&challenge, &response, b"uid")
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::InvalidAuthenticatorData(_)));
}

// ─── Authentication hardening ─────────────────────────────────────────────────

#[test]
fn rejects_sign_count_wrap_around() {
    // stored = u32::MAX, received = 0 — potential counter wrap-around.
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);
    credential.sign_count = u32::MAX;

    let ch = Challenge::new().unwrap();
    let r = fixture.make_auth_response(&ch.bytes, ORIGIN, RP_ID, 0);
    let err = rp.verify_authentication(&credential, &ch, &r).unwrap_err();
    assert!(matches!(
        err,
        WebAuthnError::SignCountInvalid {
            stored,
            received: 0
        }
        if stored == u32::MAX
    ));
}

#[test]
fn authentication_at_flag_set_is_ignored() {
    // AT flag in authenticator data is unusual during authentication but
    // must not cause an error — the AT data section is not parsed for auth.
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let credential = register_credential(&rp, &fixture);

    let ch = Challenge::new().unwrap();
    // flags = UP(0x01) | AT(0x40) — unusual but parseable
    let r = fixture.make_auth_response_flags(&ch.bytes, ORIGIN, RP_ID, 2, 0x41);
    // The AT flag causes attested cred data parsing; since there's no cred
    // data following the 37-byte header, this will error on parsing — but the
    // important thing is it errors gracefully, not panics.
    // If the parse fails, that's an InvalidAuthenticatorData, not a panic.
    let _ = rp.verify_authentication(&credential, &ch, &r);
    // We do NOT assert Ok here — the AT flag with no data is an error.
    // The test verifies no panic occurred.
}

#[test]
fn rejects_authentication_rp_id_hash_mismatch_explicit() {
    // The stored credential's rp_id differs from the authenticator data.
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let mut credential = register_credential(&rp, &fixture);
    credential.rp_id = "different.com".to_string();

    let ch = Challenge::new().unwrap();
    // Auth data is hashed against RP_ID ("example.com"), but stored credential
    // rp_id is "different.com" — rpIdHash check must fail.
    let r = fixture.make_auth_response(&ch.bytes, ORIGIN, RP_ID, 2);
    let err = rp.verify_authentication(&credential, &ch, &r).unwrap_err();
    assert!(matches!(err, WebAuthnError::RpIdHashMismatch));
}

// ─── RS256 tests ──────────────────────────────────────────────────────────────

// RSA 2048-bit test key in PKCS#8 DER format. Same key used in crypto module tests.
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

struct RsaFixture {
    rng: SystemRandom,
    key_pair: ring::rsa::KeyPair,
    cred_id: Vec<u8>,
    n: Vec<u8>,
    e: Vec<u8>,
}

impl RsaFixture {
    fn new() -> Self {
        let key_pair = ring::rsa::KeyPair::from_pkcs8(RSA_PKCS8_DER).unwrap();
        let (n, e) = extract_rsa_components(key_pair.public().as_ref());
        Self {
            rng: SystemRandom::new(),
            key_pair,
            cred_id: vec![0xCDu8; 16],
            n,
            e,
        }
    }

    fn make_registration_response(
        &self,
        challenge: &[u8],
        origin: &str,
        rp_id: &str,
        flags: u8,
        sign_count: u32,
    ) -> AuthenticatorAttestationResponse {
        let client_data_json = make_client_data_json_bytes("webauthn.create", challenge, origin);
        let cose_key = encode_rs256_cose_key(&self.n, &self.e);
        let auth_data =
            make_authenticator_data_raw(rp_id, flags, sign_count, Some((&self.cred_id, &cose_key)));
        let att_obj = make_attestation_object(&auth_data, "none");
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
        use ring::signature::RSA_PKCS1_SHA256;
        let client_data_bytes = make_client_data_json_bytes("webauthn.get", challenge, origin);
        let auth_data = make_authenticator_data_raw(rp_id, 0x01, sign_count, None);
        let client_data_hash = webauthn::crypto::sha256(&client_data_bytes);
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&client_data_hash);
        let mut sig = vec![0u8; self.key_pair.public().modulus_len()];
        self.key_pair
            .sign(&RSA_PKCS1_SHA256, &self.rng, &signed_data, &mut sig)
            .unwrap();
        AuthenticatorAssertionResponse {
            client_data_json: client_data_bytes,
            authenticator_data: auth_data,
            signature: sig,
            user_handle: None,
        }
    }
}

/// Extract RSA (n, e) from ring's RSAPublicKey DER (`SEQUENCE { INTEGER n, INTEGER e }`).
fn extract_rsa_components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pos = 0;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    // Skip SEQUENCE length
    if der[pos] < 0x80 {
        pos += 1;
    } else {
        let extra = (der[pos] & 0x7f) as usize;
        pos += 1 + extra;
    }
    // INTEGER n
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
    let n_start = if der[pos] == 0x00 { pos + 1 } else { pos };
    let n = der[n_start..pos + n_len].to_vec();
    pos += n_len;
    // INTEGER e
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let e_len = der[pos] as usize;
    pos += 1;
    let e = der[pos..pos + e_len].to_vec();
    (n, e)
}

fn encode_rs256_cose_key(n: &[u8], e: &[u8]) -> Vec<u8> {
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

/// Like `make_authenticator_data` but accepts pre-encoded COSE key bytes directly.
fn make_authenticator_data_raw(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    cred_data: Option<(&[u8], &[u8])>, // (cred_id, pre-encoded COSE key CBOR)
) -> Vec<u8> {
    let rp_hash = webauthn::crypto::sha256(rp_id.as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&rp_hash);
    out.push(flags);
    out.extend_from_slice(&sign_count.to_be_bytes());
    if let Some((cred_id, cose_cbor)) = cred_data {
        out.extend_from_slice(&[0u8; 16]); // aaguid
        out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        out.extend_from_slice(cred_id);
        out.extend_from_slice(cose_cbor);
    }
    out
}

#[test]
fn rs256_full_registration_and_authentication_flow() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = RsaFixture::new();

    // Registration
    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let reg_result = rp
        .verify_registration(&reg_challenge, &response, b"rs256-user")
        .expect("RS256 registration should succeed");

    assert_eq!(reg_result.credential.sign_count, 0);
    assert_eq!(reg_result.credential.rp_id, RP_ID);
    assert!(matches!(
        reg_result.credential.public_key,
        webauthn::PublicKey::RS256 { .. }
    ));

    // Authentication
    let mut credential = reg_result.credential;
    let auth_challenge = Challenge::new().unwrap();
    let auth_response = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 1);
    let auth_result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("RS256 authentication should succeed");

    assert_eq!(auth_result.new_sign_count, 1);
    assert!(auth_result.user_present);
    credential.sign_count = auth_result.new_sign_count;
    assert_eq!(credential.sign_count, 1);
}

#[test]
fn rs256_rejects_replay_attack() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = RsaFixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let mut credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let ch1 = Challenge::new().unwrap();
    let r1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 1);
    credential.sign_count = rp
        .verify_authentication(&credential, &ch1, &r1)
        .unwrap()
        .new_sign_count;

    // Replay with same sign count
    let ch2 = Challenge::new().unwrap();
    let r2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 1);
    let err = rp
        .verify_authentication(&credential, &ch2, &r2)
        .unwrap_err();
    assert!(matches!(
        err,
        WebAuthnError::SignCountInvalid {
            stored: 1,
            received: 1
        }
    ));
}

#[test]
fn rs256_rejects_tampered_signature() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = RsaFixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let ch = Challenge::new().unwrap();
    let mut auth_response = fixture.make_auth_response(&ch.bytes, ORIGIN, RP_ID, 1);
    auth_response.signature[10] ^= 0xFF;

    let err = rp
        .verify_authentication(&credential, &ch, &auth_response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
}

#[test]
fn rs256_rejects_signature_over_wrong_message() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = RsaFixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let ch1 = Challenge::new().unwrap();
    let ch2 = Challenge::new().unwrap();

    // Sign ch1 but present with ch2 verification context
    let response_ch1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 1);
    let mut response_ch2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 1);
    response_ch2.signature = response_ch1.signature;

    let err = rp
        .verify_authentication(&credential, &ch2, &response_ch2)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
}

// ─── EdDSA (Ed25519) tests ────────────────────────────────────────────────────

struct EdDsaFixture {
    key_pair: ring::signature::Ed25519KeyPair,
    cred_id: Vec<u8>,
    public_key_bytes: Vec<u8>, // 32-byte raw Ed25519 public key
}

impl EdDsaFixture {
    fn new() -> Self {
        use ring::signature::Ed25519KeyPair;
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        Self {
            key_pair,
            cred_id: vec![0xEFu8; 16],
            public_key_bytes,
        }
    }

    fn make_registration_response(
        &self,
        challenge: &[u8],
        origin: &str,
        rp_id: &str,
        flags: u8,
        sign_count: u32,
    ) -> AuthenticatorAttestationResponse {
        let client_data_json = make_client_data_json_bytes("webauthn.create", challenge, origin);
        let cose_key = encode_eddsa_cose_key(&self.public_key_bytes);
        let auth_data =
            make_authenticator_data_raw(rp_id, flags, sign_count, Some((&self.cred_id, &cose_key)));
        let att_obj = make_attestation_object(&auth_data, "none");
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
        let client_data_bytes = make_client_data_json_bytes("webauthn.get", challenge, origin);
        let auth_data = make_authenticator_data_raw(rp_id, 0x01, sign_count, None);
        let client_data_hash = webauthn::crypto::sha256(&client_data_bytes);
        let mut signed_data = auth_data.clone();
        signed_data.extend_from_slice(&client_data_hash);
        let sig = self.key_pair.sign(&signed_data);
        AuthenticatorAssertionResponse {
            client_data_json: client_data_bytes,
            authenticator_data: auth_data,
            signature: sig.as_ref().to_vec(),
            user_handle: None,
        }
    }
}

fn encode_eddsa_cose_key(public_key: &[u8]) -> Vec<u8> {
    let cose = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(1i64.into())), // kty: OKP
        (Value::Integer(3i64.into()), Value::Integer((-8i64).into())), // alg: EdDSA
        (Value::Integer((-1i64).into()), Value::Integer(6i64.into())), // crv: Ed25519
        (
            Value::Integer((-2i64).into()),
            Value::Bytes(public_key.to_vec()),
        ), // x: raw public key
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&cose, &mut buf).unwrap();
    buf
}

#[test]
fn eddsa_full_registration_and_authentication_flow() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = EdDsaFixture::new();

    // Registration
    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let reg_result = rp
        .verify_registration(&reg_challenge, &response, b"eddsa-user")
        .expect("EdDSA registration should succeed");

    assert_eq!(reg_result.credential.sign_count, 0);
    assert_eq!(reg_result.credential.rp_id, RP_ID);
    assert!(matches!(
        reg_result.credential.public_key,
        webauthn::PublicKey::EdDSA(_)
    ));

    // Authentication
    let mut credential = reg_result.credential;
    let auth_challenge = Challenge::new().unwrap();
    let auth_response = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 1);
    let auth_result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("EdDSA authentication should succeed");

    assert_eq!(auth_result.new_sign_count, 1);
    assert!(auth_result.user_present);
    credential.sign_count = auth_result.new_sign_count;
    assert_eq!(credential.sign_count, 1);
}

#[test]
fn eddsa_rejects_tampered_signature() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = EdDsaFixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let ch = Challenge::new().unwrap();
    let mut auth_response = fixture.make_auth_response(&ch.bytes, ORIGIN, RP_ID, 1);
    auth_response.signature[10] ^= 0xFF;

    let err = rp
        .verify_authentication(&credential, &ch, &auth_response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
}

#[test]
fn eddsa_rejects_replay_attack() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = EdDsaFixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let mut credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let ch1 = Challenge::new().unwrap();
    let r1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 1);
    credential.sign_count = rp
        .verify_authentication(&credential, &ch1, &r1)
        .unwrap()
        .new_sign_count;

    let ch2 = Challenge::new().unwrap();
    let r2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 1);
    let err = rp
        .verify_authentication(&credential, &ch2, &r2)
        .unwrap_err();
    assert!(matches!(
        err,
        WebAuthnError::SignCountInvalid {
            stored: 1,
            received: 1
        }
    ));
}

#[test]
fn eddsa_rejects_signature_over_wrong_message() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = EdDsaFixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let ch1 = Challenge::new().unwrap();
    let ch2 = Challenge::new().unwrap();

    // Sign ch1 but present with ch2 verification context.
    let response_ch1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 1);
    let mut response_ch2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 1);
    response_ch2.signature = response_ch1.signature;

    let err = rp
        .verify_authentication(&credential, &ch2, &response_ch2)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
}

// ─── ES384 (ECDSA P-384 SHA-384) tests ───────────────────────────────────────

struct Es384Fixture {
    rng: ring::rand::SystemRandom,
    key_pair: ring::signature::EcdsaKeyPair,
    cred_id: Vec<u8>,
    public_key_bytes: Vec<u8>, // 97-byte uncompressed P-384 point
}

impl Es384Fixture {
    fn new() -> Self {
        use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_ASN1_SIGNING};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let public_key_bytes = key_pair.public_key().as_ref().to_vec();
        Self {
            rng,
            key_pair,
            cred_id: vec![0xCDu8; 16],
            public_key_bytes,
        }
    }

    fn make_registration_response(
        &self,
        challenge: &[u8],
        origin: &str,
        rp_id: &str,
        flags: u8,
        sign_count: u32,
    ) -> AuthenticatorAttestationResponse {
        let client_data_json = make_client_data_json_bytes("webauthn.create", challenge, origin);
        let cose_key = encode_es384_cose_key(&self.public_key_bytes);
        let auth_data =
            make_authenticator_data_raw(rp_id, flags, sign_count, Some((&self.cred_id, &cose_key)));
        let att_obj = make_attestation_object(&auth_data, "none");
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
        let client_data_bytes = make_client_data_json_bytes("webauthn.get", challenge, origin);
        let auth_data = make_authenticator_data_raw(rp_id, 0x01, sign_count, None);
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

fn encode_es384_cose_key(uncompressed_point: &[u8]) -> Vec<u8> {
    // P-384 uncompressed point: 0x04 || x (48 bytes) || y (48 bytes) = 97 bytes total.
    assert_eq!(
        uncompressed_point.len(),
        97,
        "expected 0x04 || x(48) || y(48)"
    );
    let x = uncompressed_point[1..49].to_vec();
    let y = uncompressed_point[49..97].to_vec();
    let cose = Value::Map(vec![
        (Value::Integer(1i64.into()), Value::Integer(2i64.into())), // kty: EC2
        (Value::Integer(3i64.into()), Value::Integer((-35i64).into())), // alg: ES384
        (Value::Integer((-1i64).into()), Value::Integer(2i64.into())), // crv: P-384
        (Value::Integer((-2i64).into()), Value::Bytes(x)),          // x
        (Value::Integer((-3i64).into()), Value::Bytes(y)),          // y
    ]);
    let mut buf = Vec::new();
    ciborium::into_writer(&cose, &mut buf).unwrap();
    buf
}

#[test]
fn es384_full_registration_and_authentication_flow() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Es384Fixture::new();

    // Registration
    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let reg_result = rp
        .verify_registration(&reg_challenge, &response, b"es384-user")
        .expect("ES384 registration should succeed");

    assert_eq!(reg_result.credential.sign_count, 0);
    assert_eq!(reg_result.credential.rp_id, RP_ID);
    assert!(matches!(
        reg_result.credential.public_key,
        webauthn::PublicKey::ES384 { .. }
    ));

    // Authentication
    let mut credential = reg_result.credential;
    let auth_challenge = Challenge::new().unwrap();
    let auth_response = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 1);
    let auth_result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("ES384 authentication should succeed");

    assert_eq!(auth_result.new_sign_count, 1);
    assert!(auth_result.user_present);
    credential.sign_count = auth_result.new_sign_count;
    assert_eq!(credential.sign_count, 1);
}

#[test]
fn es384_rejects_tampered_signature() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Es384Fixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let ch = Challenge::new().unwrap();
    let mut auth_response = fixture.make_auth_response(&ch.bytes, ORIGIN, RP_ID, 1);
    auth_response.signature[10] ^= 0xFF;

    let err = rp
        .verify_authentication(&credential, &ch, &auth_response)
        .unwrap_err();
    assert!(matches!(err, WebAuthnError::SignatureVerificationFailed));
}

#[test]
fn es384_rejects_replay_attack() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Es384Fixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let mut credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let ch1 = Challenge::new().unwrap();
    let r1 = fixture.make_auth_response(&ch1.bytes, ORIGIN, RP_ID, 1);
    credential.sign_count = rp
        .verify_authentication(&credential, &ch1, &r1)
        .unwrap()
        .new_sign_count;

    let ch2 = Challenge::new().unwrap();
    let r2 = fixture.make_auth_response(&ch2.bytes, ORIGIN, RP_ID, 1);
    let err = rp
        .verify_authentication(&credential, &ch2, &r2)
        .unwrap_err();
    assert!(matches!(
        err,
        WebAuthnError::SignCountInvalid {
            stored: 1,
            received: 1
        }
    ));
}

// ─── No-panic fuzz tests ──────────────────────────────────────────────────────

#[test]
fn no_panic_on_random_registration_input() {
    use webauthn::{AuthenticatorAttestationResponse, Challenge};

    let rp = RelyingParty::new(RP_ID, ORIGIN, "Fuzz RP");

    // Deterministic pseudo-random using a simple LCG so the test is reproducible.
    let mut state: u64 = 0xDEAD_BEEF_CAFE_1234;
    let mut next = move || -> u8 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u8
    };

    for _ in 0..100 {
        let len = (next() as usize % 1000) + 1;
        let garbage: Vec<u8> = (0..len).map(|_| next()).collect();

        let challenge = Challenge {
            bytes: vec![0u8; 32],
            created_at: std::time::SystemTime::now(),
        };
        let response = AuthenticatorAttestationResponse {
            client_data_json: garbage.clone(),
            attestation_object: garbage,
        };

        // Must return Err, never panic.
        let _ = rp.verify_registration(&challenge, &response, b"u");
    }
}

#[test]
fn no_panic_on_random_authentication_input() {
    use std::time::SystemTime;
    use webauthn::{AuthenticatorAssertionResponse, Challenge, Credential, PublicKey};

    let rp = RelyingParty::new(RP_ID, ORIGIN, "Fuzz RP");

    let credential = Credential {
        id: vec![0xABu8; 16],
        public_key: PublicKey::ES256 {
            x: vec![0x01u8; 32],
            y: vec![0x02u8; 32],
        },
        sign_count: 0,
        user_id: b"u".to_vec(),
        rp_id: RP_ID.to_string(),
        created_at: SystemTime::now(),
        backup_eligible: false,
        backup_state: false,
    };

    let mut state: u64 = 0x1234_5678_9ABC_DEF0;
    let mut next = move || -> u8 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u8
    };

    for _ in 0..100 {
        let len = (next() as usize % 1000) + 1;
        let garbage: Vec<u8> = (0..len).map(|_| next()).collect();

        let challenge = Challenge {
            bytes: vec![0u8; 32],
            created_at: std::time::SystemTime::now(),
        };
        let response = AuthenticatorAssertionResponse {
            client_data_json: garbage.clone(),
            authenticator_data: garbage.clone(),
            signature: garbage,
            user_handle: None,
        };

        // Must return Err, never panic.
        let _ = rp.verify_authentication(&credential, &challenge, &response);
    }
}

// ─── Apple attestation ───────────────────────────────────────────────────────

#[test]
fn apple_attestation_accepts_valid_cert() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let reg_challenge = Challenge::new().unwrap();
    let client_data_json =
        make_client_data_json_bytes("webauthn.create", &reg_challenge.bytes, ORIGIN);
    let auth_data = make_authenticator_data(
        RP_ID,
        0x41,
        0,
        Some((&fixture.cred_id, &fixture.public_key_bytes)),
    );

    // Compute expected nonce = SHA-256(authData || SHA-256(clientDataJSON))
    let client_data_hash = webauthn::crypto::sha256(&client_data_json);
    let mut nonce_input = auth_data.clone();
    nonce_input.extend_from_slice(&client_data_hash);
    let nonce = webauthn::crypto::sha256(&nonce_input);

    // Synthetic Apple cert: correct nonce + matching credential public key.
    let cert = make_apple_cert(&fixture.public_key_bytes, &nonce);

    // Build attestation object with fmt="apple" and x5c=[cert] in attStmt.
    let att_stmt = Value::Map(vec![(
        Value::Text("x5c".to_string()),
        Value::Array(vec![Value::Bytes(cert)]),
    )]);
    let att_obj_cbor = Value::Map(vec![
        (
            Value::Text("fmt".to_string()),
            Value::Text("apple".to_string()),
        ),
        (Value::Text("attStmt".to_string()), att_stmt),
        (Value::Text("authData".to_string()), Value::Bytes(auth_data)),
    ]);
    let mut attestation_object = Vec::new();
    ciborium::into_writer(&att_obj_cbor, &mut attestation_object).unwrap();

    let response = AuthenticatorAttestationResponse {
        client_data_json,
        attestation_object,
    };

    let result = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .expect("apple attestation with valid cert should succeed");
    assert!(matches!(
        result.attestation_type,
        webauthn::AttestationType::Basic
    ));
}

/// Build a minimal synthetic Apple credential certificate.
///
/// Contains the EC P-256 SPKI structure (for key-match verification) and the
/// Apple nonce extension OID 1.2.840.113635.100.8.2 (for nonce verification).
fn make_apple_cert(pub_key_uncompressed: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
    let spki_prefix: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let apple_oid: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02,
    ];
    let mut cert = vec![0x30u8, 0x82, 0x01, 0x00]; // fake outer SEQUENCE header
    cert.extend_from_slice(spki_prefix);
    cert.extend_from_slice(pub_key_uncompressed); // 65 bytes: 0x04 || x || y
    cert.extend_from_slice(apple_oid);
    // extnValue: OCTET STRING { SEQUENCE { SEQUENCE { OCTET STRING <32 bytes> } } }
    cert.extend_from_slice(&[0x04, 0x26, 0x30, 0x24, 0x30, 0x22, 0x04, 0x20]);
    cert.extend_from_slice(nonce);
    cert
}

// ─── UV flag enforcement tests ────────────────────────────────────────────────

#[test]
fn uv_enforcement_rejects_when_uv_flag_not_set() {
    // RP requires user verification; authenticator only sets UP (not UV).
    let fixture = Fixture::new();
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").require_user_verification(true);

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        ORIGIN,
        RP_ID,
        0x41, // UP + AT
        0,
    );
    let credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let auth_challenge = Challenge::new().unwrap();
    // flags=0x01 means UP only — UV bit (0x04) is cleared.
    let auth_response =
        fixture.make_auth_response_flags(&auth_challenge.bytes, ORIGIN, RP_ID, 1, 0x01);

    let err = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .unwrap_err();
    assert!(
        matches!(err, WebAuthnError::UserNotVerified),
        "expected UserNotVerified, got {err:?}"
    );
}

#[test]
fn uv_enforcement_accepts_when_uv_flag_set() {
    // RP requires user verification; authenticator sets both UP and UV.
    let fixture = Fixture::new();
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").require_user_verification(true);

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        ORIGIN,
        RP_ID,
        0x41, // UP + AT
        0,
    );
    let credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let auth_challenge = Challenge::new().unwrap();
    // flags=0x05 means UP + UV.
    let auth_response =
        fixture.make_auth_response_flags(&auth_challenge.bytes, ORIGIN, RP_ID, 1, 0x05);

    let result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("should accept when UV flag is set");
    assert!(result.user_verified);
}

#[test]
fn uv_not_enforced_by_default_when_flag_absent() {
    // Default RP does not require UV; UP-only responses must still be accepted.
    let fixture = Fixture::new();
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");

    let reg_challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &reg_challenge.bytes,
        ORIGIN,
        RP_ID,
        0x41, // UP + AT
        0,
    );
    let credential = rp
        .verify_registration(&reg_challenge, &response, b"uid")
        .unwrap()
        .credential;

    let auth_challenge = Challenge::new().unwrap();
    let auth_response =
        fixture.make_auth_response_flags(&auth_challenge.bytes, ORIGIN, RP_ID, 1, 0x01); // UP only

    let result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("should accept UP-only response when UV is not required");
    assert!(!result.user_verified);
}

// ─── Algorithm allowlist tests ───────────────────────────────────────────────

#[test]
fn allowlist_empty_accepts_es256() {
    // Default RP (empty allowlist) must still accept ES256.
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    rp.verify_registration(&challenge, &response, b"uid")
        .expect("empty allowlist should accept ES256");
}

#[test]
fn allowlist_es256_only_accepts_es256() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").allowed_algorithms([webauthn::COSE_ES256]);
    let fixture = Fixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    rp.verify_registration(&challenge, &response, b"uid")
        .expect("ES256-only allowlist should accept ES256");
}

#[test]
fn allowlist_es256_only_rejects_rs256() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").allowed_algorithms([webauthn::COSE_ES256]);
    let fixture = RsaFixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    let err = rp
        .verify_registration(&challenge, &response, b"uid")
        .unwrap_err();
    assert!(
        matches!(err, WebAuthnError::UnsupportedAlgorithm(-257)),
        "expected UnsupportedAlgorithm(-257), got {err:?}"
    );
}

#[test]
fn allowlist_rs256_only_accepts_rs256() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").allowed_algorithms([webauthn::COSE_RS256]);
    let fixture = RsaFixture::new();
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    rp.verify_registration(&challenge, &response, b"uid")
        .expect("RS256-only allowlist should accept RS256");
}

#[test]
fn allowlist_es256_and_rs256_accepts_both() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP")
        .allowed_algorithms([webauthn::COSE_ES256, webauthn::COSE_RS256]);

    let es_fixture = Fixture::new();
    let es_challenge = Challenge::new().unwrap();
    let es_response =
        es_fixture.make_registration_response(&es_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    rp.verify_registration(&es_challenge, &es_response, b"uid")
        .expect("ES256+RS256 allowlist should accept ES256");

    let rs_fixture = RsaFixture::new();
    let rs_challenge = Challenge::new().unwrap();
    let rs_response =
        rs_fixture.make_registration_response(&rs_challenge.bytes, ORIGIN, RP_ID, 0x41, 0);
    rp.verify_registration(&rs_challenge, &rs_response, b"uid")
        .expect("ES256+RS256 allowlist should accept RS256");
}

// ─── Extension data tests (§6.1 / §10.5) ─────────────────────────────────────

#[test]
fn registration_with_extension_data_exposes_extensions() {
    // Build auth data with AT + ED flags; append a CBOR extension map after the COSE key.
    let fixture = Fixture::new();
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");

    let cose_cbor = encode_cose_key(&fixture.public_key_bytes);
    // credProps extension: {"rk": true}
    let cred_props = Value::Map(vec![(Value::Text("rk".to_string()), Value::Bool(true))]);
    let ext_map = Value::Map(vec![(
        Value::Text("credProps".to_string()),
        cred_props.clone(),
    )]);
    let mut ext_bytes = Vec::new();
    ciborium::into_writer(&ext_map, &mut ext_bytes).unwrap();

    // aaguid(16) + credentialIdLength(2) + credentialId + COSE key + extension map
    let mut at_section = vec![0u8; 16]; // aaguid
    at_section.extend_from_slice(&(fixture.cred_id.len() as u16).to_be_bytes());
    at_section.extend_from_slice(&fixture.cred_id);
    at_section.extend_from_slice(&cose_cbor);
    at_section.extend_from_slice(&ext_bytes);

    let auth_data = {
        let rp_hash = webauthn::crypto::sha256(RP_ID.as_bytes());
        let mut buf = Vec::new();
        buf.extend_from_slice(&rp_hash);
        buf.push(0xC1); // UP (0x01) | AT (0x40) | ED (0x80)
        buf.extend_from_slice(&1u32.to_be_bytes()); // sign_count
        buf.extend_from_slice(&at_section);
        buf
    };

    let challenge = Challenge::new().unwrap();
    let client_data_json = make_client_data_json_bytes("webauthn.create", &challenge.bytes, ORIGIN);
    let att_obj = make_attestation_object(&auth_data, "none");

    let response = AuthenticatorAttestationResponse {
        client_data_json,
        attestation_object: att_obj,
    };
    let result = rp
        .verify_registration(&challenge, &response, b"uid")
        .expect("registration with extension data should succeed");

    let exts = result.extensions.expect("extensions must be populated");
    assert_eq!(exts.get("credProps"), Some(&cred_props));
}

#[test]
fn authentication_with_extension_data_exposes_extensions() {
    let fixture = Fixture::new();
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");

    // Register first (no extensions during registration).
    let reg_challenge = Challenge::new().unwrap();
    let reg_response =
        fixture.make_registration_response(&reg_challenge.bytes, ORIGIN, RP_ID, 0x41, 1);
    let credential = rp
        .verify_registration(&reg_challenge, &reg_response, b"uid")
        .unwrap()
        .credential;

    // Build assertion auth data with ED flag set and an appid extension.
    let ext_map = Value::Map(vec![(Value::Text("appid".to_string()), Value::Bool(true))]);
    let mut ext_bytes = Vec::new();
    ciborium::into_writer(&ext_map, &mut ext_bytes).unwrap();

    let auth_data_bytes = {
        let rp_hash = webauthn::crypto::sha256(RP_ID.as_bytes());
        let mut buf = Vec::new();
        buf.extend_from_slice(&rp_hash);
        buf.push(0x81); // UP (0x01) | ED (0x80)
        buf.extend_from_slice(&2u32.to_be_bytes()); // sign_count > stored (1)
        buf.extend_from_slice(&ext_bytes);
        buf
    };

    let client_data_bytes =
        make_client_data_json_bytes("webauthn.get", &reg_challenge.bytes, ORIGIN);
    let auth_challenge = Challenge {
        bytes: reg_challenge.bytes.clone(),
        created_at: std::time::SystemTime::now(),
    };
    let client_data_hash = webauthn::crypto::sha256(&client_data_bytes);
    let mut signed_data = auth_data_bytes.clone();
    signed_data.extend_from_slice(&client_data_hash);
    let sig = fixture.key_pair.sign(&fixture.rng, &signed_data).unwrap();

    let auth_response = AuthenticatorAssertionResponse {
        client_data_json: client_data_bytes,
        authenticator_data: auth_data_bytes,
        signature: sig.as_ref().to_vec(),
        user_handle: None,
    };

    let result = rp
        .verify_authentication(&credential, &auth_challenge, &auth_response)
        .expect("authentication with extension data should succeed");

    let exts = result.extensions.expect("extensions must be populated");
    assert_eq!(exts.get("appid"), Some(&Value::Bool(true)));
}

#[test]
fn registration_without_extension_data_has_none_extensions() {
    let fixture = Fixture::new();
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(
        &challenge.bytes,
        ORIGIN,
        RP_ID,
        0x41, // UP + AT, no ED
        1,
    );
    let result = rp
        .verify_registration(&challenge, &response, b"uid")
        .unwrap();
    assert!(result.extensions.is_none());
}

// ─── Single-use challenge enforcement tests ───────────────────────────────────

#[test]
fn single_use_enforcement_disabled_by_default() {
    // Without opt-in, reusing the same challenge bytes must succeed (the caller
    // is responsible for single-use tracking in their session store).
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP");
    let fixture = Fixture::new();

    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&challenge.bytes, ORIGIN, RP_ID, 0x41, 1);
    rp.verify_registration(&challenge, &response, b"uid")
        .expect("first registration should succeed");

    // Same challenge, different fixture (different key/cred_id so it would
    // otherwise be valid) — library must NOT reject it when enforcement is off.
    let fixture2 = Fixture::new();
    let response2 = fixture2.make_registration_response(&challenge.bytes, ORIGIN, RP_ID, 0x41, 1);
    rp.verify_registration(&challenge, &response2, b"uid2")
        .expect("second registration with same challenge should succeed when enforcement is off");
}

#[test]
fn single_use_enforcement_rejects_duplicate_registration_challenge() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").enforce_single_use_challenges(true);
    let fixture = Fixture::new();

    let challenge = Challenge::new().unwrap();
    let response = fixture.make_registration_response(&challenge.bytes, ORIGIN, RP_ID, 0x41, 1);
    rp.verify_registration(&challenge, &response, b"uid")
        .expect("first registration should succeed");

    let fixture2 = Fixture::new();
    let response2 = fixture2.make_registration_response(&challenge.bytes, ORIGIN, RP_ID, 0x41, 1);
    let err = rp
        .verify_registration(&challenge, &response2, b"uid2")
        .unwrap_err();
    assert!(
        matches!(err, WebAuthnError::ChallengePreviouslyUsed),
        "expected ChallengePreviouslyUsed, got {err:?}"
    );
}

#[test]
fn single_use_enforcement_rejects_duplicate_authentication_challenge() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").enforce_single_use_challenges(true);
    let fixture = Fixture::new();
    let credential = {
        let ch = Challenge::new().unwrap();
        let r = fixture.make_registration_response(&ch.bytes, ORIGIN, RP_ID, 0x41, 1);
        rp.verify_registration(&ch, &r, b"uid").unwrap().credential
    };

    let auth_challenge = Challenge::new().unwrap();
    let r1 = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 2);
    let result = rp
        .verify_authentication(&credential, &auth_challenge, &r1)
        .expect("first authentication should succeed");
    let mut credential = credential;
    credential.sign_count = result.new_sign_count;

    let r2 = fixture.make_auth_response(&auth_challenge.bytes, ORIGIN, RP_ID, 3);
    let err = rp
        .verify_authentication(&credential, &auth_challenge, &r2)
        .unwrap_err();
    assert!(
        matches!(err, WebAuthnError::ChallengePreviouslyUsed),
        "expected ChallengePreviouslyUsed, got {err:?}"
    );
}

#[test]
fn single_use_enforcement_allows_distinct_challenges() {
    let rp = RelyingParty::new(RP_ID, ORIGIN, "Test RP").enforce_single_use_challenges(true);
    let fixture = Fixture::new();

    // Two different challenges must both succeed.
    let ch1 = Challenge::new().unwrap();
    let r1 = fixture.make_registration_response(&ch1.bytes, ORIGIN, RP_ID, 0x41, 1);
    rp.verify_registration(&ch1, &r1, b"uid1")
        .expect("first registration with distinct challenge should succeed");

    let fixture2 = Fixture::new();
    let ch2 = Challenge::new().unwrap();
    let r2 = fixture2.make_registration_response(&ch2.bytes, ORIGIN, RP_ID, 0x41, 1);
    rp.verify_registration(&ch2, &r2, b"uid2")
        .expect("second registration with a different challenge should succeed");
}

// ─── Multi-origin tests ───────────────────────────────────────────────────────

#[test]
fn multi_origin_relying_party_accepts_registered_origin() {
    let fixture = Fixture::new();
    let rp = RelyingParty::with_origins(
        RP_ID,
        ["https://example.com", "http://localhost:8080"],
        "Test RP",
    );
    let challenge = Challenge::new().unwrap();
    // Use the second origin in the list.
    let response = fixture.make_registration_response(
        &challenge.bytes,
        "http://localhost:8080",
        RP_ID,
        0x41, // UP + AT flags
        1,
    );
    rp.verify_registration(&challenge, &response, b"test-user")
        .unwrap();
}
