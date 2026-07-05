#![no_main]
// Authentication ceremony fuzz target.
//
// Exercises the full verify_authentication path: clientDataJSON JSON parsing,
// authenticatorData binary parsing, and signature verification dispatch.
// The hot parsing paths are:
//   client_data::parse → authenticator_data::parse → crypto::verify_*
//
// Input layout (chosen so libFuzzer can independently mutate each field):
//   bytes [0..2]  — LE u16: byte length of client_data_json
//   bytes [2..4]  — LE u16: byte length of authenticator_data
//   bytes [4..N]  — client_data_json bytes
//   bytes [N..M]  — authenticator_data bytes
//   bytes [M..]   — signature bytes
//
// The stored credential uses a known-invalid P-256 key (point coordinates are
// not on the curve), so verification always fails at the crypto step — but all
// parsing logic up to that point is exercised.
//
// The challenge is fixed to 32 zero bytes; the seed corpus supplies a matching
// clientDataJSON so the fuzzer enters the deeper CBOR/binary parsing paths.

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, SystemTime};
use webauthn::{
    AuthenticatorAssertionResponse, Challenge, Credential, PublicKey, RelyingParty,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    let cdj_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let adl = u16::from_le_bytes([data[2], data[3]]) as usize;
    let rest = &data[4..];

    let cdj_len = cdj_len.min(rest.len());
    let (client_data_json, rest) = rest.split_at(cdj_len);
    let adl = adl.min(rest.len());
    let (authenticator_data, signature) = rest.split_at(adl);

    // A large sign_count so any fuzz-generated counter value will be accepted
    // (we want to reach the signature verification step, not reject early).
    let credential = Credential {
        id: vec![0xABu8; 16],
        public_key: PublicKey::ES256 {
            x: vec![0x01u8; 32],
            y: vec![0x02u8; 32],
        },
        sign_count: 0,
        user_id: b"uid".to_vec(),
        rp_id: "example.com".to_string(),
        // Far in the past so TTL-based challenge checks don't interfere.
        created_at: SystemTime::UNIX_EPOCH + Duration::from_secs(0),
        backup_eligible: false,
        backup_state: false,
    };

    let rp = RelyingParty::new("example.com", "https://example.com", "Fuzz RP");
    let challenge = Challenge {
        bytes: vec![0u8; 32],
        created_at: SystemTime::now(),
    };
    let response = AuthenticatorAssertionResponse {
        client_data_json: client_data_json.to_vec(),
        authenticator_data: authenticator_data.to_vec(),
        signature: signature.to_vec(),
        user_handle: None,
        credential_id: vec![0xABu8; 16],
    };

    // Must never panic — any panic is a bug.
    let _ = rp.verify_authentication(&credential, &challenge, &response);
});
