#![no_main]
// Registration ceremony fuzz target.
//
// Exercises the full verify_registration path: clientDataJSON JSON parsing,
// attestationObject CBOR decoding, authenticator data binary parsing, and
// attestation verification. The hot parsing paths are:
//   client_data::parse → authenticator_data::parse → attestation::verify
//
// Input layout (chosen so libFuzzer can independently mutate each field):
//   bytes [0..2]  — LE u16: byte length of client_data_json
//   bytes [2..N]  — client_data_json bytes
//   bytes [N..]   — attestation_object bytes
//
// The challenge is fixed to 32 zero bytes so the seed corpus can supply a
// matching clientDataJSON; the fuzzer then mutates from there.

use libfuzzer_sys::fuzz_target;
use std::time::SystemTime;
use webauthn::{AuthenticatorAttestationResponse, Challenge, RelyingParty};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let cdj_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let rest = &data[2..];
    let cdj_len = cdj_len.min(rest.len());
    let (client_data_json, attestation_object) = rest.split_at(cdj_len);

    let rp = RelyingParty::new("example.com", "https://example.com", "Fuzz RP");
    let challenge = Challenge {
        bytes: vec![0u8; 32],
        created_at: SystemTime::now(),
    };
    let response = AuthenticatorAttestationResponse {
        client_data_json: client_data_json.to_vec(),
        attestation_object: attestation_object.to_vec(),
    };

    // Must never panic — any panic is a bug.
    let _ = rp.verify_registration(&challenge, &response, b"uid");
});
