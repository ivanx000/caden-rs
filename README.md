[![CI](https://github.com/ivanx000/caden-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/ivanx000/caden-rs/actions/workflows/ci.yml) ![Rust](https://img.shields.io/badge/rust-1.88%2B-orange) ![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

# Caden

A WebAuthn relying-party library written in Rust.

This library implements the server-side ceremony verification logic for both WebAuthn
flows — registration and authentication — following the
[W3C WebAuthn Level 3 specification](https://www.w3.org/TR/webauthn-3/).
It is built as a portfolio project demonstrating practical applied cryptography,
correct protocol implementation, and idiomatic Rust.

---

## What are WebAuthn and Passkeys?

**WebAuthn** (Web Authentication) is a W3C standard that lets users authenticate
to websites using public-key cryptography instead of passwords. When you register,
the authenticator (your phone, laptop, or a hardware key) generates a keypair. The
private key never leaves the device; the public key goes to the server. When you
log in, the authenticator signs a server-issued challenge with the private key, and
the server verifies the signature. An attacker who steals the server's database gets
only public keys — useless without the corresponding private keys.

**Passkeys** are the consumer-facing name for WebAuthn credentials that sync across
devices via platform ecosystems (iCloud Keychain, Google Password Manager, etc.).
Technically, a passkey is a WebAuthn credential stored in a platform authenticator.
The underlying cryptography is identical.

Both eliminate the biggest password risks: phishing (the credential is
cryptographically bound to the origin), credential stuffing (public keys are
worthless without private keys), and password reuse (each site gets a unique keypair).

---

## What this library implements

| Feature | Status |
|---------|--------|
| Registration ceremony (W3C WebAuthn §7.1) | ✅ Implemented |
| Authentication ceremony (W3C WebAuthn §7.2) | ✅ Implemented |
| ES256 (ECDSA P-256 + SHA-256, COSE -7) | ✅ Implemented |
| ES384 (ECDSA P-384 + SHA-384, COSE -35) | ✅ Implemented |
| EdDSA / Ed25519 (COSE -8) | ✅ Implemented |
| RS256 (RSA PKCS#1 v1.5 + SHA-256, COSE -257) | ✅ Implemented |
| Multiple allowed origins (`RelyingParty::with_origins`) | ✅ Implemented |
| `"none"` attestation format | ✅ Implemented |
| Packed self-attestation (no x5c) | ✅ Implemented — signature fully verified |
| Packed basic attestation (x5c present) | ✅ Implemented — signature + x5c chain order verified; optional trust-anchor pinning via `trust_anchors()` |
| FIDO U2F attestation (`"fido-u2f"`) | ✅ Implemented — signature + x5c chain order verified; cert chain requires FIDO MDS for full provenance |
| Android Key attestation (`"android-key"`) | ✅ Implemented — signature + key-match + x5c chain order verified; cert chain requires FIDO MDS for full provenance |
| Apple attestation (`"apple"`) | ✅ Implemented — nonce extension + key-match + x5c chain order verified; cert chain requires Apple MDS for full provenance |
| TPM attestation (`"tpm"`) | ✅ Implemented — certInfo + pubArea + x5c chain order verified; cert chain requires FIDO MDS for full provenance |
| UV flag enforcement (`require_user_verification`) | ✅ Implemented — opt-in via builder; off by default |
| Algorithm allowlist (`allowed_algorithms`) | ✅ Implemented — opt-in via builder; empty = accept all |
| Single-use challenge enforcement | ✅ Implemented — opt-in via `enforce_single_use_challenges(true)`; caller-managed by default |
| Sign-count replay attack detection | ✅ Implemented |
| Challenge generation (32-byte CSPRNG) | ✅ Implemented |
| `#![forbid(unsafe_code)]` | ✅ Enforced at compile time |
| No-panic guarantee on adversarial input | ✅ `#![deny(clippy::unwrap_used)]` |
| Fixed test vectors (registration + authentication) | ✅ Implemented |
| `serde` feature — Serialize/Deserialize on public types | ✅ Opt-in via `features = ["serde"]` |
| Token binding | ❌ Not implemented |
| FIDO Metadata Service (MDS) lookup | ❌ Not implemented |

This scope is intentional. The library demonstrates mastery of the core protocol
and cryptographic operations without adding surface area that obscures the design.

---

## Quick start

```rust
use webauthn::{RelyingParty, AuthenticatorAttestationResponse,
               AuthenticatorAssertionResponse, Challenge};

// 1. Configure the relying party once, at startup.
//    Use new() for a single origin, or with_origins() to accept multiple
//    (e.g. production + localhost for local development).
let rp = RelyingParty::new("example.com", "https://example.com", "My Service");
// — or —
// let rp = RelyingParty::with_origins(
//     "example.com",
//     ["https://example.com", "http://localhost:8080"],
//     "My Service",
// );

// ── Registration ──────────────────────────────────────────
// 2. Generate a challenge and send it to the browser.
let reg_challenge = Challenge::new()?;

// 3. Browser calls navigator.credentials.create() and returns:
let reg_response = AuthenticatorAttestationResponse {
    client_data_json:   todo!("raw bytes from browser response"),
    attestation_object: todo!("raw bytes from browser response"),
};

// 4. Verify and store the credential.
let result = rp.verify_registration(&reg_challenge, &reg_response, b"user-id-42")?;
let mut stored = result.credential; // persist this in your database

// ── Authentication ────────────────────────────────────────
// 5. Issue a new challenge (never reuse challenges).
let auth_challenge = Challenge::new()?;

// 6. Browser calls navigator.credentials.get() and returns:
let auth_response = AuthenticatorAssertionResponse {
    client_data_json:   todo!("raw bytes from browser response"),
    authenticator_data: todo!("raw bytes from browser response"),
    signature:          todo!("raw bytes from browser response"),
    user_handle:        None,
};

// 7. Verify, then update the stored sign count.
let auth_result = rp.verify_authentication(&stored, &auth_challenge, &auth_response)?;
stored.sign_count = auth_result.new_sign_count;
```

Run the self-contained demo to see full registration → authentication → replay-attack
sequences for ES256, RS256, ES384, and EdDSA without a browser:

```
cargo run --example demo
```

Expected output ends with: `All checks passed.`

---

## Running the examples

### End-to-end demo

Simulates full ES256, RS256, ES384, and EdDSA registration → authentication → replay
attack rejection entirely in software (no browser, no server):

```bash
cargo run --example demo
```

Expected: the final line is `All checks passed.`

### HTTP server

Runs a real Axum HTTP server on port 3000 with all WebAuthn endpoints:

```bash
cargo run --example server
```

Test it with curl:

```bash
# Health check
curl http://localhost:3000/health

# Registration begin
curl -s -X POST http://localhost:3000/register/begin \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"dXNlcjE","username":"alice"}' | jq .

# Registration complete (paste session_id and challenge from begin response,
# then build clientDataJSON/attestationObject from your authenticator)

# Authentication begin
curl -s -X POST http://localhost:3000/authenticate/begin \
  -H 'Content-Type: application/json' \
  -d '{"credential_id":"<base64url-credential-id>"}' | jq .
```

---

## Running tests

```bash
cargo test                        # all 255+ unit + integration + doc tests
cargo test --features serde       # +5 serde round-trip tests
cargo clippy -- -D warnings       # lint (zero-warning policy)
cargo fmt --check                 # formatting
cargo doc --no-deps               # API docs (zero warnings)
cargo package --dry-run           # crates.io readiness check
```

---

## Security considerations

### What the library verifies

- **Origin binding** — `clientDataJSON.origin` must exactly equal one of the origins
  in `allowed_origins`. This defeats cross-origin replays (a credential from `bank.com`
  cannot be used at `evil.com`). `RelyingParty::new` accepts a single origin;
  `RelyingParty::with_origins` accepts a list for multi-environment deployments.

- **RP ID binding** — the authenticator data's `rpIdHash` is verified to equal
  `SHA-256(rp_id)`. This binds the credential to the relying party identifier.

- **Challenge freshness** — the challenge in `clientDataJSON` must match the
  server-issued challenge byte-for-byte. Single-use enforcement is the caller's
  responsibility.

- **User presence** — the UP flag in authenticator data must be set. The
  authenticator confirmed that a human was physically present.

- **User verification (opt-in)** — when `require_user_verification(true)` is set on
  the `RelyingParty`, the UV flag must also be set. This enforces that the authenticator
  verified the user's identity (PIN, biometric) before signing. Disabled by default;
  enable for sensitive flows (payment authorization, privileged settings).

- **Cryptographic signature** — the signature over `authData || SHA-256(clientDataJSON)`
  is verified using `ring`:
  - ES256: ECDSA P-256 with SHA-256 (`ring::signature::ECDSA_P256_SHA256_ASN1`)
  - ES384: ECDSA P-384 with SHA-384 (`ring::signature::ECDSA_P384_SHA384_ASN1`)
  - EdDSA: Ed25519 (`ring::signature::ED25519`)
  - RS256: RSA PKCS#1 v1.5 with SHA-256 (`ring::signature::RSA_PKCS1_2048_8192_SHA256`,
    minimum 2048-bit key enforced)

- **Sign count** — a non-zero received count must be strictly greater than the
  stored count. A violation (including wrap-around from u32::MAX → 0) indicates a
  possible cloned authenticator.

### What the caller must provide

| Responsibility | Notes |
|----------------|-------|
| Credential storage | A durable, indexed key-value store keyed by credential ID |
| Single-use challenges | Invalidate each challenge after it is used or expires |
| Challenge expiry | `webauthn::challenge::is_expired()` checks a 5-minute window |
| HTTPS | WebAuthn requires a secure context; enforce TLS at the transport layer |
| Sign-count update | After successful auth, write `auth_result.new_sign_count` back |
| User enumeration prevention | Return the same error for unknown vs. invalid credential |

### What this library does NOT protect against

- **Full attestation chain** — `"none"`, `"packed"` (self-attestation), `"fido-u2f"`,
  and `"android-key"` are verified (signature and key-match checks). Certificate chain
  validation against the FIDO Metadata Service is not implemented for any format, so
  device provenance — distinguishing genuine hardware from a software emulator — cannot
  be fully confirmed.
- **Token binding** — `tokenBinding` in `clientDataJSON` is ignored.
- **Cloned authenticators with zero counters** — if `sign_count == 0` the spec
  allows accepting the assertion (the authenticator simply doesn't count). Clone
  detection is unavailable in this case.
- **Side-channel attacks** — `ring`'s verifiers provide constant-time signature
  comparison, but this library does not claim constant-time credential lookups or
  error responses.

### No-panic guarantee

`#![deny(clippy::unwrap_used)]` is enforced across all library code. `.unwrap()` is
a compile error; every code path on malformed or adversarial input returns a typed
`WebAuthnError` rather than panicking. Two fuzz-style tests
(`no_panic_on_random_registration_input`, `no_panic_on_random_authentication_input`)
pass 100 randomly-constructed inputs through each ceremony and assert no panic occurs.

### No-unsafe guarantee

`#![forbid(unsafe_code)]` is active. No `unsafe` block can exist anywhere in this
crate's source. All memory-safety-sensitive work — key parsing, signature verification,
SHA-256 hashing, and random number generation — is handled inside `ring`'s audited
boundary.

---

## Tech stack

| Crate | Purpose |
|-------|---------|
| `ring` 0.17 | ECDSA P-256 + RSA PKCS#1 v1.5 signature verification, SHA-256, CSPRNG |
| `ciborium` 0.2 | CBOR decoding for authenticator data and attestation objects |
| `serde` + `serde_json` 1 | `clientDataJSON` parsing (always required) |
| `serde_bytes` 0.11 | Efficient `Vec<u8>` serialization (optional, enabled by `features = ["serde"]`) |
| `base64` 0.22 | URL-safe base64 encoding/decoding |
| `thiserror` 1 | Structured, descriptive error types |

---

## Design decisions

### `ring` over RustCrypto

`ring` descends from BoringSSL and has a longer audit lineage than the RustCrypto
family. Its API is intentionally narrow — you cannot accidentally use an insecure mode
that a more flexible library might expose. `rustls` and many production TLS stacks use
it, which gives confidence in its deployment history.

### Hand-rolled DER over an ASN.1 library

RSA public keys must be presented to `ring` in DER format
(`SEQUENCE { INTEGER n, INTEGER e }`). The full DER encoding is 15 bytes of structure
around the key components. A dedicated ASN.1 library would add a dependency for work
that is simpler, clearer, and more auditable as a 30-line function in `src/der.rs`.

### `ciborium` for CBOR

WebAuthn uses CBOR for the attestation object and COSE public keys. `ciborium` decodes
into a `Value` enum (like `serde_json::Value`), which the library navigates explicitly.
This keeps parsing code readable and maps one-to-one with the CBOR structures in the
spec. Serde-derive-based CBOR would hide the wire structure behind opaque attributes,
making it harder to audit against the spec.

### `#![forbid(unsafe_code)]`

A security library that handles authentication credentials has a higher bar for memory
safety than average code. The attribute makes the guarantee machine-checked: no future
contributor can accidentally introduce unsafe code, and reviewers don't need to hunt for
it. The `ring` crate manages its own unsafe code inside a safe API boundary.

---

## References

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [RFC 9052 — CBOR Object Signing and Encryption (COSE)](https://www.rfc-editor.org/rfc/rfc9052)
- [RFC 3447 — RSA Cryptography Specifications (PKCS#1)](https://www.rfc-editor.org/rfc/rfc3447)
- [FIDO Alliance CTAP2 specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [passkeys.dev — developer documentation](https://passkeys.dev)

---

---

## Disclaimer

This is a portfolio project demonstrating a correct implementation of the WebAuthn
core ceremonies. It has not been security audited and is missing features required
for production use: full attestation certificate chain validation, FIDO Metadata
Service integration, and token binding. For production deployments, consider
[`webauthn-rs`](https://crates.io/crates/webauthn-rs).
