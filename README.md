# WebAuthn

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
| Registration ceremony (§7.1) | Implemented |
| Authentication ceremony (§7.2) | Implemented |
| ES256 (ECDSA P-256 + SHA-256, COSE -7) | Implemented |
| RS256 (RSA PKCS#1 v1.5 + SHA-256, COSE -257) | Implemented |
| Attestation format `"none"` | Implemented |
| Sign-count replay attack detection | Implemented |
| Challenge generation (32-byte CSPRNG) | Implemented |
| No-panic guarantee on adversarial input | Implemented (`#![deny(clippy::unwrap_used)]`) |
| Fixed test vectors (registration + authentication) | Implemented |
| Packed / FIDO-U2F / TPM attestation | Not implemented |
| EdDSA / Ed25519 | Not implemented |
| Token binding | Not implemented |
| FIDO Metadata Service (MDS) lookup | Not implemented |
| Attestation trust chain validation | Not implemented |

This scope is intentional. The library demonstrates mastery of the core protocol
and cryptographic operations without adding surface area that obscures the design.

---

## Quick start

```rust
use webauthn::{RelyingParty, AuthenticatorAttestationResponse,
               AuthenticatorAssertionResponse, Challenge};

// 1. Configure the relying party once, at startup.
let rp = RelyingParty::new("example.com", "https://example.com", "My Service");

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
sequences for both ES256 and RS256 without a browser:

```
cargo run --example demo
```

Expected output ends with: `All checks passed.`

---

## Running tests

```
cargo test          # 101 unit + 40 integration + 2 doc tests
cargo clippy        # lint (zero-warning policy enforced by -D warnings)
cargo fmt --check   # formatting
cargo doc --open    # API documentation
```

---

## Security considerations

### What the library verifies

- **Origin binding** — `clientDataJSON.origin` must exactly equal `expected_origin`.
  This defeats cross-origin replays (a credential from `bank.com` cannot be used at
  `evil.com`).

- **RP ID binding** — the authenticator data's `rpIdHash` is verified to equal
  `SHA-256(rp_id)`. This binds the credential to the relying party identifier.

- **Challenge freshness** — the challenge in `clientDataJSON` must match the
  server-issued challenge byte-for-byte. Single-use enforcement is the caller's
  responsibility.

- **User presence** — the UP flag in authenticator data must be set. The
  authenticator confirmed that a human was physically present.

- **Cryptographic signature** — the signature over `authData || SHA-256(clientDataJSON)`
  is verified using `ring`:
  - ES256: ECDSA P-256 with SHA-256 (`ring::signature::ECDSA_P256_SHA256_ASN1`)
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

- **Full attestation chain** — only `"none"` attestation is verified. Unverified
  attestation means you cannot distinguish genuine authenticators from software
  emulators.
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

---

## Tech stack

| Crate | Purpose |
|-------|---------|
| `ring` 0.17 | ECDSA P-256 + RSA PKCS#1 v1.5 signature verification, SHA-256, CSPRNG |
| `ciborium` 0.2 | CBOR decoding for authenticator data and attestation objects |
| `serde` + `serde_json` 1 | `clientDataJSON` parsing |
| `base64` 0.22 | URL-safe base64 encoding/decoding |
| `thiserror` 1 | Structured, descriptive error types |

---

## References

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [RFC 9052 — CBOR Object Signing and Encryption (COSE)](https://www.rfc-editor.org/rfc/rfc9052)
- [RFC 3447 — RSA Cryptography Specifications (PKCS#1)](https://www.rfc-editor.org/rfc/rfc3447)
- [FIDO Alliance CTAP2 specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [passkeys.dev — developer documentation](https://passkeys.dev)

---

> **Note:** This is a portfolio project. It has not been security audited and is
> missing several features required for production use (full attestation chain
> validation, metadata service integration, token binding). Do not use it to protect
> real user accounts without significant additional work.
