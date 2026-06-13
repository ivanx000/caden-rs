# CLAUDE.md — WebAuthn

Developer guide for this codebase. Start here every session.

---

## Project overview

This is a **WebAuthn relying-party library** written in Rust. It implements
the server-side verification logic for the two core WebAuthn ceremonies:

- **Registration** (`navigator.credentials.create`) — the authenticator generates
  a P-256 keypair, and the relying party verifies the attestation and stores the
  public key and credential ID.
- **Authentication** (`navigator.credentials.get`) — the authenticator signs a
  challenge with the stored private key, and the relying party verifies the
  signature and sign count.

The library follows the [W3C WebAuthn Level 2 specification](https://www.w3.org/TR/webauthn-2/).

### Project goals

- Correct implementation of a real cryptographic protocol (no "close enough")
- Idiomatic, readable Rust — every line explainable in an interview
- Layered module design: each file owns exactly one concept
- Precise, debuggable error messages that never leak sensitive material
- Every error path exercised by a dedicated test
- Zero custom crypto — all cryptographic operations delegated to `ring`

---

## Crate structure

| File | Purpose |
|------|---------|
| `src/lib.rs` | Public API surface: `RelyingParty`, wire types, re-exports |
| `src/error.rs` | `WebAuthnError` enum + `Result<T>` alias |
| `src/credential.rs` | `Credential`, `PublicKey`, `Challenge`, ceremony result types |
| `src/crypto.rs` | `sha256`, `verify_es256_signature`, `generate_challenge` |
| `src/challenge.rs` | Challenge expiry helpers: `is_expired`, `CHALLENGE_MAX_AGE_SECS` |
| `src/client_data.rs` | `clientDataJSON` base64url → JSON → `ClientData` |
| `src/authenticator_data.rs` | Authenticator data binary format → `AuthenticatorData` |
| `src/attestation.rs` | Attestation statement verification ("none" format) |
| `src/registration.rs` | §7.1 registration ceremony steps |
| `src/authentication.rs` | §7.2 authentication ceremony steps |
| `examples/demo.rs` | End-to-end demo that runs without a browser |
| `tests/integration.rs` | Full pipeline integration tests using real P-256 keys |

---

## Key design decisions

### `ring` over RustCrypto

`ring` is used for all cryptographic operations (ECDSA P-256 verification,
SHA-256, CSPRNG). Reasons:

- **Audit lineage**: ring descends from BoringSSL, which has a longer and
  broader audit history than the RustCrypto family.
- **Constrained API**: ring's API is intentionally narrow — you cannot
  accidentally use an insecure mode that a more flexible library might expose.
- **Production pedigree**: rustls and many production TLS stacks use ring.
- **No custom crypto**: the library does not implement any cryptographic
  primitives itself. All security-critical operations are inside ring's
  audited boundary.

### `ciborium` for CBOR

WebAuthn uses CBOR for the attestation object and the COSE public key inside
authenticator data. `ciborium` is chosen over serde-based CBOR crates because:

- It decodes into a `Value` enum (similar to `serde_json::Value`), which we
  navigate explicitly. This keeps parsing code readable and maps one-to-one
  with the CBOR structures described in the spec.
- Serde-derive-based CBOR deserialization would hide the CBOR structure behind
  opaque attributes, making it harder to audit against the spec.

### `thiserror` for structured errors

`thiserror` generates `Display` and `Error` trait implementations from the
`#[error("...")]` attribute. This keeps `WebAuthnError` definitions DRY —
the display string lives next to the variant declaration — while still
producing the `std::error::Error` impl that callers expect from a library.
Errors intentionally never include raw key bytes or challenge values.

### Spec step comments in ceremony code

`registration.rs` and `authentication.rs` cite spec step numbers inline
(`// §7.1 step 8`). This is a security-library convention: it makes the
implementation auditable against the spec without reading both documents
side-by-side. **Always add a step comment when implementing or modifying a
ceremony step.** See `/spec-audit` to check compliance.

### Stateless `RelyingParty`

`RelyingParty` holds no state. The caller passes in the stored `Credential`
and receives result types back. This design is storage-agnostic — the library
does not prescribe a database, an ORM, or a session store.

### `PublicKey::ES256(Vec<u8>)` stores the uncompressed point

The inner `Vec<u8>` is `0x04 || x (32 bytes) || y (32 bytes)` — the
uncompressed EC point format that `ring` expects for signature verification.
The COSE key encodes `x` and `y` as separate byte strings; `authenticator_data.rs`
joins them into the `0x04 || x || y` form during parsing.

---

## Registration ceremony — W3C §7.1 step mapping

`src/registration.rs::verify` implements these steps:

| Step | What it checks | Code location |
|------|---------------|---------------|
| §7.1 step 5 | Parse `clientDataJSON` (base64url → JSON) | `client_data::parse` |
| §7.1 step 7 | `type` field must equal `"webauthn.create"` | inline check |
| §7.1 step 8 | Challenge in client data must match issued challenge | inline check |
| §7.1 step 9 | Origin must match `expected_origin` exactly | inline check |
| §7.1 step 11 | Hash `clientDataJSON` with SHA-256 | `crypto::sha256` |
| §7.1 step 12 | Decode `attestationObject` (base64url → CBOR bytes) | inline |
| §7.1 step 13 | Parse CBOR attestation object → `(fmt, authData)` | `parse_attestation_object` |
| §7.1 step 14 | Parse raw authenticator data bytes | `authenticator_data::parse` |
| §7.1 step 15 | `rpIdHash` must equal SHA-256(`rp_id`) | inline check |
| §7.1 step 16 | User Present (UP) flag must be set | inline check |
| §7.1 step 21 | Extract attested credential data (credential ID + public key) | inline check |
| §7.1 step 22 | Verify attestation statement | `attestation::verify` |
| §7.1 step 25 | Assemble `Credential` struct for caller to persist | return value |

Steps not listed (e.g. steps 1–4, tokenBinding, client extension processing)
are either delegated to the caller or intentionally out of scope for a library.

---

## Authentication ceremony — W3C §7.2 step mapping

`src/authentication.rs::verify` implements these steps:

| Step | What it checks | Code location |
|------|---------------|---------------|
| §7.2 step 11 | Parse `clientDataJSON` (base64url → JSON) | `client_data::parse` |
| §7.2 step 13 | `type` field must equal `"webauthn.get"` | inline check |
| §7.2 step 14 | Challenge must match issued challenge | inline check |
| §7.2 step 15 | Origin must match `expected_origin` exactly | inline check |
| §7.2 step 17 | Hash `clientDataJSON` with SHA-256 | `crypto::sha256` |
| §7.2 step 18 | Decode + parse `authenticatorData` bytes | `authenticator_data::parse` |
| §7.2 step 19 | `rpIdHash` must equal SHA-256(credential's `rp_id`) | inline check |
| §7.2 step 20 | User Present (UP) flag must be set | inline check |
| §7.2 step 21 | UV check — optional, delegated to caller | noted in comment |
| §7.2 step 23 | Decode DER signature bytes (base64url → bytes) | inline |
| §7.2 step 24 | Verify ECDSA-P256-SHA256 over `authData \|\| SHA-256(clientDataJSON)` | `crypto::verify_es256_signature` |
| §7.2 step 25 | Sign count must be strictly greater than stored value | inline check |

---

## Common commands

```bash
# Build
cargo build

# Run all tests (unit + integration + doc tests)
cargo test

# Run only unit tests inside each module
cargo test --lib

# Run only integration tests
cargo test --test integration

# Run the end-to-end demo
cargo run --example demo

# Clippy (zero-warning policy)
cargo clippy -- -D warnings

# Auto-format
cargo fmt

# Check formatting without modifying files
cargo fmt --check

# Generate and open documentation
cargo doc --open
```

---

## Running the demo

```
cargo run --example demo
```

`examples/demo.rs` simulates a full browser/authenticator interaction entirely
in software: it generates a real P-256 keypair with `ring`, constructs valid
`clientDataJSON`, `authenticatorData`, and an attestation object, then calls
the library. The demo demonstrates:

1. A successful registration
2. A valid authentication
3. Replay attack rejection (`WebAuthnError::ChallengeMismatch`)

Expected: the final line of output is `All checks passed.`

---

## Running tests

```bash
cargo test               # everything
cargo test --lib         # unit tests only
cargo test --test integration  # integration tests only
```

Unit tests live inside each module under `#[cfg(test)]`. Follow the pattern:

```rust
#[test]
fn rejects_my_new_error_case() {
    // Arrange: minimal valid state
    // Act: mutate one thing to trigger the error
    // Assert: match on the specific WebAuthnError variant
}
```

Integration tests in `tests/integration.rs` use the `Fixture` struct which
generates a real P-256 keypair. Follow the pattern:

1. Create a `Fixture`
2. Call `fixture.make_registration_response(...)` with desired parameters
3. Call `rp.verify_registration(...)` and assert `Ok` or `Err`
4. For authentication: call `fixture.make_assertion_response(...)`

---

## W3C spec references (with links)

| Section | Topic | URL |
|---------|-------|-----|
| §6.1 | Authenticator Data binary format | https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data |
| §6.5 | Attestation object structure | https://www.w3.org/TR/webauthn-3/#sctn-attestation |
| §7.1 | Registration ceremony algorithm | https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential |
| §7.2 | Authentication ceremony algorithm | https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion |
| §8.7 | None attestation format | https://www.w3.org/TR/webauthn-3/#sctn-none-attestation |
| RFC 8152 §13 | COSE Key Parameters | https://www.rfc-editor.org/rfc/rfc8152#section-13 |
| RFC 9052 | COSE (updated) | https://www.rfc-editor.org/rfc/rfc9052 |

Canonical spec: https://www.w3.org/TR/webauthn-3/

---

## Known limitations and future work

| Limitation | Notes |
|------------|-------|
| RS256 (RSA) verification | `PublicKey::RS256` variant exists; signature check not implemented |
| EdDSA / Ed25519 | Not supported; would require `ring` Ed25519 verify path |
| Only `"none"` attestation | `"packed"`, `"tpm"`, `"android-key"` formats not implemented |
| Extension data ignored | The extensions section of authenticator data is parsed but silently skipped |
| `crossOrigin: true` accepted | Some RPs should reject cross-origin requests; currently allowed |
| Challenge single-use enforcement | The caller is responsible — the library does not maintain a used-challenge set |
| No FIDO Metadata Service | Authenticator model/provenance cannot be verified |
| UV flag not enforced | User Verification flag is returned but not required; caller decides |

---

## Contribution guidelines

### Branch naming

```
feat/<short-description>       # new capability
fix/<short-description>        # bug fix
test/<short-description>       # tests only
docs/<short-description>       # docs only
refactor/<short-description>   # no behaviour change
chore/<short-description>      # tooling, config, deps
```

### Commit format (Conventional Commits)

```
<type>(<scope>): <short description>

<optional body>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Examples:
```
feat(crypto): add EdDSA signature verification via ring
fix(auth): reject sign count equal to stored value (was: only less-than)
test(registration): add test for missing attested credential data
docs(claude): add hooks & automation section
```

### Before opening a PR

Run `/check` or manually:

```bash
cargo build
cargo clippy -- -D warnings
cargo test
cargo fmt --check
```

All four must pass. See `.github/pull_request_template.md` for the full checklist.

### Style rules

- No comments that restate what the code does — only WHY (hidden constraints,
  spec citations, non-obvious invariants).
- All public items must have `///` doc comments.
- Ceremony verification steps must cite the spec section and step number.
- Errors must be specific enough to debug without leaking key bytes or
  challenge values.
- No `unwrap()` in library code (`src/`). Tests and `examples/` may use it.

---

## Hooks & Automation

This project uses Claude Code hooks (`.claude/settings.json`) for intelligent
automation during AI-assisted development. All hooks are in `.claude/scripts/`.

### Hook summary

| Hook | Event | Trigger | What it does |
|------|-------|---------|-------------|
| build-clippy | PostToolUse | Any `.rs` file edited | Runs `cargo build` + `cargo clippy -- -D warnings`; prints ✅ or ❌ |
| docs-sync | PostToolUse | Specific `src/` files edited | Prints a targeted warning reminding Claude to check related docs |
| test-runner | PostToolUse | Any file in `src/` or `tests/` edited | Runs `cargo test`; prints ✅ or ❌ |
| log-command | PreToolUse | Every Bash command | Appends `[timestamp] command` to `.claude/logs/commands.log` |
| auto-commit | Stop | Claude's turn ends | Stages all changes, generates a conventional commit message, commits locally |

### Why git push is intentionally manual

The auto-commit hook commits to the local repo only. `git push` is never
automated because:

1. Pushing triggers CI and notifies collaborators — a deliberate decision, not a side effect.
2. Automated pushes during development create a noisy commit history on the remote.
3. The developer should review the commit message before publishing.

To push when you're ready: `git push`.

### Reading the command log

```bash
cat .claude/logs/commands.log
```

Each line is `[ISO-8601 UTC timestamp] <first line of bash command>`. The log
is never committed (it is in `.gitignore`) and resets each working directory
session.

### Custom slash commands

| Command | When to use |
|---------|-------------|
| `/add-algorithm` | Adding a new COSE algorithm (RS256, EdDSA, etc.) — scaffolds enum variant, crypto function, and tests |
| `/run-demo` | Quickly verify the end-to-end demo works and print its output |
| `/check` | Run the full quality suite (build + clippy + test + fmt) before a PR |
| `/spec-audit` | Audit ceremony code for missing W3C spec step comments — important for security review |
| `/status` | Project health snapshot: git state, build, test count, clippy warnings, public API list |

### Docs sync warnings

The `docs-sync` hook prints warnings when files with broad impact are edited:

| File edited | Warning |
|-------------|---------|
| `src/registration.rs` | Check `docs/architecture.md` and §7.1 step comments |
| `src/authentication.rs` | Check `docs/architecture.md` and §7.2 step comments |
| `src/crypto.rs` | Update `docs/security-considerations.md` if behaviour changed |
| `src/error.rs` | Ensure new variants are documented and tested |
| `src/lib.rs` | Update `README.md` quick-start if public API changed |

### Why spec compliance comments matter

This is a security library. The WebAuthn spec defines exact algorithms
for registration and authentication — implementing a step incorrectly or
skipping it can introduce authentication bypasses. Step comments (`// §7.1 step 8`)
serve as an audit trail: a reviewer can open the spec and the source file
side-by-side and confirm each step is handled. Use `/spec-audit` to check
that all implemented steps are annotated.

---

## Phase 3 — Hardening

Phase 3 (implemented June 2026) turned the library from a working demo into a
correct and robust implementation. Summary of what changed:

### Panic audit

All `src/` files were audited for `unwrap()` calls. None were found; the
library already used `expect()` with safety comments for provably-infallible
conversions (e.g., `try_into()` on slices whose length was just verified).

`#![deny(clippy::unwrap_used)]` was added to `src/lib.rs` to enforce this
as a compile-time guarantee going forward. `.expect()` in library code is
still permitted where the preceding bounds check makes the panic impossible.

### Test vectors

Fixed test vectors are stored in `tests/vectors/registration.json` and
`tests/vectors/authentication.json`. They were generated once by
`examples/generate_vectors.rs` using a simulated P-256 authenticator and
committed. The vectors contain pre-encoded `clientDataJSON`,
`attestationObject`, `authenticatorData`, and `signature` blobs; integration
tests verify the library parses and accepts them unchanged between runs.

### Edge cases now hardened

| Module | New checks |
|--------|-----------|
| `authenticator_data.rs` | credentialIdLength=0, >1023, CBOR key duplicate detection, crv≠1, missing kty/alg/crv/x/y fields, x/y coordinate length != 32, empty COSE input |
| `client_data.rs` | empty bytes, non-JSON UTF-8, missing type/challenge/origin, empty type field, origin trailing slash, crossOrigin flag |
| `challenge.rs` | TTL=0 (immediately expired), TTL=u64::MAX (never expired), future created_at, two-call non-equality |
| `crypto.rs` | 64-byte key (missing 0x04 prefix), empty key, empty signature, wrong-message signature, garbage DER |
| `registration.rs` | missing attStmt, authData not bytes |
| `authentication.rs` | sign-count wrap-around (stored=u32::MAX, received=0) now rejected |

### No-panic property

Two fuzz-style tests (`no_panic_on_random_registration_input`,
`no_panic_on_random_authentication_input`) pass 100 randomly-constructed
inputs through the full ceremony verification paths and assert no panic occurs.
Both tests use a deterministic LCG so they are fully reproducible.

### Sign-count boundary fix

The expiry check in `Challenge` was changed from `age > ttl` to `age >= ttl`
so that a TTL of 0 seconds means the challenge expires at the moment of
creation, and a challenge exactly at the boundary counts as expired (safer
default). The change propagates to `challenge::is_expired`,
`challenge::is_expired_with_max_age`, and `Challenge::is_expired`.

The sign-count check in `authentication.rs` was updated: the old check
(`received != 0 && received <= stored`) accepted any received=0 value
regardless of the stored count. The new check (`(stored > 0 || received > 0)
&& received <= stored`) rejects received=0 when stored>0, catching the
wrap-around (u32::MAX → 0) case as a `SignCountInvalid` error.
