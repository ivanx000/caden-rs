# CLAUDE.md — Caden

> This project was renamed from "WebAuthn" to "Caden" (repo: caden-rs) on 2026-06-24.
> All references to "WebAuthn" in this codebase refer to the W3C standard, not the project name.

Developer guide for this codebase. Start here every session.

---

## Project overview

This is **Caden**, a WebAuthn relying-party library written in Rust. It implements
the server-side verification logic for the two core WebAuthn ceremonies:

- **Registration** (`navigator.credentials.create`) — the authenticator generates
  a keypair (P-256 or RSA), and the relying party verifies the attestation and
  stores the public key and credential ID.
- **Authentication** (`navigator.credentials.get`) — the authenticator signs a
  challenge with the stored private key, and the relying party verifies the
  signature and sign count.

Supported algorithms: **ES256** (ECDSA P-256, COSE `-7`), **EdDSA** (Ed25519,
COSE `-8`), and **RS256** (RSA PKCS#1 v1.5 SHA-256, COSE `-257`).

The library follows the [W3C WebAuthn Level 3 specification](https://www.w3.org/TR/webauthn-3/).

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
| `src/credential.rs` | `Credential`, `PublicKey { ES256, EdDSA, RS256 }`, `Challenge`, result types |
| `src/algorithm.rs` | COSE algorithm constants: `COSE_ES256=-7`, `COSE_EDDSA=-8`, `COSE_RS256=-257`, kty values |
| `src/der.rs` | DER builder: `rsa_components_to_der(n,e)` → RSAPublicKey for ring |
| `src/crypto.rs` | `sha256`, `verify_es256`, `verify_eddsa`, `verify_rs256`, `generate_challenge` |
| `src/challenge.rs` | Challenge expiry helpers: `is_expired`, `CHALLENGE_MAX_AGE_SECS` |
| `src/client_data.rs` | `clientDataJSON` base64url → JSON → `ClientData` |
| `src/authenticator_data.rs` | Binary authenticator data → `AuthenticatorData`; `CoseKey` enum |
| `src/attestation.rs` | Attestation verification: "none", "packed", "fido-u2f", "android-key" |
| `src/registration.rs` | §7.1 registration ceremony; dispatches `CoseKey` → `PublicKey` |
| `src/authentication.rs` | §7.2 authentication ceremony; dispatches `PublicKey` → verifier |
| `examples/demo.rs` | End-to-end demo: ES256 and RS256 registration/auth/replay |
| `examples/server.rs` | Axum HTTP server: all 5 WebAuthn endpoints with in-memory state |
| `tests/integration.rs` | Integration tests for ES256, EdDSA, and RS256 full ceremony flows |

---

## Key design decisions

### `ring` over RustCrypto

`ring` is used for all cryptographic operations (ECDSA P-256 verification,
RSA PKCS#1 v1.5 verification, SHA-256, CSPRNG). Reasons:

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
| §7.1 step 9 | Origin must be in `allowed_origins` (exact match, any entry) | inline check |
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
| §7.2 step 15 | Origin must be in `allowed_origins` (exact match, any entry) | inline check |
| §7.2 step 17 | Hash `clientDataJSON` with SHA-256 | `crypto::sha256` |
| §7.2 step 18 | Decode + parse `authenticatorData` bytes | `authenticator_data::parse` |
| §7.2 step 19 | `rpIdHash` must equal SHA-256(credential's `rp_id`) | inline check |
| §7.2 step 20 | User Present (UP) flag must be set | inline check |
| §7.2 step 21 | UV flag enforced when `rp.require_user_verification == true`; skipped by default | inline check |
| §7.2 step 23 | Decode DER signature bytes (base64url → bytes) | inline |
| §7.2 step 24 | Verify signature over `authData \|\| SHA-256(clientDataJSON)` | `crypto::verify_es256` or `crypto::verify_rs256` |
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

# Run the end-to-end demo (ES256 + RS256 registration / auth / replay)
cargo run --example demo

# Run the Axum HTTP server on port 3000
cargo run --example server

# Clippy (zero-warning policy)
cargo clippy -- -D warnings

# Auto-format
cargo fmt

# Check formatting without modifying files
cargo fmt --check

# Generate API documentation (zero warnings expected)
cargo doc --no-deps

# Check crates.io packaging readiness
cargo package --no-verify --allow-dirty
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
| Packed basic attestation cert chain | `x5c` detected, `AttestationType::Basic` returned; chain not verified (no MDS) |
| FIDO U2F cert chain | Signature verified, cert chain not verified (no MDS trust anchors) |
| Android Key cert chain | Signature + key-match verified, cert chain not verified (no MDS trust anchors) |
| `"tpm"` attestation | Not implemented |
| Apple cert chain | Nonce + key-match verified; cert chain not verified (no Apple MDS trust anchors) |
| Extension data ignored | The extensions section of authenticator data is parsed but silently skipped |
| Challenge single-use enforcement | The caller is responsible — the library does not maintain a used-challenge set |
| No FIDO Metadata Service | Authenticator model/provenance cannot be verified |
| UV flag optional | Off by default; enable with `RelyingParty::new(...).require_user_verification(true)` |

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
| auto-commit | Stop | *(disabled)* | Script kept at `.claude/scripts/auto-commit.sh` but hook removed — commits are made manually per logical change |

### Why commits are manual

The auto-commit Stop hook has been disabled. Commits are made explicitly during
a turn, one per logical change, with specific conventional commit messages. This
gives a meaningful git history instead of one catch-all "update Caden (N
files changed)" commit per Claude turn.

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

---

## Phase 5 — Stretch Goals (Project complete)

Phase 5 (implemented June 2026) elevated the library from a solid implementation
to a portfolio-ready, publishable crate.

### `#![forbid(unsafe_code)]`

Added to `src/lib.rs` as the first crate-level attribute. This is a strong signal
for a security library: it eliminates entire classes of memory safety vulnerabilities
at compile time and signals to reviewers that no unsafe code exists anywhere in this
crate. All security-critical operations remain inside `ring`'s audited boundary.

### Attestation verification

`src/attestation.rs` implements multiple attestation formats:

- **Self-attestation** (`x5c` absent): `alg` verified to match the credential key
  algorithm, `authData || clientDataHash` verified using `verify_es256` or
  `verify_rs256`. Returns `AttestationType::SelfAttestation`.
- **Basic attestation** (`x5c` present): detected and returns `AttestationType::Basic`.
  Certificate chain is not verified — no FIDO MDS trust anchor set available.
- **FIDO U2F** (`"fido-u2f"`): signature verified against the attestation cert's
  EC P-256 public key. Returns `AttestationType::Basic`. Certificate chain not verified.
- **Android Key** (`"android-key"`): `alg`, `sig`, and `x5c` are required. The
  attestation cert's EC P-256 public key must equal the credential public key
  (the key security property proving the key lives in a hardware-backed Keystore).
  Signature verified over `authData || clientDataHash`. Returns `AttestationType::Basic`.
  Certificate chain not verified.
- **Apple** (`"apple"`): `x5c` is required. The credential certificate must contain
  the Apple nonce extension (OID 1.2.840.113635.100.8.2) whose value equals
  SHA-256(`authData || clientDataHash`). The cert's EC P-256 public key must equal
  the credential public key. Returns `AttestationType::Basic`. Certificate chain not verified.
- Other formats (`"tpm"`, etc.): accepted with `AttestationType::None`
  (provenance unverifiable but credential usable).

`parse_attestation_object` in `registration.rs` was updated to return the `attStmt`
CBOR value alongside `fmt` and `authData`. The `attestation::verify` signature was
extended to accept `att_stmt`, `auth_data_bytes`, `client_data_hash`, and
`credential_public_key`.

`AttestationType::Basic` variant was added to `credential.rs`.

### Axum HTTP server example (`examples/server.rs`)

A real Axum 0.7 HTTP server that exercises the full Caden library API:

| Endpoint | Description |
|----------|-------------|
| `GET  /health` | Version check |
| `POST /register/begin` | Issue registration challenge |
| `POST /register/complete` | Verify attestation, store credential |
| `POST /authenticate/begin` | Issue authentication challenge |
| `POST /authenticate/complete` | Verify assertion, update sign count |

State is in-memory (`tokio::sync::Mutex<HashMap<…>>`). `axum`, `tokio`, and `tower`
added as dev-dependencies.

### crates.io preparation

- Package name changed to `webauthn-rs-demo` (the `webauthn` name is taken);
  `[lib] name = "webauthn"` keeps the Rust import path unchanged for all existing code.
- `Cargo.toml` updated with `description`, `keywords`, `categories`, `repository`,
  `documentation`, `license = "MIT OR Apache-2.0"`, `rust-version = "1.70"`.
- `LICENSE-MIT` and `LICENSE-APACHE` added.
- `CHANGELOG.md` added.
- `cargo package --no-verify --allow-dirty` produces zero warnings (46 files, ~89 KiB).

### cargo doc polish

- `src/lib.rs` crate-level doc comment updated: complete quick-start example
  (registration + authentication), algorithm table, security properties summary,
  learning-project disclaimer, spec references.
- `src/attestation.rs` doc comment updated to reflect `"packed"` support.
- Two bare URLs in module doc comments wrapped as `<URL>` to eliminate the two
  `rustdoc::bare_urls` warnings. `cargo doc --no-deps` now produces zero warnings.

### How to prepare a release

1. Update `version` in `Cargo.toml` and `CHANGELOG.md`.
2. Run the quality suite: `cargo build && cargo clippy -- -D warnings && cargo test && cargo fmt --check && cargo doc --no-deps`.
3. `cargo package --no-verify` to verify the .crate file.
4. `git tag v<version> && git push --tags`.
5. `cargo publish` (requires `cargo login` with crates.io token first).

---

## Multiple allowed origins

`RelyingParty` now holds `allowed_origins: Vec<String>` instead of a single
`origin: String`. The origin check in `validate_client_data` accepts the
client-supplied origin if it equals **any** entry in the list (exact match).

### Constructors

| Constructor | When to use |
|-------------|-------------|
| `RelyingParty::new(id, origin, name)` | Single origin — existing callers compile unchanged |
| `RelyingParty::with_origins(id, origins, name)` | Multiple origins — accepts any `IntoIterator<Item = impl Into<String>>` |

```rust
// Single origin (backward-compatible with all existing code)
let rp = RelyingParty::new("example.com", "https://example.com", "My Service");

// Multiple origins — prod + localhost in one instance
let rp = RelyingParty::with_origins(
    "example.com",
    ["https://example.com", "http://localhost:8080"],
    "My Service",
);
```

### Error behaviour

`WebAuthnError::OriginMismatch.expected` now contains the allowed list formatted
as a comma-separated string (e.g. `"https://example.com, http://localhost:8080"`).
For a single-origin RP the string is identical to the old single-origin display.

### What changed

| File | Change |
|------|--------|
| `src/registration.rs` | `RelyingParty.origin` → `allowed_origins: Vec<String>`; added `with_origins()` |
| `src/authentication.rs` | Passes `&rp.allowed_origins` to `validate_client_data` |
| `src/client_data.rs` | `validate_client_data` last param `&str` → `&[String]`; origin check uses `.any()` |
| `tests/integration.rs` | Added `multi_origin_relying_party_accepts_registered_origin` |

---

## CI & Quality

### Pipeline overview

GitHub Actions runs `.github/workflows/ci.yml` on every push and pull request to `main`.
Three jobs run in parallel:

| Job | What it runs |
|-----|-------------|
| **Build & Test** | `cargo build`, `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo doc --no-deps`, `cargo run --example demo` |
| **MSRV (1.70)** | `cargo build` + `cargo test` on Rust 1.70 |
| **Security Audit** | `cargo audit` via `cargo-audit` |

### Always run `cargo fmt` before committing

The CI `fmt --check` step fails on any unformatted file. Run `cargo fmt` locally before
every commit to avoid a red CI build. The `/check` command does this for you.

### Running the full CI suite locally

Use `/check` or run manually in this order (same as CI):

```bash
cargo build
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo doc --no-deps 2>&1 | grep "^error" && exit 1 || true
cargo run --example demo
```

All six must pass before pushing.

### MSRV — Minimum Supported Rust Version (1.70)

`rust-version = "1.70"` in `Cargo.toml` declares that the crate compiles on Rust 1.70.
The MSRV job on CI enforces this by building and testing on that exact toolchain.
1.70 was chosen because it is the oldest stable release that supports all features used
in this crate (notably `let-else` and `is_some_and`). Bump the MSRV intentionally when
adopting a newer language feature, and update `Cargo.toml`, `CLAUDE.md`, and the CI job.

### cargo-audit — dependency vulnerability scanning

`cargo audit` checks every dependency in `Cargo.lock` against the
[RustSec Advisory Database](https://rustsec.org/). It fails the build if any dependency
has a known CVE or security advisory. The security-audit CI job installs `cargo-audit`
with `--locked` to get a reproducible version.

To run locally (requires `cargo install cargo-audit`):
```bash
cargo audit
```

If audit fails on CI, check the advisory at `rustsec.org/advisories/<ID>` and either:
- Upgrade the affected dependency to a patched version, or
- Add a `[patch]` or `[dependencies]` version bump in `Cargo.toml`.

### Fixing a failing CI build

1. Check the failing job in the GitHub Actions tab.
2. Reproduce locally with the command from the table above.
3. Fix the issue, run `/check` to confirm all six steps pass, then push.
4. For MSRV failures: the code uses a feature not available in Rust 1.70 — rewrite to avoid it.
5. For audit failures: upgrade the flagged dependency or open an issue to track it.
