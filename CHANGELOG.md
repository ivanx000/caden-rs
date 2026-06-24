# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-06-21

### Added

- **EdDSA / Ed25519** (COSE algorithm -8) — third supported signature algorithm.
  New `PublicKey::EdDSA(Vec<u8>)` variant stores the 32-byte raw public key.
  `CoseKey::OKP { alg, x }` added to the COSE key parser. `verify_eddsa()` in
  `src/crypto.rs` delegates to `ring::signature::ED25519`. Both ceremonies dispatch
  on the new variant. Integration tests cover full registration → authentication →
  replay rejection for Ed25519.

- **FIDO U2F attestation** (`"fido-u2f"`, W3C WebAuthn §8.6) — `attestation::verify`
  now handles the FIDO U2F format. The attestation cert's EC P-256 public key is
  extracted from `x5c[0]`, and a signature over the U2F verification data
  (`0x00 || rpIdHash || clientDataHash || credentialId || publicKey`) is verified.
  Returns `AttestationType::Basic`. Certificate chain not verified (no FIDO MDS).

- **Android Key attestation** (`"android-key"`, W3C WebAuthn §8.4) — `attestation::verify`
  now handles the Android Key format. Requires `alg`, `sig`, and `x5c`. The key
  security property is enforced: the attestation certificate's public key must equal
  the credential public key (proving the key lives in a hardware-backed Android
  Keystore). Signature verified over `authData || clientDataHash`. Returns
  `AttestationType::Basic`. Certificate chain not verified (no FIDO MDS).

- **Multiple allowed origins** — `RelyingParty` now holds `allowed_origins: Vec<String>`
  instead of a single `origin: String`. New `RelyingParty::with_origins(id, origins,
  name)` constructor accepts any `IntoIterator<Item = impl Into<String>>`, enabling a
  single instance to serve multiple environments (e.g. `"https://example.com"` and
  `"http://localhost:8080"`). `RelyingParty::new` wraps its argument into a
  one-element Vec — all existing callers compile unchanged. `validate_client_data`
  checks membership with `.any()` rather than equality.

- **GitHub Actions CI** — `.github/workflows/ci.yml` with three parallel jobs:
  *Build & Test* (`cargo build`, `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo test`, `cargo doc --no-deps`, `cargo run --example demo`);
  *MSRV* (Rust 1.70 build + test);
  *Security Audit* (`cargo audit` via `cargo-audit`).

### Fixed

- **CI / MSRV lockfile** — restored a Rust 1.70-compatible `Cargo.lock` so the MSRV
  job does not fail on dependency resolution (PR #1).

- **GitHub Actions build** — corrected workflow configuration so all three CI jobs
  pass on the `main` branch (PR #2).

---

## [0.1.0] — 2026-06-14

### Added

- **Registration ceremony** (W3C WebAuthn Level 2, §7.1)
  - `RelyingParty::verify_registration` verifies clientDataJSON, attestation object, and
    authenticator data for new credential registration
- **Authentication ceremony** (W3C WebAuthn Level 2, §7.2)
  - `RelyingParty::verify_authentication` verifies clientDataJSON, authenticator data, and
    ECDSA/RSA signature for subsequent authentication
- **ES256** — ECDSA P-256 + SHA-256 (COSE algorithm -7), the most common WebAuthn algorithm
- **RS256** — RSA PKCS#1 v1.5 + SHA-256 (COSE algorithm -257), for legacy YubiKey 4 devices
  and Windows Hello
- **Packed attestation** — self-attestation fully verified; basic attestation (x5c) detected
  but certificate chain not verified (no FIDO MDS integration)
- **None attestation** — accepted per §8.7
- **Sign-count replay protection** — received count must exceed stored count
- **Challenge expiry** — configurable TTL with `CHALLENGE_MAX_AGE_SECS` default
- **`#![forbid(unsafe_code)]`** — zero unsafe in this crate; enforced at compile time
- **`#![deny(clippy::unwrap_used)]`** — no panics in library code; enforced at compile time
- **No-panic fuzz tests** — two deterministic tests exercise all ceremony paths with random
  inputs and assert no panic occurs
- **Fixed test vectors** — pre-generated P-256 ceremony fixtures for regression detection
- **Axum server example** — `examples/server.rs` demonstrates real HTTP integration with all
  five WebAuthn endpoints
- **End-to-end demo** — `examples/demo.rs` exercises ES256 + RS256 registration, authentication,
  and replay attack rejection entirely in software

[0.2.0]: https://github.com/ivanxie/caden-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ivanxie/caden-rs/releases/tag/v0.1.0
