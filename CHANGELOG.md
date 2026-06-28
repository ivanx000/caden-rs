# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [0.5.0] — 2026-06-28

### Added

- **`serde` feature flag** — opt-in `Serialize` + `Deserialize` derives on all
  public types: `Credential`, `PublicKey`, `Challenge`, `RegistrationResult`,
  `AuthenticationResult`, `AttestationType`, and `WebAuthnError`. Enable with
  `features = ["serde"]` in `Cargo.toml`. `Vec<u8>` fields use
  `serde_bytes` so they round-trip as compact byte sequences (base64 in JSON)
  rather than arrays of integers. `serde` itself remains an unconditional
  dependency (used internally for `clientDataJSON` parsing); only the public-type
  derives are gated behind the feature. New optional dependency: `serde_bytes 0.11`.

---

## [0.4.0] — 2026-06-27

### Added

- **Cross-origin rejection** (`RelyingParty::reject_cross_origin`) — new opt-in
  policy (default `false`). When enabled, `verify_registration` and
  `verify_authentication` return `WebAuthnError::CrossOriginNotAllowed` for any
  response whose `clientDataJSON` contains `crossOrigin: true` (§7.1 step 10 /
  §7.2 step 12). Use when your RP never embeds WebAuthn in a cross-origin
  iframe.

- **Algorithm allowlist** (`RelyingParty::allowed_algorithms`) — new opt-in
  builder method. When the list is non-empty, `verify_registration` returns
  `WebAuthnError::UnsupportedAlgorithm` for any credential algorithm not in
  the list (§7.1 step 17). An empty list (the default) accepts all three
  supported algorithms (ES256, EdDSA, RS256). Accepts any `IntoIterator<Item =
  i64>`, e.g. `.allowed_algorithms([COSE_ES256])`.

- **BE / BS flag support** (W3C WebAuthn §6.1) — `AuthenticatorFlags` now
  parses the Backup Eligibility (BE, bit 3) and Backup State (BS, bit 4) flags.
  The §6.1 invariant (BS requires BE) is enforced at parse time; a BS-without-BE
  combination returns `WebAuthnError::InvalidAuthenticatorData`. Both flags are
  exposed on `RegistrationResult` and `AuthenticationResult`.

- **Backup Eligibility policies** — two new opt-in `RelyingParty` policies
  enforced at both ceremonies (§7.1 step 18 / §7.2 step 21):
  - `require_backup_eligible(true)` — rejects credentials with BE=false
    (`WebAuthnError::BackupEligibilityRequired`). Use for consumer passkey
    deployments that rely on platform sync (iCloud Keychain, Google Password
    Manager).
  - `reject_backup_eligible(true)` — rejects credentials with BE=true
    (`WebAuthnError::BackupEligibleNotAllowed`). Use for high-security
    environments that require hardware-bound, non-syncable keys.

- **BE immutability enforcement** — `Credential` now stores `backup_eligible`
  (populated at §7.1 step 25). `verify_authentication` checks that the BE flag
  in the authenticator data matches the stored value; a mismatch returns
  `WebAuthnError::BackupEligibilityChanged`. BE is immutable per spec — a
  changed value indicates a possible credential substitution attack.

---

## [0.3.0] — 2026-06-24

### Added

- **Apple attestation** (`"apple"`, W3C WebAuthn §8.8) — `attestation::verify` now handles
  the Apple format. `x5c` is required. The Apple nonce extension (OID
  `1.2.840.113635.100.8.2`) is extracted from the credential certificate; its value must
  equal `SHA-256(authData || clientDataHash)`. The cert's EC P-256 public key must match
  the credential public key. Returns `AttestationType::Basic`. Certificate chain not
  verified (no Apple MDS trust anchors). DER TLV parsing helpers (`der_parse_tlv`,
  `der_unwrap_sequence`, `der_unwrap_octet_string`) added inline — no new dependencies.

- **UV flag enforcement** (`RelyingParty::require_user_verification`) — `RelyingParty`
  now has a `require_user_verification: bool` field (defaults to `false` — no breaking
  change). Set via the new builder method `require_user_verification(true)`. When enabled,
  `verify_authentication` enforces §7.2 step 21: if the UV flag is not set, it returns
  `WebAuthnError::UserNotVerified` (new error variant). This is the library-level mechanism
  for applications that need mandatory biometric or PIN verification on every sign-in.

---

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

[0.5.0]: https://github.com/ivanxie/caden-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ivanxie/caden-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ivanxie/caden-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ivanxie/caden-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ivanxie/caden-rs/releases/tag/v0.1.0
