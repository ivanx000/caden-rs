# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Packed attestation AAGUID certificate binding** (W3C §8.2.1 step 2) — when
  a `"packed"` basic-attestation leaf certificate carries the
  `id-fido-gen-ce-aaguid` X.509 extension (OID `1.3.6.1.4.1.45724.1.1.4`), its
  value is now verified against the AAGUID reported in `authenticatorData`.
  The extension is optional and the check is skipped when it is absent (or
  when the leaf certificate cannot be parsed as DER, matching the existing
  fast path used when no chain/trust-anchor validation is in play). A
  mismatch returns the new `WebAuthnError::AttestationAaguidMismatch`
  variant.

- **FIDO Metadata Service (MDS) status consumption** (W3C §14.4) — new
  `src/metadata.rs` module with an `AuthenticatorStatus` enum mirroring the
  FIDO Alliance MDS `AuthenticatorStatus` values, plus
  `RelyingParty::authenticator_metadata` for supplying per-AAGUID status
  lists. `caden` does not fetch or parse the MDS BLOB itself (that requires
  network access and JWS verification, which conflicts with the library's
  stateless, I/O-free design) — the caller fetches and verifies the BLOB
  out-of-band and passes the resulting statuses in. When a registering
  authenticator's AAGUID has an entry containing a status for which
  `AuthenticatorStatus::is_compromised()` is `true` (`Revoked`,
  `AttestationKeyCompromise`, `UserKeyRemoteCompromise`,
  `UserKeyPhysicalCompromise`, `UserVerificationBypass`),
  `verify_registration` now returns the new
  `WebAuthnError::AuthenticatorStatusUntrusted` variant.

- **Packed attestation cert Basic Constraints check** (W3C §8.2.1 Certificate
  Requirements for Packed Attestation Statements) — a `"packed"`
  basic-attestation leaf certificate whose Basic Constraints extension has
  the CA component set to `true` is now rejected with the new
  `WebAuthnError::AttestationCertIsCa` variant. A CA-capable leaf is a signal
  that a CA certificate is being substituted for a genuine attestation
  leaf. As with the AAGUID extension check, this is only enforced when the
  extension is present and parseable — many real-world attestation
  certificates omit Basic Constraints entirely for non-CA end-entity certs
  rather than including it with an explicit `CA:FALSE`, so an absent
  extension is not treated as a failure.

---

## [0.9.0] — 2026-07-14

### Added

- **`RegistrationOptions::exclude_credentials`** — new field on [`RegistrationOptions`]
  populated from a new `exclude_credentials` parameter on
  [`RelyingParty::begin_registration`]. Pass the credential IDs already
  registered for the user; the browser instructs the authenticator to refuse
  re-registering any matching credential. Serialized as `"excludeCredentials"`
  (same shape as `"allowCredentials"`). An empty iterator produces an empty
  array — the browser treats this as no restriction, matching the previous
  behaviour. **Breaking change**: `begin_registration` now requires a second
  argument; existing callers must add `std::iter::empty::<Vec<u8>>()` (or the
  real credential list) to compile.

- **`RelyingParty::default_authenticator_selection`** — new builder method that
  sets a default [`AuthenticatorSelection`] value. When set, the value is
  copied into every [`RegistrationOptions`] produced by `begin_registration`.
  When `None` (the default), the `"authenticatorSelection"` field is omitted
  from the serialized JSON as before. The corresponding
  `default_authenticator_selection` field on `RelyingParty` is `pub`.

- **`RelyingParty::authentication_options`** — new method that builds and returns
  an [`AuthenticationOptions`] value ready to serialize and send to the browser
  as `PublicKeyCredentialRequestOptions`. Accepts an iterator of raw credential
  ID bytes for the `allowCredentials` list; an empty iterator produces the
  discoverable-credential (passkey) flow where the authenticator picks any
  matching credential. New supporting types added to `src/options.rs`:
  [`AuthenticationOptions`], [`PublicKeyCredentialDescriptor`],
  [`AuthenticatorTransport`]. All W3C JSON keys use camelCase and IDs are
  base64url-encoded with no padding.

---

## [0.8.0] — 2026-07-05

### Added

- **Typed extension accessors** (`src/extensions.rs`) — new public module with
  three typed extension types:
  - [`CredProps`] (`"credProps"`, §10.4) — `rk: Option<bool>` indicating whether
    the credential was created as a discoverable credential.
  - `appid` (`"appid"`, §10.1) — `Option<bool>` indicating whether the legacy
    U2F App ID substitution was applied.
  - [`PrfExtension`] / [`PrfValues`] (`"prf"`) — typed PRF output with `first`
    and optional `second` byte-string results.
  - [`ExtensionView`] — a borrow of the raw extension map with typed accessor
    methods `cred_props()`, `appid()`, and `prf()`.

- **`RegistrationResult::extensions()`** and **`AuthenticationResult::extensions()`**
  — new methods returning `Option<ExtensionView<'_>>`. When extension data is
  present these provide typed accessors; the raw `extensions` field remains
  accessible for extensions not yet modelled by the typed API.

- **`#[non_exhaustive]`** on `AttestationType`, `PublicKey`, and `WebAuthnError`
  — adding any new variant to these public enums is no longer a semver-breaking
  change. Downstream callers matching exhaustively will need a `_ => ...`
  wildcard arm; callers that use `matches!()` or `if let` are unaffected.

---

## [0.7.0] — 2026-07-03

### Added

- **`backup_state` field on `Credential`** — tracks whether the credential's
  private key is currently backed up to a cloud or sync service, derived from
  the BS flag in `authenticatorData`. Complements the existing `backup_eligible`
  field; both fields are exposed in `RegistrationResult` and
  `AuthenticationResult`. `serde` serialization round-trips the field correctly.

- **EdDSA (Ed25519) in `examples/demo.rs`** — the end-to-end demo now exercises
  the full EdDSA ceremony: registration, successful authentication, and replay
  attack rejection, mirroring the ES256/RS256/ES384 blocks already present.

- **ES384 in `examples/demo.rs`** — the end-to-end demo now exercises the full
  ES384 ceremony: registration, successful authentication, and replay attack
  rejection.

- **EdDSA advertised in `examples/server.rs`** — `POST /register/begin` now
  includes `{ type: "public-key", alg: -8 }` (EdDSA/Ed25519) in
  `pub_key_cred_params`, alongside ES256 (-7), ES384 (-35), and RS256 (-257).

- **ES384 advertised in `examples/server.rs`** — `POST /register/begin` now
  includes `{ type: "public-key", alg: -35 }` (ES384/P-384) in
  `pub_key_cred_params`.

---

## [0.6.0] — 2026-07-01

### Added

- **TPM attestation** (`"tpm"`, W3C WebAuthn §8.3) — full TPM 2.0 certify
  attestation verification. `ver` must be `"2.0"`, `alg` must match the
  credential key algorithm, and `x5c` must be present (ECDAA is not supported).
  `certInfo` (TPM2B_ATTEST) is parsed and validated: magic `0xFF544347`, type
  `0x8017`, `extraData` must equal `SHA-256(authData || clientDataHash)`, and
  `attested.name` must equal `nameAlg_bytes || H_nameAlg(pubArea)`. `pubArea`
  (TPMT_PUBLIC) is parsed for ECC (`0x0023`) and RSA (`0x0001`) key types; the
  unique field is compared against the stored credential key. `sig` is verified
  over the raw `certInfo` bytes using the AIK certificate's public key.
  `nameAlg` supports SHA-256 (`0x000B`) and SHA-384 (`0x000C`). Returns
  `AttestationType::Basic`.

- **Authenticator extension map** (W3C WebAuthn §6.1 / §10.5) — when the ED
  flag (bit 7) is set in `authenticatorData`, the trailing CBOR extension map
  is now decoded and stored as `extensions: Option<HashMap<String,
  ciborium::Value>>` on `AuthenticatorData`. `parse_extension_map` decodes the
  CBOR; `parse_attested_credential_data` now returns `(AttestedCredentialData,
  usize)` so the caller can locate extension bytes that follow the COSE key
  without a second parse path.

- **Extension data in result types** — `RegistrationResult` and
  `AuthenticationResult` now expose `extensions: Option<HashMap<String,
  ciborium::Value>>` forwarded directly from `AuthenticatorData`. Callers can
  inspect authenticator extension data (e.g. `credProps`, `appid`) after a
  successful ceremony. The field is excluded from `serde` serialization because
  `ciborium::Value` has no portable JSON representation.

- **`x5c` certificate chain verification** — the `x5c` array in `"packed"`,
  `"fido-u2f"`, `"android-key"`, `"apple"`, and `"tpm"` attestation formats is
  now verified for correct chain order: each certificate must be signed by the
  next entry in the array (§7.1 step 22). New dependency: `x509-parser 0.16`
  (with the `verify` feature). New dev-dependency: `rcgen 0.13` (used in chain
  verification tests).

- **`RelyingParty::trust_anchors`** — new builder method that accepts a list
  of DER-encoded root CA certificates. When configured, the chain root is
  checked against the anchor set after order verification. A chain whose root
  matches a trust anchor returns `AttestationType::BasicVerified`; one that
  does not returns `AttestationType::Basic`.

- **`AttestationType::BasicVerified`** — new variant on `AttestationType`
  (`credential.rs`) indicating that the attestation certificate chain was
  verified all the way to a configured trust anchor.

- **`WebAuthnError::AttestationChainInvalid`** — returned when `x5c` chain
  order verification fails (a certificate is not signed by the next entry).

- **`WebAuthnError::AttestationRootUntrusted`** — returned when trust anchors
  are configured and the chain root does not match any of them.

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

[0.9.0]: https://github.com/ivanxie/caden-rs/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/ivanxie/caden-rs/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/ivanxie/caden-rs/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/ivanxie/caden-rs/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/ivanxie/caden-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ivanxie/caden-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ivanxie/caden-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ivanxie/caden-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ivanxie/caden-rs/releases/tag/v0.1.0
