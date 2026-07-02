// Safety: This library handles security-critical operations. Unsafe code
// is forbidden to eliminate entire classes of memory safety vulnerabilities.
// All cryptographic operations are delegated to the `ring` crate which
// manages its own unsafe code behind a safe API.
#![forbid(unsafe_code)]
// Security libraries must not panic on any input — a panic in a security
// check aborts the ceremony rather than returning a typed error, potentially
// allowing callers to misinterpret the outcome. Use ? and explicit error
// variants everywhere; reserve .expect() for invariants guaranteed by the
// surrounding bounds checks (e.g. try_into() on a slice whose length was
// just verified). .unwrap() is unconditionally forbidden in library code.
#![deny(clippy::unwrap_used)]

//! # webauthn — WebAuthn relying-party library
//!
//! Server-side (relying party) verification for the two core WebAuthn ceremonies:
//!
//! - **Registration** (`navigator.credentials.create`) — the authenticator generates
//!   a public/private keypair. The relying party verifies the attestation and stores
//!   the public key and credential ID.
//! - **Authentication** (`navigator.credentials.get`) — the authenticator signs a
//!   challenge with the stored private key. The relying party verifies the signature
//!   and sign count.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use webauthn::{
//!     AuthenticatorAssertionResponse, AuthenticatorAttestationResponse,
//!     Challenge, RelyingParty,
//! };
//!
//! // Configure the relying party once at startup.
//! let rp = RelyingParty::new("example.com", "https://example.com", "My Service");
//!
//! // ── Registration ──────────────────────────────────────────────────────────
//!
//! // Issue a challenge, send it to the browser, receive the attestation response.
//! let reg_challenge = Challenge::new().expect("RNG failure");
//! # let reg_response = AuthenticatorAttestationResponse {
//! #     client_data_json: vec![],
//! #     attestation_object: vec![],
//! # };
//!
//! // Verify the registration and persist the returned credential.
//! let reg_result = rp
//!     .verify_registration(&reg_challenge, &reg_response, b"user-id-42")
//!     .expect("registration failed");
//! let stored_credential = reg_result.credential;
//!
//! // ── Authentication ────────────────────────────────────────────────────────
//!
//! // Issue a new challenge, send it to the browser, receive the assertion response.
//! let auth_challenge = Challenge::new().expect("RNG failure");
//! # let auth_response = AuthenticatorAssertionResponse {
//! #     client_data_json: vec![],
//! #     authenticator_data: vec![],
//! #     signature: vec![],
//! #     user_handle: None,
//! # };
//!
//! // Verify the assertion and update the stored sign count.
//! let auth_result = rp
//!     .verify_authentication(&stored_credential, &auth_challenge, &auth_response)
//!     .expect("authentication failed");
//! // Persist auth_result.new_sign_count to your database.
//! ```
//!
//! ## Supported algorithms
//!
//! | Algorithm | COSE ID | Description |
//! |-----------|---------|-------------|
//! | ES256     | `-7`    | ECDSA P-256 with SHA-256 — recommended, most common |
//! | ES384     | `-35`   | ECDSA P-384 with SHA-384 |
//! | EdDSA     | `-8`    | Ed25519 — newer FIDO2 authenticators |
//! | RS256     | `-257`  | RSA PKCS#1 v1.5 with SHA-256 — legacy YubiKey 4, Windows Hello |
//!
//! See the [COSE algorithm registry](https://www.iana.org/assignments/cose/cose.xhtml)
//! for the full list of identifiers.
//!
//! ## Security properties
//!
//! - **No unsafe code** — `#![forbid(unsafe_code)]` is enforced at compile time.
//!   All cryptographic operations are delegated to [`ring`], which descends from
//!   BoringSSL and manages its own unsafe code behind a safe API boundary.
//! - **No panics** — `#![deny(clippy::unwrap_used)]` prevents `.unwrap()` in library
//!   code. Every error path returns a typed [`WebAuthnError`] variant.
//! - **No custom crypto** — signature verification, hashing, and random number
//!   generation are all inside `ring`'s audited boundary.
//! - **Caller responsibilities** — credential uniqueness checks and FIDO
//!   Metadata Service integration are out of scope. Challenge single-use
//!   enforcement is opt-in via
//!   [`RelyingParty::enforce_single_use_challenges`].
//!
//! > **Learning project** — this library is a portfolio demonstration of a correct
//! > WebAuthn implementation. For production use, consider
//! > [`webauthn-rs`](https://crates.io/crates/webauthn-rs), which includes FIDO MDS
//! > integration and a broader attestation format set.
//!
//! ## Features
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `serde` | off | Derives [`serde::Serialize`] and [`serde::Deserialize`] on [`Credential`], [`PublicKey`], [`Challenge`], [`RegistrationResult`], [`AuthenticationResult`], [`AttestationType`], and [`WebAuthnError`]. `Vec<u8>` fields are encoded as compact byte sequences via [`serde_bytes`](https://docs.rs/serde_bytes) rather than arrays of integers. Enable with `features = ["serde"]` in `Cargo.toml`. |
//!
//! Note: `serde` and `serde_json` are unconditional dependencies used internally
//! for `clientDataJSON` parsing. The `serde` feature only controls whether the
//! public-facing types implement `Serialize`/`Deserialize`.
//!
//! ## Spec references
//!
//! - [W3C WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)
//! - [FIDO Alliance specifications](https://fidoalliance.org/specifications/)
//! - [RFC 8152 — COSE](https://www.rfc-editor.org/rfc/rfc8152)

// Internal modules
pub mod algorithm;
pub mod attestation;
pub mod authenticator_data;
pub mod challenge;
pub mod client_data;
pub mod credential;
pub mod crypto;
pub mod der;
pub mod error;

mod authentication;
mod registration;

// ─── Public re-exports ────────────────────────────────────────────────────────

pub use algorithm::{COSE_EDDSA, COSE_ES256, COSE_ES384, COSE_RS256};
pub use authentication::AuthenticatorAssertionResponse;
pub use challenge::{is_expired, is_expired_with_max_age, CHALLENGE_MAX_AGE_SECS};
pub use credential::{
    AttestationType, AuthenticationResult, AuthenticatorAttestationResponse, Challenge, Credential,
    PublicKey, RegistrationResult,
};
pub use crypto::{generate_challenge, random_bytes, rsa_components_to_der, sha256};
pub use error::{Result, WebAuthnError};
pub use registration::RelyingParty;
