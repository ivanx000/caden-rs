// Security libraries must not panic on any input — a panic in a security
// check aborts the ceremony rather than returning a typed error, potentially
// allowing callers to misinterpret the outcome. Use ? and explicit error
// variants everywhere; reserve .expect() for invariants guaranteed by the
// surrounding bounds checks (e.g. try_into() on a slice whose length was
// just verified). .unwrap() is unconditionally forbidden in library code.
#![deny(clippy::unwrap_used)]

//! # webauthn — WebAuthn relying-party library
//!
//! Implements the server-side (relying party) logic for the two core
//! WebAuthn ceremonies:
//!
//! - **Registration** — the authenticator generates a keypair and the relying
//!   party verifies and stores the public key.
//! - **Authentication** — the authenticator signs a challenge with the private
//!   key and the relying party verifies the signature.
//!
//! > **Learning project** — this library demonstrates a correct implementation
//! > of the W3C WebAuthn spec. It is not intended for production use without
//! > additional review: challenge single-use enforcement, credential uniqueness
//! > checks, and FIDO Metadata Service integration are all the caller's
//! > responsibility.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use webauthn::{RelyingParty, AuthenticatorAttestationResponse};
//! use webauthn::Challenge;
//!
//! // 1. Configure the relying party once, at startup.
//! let rp = RelyingParty::new("example.com", "https://example.com", "My Service");
//!
//! // 2. Issue a registration challenge for this user.
//! let challenge = Challenge::new().unwrap();
//!
//! // 3. Receive the attestation response from the browser.
//! # let response = AuthenticatorAttestationResponse {
//! #     client_data_json: vec![],
//! #     attestation_object: vec![],
//! # };
//! let result = rp.verify_registration(&challenge, &response, b"user-id-42").unwrap();
//!
//! // 4. Store result.credential in your database.
//! let stored = result.credential;
//! ```
//!
//! ## Supported algorithms
//!
//! | Algorithm | COSE ID | Description |
//! |-----------|---------|-------------|
//! | ES256     | `-7`    | ECDSA P-256 with SHA-256 — recommended, most common |
//! | RS256     | `-257`  | RSA PKCS#1 v1.5 with SHA-256 — legacy devices |
//!
//! EdDSA and ES384 are not yet supported. See the
//! [COSE algorithm registry](https://www.iana.org/assignments/cose/cose.xhtml)
//! for the full list of identifiers.
//!
//! ## Spec references
//!
//! - [W3C WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/)
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

pub use algorithm::{COSE_ES256, COSE_RS256};
pub use authentication::AuthenticatorAssertionResponse;
pub use challenge::{is_expired, is_expired_with_max_age, CHALLENGE_MAX_AGE_SECS};
pub use credential::{
    AttestationType, AuthenticationResult, AuthenticatorAttestationResponse, Challenge, Credential,
    PublicKey, RegistrationResult,
};
pub use crypto::{generate_challenge, random_bytes, rsa_components_to_der, sha256};
pub use error::{Result, WebAuthnError};
pub use registration::RelyingParty;
