# Architecture

How this WebAuthn library is structured and why.

---

## Module map

```
webauthn
├── lib.rs                  Public API surface
│   └── RelyingParty        Stateless ceremony verifier (entry point)
│   └── AuthenticatorAttestationResponse   Registration wire type
│   └── AuthenticatorAssertionResponse     Authentication wire type
│
├── error.rs                WebAuthnError enum + Result alias
│
├── credential.rs           Domain types
│   ├── Credential          Stored credential (post-registration)
│   ├── PublicKey           ES256 { x, y } / RS256 { n, e } public key wrapper
│   ├── Challenge           Random bytes + creation timestamp
│   ├── RegistrationResult  Return value of verify_registration
│   ├── AuthenticationResult Return value of verify_authentication
│   └── AttestationType     None / SelfAttestation
│
├── algorithm.rs            COSE algorithm + key-type constants
│   ├── COSE_ES256 = -7     ECDSA P-256 with SHA-256
│   ├── COSE_RS256 = -257   RSA PKCS#1 v1.5 with SHA-256
│   ├── COSE_KTY_EC2 = 2    EC2 key type
│   ├── COSE_KTY_RSA = 3    RSA key type
│   └── COSE_CRV_P256 = 1   P-256 curve
│
├── der.rs                  Minimal DER builder for RSA public keys
│   ├── rsa_components_to_der()  (n, e) → SEQUENCE { INTEGER n, INTEGER e }
│   └── der_length / der_sequence / der_integer / der_bit_string / der_oid
│
├── crypto.rs               Cryptographic primitives (delegated to ring)
│   ├── sha256()            SHA-256 digest
│   ├── verify_es256()      ECDSA P-256 verification
│   ├── verify_rs256()      RSA PKCS#1 v1.5 SHA-256 verification
│   └── generate_challenge() 32-byte CSPRNG challenge
│
├── challenge.rs            Challenge lifecycle helpers
│   ├── is_expired()        Checks against 5-minute default
│   └── is_expired_with_max_age()  Configurable expiry
│
├── client_data.rs          clientDataJSON parsing
│   └── parse_client_data() raw bytes → UTF-8 → JSON → ClientData
│
├── authenticator_data.rs   Binary authenticator data parsing
│   ├── parse_authenticator_data()  Raw bytes → AuthenticatorData
│   └── (internal) parse_cose_key()  CBOR COSE key → CoseKey enum
│         ├── CoseKey::EC2 { alg, crv, x, y }   for ES256
│         └── CoseKey::RSA { alg, n, e }         for RS256
│
├── attestation.rs          Attestation statement verification
│   └── verify()            Only "none" format currently supported
│
├── registration.rs         §7.1 registration ceremony
│   └── verify_registration()  Dispatches CoseKey → PublicKey::ES256 or ::RS256
│
└── authentication.rs       §7.2 authentication ceremony
    └── verify_authentication()  Dispatches PublicKey → verify_es256 or verify_rs256
```

---

## Data flow: registration

```
AuthenticatorAttestationResponse
    │
    │  client_data_json  (raw bytes)
    ├─► UTF-8 decode → serde_json::parse → ClientData
    │     │
    │     ├─ verify type == "webauthn.create"
    │     ├─ verify challenge bytes match issued challenge
    │     └─ verify origin == expected_origin
    │
    │  attestation_object  (raw bytes)
    └─► CBOR decode (ciborium) → {fmt, authData}
          │
          │  authData  (raw bytes)
          └─► parse_authenticator_data()
                ├─ rp_id_hash [0..32]  → verify == SHA-256(rp_id)
                ├─ flags [32]          → verify UP bit is set
                ├─ sign_count [33..37] → stored in Credential
                └─ attested_credential_data [37..]
                      ├─ aaguid [0..16]
                      ├─ credential_id
                      └─ COSE key (CBOR) → parse_cose_key()
                            ├─ kty=2 (EC2): x, y → 0x04 || x || y → PublicKey::ES256
                            └─ kty=3 (RSA): n, e → PublicKey::RS256

→ attestation::verify(fmt, ...)   [only "none" accepted]
→ Credential { id, public_key, sign_count, user_id, rp_id, created_at }
→ RegistrationResult { credential, attestation_type }
```

## Data flow: authentication

```
Stored Credential + AuthenticatorAssertionResponse
               │
        parse_client_data()
         [type="webauthn.get"]
               │
        validate_client_data()
         challenge match + origin match
               │
        SHA-256(clientDataJSON bytes) → clientDataHash
               │
        parse_authenticator_data()
         [verify rpIdHash + UP flag]
               │
        build verification data:
        authData bytes || clientDataHash
               │
        dispatch on PublicKey variant:
         ES256 → verify_es256()  [ring ECDSA_P256_SHA256_ASN1]
         RS256 → rsa_components_to_der(n,e) → verify_rs256()
                  [ring RSA_PKCS1_2048_8192_SHA256]
               │
        check sign_count > stored
         [SignCountInvalid if not]
               │
        return AuthenticationResult {
          credential_id, new_sign_count,
          user_present, user_verified
        }
```

---

## Design decisions

### Why `ring` instead of RustCrypto?

`ring` is a production-grade crypto library descended from BoringSSL. It:
- Has been audited by Cure53
- Is used in production by Cloudflare, Firefox, and many others
- Minimizes the API surface to reduce misuse (no ad-hoc cipher composition)
- Provides constant-time implementations by default

RustCrypto (`ecdsa`, `p256`, `sha2`) is also correct and audited, but `ring`'s
more constrained API is harder to misuse — appropriate for a security-focused project.

### Why `ciborium` for CBOR?

ciborium is a pure-Rust CBOR library that implements RFC 7049 and deserializes into
a `Value` enum. WebAuthn uses CBOR in two places: the attestation object and the
COSE key inside authenticator data. ciborium's `Value` type lets us navigate these
structures without defining serde schemas for CBOR, keeping the parsing code explicit
and easy to follow.

### Why separate registration.rs and authentication.rs?

The W3C spec separates the two ceremonies into §7.1 and §7.2. Keeping them in
separate files means each file directly maps to one spec section. Reviewers can
read the spec and the code side-by-side without context-switching.

### Why is RelyingParty stateless?

Credential storage is application-specific. A relying party might store credentials
in Postgres, Redis, DynamoDB, or an in-memory hashmap. Baking storage into
`RelyingParty` would force a choice that most callers would need to undo. The
caller passes `&Credential` in and gets a `Credential` out; they are responsible
for persistence.

### Why are the response types separate from the core types?

`AuthenticatorAttestationResponse` and `AuthenticatorAssertionResponse` are wire
types — they match the shape of the `navigator.credentials` API in browsers. The
internal types (`ClientData`, `AuthenticatorData`) are richer, fully parsed
representations. Keeping them separate means the parsing code is testable
independently of the rest of the verification logic.

### Algorithm dispatch

`PublicKey` is an enum with two variants: `ES256 { x, y }` and `RS256 { n, e }`.
The authentication ceremony matches on the variant and calls the appropriate
verifier. Adding a third algorithm (e.g., EdDSA) means extending the enum,
adding a COSE parser branch, and adding a `verify_ed25519` function — no changes
to the ceremony control flow.

### Why does ES256 use the uncompressed point format?

ring's `ECDSA_P256_SHA256_ASN1` verifier expects public keys as uncompressed EC
points: `0x04 || x (32 bytes) || y (32 bytes)`. COSE keys encode `x` and `y`
separately; the library reassembles the uncompressed point at authentication time.

### Why does RS256 use RSAPublicKey (not SubjectPublicKeyInfo)?

ring's RSA verification API (`RSA_PKCS1_2048_8192_SHA256` with `UnparsedPublicKey`)
parses the public key as an `RSAPublicKey` per RFC 3447 §A.1.1:
`SEQUENCE { INTEGER n, INTEGER e }`. This is the inner format, without the
SubjectPublicKeyInfo wrapper (OID + BIT STRING). `der.rs` builds exactly this
structure. The empirical evidence: `ring::rsa::KeyPair::public().as_ref()`
returns 270 bytes (RSAPublicKey), not 294 bytes (SubjectPublicKeyInfo).

---

## Spec compliance reference

| Spec section | Library location |
|---|---|
| §6.1 Authenticator Data | `authenticator_data.rs` |
| §6.5 Attestation | `attestation.rs` |
| §7.1 Registration | `registration.rs` |
| §7.2 Authentication | `authentication.rs` |
| §8.7 "none" attestation | `attestation.rs::verify` |
| RFC 8152 COSE keys | `authenticator_data::parse_cose_key` |

---

## Error handling philosophy

Every error in this library follows three rules:

1. **Typed and named** — every failure mode has its own `WebAuthnError` variant.
   Callers can match on the exact variant to decide how to respond (log and reject
   vs. block the user vs. flag for review).

2. **The library never panics** — `#![deny(clippy::unwrap_used)]` is enforced
   at compile time. `.unwrap()` is a compile error in all library code. This
   guarantees that malformed, truncated, or adversarial input always produces a
   `Result::Err`, never a panic. This property is verified by the no-panic fuzz
   tests in `tests/integration.rs`.

3. **Messages are informative but do not leak secrets** — error messages name
   the exact failing field and include context (e.g., actual vs. expected length),
   but never include raw key bytes, signature bytes, or challenge values. A
   developer can diagnose the problem from the error message alone without a
   stack trace.

---

## Known limitations and future work

- **EdDSA / Ed25519** — not supported; would require `ring`'s Ed25519 verify path.
- **ES384 / ES512** — not supported; would require P-384/P-521 ring API.
- **Packed attestation** — requires certificate chain validation against the FIDO
  MDS. Substantial additional code.
- **Extension data** — authenticator data extensions are silently ignored.
- **Token binding** — not checked.
- **Multiple origins** — a `Vec<String>` of allowed origins could replace the
  single `expected_origin`.
- **`crossOrigin` enforcement** — the `crossOrigin: true` case is accepted, which
  some relying parties should reject.
