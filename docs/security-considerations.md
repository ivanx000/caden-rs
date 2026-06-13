# Security Considerations

Detailed security notes for implementers using this WebAuthn library.

---

## Challenge security

### Why challenges must be random

The challenge is the relying party's proof that a ceremony response was produced
*now* and *for this session*. If an attacker can predict or reuse a challenge, they
can pre-compute or replay a valid signature.

**Requirements:**
- At least 128 bits of entropy (this library uses 256 bits — 32 bytes from the OS CSPRNG)
- Generated fresh for every ceremony, never reused
- Destroyed after a single use (the relying party must enforce this)

Challenges are generated via `ring::rand::SystemRandom`, which reads from
`/dev/urandom` on Linux/macOS and `BCryptGenRandom` on Windows. These are
cryptographically secure and cannot be predicted by an attacker.

### Why challenges must be single-use

A captured challenge + response could be replayed to authenticate without the
authenticator. If the same challenge is accepted more than once, a man-in-the-middle
who observed one authentication can impersonate the user in a second session.

**This library does not enforce single-use** — this is the caller's responsibility.
After calling `verify_registration` or `verify_authentication`, mark the challenge
as consumed in your session store and reject any future presentation of it.

### Challenge expiry

This library provides `webauthn::challenge::is_expired()` which checks a 5-minute
window. Long-lived challenges give attackers more time to observe and replay. The
5-minute default is conservative; a 60-second window is common in production.

```rust
if webauthn::challenge::is_expired(&challenge) {
    return Err("challenge expired");
}
```

---

## Origin and RP ID verification

### Why origin verification matters

The `origin` field in `clientDataJSON` is set by the **browser** (not the
authenticator). A malicious page at `https://evil.com` that tricks a user into
running a WebAuthn ceremony will produce a response with `origin: "https://evil.com"`.
If the relying party at `https://bank.com` does not check the origin, that
response could be used to authenticate there.

This library compares `client_data.origin == expected_origin` as an exact byte
comparison. There is no fuzzy matching, subdomain allowlisting, or wildcards.
The caller must supply the exact origin (scheme + host + port) that should be accepted.

**Example values:**
- `"https://example.com"` — production
- `"http://localhost:8080"` — local development (note: HTTP is allowed for localhost)

### Why RP ID hash verification matters

The `rpIdHash` in authenticator data is computed **by the authenticator** as
`SHA-256(rp_id)`. The authenticator refuses to sign for an RP ID that does not
match the origin the browser reports. This binding is enforced in hardware on
platform authenticators and in firmware on FIDO2 hardware keys.

If the relying party doesn't verify the RP ID hash, an attacker could present an
authenticator data blob from a *different* RP — one they control — with a valid
signature, but where the public key matches a credential registered to the victim
site. This attack is stopped by the RP ID hash check.

This library verifies `auth_data.rp_id_hash == SHA-256(rp_id)` on every ceremony.

---

## Sign count and replay attack protection

### What the sign count protects against

The sign count is a monotonically increasing integer maintained by the authenticator.
Each authentication increments it by at least 1. The relying party stores the last
seen count and rejects any assertion where the received count is not strictly greater.

This detects **cloned authenticators**: if an attacker extracts a private key from
one device and installs it on another, both devices will produce signatures from the
same counter starting point. When the cloned device's count is lower than the
legitimate device's count (or vice versa), the relying party sees a violation.

**This library's check (§7.2 step 25):**
```
if received != 0 && received <= stored {
    return Err(SignCountInvalid { stored, received });
}
```

### Why both-zero is a valid state

The WebAuthn spec permits authenticators to not implement a sign counter. These
authenticators always report a sign count of zero. A received count of zero when
the stored count is also zero means the authenticator simply does not support
counters — the library accepts this case per spec requirement. Clone detection is
not available for these authenticators.

Platform passkeys (iCloud Keychain, Google Password Manager) typically set the
counter to zero because the private key is synced across multiple devices — a
per-device counter would be meaningless. This is expected behavior, not a defect.

### Limitations of sign count

**Synced credentials (passkeys)** — when a private key is synced across devices via
iCloud Keychain or Google Password Manager, all devices share the key but may not
share the counter. Platforms typically set the counter to 0 for synced credentials.
This library accepts count 0 (spec requirement) but this means clone detection is not
available for synced passkeys.

**Non-monotonic increments** — the spec allows the count to increase by more than 1
per authentication. An attacker who intercepts an assertion and plays it back slightly
later might succeed if the legitimate device hasn't incremented past the replay count.
The protection is probabilistic, not absolute.

**First assertion** — a freshly registered credential with a sign count of 1 (or 0)
provides no clone-detection baseline. Clone detection only becomes meaningful after
at least one successful authentication.

### What to do when sign count is violated

A `SignCountInvalid` error does not definitively prove cloning — it could be a
legitimate app bug or platform sync issue. The recommended response:

1. Log the anomaly with credential ID, stored count, received count, and timestamp.
2. Reject the current authentication attempt.
3. Flag the credential for review or require re-enrollment.
4. Notify the user (optional, to avoid alarming legitimate users of synced keys).

---

## User Verification (UV) flag

### What UV means

The User Verification (UV) flag indicates that the authenticator performed a
verification step beyond simple presence — for example, a biometric check (Touch ID,
Face ID) or a PIN entry. It does not mean the user typed a password.

### Why this library does not enforce UV by default

The WebAuthn spec (§7.2 step 21) states that UV enforcement is optional and
application-specific. Some applications (e.g. low-risk account actions) only need
User Presence; others (e.g. payment authorization, sensitive settings) need User
Verification. Enforcing UV inside the library would be too opinionated.

Instead, `AuthenticationResult` exposes `user_verified: bool`. The caller decides
whether to require it for their threat model:

```rust
let result = rp.verify_authentication(&credential, &challenge, &response)?;
if requires_uv && !result.user_verified {
    return Err("user verification required for this action");
}
```

---

## What the caller is responsible for

| Property | Notes |
|----------|-------|
| Challenge single-use | Mark challenge as consumed in your session store after use |
| Challenge storage | Store server-side; never trust the client to return the challenge |
| Credential lookup | Look up stored credential by credential ID before calling verify |
| Sign count update | Write `auth_result.new_sign_count` to your database after success |
| UV enforcement | Check `auth_result.user_verified` if your flow requires it |
| HTTPS enforcement | WebAuthn ceremonies only work in secure contexts |
| Attestation trust | Only `"none"` attestation is verified; device provenance is unverified |

---

## What this library does NOT protect against

### Full attestation chain

This library only accepts the `"none"` attestation format. This means you cannot verify:
- That the authenticator is genuine hardware (not a software emulator)
- The authenticator model or firmware version
- Whether the device has been compromised at the hardware level

For applications where device provenance matters (banking, government, enterprise),
implement `"packed"` attestation and validate the certificate chain against the
[FIDO Metadata Service (MDS)](https://fidoalliance.org/metadata/).

### Token binding

The `tokenBinding` field in `clientDataJSON` is ignored. Token binding cryptographically
ties a session to a TLS channel, preventing token theft. It is rarely implemented and
has been removed from most browsers, but if you need it, this library does not provide it.

### Side-channel attacks

This library uses `ring` for signature verification, which provides constant-time
ECDSA operations. However, the library itself does not guarantee constant-time
credential lookups, error responses, or JSON parsing. A timing attacker observing
response latency might infer whether a credential ID was found in the database.
Use constant-time credential ID comparison if this is a concern.

### Credential storage security

This library returns a `Credential` struct containing the public key. The caller must
store it securely. Public keys are not secret, but credential IDs can be used to
determine which users are registered, so treat the credential table as sensitive:

- Index by credential ID (opaque bytes, not user-chosen)
- Protect with row-level access control
- Audit reads of the credential table
- Consider encrypting at rest if your threat model includes database theft

---

## Algorithm considerations

### ES256 vs RS256

| Property | ES256 (ECDSA P-256) | RS256 (RSA 2048) |
|----------|---------------------|------------------|
| COSE alg ID | -7 | -257 |
| Key size | 64 bytes (x+y) | ≥256 bytes modulus |
| Signature size | 64–72 bytes (DER ASN.1) | 256 bytes (2048-bit) |
| Speed | Fast | Slower |
| Security level | ~128-bit | ~112-bit |
| Common on | FIDO2 hardware keys, passkeys | Legacy FIDO U2F, older hardware |

Both algorithms are verified using `ring` with the same no-panic, no-custom-crypto
guarantee. The COSE key type determines which path is taken:

- `kty=2` (EC2), `alg=-7` → `verify_es256` with ring's `ECDSA_P256_SHA256_ASN1`
- `kty=3` (RSA), `alg=-257` → `rsa_components_to_der(n, e)` + `verify_rs256`
  with ring's `RSA_PKCS1_2048_8192_SHA256`

ring enforces a minimum 2048-bit RSA key. Keys shorter than 2048 bits are rejected
with `SignatureVerificationFailed`.

### Why ES256 is preferred

ES256 is the mandatory-to-implement algorithm in the WebAuthn spec (§5.8.5). All
FIDO2-certified authenticators support it. Modern passkey implementations use P-256.
RS256 is supported for backward compatibility with older FIDO U2F credentials and
legacy authenticators that predate the FIDO2 era.

---

## Phase 3 hardening — no-panic guarantee

### Why `#![deny(clippy::unwrap_used)]`

A panic in a security library is indistinguishable from a crash to the caller.
If a parsing function panics on malformed authenticator data, the ceremony
function never returns a typed error — the stack unwinds past any caller
error-handling code. The caller may log the crash but cannot inspect or
reason about the specific failure, and in some runtime environments (async
executors, FFI) panics have undefined or dangerous behavior.

This library adds `#![deny(clippy::unwrap_used)]` to the crate root so that
`.unwrap()` is a compile error in all library code. `.expect()` is permitted
only where the surrounding bounds check makes the panic provably impossible
(e.g., `slice[0..32].try_into().expect("...")` after checking `len >= 37`).

### Input validation philosophy

Authenticator data, client data JSON, and attestation objects all arrive from
untrusted sources (the browser / client) and must be treated as adversarial.
This library follows these rules:

1. **Check bounds before indexing** — every slice access is guarded by an
   explicit length check or uses `.get()` which returns `Option`.
2. **Return typed errors** — every error case produces a named `WebAuthnError`
   variant with a descriptive message, never a generic "parse error".
3. **Never panic on any input** — the fuzz-style tests
   (`no_panic_on_random_registration_input` and `no_panic_on_random_authentication_input`)
   verify this property across 100 random inputs of varying lengths.

### Attestation verification scope

This library verifies the `"none"` attestation format only. Any other format
(packed, tpm, fido-u2f, android-key, apple) is rejected with an explicit error.

**What "none" attestation means:** the authenticator does not provide a
certificate chain linking it to a known manufacturer. Registration still
succeeds, and the public key is stored. But you cannot verify:
- That the key was generated inside genuine FIDO2 hardware
- The authenticator model or firmware version

If you need attestation chain verification, integrate with the
[FIDO Metadata Service (MDS)](https://fidoalliance.org/metadata/).

**Known limitation introduced by this scope:** relying parties that require
high-assurance device binding (banking, government) must validate attestation
outside this library.

---

## Summary of security responsibilities

| Property | Enforced by | Notes |
|----------|-------------|-------|
| Challenge randomness | Library (`ring` CSPRNG) | 256 bits entropy |
| Challenge single-use | **Caller** | Must invalidate after use |
| Challenge expiry | Caller via `is_expired()` | Default 5 min |
| Origin binding | Library | Exact string match |
| RP ID binding | Library | SHA-256 comparison |
| User presence | Library | UP flag check |
| Signature validity | Library (`ring` ECDSA/RSA) | Constant-time |
| Sign count monotonicity | Library | Non-zero counts only |
| User verification | **Caller** | Check `user_verified` if required |
| HTTPS enforcement | **Caller** / infrastructure | Browsers require it |
| Attestation trust | **Caller** | Library only validates "none" |
| Credential storage | **Caller** | Treat as sensitive data |
