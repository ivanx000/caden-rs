# /status

Print a project health summary for WebAuthn.

## Steps

Run each of the following and aggregate results:

1. **Git state**
   ```
   git branch --show-current
   git log -1 --oneline
   git status --short
   ```
   Report: current branch, last commit hash + message, number of uncommitted changes.

2. **Build status**
   ```
   cargo build 2>&1
   ```
   Report: ✅ OK or ❌ with error count.

3. **Test results**
   ```
   cargo test 2>&1
   ```
   Report: number of tests passed, number failed (parse from `test result:` line).

4. **Clippy warnings**
   ```
   cargo clippy -- -D warnings 2>&1
   ```
   Report: ✅ zero warnings or ❌ N warnings.

5. **Public API surface** — list all public types exported from `src/lib.rs`:
   - `pub use` re-exports
   - `pub struct` / `pub enum` definitions

## Output format

```
=== WebAuthn project status ===
Branch:   main
Commit:   abc1234 feat: add EdDSA support
Unstaged: 0 files changed

Build:    ✅ OK
Tests:    ✅ 42 passed, 0 failed
Clippy:   ✅ 0 warnings

Public API:
  RelyingParty
  AuthenticatorAttestationResponse
  AuthenticatorAssertionResponse
  Credential, PublicKey, Challenge
  RegistrationResult, AuthenticationResult, AttestationType
  WebAuthnError, Result
  generate_challenge, is_expired, is_expired_with_max_age
  CHALLENGE_MAX_AGE_SECS
================================
```
