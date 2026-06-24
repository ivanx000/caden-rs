# /spec-audit

Audit the Caden codebase for W3C WebAuthn spec compliance.

This command matters because Caden is a security library. Every step in the W3C WebAuthn §7.1 and §7.2 algorithms must either be implemented or have an explicit note explaining why it is omitted. Missing steps are vulnerabilities.

## Steps

1. **Audit `src/registration.rs`** against §7.1 of https://www.w3.org/TR/webauthn-3/

   For each step in §7.1 (steps 1–25), determine:
   - Is the step implemented in `registration.rs::verify`?
   - If implemented, does it have a `// §7.1 step N` comment?
   - If omitted, is there an explanatory comment saying why (e.g. "delegated to caller", "out of scope for a library")?

   List: ✅ implemented+commented | ⚠️ implemented but no comment | ❌ missing and unexplained

2. **Audit `src/authentication.rs`** against §7.2

   Same process as above but for §7.2 steps.

3. **Check attestation coverage** in `src/attestation.rs`

   - Is the "none" format handled?
   - Is there a clear error for unsupported formats?

4. **Print compliance summary**

   ```
   === Spec compliance audit ===
   §7.1 Registration (N steps checked):
     ✅ Step 5  — clientDataJSON parsed
     ✅ Step 7  — type verified
     ...
     ⚠️ Step 10 — tokenBinding: implemented, missing spec comment
     ...

   §7.2 Authentication (N steps checked):
     ...

   === Summary ===
   Registration: N/N steps covered, M missing comments
   Authentication: N/N steps covered, M missing comments
   ```

5. If any steps are missing comments, add the `// §7.X step N` comment to the source now. If any steps are missing implementation, flag them clearly and recommend next actions.
