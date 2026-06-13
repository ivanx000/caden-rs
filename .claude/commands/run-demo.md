# /run-demo

Run the end-to-end webauthn demo binary and print its output.

## Steps

1. Run the demo with full output:
   ```
   cargo run --example demo
   ```

2. Print the complete output, including:
   - The registration result (credential ID, public key algorithm)
   - The authentication result (sign count, user verified flag)
   - The replay attack rejection (the specific `WebAuthnError` variant returned)

3. Confirm the final line of output is `All checks passed.`

4. If the demo fails, show the full error and diagnose whether it is a build error, a runtime panic, or a ceremony verification failure.
