# /run

Simulate the full Caden experience from a new user's perspective: build the library, walk through every feature, and verify everything works end-to-end.

---

## Phase 1 — Setup

Build the library and all examples so binaries are ready before the server phase:

```bash
cargo build --examples
```

Report ✅ or ❌. If it fails, show the compiler error and stop.

---

## Phase 2 — Demo: all four algorithms

Run the end-to-end demo. This is the fastest way to see all four COSE algorithms (ES256, RS256, ES384, EdDSA) completing a full WebAuthn session — registration, authentication, and replay-attack rejection — entirely in software with no browser needed.

```bash
cargo run --example demo
```

Print the **complete output**. Confirm the final line is `All checks passed.`

If it fails, show the full error and diagnose: build error, runtime panic, or ceremony verification failure.

---

## Phase 3 — Test suite

Run the full suite and print the last 20 lines:

```bash
cargo test 2>&1 | tail -20
```

Note the test count (e.g. `N passed, 0 failed`) and any ignored tests.

---

## Phase 4 — HTTP server walkthrough

**4a. Start the server in the background.**

Use `run_in_background=true` for the Bash tool:

```bash
cargo run --example server
```

**4b. Wait for the server to be ready** (binary is pre-built so startup is fast):

```bash
sleep 2
```

**4c. Walk through each endpoint as a new user would.**

**Health check — is the server alive?**
```bash
curl -s http://localhost:3000/health | python3 -m json.tool
```
Expected: `{"status":"ok","version":"..."}`.

**Registration begin — start registering a new user "alice"**
```bash
curl -s -X POST http://localhost:3000/register/begin \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"user-alice","username":"alice"}' | python3 -m json.tool
```
Note: the response includes a random base64url `challenge`, `rp.id = "localhost"`, `user.name = "alice"`, and the list of allowed public-key algorithms.

**Registration complete — bad session (exercises the error pipeline)**
```bash
curl -s -X POST http://localhost:3000/register/complete \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"BOGUS","client_data_json":"aGVsbG8","attestation_object":"aGVsbG8"}' \
  | python3 -m json.tool
```
Expected: `{"error":"...","code":"SESSION_NOT_FOUND"}`. The server correctly rejects a non-existent session before touching any crypto.

**Authentication begin — unknown credential (exercises credential lookup)**
```bash
curl -s -X POST http://localhost:3000/authenticate/begin \
  -H 'Content-Type: application/json' \
  -d '{"credential_id":"AAAA"}' | python3 -m json.tool
```
Expected: `{"code":"CREDENTIAL_NOT_FOUND",...}`.

**Passkey / discoverable-credential flow — begin with no credential hint**
```bash
curl -s -X POST http://localhost:3000/passkey/authenticate/begin \
  -H 'Content-Type: application/json' \
  -d '{}' | python3 -m json.tool
```
Expected: JSON with a non-empty `session_id` and `"allowCredentials":[]`. The empty list is the W3C signal for the passkey flow — the browser shows the user all matching credentials rather than requiring the server to specify one.

**4d. Stop the server.**

Find and kill the background server process:
```bash
pkill -f 'target/debug/examples/server' 2>/dev/null || true
```

---

## Phase 5 — Summary

Print a final summary table. Mark each step ✅ or ❌:

```
=== Caden /run walkthrough ===
✅ build
✅ demo  (ES256 · RS256 · ES384 · EdDSA — registration + auth + replay rejection)
✅ tests (N passed, 0 failed)
✅ server  GET  /health
✅ server  POST /register/begin
✅ server  POST /register/complete   (SESSION_NOT_FOUND error path)
✅ server  POST /authenticate/begin  (CREDENTIAL_NOT_FOUND error path)
✅ server  POST /passkey/authenticate/begin
==============================
All checks passed.
```

If any step is ❌, show the output and name the root cause before stopping.
