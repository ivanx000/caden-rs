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

**4a. Discover routes from source.**

Read `examples/server.rs` and extract every `.route(...)` call from the `Router::new()` chain to build the authoritative `(METHOD, path)` list. Do not rely on any hardcoded list of endpoints — test exactly what the code currently exposes.

For each route, classify it by method and path shape to decide how to probe it:

| Route shape | How to test |
|-------------|-------------|
| `GET` any path | Plain curl; expect 200 with a JSON body. |
| `POST` path ending in `/begin`, no credential hint needed (e.g. `/passkey/authenticate/begin`) | Send `{}` or the minimal body the handler requires; expect 200 with `session_id` + `challenge`. |
| `POST` path ending in `/begin`, requires a field (e.g. `/register/begin`, `/authenticate/begin`) | Send a minimal valid body (e.g. `{"user_id":"u1","username":"alice"}` or `{"credential_id":"AAAA"}`); expect 200 or a typed error code. |
| `POST` path ending in `/complete` | Send a payload with `"session_id":"BOGUS"` and dummy base64url values for any other required fields; the server must reject it with a known error code (e.g. `SESSION_NOT_FOUND`) *before* touching any crypto — this confirms the session-management pipeline. |

**4b. Start the server in the background.**

Use `run_in_background=true` for the Bash tool:

```bash
cargo run --example server
```

**4c. Wait for the server to be ready** (binary is pre-built so startup is fast):

```bash
sleep 2
```

**4d. Exercise every discovered route.**

For each `(METHOD, path)` from step 4a, send the appropriate curl request (as determined by the classification table above), print the response, and record ✅ (got the expected response or error code) or ❌ (unexpected failure or wrong HTTP status).

**4e. Stop the server.**

```bash
pkill -f 'target/debug/examples/server' 2>/dev/null || true
```

---

## Phase 5 — Summary

Print a final summary table. The server rows are generated from the route list discovered in step 4a — one row per route. Mark each step ✅ or ❌:

```
=== Caden /run walkthrough ===
✅ build
✅ demo  (<algorithms from demo.rs> — registration + auth + replay rejection)
✅ tests (N passed, 0 failed)
✅ server  <METHOD>  <path>   (<what was verified>)
  ... one row per discovered route ...
==============================
All checks passed.
```

If any step is ❌, show the output and name the root cause before stopping.
