# /check

Run the full Caden quality suite, mirroring CI exactly, and report results.

## Steps

Run each check sequentially and collect pass/fail status:

1. **Build**
   ```
   cargo build
   ```

2. **Format**
   ```
   cargo fmt --check
   ```

3. **Clippy**
   ```
   cargo clippy -- -D warnings
   ```

4. **Tests**
   ```
   cargo test
   ```

5. **Doc check**
   ```
   cargo doc --no-deps 2>&1 | grep "^error" && exit 1 || true
   ```

6. **Demo**
   ```
   cargo run --example demo
   ```

## Output format

After all checks complete, print a summary table:

```
=== Caden quality check ===
✅ build
✅ fmt
✅ clippy
✅ test
✅ doc
✅ demo
================================
All checks passed.
```

Or if any fail:

```
=== Caden quality check ===
✅ build
❌ fmt    — run `cargo fmt` to fix
✅ clippy
✅ test
✅ doc
❌ demo   — see output above
================================
2 checks failed.
```

Fix any failures before reporting the task as done.
