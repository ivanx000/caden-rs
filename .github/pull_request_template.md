## Summary

<!-- 1–3 bullet points describing what this PR does. -->

## Spec reference

<!-- If this changes ceremony behaviour, cite the W3C WebAuthn section(s).
     Example: §7.1 step 16 (User Present flag), §8.2 (packed attestation) -->

## Checklist

- [ ] `cargo build` passes
- [ ] `cargo test` passes — all existing tests green, new tests added for changed behaviour
- [ ] `cargo clippy -- -D warnings` passes — zero warnings
- [ ] `cargo fmt` applied
- [ ] W3C spec step comments present for any changes to `registration.rs` or `authentication.rs`
- [ ] `docs/` updated if behaviour or architecture changed
- [ ] `CLAUDE.md` updated if crate structure or design decisions changed
- [ ] "Known limitations" in `CLAUDE.md` updated if a limitation was resolved
- [ ] New `WebAuthnError` variants have `///` doc comments and test coverage
- [ ] No `unwrap()` in library code (tests and demo are fine)
- [ ] No `git push` performed — push is always manual
