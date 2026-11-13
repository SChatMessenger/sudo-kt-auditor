# sudo-kt-auditor

The independent key transparency auditor for Sudo: a command-line program anyone can run. It walks a relay's public audit proofs (spec §6.4, §10.14) from the first epoch, checks every signed head and every append-only proof, records the heads it checked, and stops with evidence if the relay ever rewrote its key directory.

This repo is part of the Sudo secure messenger, a multi-repo project. The spec is in `../sudo-protocol/sudoproto.md` and the project overview in `../sudo-protocol/Readme.md` (when the whole `sudo-workspace` folder is open, it is already visible; if this repo is opened on its own, start Claude Code with `--add-dir ../sudo-protocol`).

## Spec sections for this repo
- §6 key transparency (especially §6.1 signed heads, §6.4 split views and audits), §10.14 public audit proofs
- §4 the key transparency exceptions (BLAKE3, RFC 9381 VRF, `akd` 0.13.0) and `SPEC-QUESTIONS.md` Q57-Q65

## Rules that apply to every Sudo repo
- No custom cryptography. Crypto and protocol logic belong in `sudo-sdk`; use a released version of it.
- Never log or store keys, message content, phone numbers or IP addresses.
- No analytics, ads or tracking. Ask before adding any dependency or outside service.
- No secrets in the repository (API keys, signing keys, passwords). Use environment variables or a secrets manager.
- If the spec is unclear, write the question into `SPEC-QUESTIONS.md` and stop.

## Repo-specific rules
- Every check is done by released libraries: head parsing and signature checks by `sudo-kt` (a released `sudo-sdk` tag), append-only proofs by `akd` =0.13.0's own audit check (the owner approved `akd`, Q57). This repo only fetches, orders and records.
- **Fail loudly.** Any proof or signature that does not verify, any epoch number out of order, or a different root for an epoch already checked stops the run with a non-zero exit code, and the relay's exact answer is kept as evidence. Never retry silently or skip an epoch.
- What it stores is public information only: epoch numbers, roots, signed heads and proofs. No usernames, no keys other than the relay's public ones.
- No TLS yet (like `sudo-cli`): only relays on this computer, until deployment brings §10.1.

## Commands (all must pass before you say a task is done)
```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cargo audit
```

## How to work
- Plan first for anything security-related and wait for approval.
- One small step at a time, with tests (including a dishonest relay that rewrites, forks or forges).
