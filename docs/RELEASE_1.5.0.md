# Release 1.5.0 — checklist

App **1.5.0**, engine core **2.4.0**, ported from Aether Mobile **1.7.0**. User-facing notes: [`release-notes.md`](../release-notes.md) (the CI publishes `.github/release-notes.md`, identical). Technical report (Persian): [`PORT_1.5.0_REPORT.fa.md`](PORT_1.5.0_REPORT.fa.md).

## Artifacts

| File | |
|---|---|
| `Aether-Setup-1.5.0-x64.exe` | 64-bit installer |
| `Aether-Setup-1.5.0-x86.exe` | 32-bit installer |
| `Aether-Portable-1.5.0-x64.zip` | 64-bit portable |
| `Aether-Portable-1.5.0-x86.zip` | 32-bit portable |
| `SHA256SUMS.txt` | checksums |

## Version is 1.5.0 in

`package.json`, `package-lock.json` (root and `packages[""]`), `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock` (`aether-desktop`), `installer/aether.iss`, `src-tauri/windows-manifest.xml` (`1.5.0.0`), `PATCHLEVEL`, `tests/rust-port` and `tests/core-policy` manifests. CI step *Version must be identical everywhere* and `scripts/verify-package.sh` check this.

## What changed (code map)

- `src-tauri/src/readiness.rs` (new) — per-process serving/fatal tracking, blocking `await_ready`, non-blocking `Gate`.
- `src-tauri/src/engine.rs` — fresh `Readiness` per start, fed by the stdout/stderr drains (session and race lanes).
- `src-tauri/src/state.rs` — readiness gate before data path / self-test / chain stage 2; new Smart flow (race → measure → rank → confirm → last resort); serial-ladder memory; MASQUE QUIC probe in the fingerprint.
- `src-tauri/src/smart_plus/{plan,scheduler,mod}.rs` — mobile 1.7.0 catalogue, fair race with quality window, measurement and ranking.
- `src-tauri/src/probe.rs` — `measure_tunnel_quality`, `masque_quic_reachable`, `socks_greeting_within`.
- `src-tauri/src/smart_auto.rs` — no automatic ECH, ladder from the Smart catalogue, three-pass manual MASQUE, `quic_reachable` in `NetFingerprint`.
- `scripts/patch-engine-dependencies.py` + workflow step *Engine dependency security floors* (before *Build engine*).
- `src/news/announcements.js`, `src/i18n.js`, `src/views/advanced.js` — 1.5.0 what's-new, new strings (EN + FA).

## Before tagging

1. CI green on both architectures (first real compile of the Rust changes and first run of the new unit tests — they were not compiled where the port was written).
2. On a Windows machine in Iran: Smart connects; the log shows `fair race[…@+0s | …@+0s]`, `engine-serving after=…ms`, a `Smart: ranking …` line when two routes proved, and no `--ech` unless the user enabled ECH.
3. Manual MASQUE: the plan log shows `as configured → MASQUE · h2 (TCP carrier) → hardened anti-DPI · h2`.
4. What's new dialog opens once for 1.5.0 and contains the *If you cannot connect at all* steps.
