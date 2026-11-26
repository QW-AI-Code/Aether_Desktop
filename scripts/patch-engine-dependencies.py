#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""1.5.0 - security floors for the engine's locked Rust dependencies.

Port of Aether Mobile 1.7.0 `scripts/patch-engine-dependencies.py`. The mobile
build hit these advisories in a strict `cargo audit`; the Windows build vendors
the very same `native/aether/aether/Cargo.lock`:

    quinn-proto   <= 0.11.18 -> 0.11.19   RUSTSEC-2026-0523, RUSTSEC-2026-0524
    quinn-udp        0.5.15  -> 0.5.16    RUSTSEC-2026-0538
    url              2.5.8   -> 2.5.9     RUSTSEC-2026-0592
    cookie           0.18.2  -> 0.18.3    RUSTSEC-2026-0594

For every fix: only when a locked version is on the same semver line
(`major.minor`) and below the floor, run

    cargo update --package <name>@<old> --precise <new>

inside the core crate, then re-read Cargo.lock and require that the old version
is gone. Nothing else in the lock file moves (`--precise` on one package).

Runs in CI **after** the pristine check of the vendored core (that check compares
the repository copy with upstream; this step only edits the build job's working
copy) and **before** `build-engine.ps1`, which builds with `--locked` and so
uses the raised lock file.

libsqlite3-sys 0.37.0 (RUSTSEC-2026-0459) is deliberately not raised: 0.39 needs
rusqlite 0.41, which tor-dirmgr 0.46 does not accept. SQLite only opens Tor's
directory cache inside the app's private data folder.

Usage: patch-engine-dependencies.py [core-dir] [--dry-run]
"""
import re
import subprocess
import sys
from pathlib import Path

FIXES = [
    ("quinn-proto", (0, 11, 19)),
    ("quinn-udp", (0, 5, 16)),
    ("url", (2, 5, 9)),
    ("cookie", (0, 18, 3)),
]


def say(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def parse(version):
    core = version.split("+", 1)[0].split("-", 1)[0]
    try:
        return tuple(int(x) for x in core.split("."))
    except ValueError:
        return None


def locked(lock_text):
    """[(name, version)] of every [[package]] in a Cargo.lock."""
    try:
        import tomllib  # Python 3.11+

        data = tomllib.loads(lock_text)
        return [(p["name"], p["version"]) for p in data.get("package", [])]
    except ModuleNotFoundError:
        out = []
        for block in lock_text.split("[[package]]")[1:]:
            n = re.search(r'^name = "([^"]+)"', block, re.M)
            v = re.search(r'^version = "([^"]+)"', block, re.M)
            if n and v:
                out.append((n.group(1), v.group(1)))
        return out


def plan(packages):
    """[(name, old, new)] - only same-line versions below the floor."""
    todo = []
    for name, floor in FIXES:
        for pname, version in packages:
            if pname != name:
                continue
            parts = parse(version)
            if parts is None or len(parts) < 3:
                continue
            if parts[:2] == floor[:2] and parts < floor:
                todo.append((name, version, ".".join(map(str, floor))))
    return todo


def main(argv):
    dry = "--dry-run" in argv
    args = [a for a in argv if not a.startswith("--")]
    root = Path(__file__).resolve().parent.parent
    core = Path(args[0]) if args else root / "native" / "aether" / "aether"
    lock = core / "Cargo.lock"
    if not lock.is_file():
        say(f"::warning::{lock} not found - no dependency floors applied.")
        return 0
    todo = plan(locked(lock.read_text(encoding="utf-8")))
    if not todo:
        say("OK: every engine dependency already meets its security floor.")
        return 0
    for name, old, new in todo:
        cmd = ["cargo", "update", "--package", f"{name}@{old}", "--precise", new]
        say(f"==> {name} {old} -> {new}: {' '.join(cmd)}")
        if dry:
            continue
        rc = subprocess.call(cmd, cwd=str(core))
        if rc != 0:
            say(f"::error::cargo update for {name} {old} -> {new} failed (exit {rc}).")
            return 1
    if dry:
        return 0
    after = locked(lock.read_text(encoding="utf-8"))
    bad = [(n, o) for n, o, _ in todo if (n, o) in after]
    if bad:
        for n, o in bad:
            say(f"::error::{n} {o} is still in Cargo.lock after the update.")
        return 1
    left = plan(after)
    if left:
        say(f"::error::still below the floor: {left}")
        return 1
    say(f"OK: raised {len(todo)} engine dependenc{'y' if len(todo) == 1 else 'ies'} to the security floor.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
