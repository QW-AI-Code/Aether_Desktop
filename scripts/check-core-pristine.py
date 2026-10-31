#!/usr/bin/env python3
"""Verify the immutable upstream 2.4.0 baseline plus explicit 1.4.0 mobile ports.
Every changed/added file requires matching original AND delivered hashes in
CORE_PORT_PATCHES.json. Unrecorded drift, deletions and version drift fail.
--update is forbidden while the overlay is active; rebases are deliberate.
"""
import json
import fnmatch
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORE = ROOT / "native" / "aether"
MANIFEST = CORE / "UPSTREAM-SHA256SUMS"
SKIP = {"CORE_VERSION", "UPSTREAM-SHA256SUMS"}
IGNORED_DIRS = {"target", ".git"}


def tree():
    out = {}
    for p in sorted(CORE.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(CORE)
        if rel.name in SKIP and len(rel.parts) == 1:
            continue
        if any(part in IGNORED_DIRS for part in rel.parts):
            continue
        out["./" + rel.as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _gitignore_globs(directory):
    """Slash-free patterns of one .gitignore (the only kind that can hide a file here)."""
    f = directory / ".gitignore"
    if not f.is_file():
        return []
    out = []
    for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!") or "/" in line.rstrip("/"):
            continue
        out.append(line.rstrip("/"))
    return out


def git_cannot_carry(name):
    """True if upstream's own .gitignore keeps `git add` from committing this file.

    Upstream ships a few test keys (quiche/**/cert.key) although its .gitignore
    says `*.key`. A plain `git add .` + push silently drops them, so a fresh
    checkout in CI never has them (build log 2026-10-08, preflight step 18).
    They are test fixtures of quiche's examples and are not part of the engine
    build, so their *absence* is tolerated; if present they must still match.
    """
    rel = pathlib.PurePosixPath(name[2:] if name.startswith("./") else name)
    d = CORE
    for part in rel.parts[:-1] + ("",):
        for pat in _gitignore_globs(d):
            if fnmatch.fnmatch(rel.name, pat):
                return True
        if part:
            d = d / part
    return False


def main() -> int:
    if not CORE.is_dir():
        print(f"✗ core tree missing: {CORE.relative_to(ROOT)}")
        return 1
    current = tree()
    if "--update" in sys.argv:
        if (ROOT / "CORE_PORT_PATCHES.json").exists():
            print("Refusing to overwrite upstream baseline while a reviewed overlay is active. Explicit rebase required.")
            return 1
        old_links = [
            l for l in (MANIFEST.read_text(encoding="utf-8").splitlines() if MANIFEST.is_file() else [])
            if l.startswith("# symlink ")
        ]
        skip = {l[len("# symlink "):].strip() for l in old_links}
        MANIFEST.write_text(
            "".join(l + "\n" for l in old_links)
            + "".join(f"{h}  {name}\n" for name, h in sorted(current.items()) if name not in skip),
            encoding="utf-8",
        )
        print(f"✓ manifest rewritten: {len(current)} files")
        return 0

    errors = []
    if not MANIFEST.is_file():
        print("✗ native/aether/UPSTREAM-SHA256SUMS is missing")
        return 1
    expected = {}
    links = set()
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.startswith("# symlink "):
            # Upstream symlinks: git on Windows checks them out as small text
            # files, so their content is platform-dependent and not compared.
            links.add(line[len("# symlink "):].strip())
        elif line.strip() and not line.startswith("#"):
            digest, name = line.split(None, 1)
            expected[name.strip()] = digest
    current = {k: v for k, v in current.items() if k not in links}

    overlay_file=ROOT / "CORE_PORT_PATCHES.json"
    overlay={r["path"]:r for r in json.loads(overlay_file.read_text())["records"]} if overlay_file.is_file() else {}
    for name,r in overlay.items():
        key="./"+name if "./"+name in expected or "./"+name in current else name
        if expected.get(key)!=r["upstream_sha256"] or current.get(key)!=r["ported_sha256"]:
            errors.append(f"reviewed core overlay mismatch: {name}")
    def reviewed(name):
        r=overlay.get(name.removeprefix("./"))
        return r is not None and current.get(name)==r["ported_sha256"]
    tolerated = []
    for name in sorted(set(expected) - set(current)):
        if git_cannot_carry(name):
            tolerated.append(name)
        else:
            errors.append(f"removed from the core: {name}")
    for name in sorted(set(current) - set(expected)):
        if not reviewed(name): errors.append(f"not part of upstream: {name}")
    for name in sorted(set(current) & set(expected)):
        if current[name] != expected[name] and not reviewed(name):
            errors.append(f"modified: {name}")

    for p in (CORE / "aether").rglob("*"):
        if p.is_file() and p.suffix in {".rs", ".toml"} and "target" not in p.parts:
            if "AETHER-APP-PATCH" in p.read_text(encoding="utf-8", errors="replace") and p.relative_to(CORE).as_posix() not in overlay:
                errors.append(f"app patch marker inside the core: {p.relative_to(ROOT)}")

    root_ver = (ROOT / "CORE_VERSION").read_text(encoding="utf-8").strip()
    core_ver_file = CORE / "CORE_VERSION"
    core_ver = core_ver_file.read_text(encoding="utf-8").strip() if core_ver_file.is_file() else ""
    m = re.search(r'^version\s*=\s*"([^"]+)"', (CORE / "aether" / "Cargo.toml").read_text(encoding="utf-8"), re.M)
    cargo_ver = m.group(1) if m else ""
    if not (root_ver == core_ver == cargo_ver):
        errors.append(
            f"version mismatch: CORE_VERSION={root_ver!r}, native/aether/CORE_VERSION={core_ver!r}, "
            f"core Cargo.toml={cargo_ver!r}"
        )

    if errors:
        print("✗ the vendored core differs from upstream plus its reviewed overlay:")
        for e in errors[:40]:
            print(f"   - {e}")
        if len(errors) > 40:
            print(f"   … and {len(errors) - 40} more")
        return 1
    for name in tolerated:
        print(f"  ~ absent but ignored by upstream's .gitignore (not in a git checkout): {name}")
    print(f"✓ core {cargo_ver} matches the upstream baseline plus reviewed overlay ({len(current)} files; {len(overlay)} reviewed ports)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
