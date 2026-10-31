#!/usr/bin/env python3
"""Remove what Aether Windows 1.2.5 left behind in a 1.3.0 tree.

Why this exists
---------------
1.3.0 is usually pushed on top of an existing 1.2.5 repository (or unpacked
over a 1.2.5 working copy). Files that 1.3.0 *deleted* are then still there:

  * root/scripts/src-tauri files that 1.3.0 no longer has (UPGRADE-1.2.1..4,
    the old core-upgrade/check scripts, src-tauri/src/psiphon.rs, …);
  * the hashed bundle of the old UI in dist-web/assets/;
  * files inside native/aether that are not part of upstream core 2.4.0
    (.upstream-baseline/, aether/build.rs, aether/src/apifront.rs,
    quiche/fuzz/, …). check-core-pristine.py fails on every one of them with
    "not part of upstream".

What it never does
------------------
  * It never edits a file, and never removes a file that 1.3.0 ships: inside
    native/aether the upstream manifest (UPSTREAM-SHA256SUMS) is the whitelist;
    outside it only the explicit LEGACY list below is removed.
  * It never touches target/, .git/, node_modules/, dist/, dist-engine/ or
    native/.core-prev (build outputs belong to enforce-release-tree.sh).
  * It does not change any version: 1.3.0 stays 1.3.0.

Usage
-----
  python3 scripts/clean-legacy-1.2.5.py            # dry run: list only
  python3 scripts/clean-legacy-1.2.5.py --apply    # delete
  python3 scripts/clean-legacy-1.2.5.py --ci       # delete; tracked files via `git rm`
                                                   # so `git diff --quiet` stays true
  python3 scripts/clean-legacy-1.2.5.py --check    # exit 1 if anything is left
"""
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORE = ROOT / "native" / "aether"
MANIFEST = CORE / "UPSTREAM-SHA256SUMS"
CORE_SKIP = {"CORE_VERSION", "UPSTREAM-SHA256SUMS"}
CORE_IGNORED_DIRS = {"target", ".git"}
TAG = "clean-legacy-1.2.5"


def _utf8_stdio():
    """Never die on printing.

    On the Windows runner stdout is a pipe and Python picks the ANSI code page
    (cp1252), which cannot encode e.g. U+2713. CI run 2026-10-10 failed with
    UnicodeEncodeError on the very first line. Output below is plain ASCII
    anyway; this also covers non-ASCII file names (errors="replace").
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

# Paths (relative to the repository root) that exist in 1.2.5 and not in 1.3.0.
LEGACY = [
    "UPGRADE-1.2.1.md",
    "UPGRADE-1.2.2.md",
    "UPGRADE-1.2.3.md",
    "UPGRADE-1.2.4.md",
    "scripts/check-bridge-lines.py",
    "scripts/check-core-patches-negative.sh",
    "scripts/check-core-patches.py",
    "scripts/check-tor-runtime.py",
    "scripts/check-tor-watchdog.py",
    "scripts/core-install-1.9.0.py",
    "scripts/core-upgrade-1.9.0.py",
    "scripts/core-upgrade-resolve.py",
    "src-tauri/src/psiphon.rs",
    "src-tauri/src/psiphon_health.rs",
    "native/aether/.upstream-baseline",
]


def rel(p: pathlib.Path) -> str:
    return p.relative_to(ROOT).as_posix()


def stale_web_assets():
    """Hashed index-*.js / index-*.css that dist-web/index.html no longer loads."""
    web = ROOT / "dist-web"
    index = web / "index.html"
    assets = web / "assets"
    if not index.is_file() or not assets.is_dir():
        return []
    html = index.read_text(encoding="utf-8", errors="replace")
    live = set(re.findall(r"assets/([A-Za-z0-9._-]+)", html))
    if not live:
        return []  # an index.html we cannot read is no reason to delete anything
    out = []
    for p in sorted(assets.iterdir()):
        if p.is_file() and re.fullmatch(r"index-[A-Za-z0-9_-]+\.(js|css)", p.name) and p.name not in live:
            out.append(p)
    return out


def _gitignore_globs(directory: pathlib.Path):
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


def core_extras():
    """Files under native/aether that UPSTREAM-SHA256SUMS does not list.

    Same walk as check-core-pristine.py, so whatever this leaves is exactly
    what that guard accepts. Without a manifest nothing is removed.
    """
    if not MANIFEST.is_file():
        return []
    expected = set()
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.startswith("# symlink "):
            expected.add(line[len("# symlink "):].strip())
        elif line.strip() and not line.startswith("#"):
            expected.add(line.split(None, 1)[1].strip())
    overlay=ROOT / "CORE_PORT_PATCHES.json"
    if overlay.is_file():
        import json
        expected.update("./"+r["path"] for r in json.loads(overlay.read_text())["records"])
    out = []
    for p in sorted(CORE.rglob("*")):
        if not p.is_file() and not p.is_symlink():
            continue
        r = p.relative_to(CORE)
        if r.name in CORE_SKIP and len(r.parts) == 1:
            continue
        if any(part in CORE_IGNORED_DIRS for part in r.parts):
            continue
        if "./" + r.as_posix() not in expected:
            out.append(p)
    return out


def candidates():
    seen = []
    for name in LEGACY:
        p = ROOT / name
        if p.exists() or p.is_symlink():
            seen.append(p)
    seen += stale_web_assets()
    covered = [p for p in seen if p.is_dir()]
    for p in core_extras():
        if not any(c in p.parents for c in covered):
            seen.append(p)
    # unique, stable
    out, keys = [], set()
    for p in seen:
        k = rel(p)
        if k not in keys:
            keys.add(k)
            out.append(p)
    return out


def tracked(p: pathlib.Path) -> bool:
    try:
        r = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", rel(p)],
            cwd=ROOT, capture_output=True, text=True,
        )
        return r.returncode == 0
    except OSError:
        return False


def _force_writable(func, path, _exc):
    """Windows refuses to delete read-only files; clear the flag and retry."""
    import os
    import stat
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        func(path)
    except OSError:
        raise


def remove(p: pathlib.Path, ci: bool):
    if ci and tracked(p):
        subprocess.run(["git", "rm", "-r", "-q", "--cached", "--", rel(p)], cwd=ROOT, check=False)
    if p.is_dir() and not p.is_symlink():
        if sys.version_info >= (3, 12):
            shutil.rmtree(p, onexc=_force_writable)
        else:
            shutil.rmtree(p, onerror=_force_writable)
    else:
        try:
            p.unlink()
        except PermissionError:
            _force_writable(lambda q: pathlib.Path(q).unlink(), str(p), None)


def prune_empty_dirs(base: pathlib.Path):
    if not base.is_dir():
        return
    for d in sorted((x for x in base.rglob("*") if x.is_dir()), key=lambda x: len(x.parts), reverse=True):
        if any(part in CORE_IGNORED_DIRS for part in d.relative_to(base).parts):
            continue
        try:
            next(d.iterdir())
        except StopIteration:
            d.rmdir()
        except OSError:
            pass


def main(argv) -> int:
    _utf8_stdio()
    apply = "--apply" in argv or "--ci" in argv
    ci = "--ci" in argv
    check = "--check" in argv
    found = candidates()
    if not found:
        print(f"[{TAG}] OK: no 1.2.5 leftovers in this tree")
        return 0
    print(f"[{TAG}] {len(found)} leftover(s) of 1.2.5 {'removed' if apply else 'found'}:")
    shown = 0
    for p in found:
        if shown < 60:
            kind = "dir " if p.is_dir() else "file"
            print(f"[{TAG}]   {kind} {rel(p)}")
        shown += 1
        if apply:
            remove(p, ci)
    if shown > 60:
        print(f"[{TAG}]   ... and {shown - 60} more")
    if apply:
        prune_empty_dirs(CORE)
        if ci:
            print(f"::notice::[{TAG}] removed {len(found)} file(s) left behind by 1.2.5 (not part of 1.3.0)")
        print(f"[{TAG}] OK: done; run scripts/check-core-pristine.py to confirm the core")
        return 0
    if check:
        print(f"[{TAG}] FAIL: leftovers present - run with --apply")
        return 1
    print(f"[{TAG}] dry run - nothing deleted (use --apply)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
