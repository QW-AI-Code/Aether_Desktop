#!/usr/bin/env python3
"""Static compatibility guard for the Psiphon and engine regressions of 1.3.0.

Not a replacement for a Windows build or a connection test. Run in CI preflight.
"""
from pathlib import Path
import json
import re
import sys

root = Path(__file__).resolve().parent.parent
pin = '83aa73b9b982e7421e00117f5b0c5aceb5dda452'

def read(rel):
    return (root / rel).read_text(encoding='utf-8')

def require(ok, why):
    if not ok:
        print('FAIL:', why, file=sys.stderr)
        raise SystemExit(1)
    print('OK:', why)

require(read('CORE_VERSION').strip() == read('native/aether/CORE_VERSION').strip() == '2.4.0', 'both engine version files are 2.4.0')
require(re.search(r'^version\s*=\s*"2\.4\.0"', read('native/aether/aether/Cargo.toml'), re.M), 'vendored engine Cargo version is 2.4.0')
require(json.loads(read('package.json'))['version'] == json.loads(read('src-tauri/tauri.conf.json'))['version'] == '1.4.0', 'desktop version stays 1.4.0')
workflow = read('.github/workflows/build.yml')
script = read('scripts/build-psiphon.ps1')
engine = read('src-tauri/src/engine.rs')
core = read('native/aether/aether/src/psiphon.rs')
require('PSIPHON_VERSION: ' + pin in workflow and pin in script, 'Psiphon CI and build script pin the same reviewed commit')
require('CluvexStudio/psiphon-tunnel-core.git' in script and 'Psiphon-Labs/psiphon-tunnel-core.git' not in script and 'git checkout --detach $Version' in script and '$actual -ne $Version' in script, 'build pins the compatible Psiphon fork, rejects a mismatched checkout')
require('AETHER_PSIPHON_SERVER_ENTRIES' in engine and 'AETHER_PSIPHON_SERVER_ENTRIES' in core and 'client_arguments(&config_path, state, entries.as_deref())' in core, 'the supplied server list reaches the core-managed Psiphon child')
require('FRONTED-MEEK-CDN-OSSH' in core, 'the name rejected by the old Psiphon binary is covered by the matching fork')
require("'Waiting for engine-managed Psiphon…': 'در انتظار راه‌اندازی سایفون توسط هسته…'" in read('src/i18n.js'), 'Persian status line has an exact translation')
require("CORE_SYNC: 'off'" in workflow and 'core_sync' not in workflow, 'CI keeps the reviewed 2.4.0 core by default')
print('Psiphon and core static guard passed; runtime connection testing remains necessary.')
