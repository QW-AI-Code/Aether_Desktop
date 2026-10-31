#!/usr/bin/env bash
# Negative checks for scripts/check-core-pristine.py: each way the core can stop
# being the unmodified upstream source must turn the guard red.
set -u
cd "$(dirname "$0")/.."
GUARD=scripts/check-core-pristine.py
L=native/aether/aether/src/lib.rs
T=native/aether/aether/Cargo.toml
cp native/aether/aether/build.rs /tmp/p.build; cp "$L" /tmp/p.lib; cp "$T" /tmp/p.toml; cp CORE_VERSION /tmp/p.ver
restore() {
  cp /tmp/p.lib "$L"; cp /tmp/p.toml "$T"; cp /tmp/p.ver CORE_VERSION
  cp /tmp/p.build native/aether/aether/build.rs
  rm -f native/aether/aether/src/app_patch.rs
}
fails=0
expect_red() {
  if python3 "$GUARD" >/dev/null 2>&1; then
    echo "  ✗ not caught: $1"; fails=$((fails + 1))
  else
    echo "  ✓ caught: $1"
  fi
  restore
  python3 "$GUARD" >/dev/null 2>&1 || { echo "  ✗ restore incomplete"; fails=$((fails + 1)); }
}
python3 "$GUARD" >/dev/null 2>&1 || { echo "✗ guard is red on the clean tree"; exit 1; }

printf '\n// tweak\n' >> "$L";                                   expect_red "a modified core source file"
printf '// >>> AETHER-APP-PATCH x\nfn main(){}\n' > native/aether/aether/build.rs; expect_red "an app-owned file added to the core"
echo 'pub fn x() {}' > native/aether/aether/src/app_patch.rs;   expect_red "a new source file in the core"
sed -i 's/^version = "2.4.0"/version = "2.4.1"/' "$T";           expect_red "a different core version"
echo "2.2.0" > CORE_VERSION;                                     expect_red "CORE_VERSION out of step with the core"
# A deleted source file (not covered by upstream's .gitignore) must still be red.
cp native/aether/aether/src/cli.rs /tmp/p.cli; rm native/aether/aether/src/cli.rs
if python3 "$GUARD" >/dev/null 2>&1; then echo "  ✗ not caught: a deleted core source file"; fails=$((fails + 1)); else echo "  ✓ caught: a deleted core source file"; fi
cp /tmp/p.cli native/aether/aether/src/cli.rs

# Positive control (build log 2026-10-08): quiche's test keys match upstream's own
# `*.key` rule, so a git checkout never has them. Their absence must stay green.
K=native/aether/quiche/apps/src/bin/cert.key
if [ -f "$K" ]; then
  cp "$K" /tmp/p.key; rm "$K"
  if python3 "$GUARD" >/dev/null 2>&1; then echo "  ✓ green: a git-ignored test key absent from the checkout"
  else echo "  ✗ red on a fresh git checkout (missing $K)"; fails=$((fails + 1)); fi
  cp /tmp/p.key "$K"
fi

if [ "$fails" -eq 0 ]; then echo "✓ all 6 negative checks went red (and the git-checkout control stayed green)"; exit 0; fi
echo "✗ $fails negative check(s) were not caught"; exit 1
