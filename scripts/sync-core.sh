#!/usr/bin/env bash
# =============================================================================
#  همگام‌سازی هستهٔ Aether — هستهٔ دست‌نخورده (pristine).
# -----------------------------------------------------------------------------
#  از ۱.۳.۰ (بازسازی روی Aether 2.4.0) هستهٔ native/aether کپیِ بایت‌به‌بایتِ
#  آپ‌استریم است: هیچ پچ، هیچ build.rs اختصاصی و هیچ .upstream-baseline ندارد.
#  پس ارتقا دیگر merge سه‌طرفه نیست: کلِ درخت با نسخهٔ جدید عوض می‌شود، فایلِ
#  CORE_VERSION (هم native/aether و هم ریشه) نوشته می‌شود و مانیفستِ
#  UPSTREAM-SHA256SUMS با scripts/check-core-pristine.py --update بازتولید می‌شود.
#  پیش‌فرضِ CI همچنان CORE_SYNC=off است؛ یعنی بیلد دقیقاً همین هستهٔ وندورشده را
#  می‌سازد.
# =============================================================================
set -euo pipefail

BASELINE="2.4.0"
CORE_DIR="native/aether"
PREV_DIR="native/.core-prev"
STATE_FILE="native/.core-sync-state"

AETHER_REPO="${AETHER_REPO:-CluvexStudio/Aether}"
CORE_API_BASE="${CORE_API_BASE:-https://api.github.com}"
CORE_GIT_BASE="${CORE_GIT_BASE:-https://github.com}"

note() { echo "::notice::$*"; }
warn() { echo "::warning::$*"; }
emit() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/null}"; }

if [[ ! -f "$CORE_DIR/CORE_VERSION" ]]; then
  echo "::error::$CORE_DIR/CORE_VERSION is missing - the vendored core is incomplete."
  exit 1
fi
VENDORED="$(tr -d '[:space:]' < "$CORE_DIR/CORE_VERSION")"
echo "Vendored core version: ${VENDORED}"

if [[ "${CORE_SYNC:-off}" == "off" ]]; then
  note "CORE_SYNC=off - keeping the vendored core at ${VENDORED}."
  emit core_version "$VENDORED"
  exit 0
fi

LATEST="${CORE_TARGET:-}"
if [[ -z "$LATEST" ]]; then
  LATEST="$(curl -fsSL \
      -H 'Accept: application/vnd.github+json' \
      ${GITHUB_TOKEN:+-H "Authorization: Bearer ${GITHUB_TOKEN}"} \
      "${CORE_API_BASE}/repos/${AETHER_REPO}/releases/latest" 2>/dev/null \
    | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -n1 || true)"
fi
if [[ -z "$LATEST" ]]; then
  warn "Could not reach upstream - keeping ${VENDORED}."
  emit core_version "$VENDORED"; exit 0
fi
echo "Upstream latest: ${LATEST}"
if [[ "$LATEST" == "$VENDORED" ]]; then
  note "Core already at ${VENDORED}."
  emit core_version "$VENDORED"; exit 0
fi

# 1.4.0: never silently discard reviewed mobile networking/security fixes.
if [[ -f CORE_PORT_PATCHES.json ]]; then
  echo "::error::Core 2.4.0 has a reviewed mobile overlay. Rebase CORE_PORT_PATCHES.json explicitly before upgrading the core."
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
if ! git clone --depth 1 --branch "v${LATEST}" \
      "${CORE_GIT_BASE}/${AETHER_REPO}.git" "$TMP/new" 2>/dev/null; then
  warn "Could not fetch v${LATEST} - keeping ${VENDORED}."
  emit core_version "$VENDORED"; exit 0
fi
rm -rf "$TMP/new/.git"

note "Upgrading core ${VENDORED} -> ${LATEST}"
rm -rf "$PREV_DIR"; mkdir -p "$PREV_DIR"
cp -a "$CORE_DIR/." "$PREV_DIR/"
cp -a CORE_VERSION "$PREV_DIR/.root-CORE_VERSION" 2>/dev/null || true

rm -rf "$CORE_DIR"
cp -a "$TMP/new" "$CORE_DIR"
echo "$LATEST" > "$CORE_DIR/CORE_VERSION"
echo "$LATEST" > CORE_VERSION
if ! python3 scripts/check-core-pristine.py --update; then
  warn "Could not regenerate the core manifest - restoring ${VENDORED}."
  rm -rf "$CORE_DIR"; cp -a "$PREV_DIR" "$CORE_DIR"
  mv -f "$CORE_DIR/.root-CORE_VERSION" CORE_VERSION 2>/dev/null || echo "$VENDORED" > CORE_VERSION
  emit core_version "$VENDORED"; exit 0
fi
rm -f "$CORE_DIR/.root-CORE_VERSION"

{
  echo "CORE_PREV_VERSION=$VENDORED"
  echo "CORE_NEW_VERSION=$LATEST"
  echo "CORE_UPGRADED=1"
} > "$STATE_FILE"
note "Core staged at ${LATEST} (rollback snapshot kept in ${PREV_DIR})."
emit core_version "$LATEST"
