#!/usr/bin/env bash
# گام‌های Preflight که بی‌ویندوز هم قابل اجرا هستند، عیناً از .github/workflows.
# قبل از هر بسته‌بندی اجرا می‌شود: یک ZIP که CI ردش می‌کند، تحویل نیست.
set -u
cd "$(dirname "$0")/.." || exit 1
fail=0

echo "── ۱) فایل‌های لازم"
missing=0
for f in $(sed -n '/required=(/,/)/p' .github/workflows/build.yml | grep -oE '"[^"]+"' | tr -d '"'); do
  [ -e "$f" ] || { echo "  ✗ غایب: $f"; missing=1; }
done
[ $missing -eq 0 ] && echo "  ✓ همه هست" || fail=1

echo "── ۲) JSON‌ها معتبرند"
for f in package.json src-tauri/tauri.conf.json src-tauri/capabilities/default.json; do
  if python3 -c "import json,sys; json.load(open('$f'))" 2>/dev/null; then
    echo "  ✓ $f"
  else
    echo "  ✗ $f"; fail=1
  fi
done

echo "── ۳) نسخه در همهٔ جاها یکی است"
v_pkg=$(python3 -c "import json;print(json.load(open('package.json'))['version'])")
v_conf=$(python3 -c "import json;print(json.load(open('src-tauri/tauri.conf.json'))['version'])")
v_cargo=$(grep -m1 '^version' src-tauri/Cargo.toml | cut -d'"' -f2)
v_iss=$(grep -m1 'define MyAppVersion' installer/aether.iss | cut -d'"' -f2)
# اولین version در XML، اعلانِ خودِ XML است (1.0) — نسخهٔ برنامه در assemblyIdentity است.
v_man=$(grep -oE 'assemblyIdentity version="[0-9.]+"' src-tauri/windows-manifest.xml | head -1 | cut -d'"' -f2)
echo "  package.json=$v_pkg tauri.conf=$v_conf Cargo=$v_cargo installer=$v_iss manifest=$v_man"
if [ "$v_pkg" = "$v_conf" ] && [ "$v_pkg" = "$v_cargo" ] && [ "$v_pkg" = "$v_iss" ] && [ "$v_man" = "$v_pkg.0" ]; then
  echo "  ✓ همه $v_pkg"
else
  echo "  ✗ ناهمخوانی نسخه"; fail=1
fi

echo "── ۳ب) هم‌خوانی سایفون، هسته و رابط فارسی"
if out=$(python3 scripts/check-psiphon-core-compat.py 2>&1); then
  echo "  ✓ سازگاری نسخه، باینری سایفون و ترجمه"
else
  echo "  ✗ سازگاری سایفون/هسته"; echo "$out" | tail -12; fail=1
fi

echo "── ۴) حالت پراکسی نباید مسیر کد داشته باشد"
if grep -rniE 'proxy[_-]?mode' src src-tauri/src installer 2>/dev/null | grep -vE 'profile\.rs|\.md$'; then
  echo "  ✗ پیدا شد"; fail=1
else
  echo "  ✓ هیچ مسیری نیست"
fi

echo "── ۵) بیلد وب"
if npx vite build >/tmp/vite.log 2>&1; then
  echo "  ✓ $(grep -c . /tmp/vite.log) خط، بدون خطا"
else
  echo "  ✗ شکست:"; tail -5 /tmp/vite.log; fail=1
fi

# دقیقاً همان فرمانی که CI صدا می‌زند — نه یک بازنویسی مشابه. اگر این دو از هم
# فاصله بگیرند، preflight سبز می‌شود و بیلد می‌شکند؛ یک بار همین اتفاق افتاد.
echo "── ۶) تست‌های JS (npm test — همان فرمان CI)"
if out=$(npm test 2>&1); then
  echo "  ✓ npm test"
else
  echo "  ✗ npm test"; echo "$out" | tail -20; fail=1
fi

echo "── ۷) تست چیدمان در مرورگر واقعی (npm run test:layout)"
if out=$(npm run test:layout 2>&1); then
  if echo "$out" | grep -q '^SKIP'; then
    echo "  ~ رد شد: $(echo "$out" | grep '^SKIP' | head -1)"
  else
    echo "  ✓ $(echo "$out" | grep -E 'ALL OK|همه' | tail -1)"
  fi
else
  echo "  ✗ test:layout"; echo "$out" | tail -20; fail=1
fi

echo "── ۸) ترتیب گام‌های ورک‌فلو (پچ منابع برای گام تست)"
if out=$(python3 scripts/check-workflow-order.py 2>&1); then
  echo "  ✓ ${out##*✓ }"
else
  echo "  ✗ ترتیب گام‌ها"; echo "$out" | head -5; fail=1
fi

echo "── ۸ب) هیچ باقی‌مانده‌ای از ۱.۲.۵ در درخت نیست"
if out=$(python3 scripts/clean-legacy-1.2.5.py --check 2>&1); then
  echo "  ✓ $(echo "$out" | tail -1)"
else
  echo "  ✗ باقی‌ماندهٔ ۱.۲.۵ (python3 scripts/clean-legacy-1.2.5.py --apply)"; echo "$out" | head -8; fail=1
fi

echo "── ۹) هستهٔ 2.4.0 با baseline و پچ‌های ثبت‌شده تطبیق دارد"
if out=$(python3 scripts/check-core-pristine.py 2>&1); then
  echo "  ✓ $(echo "$out" | tail -1)"
else
  echo "  ✗ هسته با آپ‌استریم نمی‌خواند"; echo "$out" | head -8; fail=1
fi

echo "── ۱۰) و همان نگهبان، تغییرِ هسته را می‌گیرد"
if out=$(bash scripts/check-core-pristine-negative.sh 2>&1); then
  echo "  ✓ $(echo "$out" | tail -1)"
else
  echo "  ✗ کنترل‌های منفیِ هسته"; echo "$out" | tail -8; fail=1
fi

echo "── ۱۱) سازگاریِ Psiphon با هستهٔ وندورشده"
if out=$(python3 scripts/check-psiphon-core-compat.py 2>&1); then
  echo "  ✓ $(echo "$out" | tail -1)"
else
  echo "  ✗ سازگاریِ Psiphon"; echo "$out" | head -8; fail=1
fi

echo "── ۱۲) «تور تنها» از tor.exe رسمی می‌گذرد"
if out=$(python3 scripts/check-tor-native.py 2>&1); then
  echo "  ✓ ${out##*✓ }"
else
  echo "  ✗ سیم‌کشیِ تورِ بومی"; echo "$out" | head -8; fail=1
fi

echo "── ۱۳) و همان نگهبان، سیم‌کشیِ شکسته را می‌گیرد"
if out=$(bash scripts/check-tor-native-negative.sh 2>&1); then
  echo "  ✓ ${out##*✓ }"
else
  echo "  ✗ کنترل‌های منفیِ تورِ بومی"; echo "$out" | tail -8; fail=1
fi

echo "── ۱۴) تورِ رسمی برای هر معماریِ ساخته‌شده پین شده است"
if out=$(python3 scripts/check-tor-staging.py 2>&1); then
  echo "  ✓ ${out##*✓ }"
else
  echo "  ✗ استیجِ تور"; echo "$out" | head -8; fail=1
fi

echo "── ۱۵) داوری‌های نشست (لاگِ ۱۶ سپتامبر ۲۰:۰۴)"
if out=$(python3 scripts/check-session-verdicts.py 2>&1); then
  echo "  ✓ ${out##*✓ }"
else
  echo "  ✗ منطقِ نشست"; echo "$out" | head -10; fail=1
fi

echo "── ۱۶) و همان نگهبان، هر هشت بازگشت را می‌گیرد"
if out=$(bash scripts/check-session-verdicts-negative.sh 2>&1); then
  echo "  ✓ ${out##*✓ }"
else
  echo "  ✗ کنترل‌های منفیِ نشست"; echo "$out" | tail -10; fail=1
fi

echo "── ۱۷) کارتِ اتصال و زنجیره‌های تور (لاگ‌های ۱۷ سپتامبر: loge1/3/4)"
if out=$(python3 scripts/check-connection-card.py 2>&1); then
  echo "  ✓ ${out##*✓ }"
else
  echo "  ✗ کارتِ اتصال"; echo "$out" | head -12; fail=1
fi

echo "── ۱۸) و همان نگهبان، هر ۱۴ بازگشت را می‌گیرد"
if out=$(bash scripts/check-connection-card-negative.sh 2>&1); then
  echo "  ✓ ${out##*✓ }"
else
  echo "  ✗ کنترل‌های منفیِ کارتِ اتصال"; echo "$out" | tail -12; fail=1
fi

echo "── ۱۹) هر فایلِ .rs در عمل parse می‌شود (خطای بیلدِ ۱۷ سپتامبر)"
if out=$(python3 scripts/check-rust-parses.py 2>&1); then
  echo "  ✓ ${out##*✓ }"
else
  echo "  ✗ نحوِ Rust"; echo "$out" | head -8; fail=1
fi

echo "── ۲۰) و همان نگهبان، پنج آسیب را می‌گیرد و کدِ سالم را قرمز نمی‌کند"
if out=$(bash scripts/check-rust-parses-negative.sh 2>&1); then
  echo "  ✓ ${out##*✓ }"
else
  echo "  ✗ کنترل‌های نحو"; echo "$out" | tail -8; fail=1
fi

# ۲۳) Windows type checking uses the same resource-only override as CI.
# This does not manufacture engine executables and does not certify linking/installers.
echo "── ۲۳) cargo check برای هر دو معماری MSVC"
if command -v cargo >/dev/null 2>&1; then
  for target in x86_64-pc-windows-msvc i686-pc-windows-msvc; do
    if rustup target list --installed 2>/dev/null | grep -qx "$target"; then
      if out=$(TAURI_CONFIG='{"bundle":{"resources":[]}}' cargo check --manifest-path src-tauri/Cargo.toml --target "$target" --tests -j2 2>&1); then
        echo "  ✓ $target: $(echo "$out" | grep -m1 Finished | sed 's/^ *//')"
      else
        echo "  ✗ $target"; echo "$out" | tail -15; fail=1
      fi
    else
      echo "  ⚠ SKIP: Rust target $target نصب نیست"
    fi
  done
else
  echo "  ⚠ SKIP: cargo نصب نیست"
fi

echo "── ۲۴) تست‌های واقعی ماژول‌های قابل‌حمل Rust"
if command -v cargo >/dev/null 2>&1; then
  for manifest in tests/rust-port/Cargo.toml tests/core-policy/Cargo.toml; do
    if out=$(cargo test --manifest-path "$manifest" -j2 2>&1); then
      echo "  ✓ $manifest"; echo "$out" | grep 'test result:'
    else
      echo "  ✗ $manifest"; echo "$out" | tail -15; fail=1
    fi
  done
else
  echo "  ⚠ SKIP: Rust host tests؛ cargo نصب نیست"
fi

echo
[ $fail -eq 0 ] && echo "PREFLIGHT OK" || echo "PREFLIGHT FAILED"
exit $fail
