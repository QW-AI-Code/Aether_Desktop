#!/usr/bin/env bash
# بازرسی روی خودِ ZIP، از حالت استخراج‌شده — نه روی پوشهٔ کاری.
# چیزی که تحویل می‌شود همین است، پس همین سنجیده می‌شود.
#
# استفاده:  bash scripts/verify-package.sh [path/to/Aether_Windows_V1.4.0.zip]
#   مسیرِ ZIP از آرگومانِ اول یا متغیرِ AETHER_ZIP می‌آید (پیش‌فرض:
#   dist/Aether_Windows_V1.4.0.zip کنارِ ریشهٔ مخزن). پوشهٔ بالاییِ ZIP خودکار
#   پیدا می‌شود؛ هیچ مسیرِ ثابتی از محیطِ دیگری فرض نمی‌شود.
set -u
EXPECT_VERSION="1.4.0"
EXPECT_CORE="2.4.0"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIP="${1:-${AETHER_ZIP:-$REPO_ROOT/dist/Aether_Windows_V${EXPECT_VERSION}.zip}}"
[ -f "$ZIP" ] || { echo "✗ ZIP پیدا نشد: $ZIP"; exit 1; }
ZIP="$(cd "$(dirname "$ZIP")" && pwd)/$(basename "$ZIP")"
V="${VERIFY_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/aether-verify.XXXXXX")}"
rm -rf "$V" && mkdir -p "$V"
unzip -q "$ZIP" -d "$V" || { echo "✗ ZIP باز نشد: $ZIP"; exit 1; }
TOP=$(find "$V" -mindepth 1 -maxdepth 2 -name package.json -path '*/package.json' | head -1)
[ -n "$TOP" ] || { echo "✗ package.json در ZIP نیست"; exit 1; }
cd "$(dirname "$TOP")" || exit 1
echo "ZIP: $ZIP"
fail=0
ok()   { echo "  ✓ $1"; }
bad()  { echo "  ✗ $1"; fail=1; }
have() { if grep -qF -- "$2" "$1" 2>/dev/null; then ok "$3"; else bad "$3"; fi; }
# متنِ یک تابع، نه کلِ فایل: «این کلید در این تابع نیست» را نمی‌شود با grep
# روی فایل سنجید.
fnbody() { sed -n "/$2/,/^}/p" "$1"; }

echo "── نسخه"
for f in package.json src-tauri/tauri.conf.json; do
  v=$(python3 -c "import json;print(json.load(open('$f'))['version'])")
  [ "$v" = "$EXPECT_VERSION" ] && ok "$f = $v" || bad "$f = $v"
done
v=$(grep -m1 '^version' src-tauri/Cargo.toml | cut -d'"' -f2); [ "$v" = "$EXPECT_VERSION" ] && ok "Cargo.toml = $v" || bad "Cargo.toml = $v"
v=$(grep -m1 'define MyAppVersion' installer/aether.iss | cut -d'"' -f2); [ "$v" = "$EXPECT_VERSION" ] && ok "installer = $v" || bad "installer = $v"
v=$(grep -oE 'assemblyIdentity version="[0-9.]+"' src-tauri/windows-manifest.xml | head -1 | cut -d'"' -f2); [ "$v" = "$EXPECT_VERSION.0" ] && ok "manifest = $v" || bad "manifest = $v"
v=$(sed -n '/name = "aether-desktop"/,+1p' src-tauri/Cargo.lock | grep -m1 '^version' | cut -d'"' -f2); [ "$v" = "$EXPECT_VERSION" ] && ok "Cargo.lock = $v" || bad "Cargo.lock = $v"
[ "$(tr -d '\r\n' < CORE_VERSION)" = "$EXPECT_CORE" ] && ok "CORE_VERSION = $EXPECT_CORE" || bad "CORE_VERSION = $(cat CORE_VERSION)"

echo "── مورد ۱: تور روی فلگ‌های خودِ هسته می‌نشیند"
have src-tauri/src/profile.rs 'pub enum TorMode' 'profile: TorMode هست'
have src-tauri/src/profile.rs 'pub enum TorBridges' 'profile: TorBridges هست'
for flag in '"--tor"' '"--tor-only"' '"--tor-reverse"'; do
  have src-tauri/src/profile.rs "$flag" "profile: فلگِ $flag فرستاده می‌شود"
done
# چهار بک‌اند، و هر چهارتا در نگاشتِ حالت. اگر کسی یکی اضافه کند و از نگاشت جا
# بماند، `tor_mode` برایش None می‌دهد و بی‌صدا مثل تونلِ ساده رفتار می‌کند.
for b in 'Tor' 'AetherTor' 'TorPsiphon' 'TorAether'; do
  if fnbody src-tauri/src/profile.rs 'fn tor_mode' | grep -q "TransportBackend::$b"; then
    ok "tor_mode: $b نگاشت شده"
  else
    bad "tor_mode: $b در نگاشت نیست"
  fi
done
# قلبِ A15: انتخابِ درگاه. در `--tor-only` درگاهِ خودِ تونل، در زنجیره و معکوس
# درگاهِ تور. اشتباهش خطا نمی‌دهد، فقط خروجیِ غلط — پس همین‌جا قفل می‌شود.
if python3 - <<'PY'
import sys
s = open('src-tauri/src/profile.rs', encoding='utf-8').read()
body = s[s.index('fn tor_socks_port'):]
body = body[:body.index('\n    }')]
only = body[body.index('TorMode::Only'):]
sys.exit(0 if 'LOCAL_SOCKS_PORT' in only.split('\n')[0] and 'TOR_SOCKS_PORT' in body else 1)
PY
then ok "tor_socks_port: تنها-تور درگاهِ تونل، زنجیره/معکوس درگاهِ تور"
else bad "tor_socks_port: نگاشتِ درگاه درست نیست"; fi

echo "── مورد ۲: پل فقط جایی که معنا دارد"
have src-tauri/src/profile.rs '--tor-bridge' 'profile: سطرهای پل به هسته می‌روند'
have src-tauri/src/profile.rs 'fn sanitized_bridges' 'profile: پل‌های کاربر اعتبارسنجی می‌شوند'
# در `Aether → Tor` تور از داخل تونل شماره‌گیری می‌شود، پس کنترل‌های پل باید در
# رابط رندر نشوند و دلیلش نوشته شود — نه فعال و بی‌اثر.
have src/views/advanced.js 'torChained(p.backend)' 'advanced.js: کنترلِ پل به حالتِ زنجیره‌ای شرطی است'
have src/views/advanced.js 'Not needed in this mode: Tor is dialled through the Aether tunnel' 'advanced.js: دلیلِ بی‌اثر بودنِ پل روی صفحه هست'
# دروازهٔ قابلیت: با هستهٔ قدیمی‌تر، بک‌اندهای تور غیرفعال و توضیح‌دار می‌شوند.
have src/views/advanced.js 'caps.tor' 'advanced.js: بک‌اندهای تور به CoreCaps بسته‌اند'
have src/views/advanced.js 'tor-caps-note' 'advanced.js: یادداشتِ هستهٔ قدیمی هست'
# هر دو متنِ تازه باید ترجمهٔ فارسی داشته باشند، وگرنه رابطِ فارسی انگلیسی می‌ماند.
for key in 'Not needed in this mode: Tor is dialled through the Aether tunnel' 'The Tor modes need engine core 2.0.0 or newer'; do
  if python3 - "$key" <<'PY'
import sys
s = open('src/i18n.js', encoding='utf-8').read()
key = sys.argv[1]
i = s.find(key)
if i == -1:
    sys.exit(1)
# پس از کلید باید یک رشتهٔ فارسی بیاید؛ ASCII خالی یعنی ترجمه‌نشده.
seg = s[i:i + 1200]
seg = seg[seg.index("':") + 2:] if "':" in seg else seg
sys.exit(0 if any('\u0600' <= c <= '\u06ff' for c in seg[:600]) else 1)
PY
  then ok "i18n: ترجمهٔ «${key:0:38}…» هست"; else bad "i18n: ترجمهٔ «${key:0:38}…» نیست"; fi
done

echo "── مورد ۳: درصدِ راه‌اندازی ترجمه‌پذیر است"
have src-tauri/src/state.rs 'tor_percent' 'state: درصد یک فیلدِ عددیِ جداست'
have src-tauri/src/tor_bootstrap.rs 'fn snapshot' 'tor_bootstrap: خواندنِ وضعیت از لاگ'
have src-tauri/src/tor_bootstrap.rs 'fn stalled' 'tor_bootstrap: گیرکردن از کندی جدا است'
have src-tauri/src/state.rs 'Stalled' 'state: دروازهٔ تور حالتِ Stalled دارد'
# اشکالی که در همین نسخه اصلاح شد: جمله نباید در Rust ساخته شود و به UI برود،
# وگرنه رابطِ فارسی یک خطِ انگلیسی نشان می‌دهد.
if grep -nE '"[^"]*\{[a-z_]*\}%|% *\)' src-tauri/src/state.rs | grep -q 'percent'; then
  bad "state.rs: درصد داخلِ یک رشته جاسازی شده"
else
  ok "state.rs: هیچ رشتهٔ آماده‌ای با درصد ساخته نمی‌شود"
fi
have src/views/home.js 'torPercent' 'home.js: درصد را از snapshot می‌گیرد'
if fnbody src/views/home.js 'function captionFor' | grep -q "t("; then
  ok "home.js: خطِ وضعیت از لایهٔ ترجمه می‌آید"
else
  bad "home.js: خطِ وضعیت ترجمه نمی‌شود"
fi

echo "── مورد ۴: ترابرِ افزونه، و اینکه انتشار را نگه ندارد"
[ -f scripts/build-pt.ps1 ] && ok "scripts/build-pt.ps1 هست" || bad "scripts/build-pt.ps1 غایب"
have scripts/build-pt.ps1 'lyrebird-0.6.1' 'build-pt: نسخه پین شده'
have scripts/build-pt.ps1 'CGO_ENABLED' 'build-pt: بی CGO بیلد می‌شود'
# هیچ مسیری از این اسکریپت نباید بیلد را بکشد: هر خروجِ زودهنگام صفر است.
if grep -nE '^\s*exit [1-9]' scripts/build-pt.ps1 >/dev/null; then
  bad "build-pt: یک exit غیرصفر دارد — پل‌ها افزونه‌اند و نباید انتشار را بکشند"
else
  ok "build-pt: هر مسیرِ شکست با exit 0 رد می‌شود"
fi
have scripts/stage-payload.ps1 'engine/pt' 'stage-payload: ترابر در engine/pt بسته می‌شود'
have scripts/stage-payload.ps1 'NOTE' 'stage-payload: نبودِ ترابر فقط یادداشت است'
have .github/workflows/build.yml 'build-pt.ps1' 'workflow: مرحلهٔ PT هست'
have .github/workflows/build.yml 'LYREBIRD_VERSION' 'workflow: نسخهٔ lyrebird پین شده'
# دو تلهٔ خاموشِ همین نسخه: زیرپوشه باید کپی شود و متغیر باید engine/pt را بدهد.
if fnbody src-tauri/src/engine.rs 'fn prepare_runtime_engine' | grep -q '"pt"'; then
  ok "engine.rs: زیرپوشهٔ pt به پوشهٔ اجرا کپی می‌شود"
else
  bad "engine.rs: زیرپوشهٔ pt کپی نمی‌شود — پل بی ترابر می‌ماند"
fi
# مسیرها از engine.rs به pt.rs کوچ کردند (همان دوری که تکرار حذف شد)، پس سنجه
# هم باید همان‌جا را بپرسد — وگرنه قابلیتِ سالم را قرمز گزارش می‌کند.
if fnbody src-tauri/src/pt.rs 'pub fn dirs' | grep -q 'join("engine").join("pt")' \
   && fnbody src-tauri/src/pt.rs 'pub fn dirs' | grep -q 'join("pt")'; then
  ok "pt.rs: هر دو مسیرِ ترابر — engine/pt (جای هستهٔ ۲.۰.۰) و pt"
else
  bad "pt.rs: مسیرِ PT با جایی که هستهٔ ۲.۰.۰ می‌گردد یکی نیست"
fi
if fnbody src-tauri/src/engine.rs 'fn tor_runtime_dirs' | grep -q 'AETHER_TOR_PT_DIR'; then
  ok "engine.rs: همان مسیرها در AETHER_TOR_PT_DIR به موتور می‌رسند"
else
  bad "engine.rs: AETHER_TOR_PT_DIR فرستاده نمی‌شود"
fi

echo "── مورد ۵: اصلاحِ A14 — پرسشِ کشور بی‌رمز و بیرون از تونل نمی‌رود"
have src-tauri/src/probe.rs 'fn should_refine_country' 'probe: تصمیم یک تابعِ آزمون‌پذیر است'
# ساختاری و نه رفتاری: در خودِ تابعِ اصلاح نباید هیچ مسیر مستقیمی باشد.
# خطوطِ توضیح کنار گذاشته می‌شوند: خودِ کامنتِ همین تابع توضیح می‌دهد که
# چرا شاخهٔ `connect_direct_ipv4` حذف شده، و یک بار همین سنجه را قرمز کرد.
if fnbody src-tauri/src/probe.rs 'fn refine_country' \
   | grep -vE '^\s*(//|/\*|\*)' | grep -q 'connect_direct_ipv4'; then
  bad "probe: مسیرِ مستقیم در refine_country مانده"
else
  ok "probe: refine_country فقط از تونل می‌رود"
fi
if grep -q 'fn refinement_only_when_unknown_and_tunnelled' src-tauri/src/probe.rs; then
  ok "probe: آزمونِ واحدِ همین شرط هست"
else
  bad "probe: آزمونِ شرط غایب"
fi

echo "── پس‌رفت‌های ۱.۲.۴ که نباید برگردند"
for k in upstream routeDirect manualPeer backend splitMode lanShare killSwitch accessSecret; do
  if fnbody src-tauri/src/ai_patch.rs 'fn chat_writable' | grep -q "\"$k\""; then
    bad "کلیدِ خطرناک در فهرستِ چت: $k"
  else
    ok "چت نمی‌تواند $k را بنویسد"
  fi
done
if python3 - <<'PY'
import sys
s = open('src/main.js', encoding='utf-8').read()
body = s[s.index('export async function saveProfile'):]
body = body[:body.index("\n}\n")]
read, write = body.find("invoke('get_profile')"), body.find("invoke('set_profile'")
sys.exit(0 if (read != -1 and write != -1 and read < write) else 1)
PY
then ok "saveProfile اول می‌خواند بعد می‌نویسد"; else bad "saveProfile روی کپیِ محلی می‌نویسد"; fi

echo "── اسناد ۱.۳.۰ (هستهٔ دست‌نخوردهٔ 2.4.0)"
for f in README.md README.fa.md release-notes.md .github/release-notes.md; do
  if grep -qiE 'اصلاحیهٔ p[0-9]|correction p[0-9]|چرا بیلد قبلی سبز نشد' "$f"; then
    bad "$f: رد پای اصلاحیه‌های ما"
  else
    ok "$f: پاک"
  fi
  have "$f" 'Aether Core 2.4.0' "$f: هستهٔ 2.4.0 را معرفی می‌کند"
done
have README.md "## What's new in 1.4.0" 'README.md: بخشِ ۱.۴.۰ هست'
have README.fa.md 'تازه‌های نسخهٔ ویندوز ۱.۳.۰' 'README.fa.md: بخشِ ۱.۴.۰ هست'
have release-notes.md '# Aether Desktop 1.4.0' 'release-notes.md: تیترِ ۱.۴.۰'
have .github/release-notes.md '# Aether Desktop 1.4.0' '.github/release-notes.md: تیترِ ۱.۴.۰'
have release-notes.md 'Tor → Psiphon' 'release-notes: رفعِ برچسبِ SMART نوشته شده'
# هیچ سندی نباید نسخهٔ ۱.۲.۵ را «نسخهٔ فعلی» معرفی کند.
if grep -qE '^# Aether Desktop 1\.2\.5' README.md release-notes.md .github/release-notes.md; then
  bad "اسناد: تیترِ اصلی هنوز ۱.۲.۵ است"
else ok "اسناد: تیترِ اصلی ۱.۲.۵ نیست"; fi

# Neue Sonden für 1.2.5-p2 -- werden in verify-package.sh eingesetzt.
echo "── مورد ۶ (۱.۲.۵-p2): ترابرِ تور از وجودِ فایل تشخیص داده می‌شود"
[ -f src-tauri/src/pt.rs ] && ok "pt.rs هست" || bad "pt.rs غایب"
have src-tauri/src/main.rs 'mod pt;' 'main.rs: ماژول pt وصل است'
# ریشهٔ باگِ «تلهٔ خاموش»: پوشهٔ pt وجود داشت و خالی بود، و کد وجودِ *پوشه* را
# ترابر می‌شمرد. سنجه: هیچ‌کس دیگر با is_dir تصمیم نگیرد و engine از pt بپرسد.
have src-tauri/src/pt.rs 'lyrebird' 'pt.rs: نامِ اجراییِ ترابر را می‌شناسد'
have src-tauri/src/engine.rs 'crate::pt::installed' 'engine.rs: نصب‌بودن را از pt می‌پرسد'
have src-tauri/src/engine.rs 'crate::pt::dirs' 'engine.rs: مسیرهای ترابر از pt می‌آید'
# دقتِ سنجه: `is_dir()` در این تابع بدجا نیست — تصمیم می‌گیرد کدام *پوشه* به
# هسته معرفی شود. آن‌چه نباید از پوشه استنتاج شود، «ترابر نصب است» است. پس
# سنجه روی همان تصمیم است، نه روی وجودِ کلمه.
if fnbody src-tauri/src/engine.rs 'fn tor_runtime_dirs' | grep -q 'crate::pt::installed'; then
  ok "engine.rs: «ترابر نصب است» از pt پرسیده می‌شود، نه از وجودِ پوشه"
else
  bad "engine.rs: تصمیمِ نصب‌بودنِ ترابر به pt واگذار نشده"
fi
if fnbody src-tauri/src/pt.rs 'pub fn find' | grep -q 'is_file()'; then
  ok "pt.rs: تشخیص روی فایلِ اجرایی است"
else
  bad "pt.rs: تشخیص روی فایلِ اجرایی نیست"
fi
have src-tauri/src/engine.rs 'fn transport_installed' 'engine.rs: transport_installed برای پیام/گیت هست'

echo "── مورد ۷: پیامِ شکستِ تور به شکلِ همان تلاش بستگی دارد"
have src-tauri/src/diagnostics.rs 'pub enum TorShape' 'diagnostics: TorShape هست'
have src-tauri/src/diagnostics.rs 'fn stage_failure_message(tor: Option<TorShape>)' 'diagnostics: پیام از شکلِ تلاش می‌آید'
have src-tauri/src/diagnostics.rs 'No pluggable transport' 'diagnostics: پیامِ بی‌ترابر صریح است'
have src-tauri/src/diagnostics.rs 'plain bridges' 'diagnostics: می‌گوید فقط پلِ ساده می‌ماند'
have src-tauri/src/diagnostics.rs 'The tunnel is up' 'diagnostics: پیامِ تورِ داخلِ تونل جدا است'
# در حالتِ زنجیره‌ای، «پل را روشن کن» توصیهٔ غلط است — تونل بالاست و پل نقشی ندارد.
if python3 - <<'PY'
import sys
s = open('src-tauri/src/diagnostics.rs', encoding='utf-8').read()
i = s.index('if shape == TorShape::ThroughTunnel {')
body = s[i:s.index('    let snap = crate::tor_bootstrap::snapshot();', i + 10)]
sys.exit(1 if 'bridges on' in body else 0)
PY
then ok "diagnostics: در تورِ داخلِ تونل پیشنهادِ پل داده نمی‌شود"
else bad "diagnostics: در تورِ داخلِ تونل پیشنهادِ پل داده می‌شود"; fi
# بودجه/آستانه باید از پروفایلِ همین تلاش بیاید، نه از پروفایلِ کاربر.
have src-tauri/src/state.rs 'fn tor_shape' 'state.rs: شکلِ تور برای همین تلاش حساب می‌شود'
have src-tauri/src/state.rs 'fn tor_bridges_can_help' 'state.rs: گیتِ پل مود-آگاه است'
if grep -q 'fn tor_bridges_allowed' src-tauri/src/state.rs; then
  bad "state.rs: گیتِ مود-کورِ قبلی هنوز هست"
else
  ok "state.rs: گیتِ مود-کورِ قبلی برداشته شد"
fi

echo "── مورد ۸: پیام‌های تازه به فارسی می‌رسند"
# `snapshot.detail` جملهٔ کاملِ Rust است و در home.js از t() می‌گذرد؛ جملهٔ دارای
# عدد در جدولِ متن-به-متن پیدا نمی‌شود، پس t() یک تلاشِ دومِ الگویی دارد.
have src/i18n.js 'function numbered' 'i18n: تلاشِ دومِ الگویی برای جمله‌های دارای عدد'
have src/i18n.js 'Tor stopped at {0}% and could not reach the Tor network' 'i18n: ترجمهٔ پیامِ بی‌ترابر با {0}'
have src/i18n.js 'The tunnel started but the self-test failed.' 'i18n: ترجمهٔ پیامِ خودآزما'
have tests/assistant-smoke.mjs 'همان الگو برای هر درصدی کار می‌کند' 'تست: الگوی درصد سنجیده می‌شود'

echo "── مورد ۹: پیش‌فرض‌ها همان موبایل ۱.۳.۰"
have src-tauri/src/profile.rs 'scan_mode: ScanMode::Balanced' 'profile: scanMode = BALANCED مثل موبایل'
have src-tauri/src/profile.rs 'reconnect_attempts: 5' 'profile: reconnectRetryLimit = 5 مثل موبایل'
# و شرطی که این پیش‌فرض بی آن یک پسرفت است: هر پلهٔ نردبان Turbo باشد.
if fnbody src-tauri/src/smart_auto.rs 'fn auto_plan' | grep -q 'scan_mode = ScanMode::Turbo'; then
  ok "smart_auto: هر پلهٔ نردبان Turbo می‌گیرد (مثل SmartAuto.kt)"
else
  bad "smart_auto: پله‌ها Turbo نمی‌گیرند — بودجهٔ هر پله ۱۵۰ ثانیه می‌شود"
fi
have src-tauri/src/smart_auto.rs 'fn every_ladder_rung_scans_in_turbo_while_the_profile_stays_balanced' 'تست: پاریتیِ نردبان قفل شده'
have src-tauri/src/smart_auto.rs 'fn a_manual_protocol_keeps_the_users_own_scan_mode' 'تست: مسیرِ دستی بودجهٔ کامل می‌گیرد'

echo "── مورد ۱۰: تنظیماتی که Rust نوشته روی صفحه می‌آید"
have src/main.js 'function dropProfileViews' 'main.js: نمای پروفایل‌محور باطل می‌شود'
if fnbody src/main.js 'export function applyProfileSnapshot' | grep -q 'dropProfileViews()'; then
  ok "main.js: رخدادِ پروفایل نمای ساخته‌شده را باطل می‌کند"
else
  bad "main.js: رخدادِ پروفایل فقط emit می‌کند — پنل کهنه می‌ماند"
fi
have src/main.js 'function editingInside' 'main.js: بازسازی وسطِ تایپِ کاربر عقب می‌افتد'
have src/main.js 'export function showTab' 'main.js: ریل و تست از یک مسیر می‌روند'
have tests/profile-sync.mjs 'پس از رخدادِ پروفایل، کنترل مقدارِ تازه را دارد' 'تست: پنلِ ساخته‌شده سنجیده می‌شود'

echo "── مورد ۱۱: بستهٔ منتشرشده بی‌ترابر نمی‌رود"
have .github/workflows/build.yml 'A published build must carry the pluggable transport' 'CI: گیتِ ترابر هست'
if python3 - <<'PY'
import re
import sys

TEXT = open('.github/workflows/build.yml', encoding='utf-8').read()


def steps_with_pyyaml():
    """راهِ دقیق، وقتی PyYAML باشد."""
    import yaml
    d = yaml.safe_load(TEXT)
    out = []
    for s in d['jobs']['build']['steps']:
        out.append({
            'name': s.get('name', ''),
            'if': s.get('if'),
            'coe': s.get('continue-on-error') is True,
        })
    return out


def steps_without_pyyaml():
    """راهِ بی‌وابستگی: فهرستِ گام‌های job `build` را دستی می‌خوانَد.

    فقط همان چیزی که این سنجه لازم دارد — مرزِ گام‌ها (`- name:` یا `- uses:`)
    و کلیدهای `name`، `if` و `continue-on-error`. عمداً هیچ ادعای عمومی
    دربارهٔ YAML ندارد.
    """
    lines = TEXT.splitlines()
    # آغازِ `build:` داخلِ `jobs:` و آغازِ `steps:` آن.
    in_jobs = False
    build_indent = None
    steps_indent = None
    steps_lines = []
    for line in lines:
        if re.match(r'^jobs:\s*$', line):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        m = re.match(r'^(\s+)([A-Za-z0-9_-]+):\s*$', line)
        if m and build_indent is None and m.group(2) == 'build':
            build_indent = len(m.group(1))
            continue
        if build_indent is None:
            continue
        # پایانِ job: هر کلیدِ هم‌ترازِ دیگر
        if steps_indent is not None:
            indent = len(line) - len(line.lstrip())
            if line.strip() and indent <= build_indent and not line.lstrip().startswith('-'):
                break
            steps_lines.append(line)
            continue
        if re.match(r'^\s+steps:\s*$', line):
            steps_indent = len(line) - len(line.lstrip())
    out = []
    cur = None
    item_indent = None
    for line in steps_lines:
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if stripped.startswith('- '):
            if item_indent is None:
                item_indent = indent
            if indent == item_indent:
                if cur is not None:
                    out.append(cur)
                cur = {'name': '', 'if': None, 'coe': False}
                stripped = stripped[2:]
                indent += 2
        if cur is None:
            continue
        # کلیدهای سطحِ خودِ گام، نه کلیدهای تودرتو مثلِ `with:`
        if item_indent is not None and indent != item_indent + 2:
            continue
        m = re.match(r"(name|if|continue-on-error):\s*(.*)$", stripped)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip()
        # فقط گیومهٔ *دورِ کل مقدار* برداشته می‌شود. strip() ساده، `'` انتهایی
        # شرطِ `!= 'pull_request'` را هم می‌بُرد و سنجه قرمزِ کاذب می‌داد.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        if key == 'name':
            cur['name'] = value
        elif key == 'if':
            cur['if'] = value
        else:
            cur['coe'] = value.lower() == 'true'
    if cur is not None:
        out.append(cur)
    return out


try:
    steps = steps_with_pyyaml()
    how = 'PyYAML'
except ImportError:
    steps = steps_without_pyyaml()
    how = 'خوانشِ مستقیم (PyYAML نبود)'

names = [s['name'] for s in steps]
try:
    gate = next(i for i, n in enumerate(names) if n.startswith('A published build must carry'))
    build = next(i for i, n in enumerate(names) if n.startswith('Build pluggable transport'))
    stage = next(i for i, n in enumerate(names) if n == 'Stage payload')
except StopIteration:
    print('    گامِ لازم در فهرست پیدا نشد (%s): %d گام خوانده شد' % (how, len(steps)))
    sys.exit(1)

problems = []
if steps[gate]['if'] != "github.event_name != 'pull_request'":
    problems.append('شرطِ گیت درست نیست: %r' % steps[gate]['if'])
if not (build < stage < gate):
    problems.append('ترتیبِ گام‌ها: ساخت=%d، استیج=%d، گیت=%d' % (build, stage, gate))
if not steps[build]['coe']:
    problems.append('گامِ ساختِ ترابر باید continue-on-error بماند')
if steps[gate]['coe']:
    problems.append('گیت خودش continue-on-error دارد — یعنی بی‌اثر است')
for x in problems:
    print('    ' + x)
sys.exit(1 if problems else 0)
PY
then ok "CI: گیت بعد از استیج، فقط در بیلدِ منتشرشدنی، و بی continue-on-error"
else bad "CI: چیدمانِ گیتِ ترابر درست نیست"; fi

echo "── مورد ۱۲ (۱.۲.۵): ابعاد پنجره ذخیره و بازگردانی می‌شود"
# window.rs منطقِ خالص است (بی هیچ importی از tauri، تا آزمون‌پذیر بماند) و
# چسبِ پنجره در main.rs است. پس هر کدام را همان‌جا که هست می‌سنجیم.
have src-tauri/src/window.rs 'pub fn place' 'window: منطقِ جای‌گذاری هست'
have src-tauri/src/window.rs 'pub fn encode' 'window: سریال‌سازیِ هندسه هست'
have src-tauri/src/window.rs 'pub fn decode' 'window: خواندنِ هندسه هست'
have src-tauri/src/window.rs 'pub const PREFS_KEY: &str = "windowGeometryMobile"' 'window: کلیدِ prefs همان windowGeometryMobile است'
have src-tauri/src/main.rs 'fn remember_window_geometry' 'window: ذخیرهٔ هندسه در main.rs هست'
have src-tauri/src/main.rs 'fn restore_window_geometry' 'window: بازگردانیِ هندسه در main.rs هست'
# فقط بودنِ فایل کافی نیست — ۱.۲.۵ یک بار همین‌جا گیر کرد: ماژول نوشته و
# آزمون‌شده بود ولی به main.rs وصل نبود، پس در برنامهٔ در حال اجرا هیچ اثری
# نداشت. پس وصل‌بودن هم سنجیده می‌شود.
have src-tauri/src/main.rs 'mod window;' 'window: ماژول در main.rs ثبت است'
have src-tauri/src/main.rs 'restore_window_geometry(&win' 'window: بازگردانی پیش از نخستین فریم صدا زده می‌شود'
for ev in 'Resized' 'Moved' 'CloseRequested'; do
  if sed -n '/on_window_event/,/});/p' src-tauri/src/main.rs | grep -q "$ev"; then
    ok "window: رویدادِ $ev به ذخیره وصل است"
  else bad "window: رویدادِ $ev به ذخیره وصل نیست"; fi
done
# و کمینه‌ها باید با tauri.conf.json یکی باشند: کمینه‌ای بلندتر از ناحیهٔ کار
# همان چیزی است که کاربر گزارش کرد (پنجره بزرگ‌تر از صفحه باز می‌شد).
# دقتِ الگو مهم است: `MIN_W[^0-9]*` روی `pub const MIN_W: u32 = 960` عددِ
# ۳۲ را از `u32` برمی‌داشت. پس کلِ اعلان سنجیده می‌شود.
minw=$(sed -n 's/^pub const MIN_W: u32 = \([0-9]*\);/\1/p' src-tauri/src/window.rs | head -1)
minh=$(sed -n 's/^pub const MIN_H: u32 = \([0-9]*\);/\1/p' src-tauri/src/window.rs | head -1)
confw=$(python3 -c "import json;w=json.load(open('src-tauri/tauri.conf.json'))['app']['windows'][0];print(int(w.get('minWidth',0)))" 2>/dev/null)
confh=$(python3 -c "import json;w=json.load(open('src-tauri/tauri.conf.json'))['app']['windows'][0];print(int(w.get('minHeight',0)))" 2>/dev/null)
if [ -n "$minw" ] && [ "$minw" = "$confw" ] && [ "$minh" = "$confh" ]; then
  ok "window: کمینه‌ها با tauri.conf.json یکی‌اند (${minw}×${minh})"
else
  bad "window: کمینهٔ کد ${minw}×${minh} با tauri.conf.json ${confw}×${confh} نمی‌خواند"
fi

echo "── مورد ۱۳ (۱.۲.۵): ترتیب نردبان از شکل فیلترینگ می‌آید، نه از آرایهٔ ثابت"
have src-tauri/src/smart_auto.rs 'pub enum DpiClass' 'ladder: DpiClass هست'
have src-tauri/src/smart_auto.rs 'fn preference_for' 'ladder: ترتیب از preference_for می‌آید'
if sed -n '/fn auto_plan/,/^}/p' src-tauri/src/smart_auto.rs | grep -q 'preference_for(fp)'; then
  ok "ladder: auto_plan همان تابع را صدا می‌زند"
else bad "ladder: auto_plan هنوز به آرایهٔ ثابت وصل است"; fi
# و ترتیبِ هر کلاس. WireGuard روی شبکهٔ باز باید **اول** باشد؛ این همان
# ایرادِ گزارش‌شده بود («WireGuard نادیده گرفته می‌شود»).
if sed -n '/fn preference_for/,/^}/p' src-tauri/src/smart_auto.rs |
   grep -qE 'DpiClass::Open => \[Protocol::Wireguard'; then
  ok "ladder: روی شبکهٔ باز WireGuard اول است"
else bad "ladder: روی شبکهٔ باز WireGuard اول نیست"; fi
if sed -n '/fn preference_for/,/^}/p' src-tauri/src/smart_auto.rs |
   grep -qE 'DpiClass::SniFiltering => \[Protocol::Wireguard'; then
  ok "ladder: با فیلترینگِ SNI هم WireGuard اول است"
else bad "ladder: با فیلترینگِ SNI ترتیب درست نیست"; fi
if sed -n '/fn preference_for/,/^}/p' src-tauri/src/smart_auto.rs |
   grep -qE 'DpiClass::UdpThrottled \| DpiClass::Hostile => PREFERENCE'; then
  ok "ladder: بی‌UDP همان ترتیبِ قبلی می‌ماند (WireGuard آخر)"
else bad "ladder: مسیرِ بی‌UDP درست نیست"; fi
# بودجه: سقفِ پاسِ اول و رزروِ راه‌اندازیِ موتور یک حساب‌اند و باید یک‌جا باشند.
have src-tauri/src/budgets.rs 'pub const FIRST_PASS_MAX_MS: u64 = 75_000' 'budget: سقفِ پاسِ اول ۷۵ ثانیه (عددِ اندروید)'
have src-tauri/src/budgets.rs 'pub const ENGINE_TURBO_SCAN_MS' 'budget: پنجرهٔ اسکنِ turboِ موتور نام‌گذاری شده'
have src-tauri/src/budgets.rs 'const _: () = assert!(FIRST_PASS_MAX_MS >= ENGINE_SETUP_RESERVE_MS + ENGINE_TURBO_SCAN_MS)' \
     'budget: رابطه با assertِ زمانِ کامپایل قفل است'
# و هیچ‌کدام از دو مصرف‌کننده نباید نسخهٔ خودش را داشته باشد.
if grep -qE '^const (ENGINE_SETUP_RESERVE_MS|MIN_SCAN_BUDGET_MS|FIRST_PASS_MAX_MS)' \
      src-tauri/src/engine.rs src-tauri/src/smart_auto.rs; then
  bad "budget: یکی از عددها باز هم کپی شده"
else ok "budget: engine.rs و smart_auto.rs هر دو از budgets.rs می‌خوانند"; fi
# نتیجهٔ عددی: پلهٔ turbo (۶۰s) باید بیش از پنجرهٔ اسکن به موتور بدهد.
python3 - <<'PY' && ok "budget: پلهٔ turbo ۴۶ ثانیه اسکن می‌دهد ≥ ۴۵ ثانیهٔ موتور" || bad "budget: پلهٔ turbo اسکن را گرسنه می‌گذارد"
import re, sys
s = open('src-tauri/src/budgets.rs', encoding='utf-8').read()
num = lambda k: int(re.search(r'pub const ' + k + r': u64 = ([0-9_]+)', s).group(1).replace('_', ''))
reserve, floor, turbo, first = (num('ENGINE_SETUP_RESERVE_MS'), num('MIN_SCAN_BUDGET_MS'),
                               num('ENGINE_TURBO_SCAN_MS'), num('FIRST_PASS_MAX_MS'))
rung = min(60_000, first)
sys.exit(0 if max(rung - reserve, floor) >= turbo else 1)
PY

echo "── مورد ۱۴ (۱.۴.۰): هستهٔ Aether 2.4.0 و overlay ثبت‌شده و هویتِ موتور"
[ "$(tr -d '\r\n' < PATCHLEVEL)" = "1.4.0" ] && ok "PATCHLEVEL = 1.4.0" || bad "PATCHLEVEL = $(cat PATCHLEVEL 2>/dev/null)"
if python3 scripts/check-core-pristine.py >/dev/null 2>&1; then
  ok "core: baseline + reviewed hash-locked mobile overlay"
else bad "core: native/aether با مانیفستِ آپ‌استریم نمی‌خواند"; fi
if [ -f CORE_PORT_PATCHES.json ] && python3 scripts/check-core-pristine.py >/dev/null 2>&1; then
  ok "core: build provenance is part of the reviewed hash-locked overlay"
else bad "core: missing or invalid reviewed overlay"; fi
[ -d native/aether/.upstream-baseline ] && bad "core: .upstream-baseline برگشته" || ok "core: بی‌.upstream-baseline"
have src-tauri/src/provenance.rs 'fn banner_version' 'identity: نسخه از بنرِ خودِ موتور خوانده می‌شود'
if sed -n '/fn spawn_drain/,/^}/p' src-tauri/src/engine.rs | grep -q 'provenance::ingest'; then
  ok "identity: خروجیِ موتور واقعاً بازرسی می‌شود"
else bad "identity: قلابِ ingest در spawn_drain نیست"; fi
have src-tauri/src/state.rs 'provenance::log_app_identity' 'identity: هویتِ برنامه در هر اتصال لاگ می‌شود'
have src-tauri/src/diagnostics.rs 'Build identity' 'identity: در گزارشِ محیط هم می‌آید'
for g in 'Core must match upstream plus reviewed overlay' \
         'Engine must be the bundled core version' \
         'A published payload must carry the bundled core version'; do
  have .github/workflows/build.yml "$g" "CI: گیتِ «$g»"
done

echo "── مورد ۱۵ (۱.۲.۵): آنچه لاگ ۲۰۲۶-۰۹-۱۶ نشان داد"
# (بررسی‌های داخلیِ arti/پل‌های هسته حذف شدند: هسته حالا دست‌نخورده است و
#  همهٔ حالت‌های تور از tor.exe رسمی می‌گذرند.)
have src-tauri/src/tor_native.rs 'get_info("status/bootstrap-phase"' 'tor بومی: فازِ bootstrap از پورتِ کنترل پرسیده می‌شود'
have src-tauri/src/tor_native.rs 'fn parse_log_progress(' 'tor بومی: لاگِ خودِ تور مسیرِ دومِ پیشرفت است'
have src-tauri/src/tor_native.rs 'fn is_timeout(' 'tor بومی: مهلتِ خواندن معنای شکست ندارد (لاگِ ۱۷ سپتامبر: os error 10060)'
have src-tauri/src/tor_native.rs 'launch.budget.unwrap_or(BOOTSTRAP_TIMEOUT)' 'tor بومی: بودجه از برنامه می‌آید'
have src-tauri/src/tor_native.rs 'fn plan_waves(' 'tor بومی: موج‌های ترابر obfs4 → snowflake'
have src-tauri/src/tor_native.rs 'ClientTransportPlugin {methods} exec {}' 'tor بومی: مسیرِ ترابر بی‌نقل‌قول و روش‌ها از بایناریِ موجود'
have scripts/stage-tor.ps1 'snowflake-client.exe' 'تدارک: اسنوفلیک از بستهٔ رسمی برداشته می‌شود'
have src-tauri/src/main.rs 'mod tor_native;' 'ماژولِ تورِ بومی ثبت شده'
have src-tauri/src/state.rs 'self.start_native_tor(&cand)?' 'حالتِ «تور تنها» به tor.exe رسمی وصل است'
have src-tauri/src/state.rs 'fn carrier_alive(' 'زنده‌بودن از حامل پرسیده می‌شود، نه فقط از موتور'
have src-tauri/src/engine.rs 'fn native_tor(' 'مسیرهای تورِ رسمی از engine.rs می‌آیند'
have scripts/stage-tor.ps1 '1e4de9a4f1d99b8f40b5e0c75f3dcc3ea51b0aeab040d48fd23881e9fa94979a' 'دایجستِ بستهٔ i686 (x86) پین شده'
have scripts/stage-tor.ps1 'i686' 'استیجِ تور معماری x86 را می‌شناسد'
have scripts/stage-tor.ps1 '231dad6b9cb401a54c260db7046965ef04e4f72ff071b140d423fb5da281ab1e' 'دایجستِ بستهٔ رسمیِ تور پین شده'

# ۳) بک‌اندِ ذخیره‌شده یک بار به Aether برمی‌گردد.
v=$(grep -m1 'pub const SETTINGS_REV' src-tauri/src/profile.rs | sed 's/.*=\s*//; s/;.*//' | tr -d ' ')
# عددِ ثابت هر انتشار باید دستی بالا می‌رفت؛ چیزی که واقعاً اهمیت دارد این است
# که مهاجرت ۴ یا بالاتر باشد و خودِ برگرداندنِ بک‌اند هم سرجایش مانده باشد.
if [ "$v" -ge 4 ] 2>/dev/null; then ok "store: SETTINGS_REV = $v (≥ 4)"; else bad "store: SETTINGS_REV = $v (۴ یا بالاتر لازم است)"; fi
have src-tauri/src/state.rs 'tor.mark_starting()' 'تورِ در حالِ انلاق زنده حساب می‌شود'
have src-tauri/src/diagnostics.rs 'udp_open_by_design' 'داوریِ نشتی دامنهٔ بلوکِ UDP را می‌خواند'
have src-tauri/src/leakguard.rs 'fn restore_policies(' 'بازگردانیِ سیاست‌ها موازی است'
# ۱.۳.۰: انتخابِ ذخیره‌شدهٔ کاربر دیگر در مهاجرت ریست نمی‌شود.
if fnbody src-tauri/src/store.rs 'fn migrate' | grep -qF 'TransportBackend::'; then
  bad 'store: مهاجرت بک‌اندِ ذخیره‌شدهٔ کاربر را عوض می‌کند'
else
  ok 'store: مهاجرت بک‌اندِ ذخیره‌شدهٔ کاربر را دست نمی‌زند'
fi


echo "── ساختار"
for f in src-tauri/src/tor_bootstrap.rs src-tauri/src/pt.rs scripts/build-pt.ps1 UPGRADE-1.2.5.md \
         src/views/home.js src/i18n.js; do
  [ -f "$f" ] && ok "$f هست" || bad "$f غایب"
done
[ -d node_modules ] && bad "node_modules داخل بسته است" || ok "بی‌node_modules"
# >>> AETHER-APP-PATCH custom-configs
have scripts/stage-xray.ps1 "25.12.8" 'stage-xray: نسخهٔ Xray پین شده'
have scripts/stage-xray.ps1 "5419794670658e14519409320752329375e0fd8a57089f373b3febe9bf3ec5d5" 'stage-xray: دایجستِ x64 پین شده'
have scripts/stage-xray.ps1 "b270190001fd9e566b8c1dc5f4bd8dac62d261d26fe23b7e42953e11adcde8f9" 'stage-xray: دایجستِ x86 پین شده'
have scripts/stage-payload.ps1 'engine/xray' 'stage-payload: Xray در engine/xray بسته می‌شود'
have .github/workflows/build.yml 'stage-xray.ps1' 'workflow: مرحلهٔ Xray هست'
have src-tauri/src/state_custom.rs 'fn custom_begin' 'state_custom: ورودِ کانفیگ سفارشی'
have src-tauri/src/main.rs 'custom::store::init' 'main: مخزنِ کانفیگ‌ها باز می‌شود'
have src/views/settings.js "'custom'" 'settings: ردیفِ کانفیگ‌های سفارشی'
# <<< AETHER-APP-PATCH custom-configs
[ -d src-tauri/target ] && bad "target داخل بسته است" || ok "بی‌target"
[ -d dist-engine ] && bad "dist-engine داخل بسته است" || ok "بی‌dist-engine"

echo
echo "── و همان فرمان‌های CI روی خودِ بستهٔ استخراج‌شده"
# node_modules از پوشهٔ کار قرض گرفته می‌شود تا بسته را آلوده نکند. اگر نبود،
# این گام SKIP می‌شود و صریح می‌گوید — یک گامِ بی‌صدا که سبز به نظر برسد بدتر است.
NM=${NODE_MODULES:-}
if [ -z "$NM" ]; then
  for c in "$REPO_ROOT/node_modules"; do
    [ -d "$c" ] && NM=$c && break
  done
fi
if [ -n "$NM" ] && [ -d "$NM" ]; then
  cp -r "$NM" ./node_modules
  if out=$(npm test 2>&1); then ok "npm test ($(echo "$out" | grep -c '^  ok') سنجه)"; else bad "npm test"; echo "$out" | tail -15; fi
  if out=$(bash scripts/preflight-local.sh 2>&1); then ok "$(echo "$out" | tail -1)"; else bad "preflight"; echo "$out" | tail -15; fi
  rm -rf node_modules
else
  echo "  ⚠ SKIP: node_modules پیدا نشد — npm test و preflight اجرا نشدند (NODE_MODULES=... بده)"
fi

echo
[ $fail -eq 0 ] && echo "VERIFY OK" || echo "VERIFY FAILED"
exit $fail
