# راهنمای مرحله‌به‌مرحلهٔ راه‌اندازی مخزن و اتوماسیون

> هدف: پس از این مراحل، هر `git push` به‌طور کاملاً خودکار چهار فایل نهایی
> (Setup x64/x86 و Portable x64/x86) را می‌سازد و در Releases منتشر می‌کند.
> هیچ مرحلهٔ دستی، هیچ بیلد محلی، هیچ آپلود دستی.

---

## ۰. پیش‌نیازها

هیچ‌کدام از این‌ها روی سیستم شما لازم نیست — همه روی runner گیت‌هاب نصب می‌شوند:
Rust، Node 22.12 یا جدیدتر، Inno Setup 6، Wintun. فقط یک حساب گیت‌هاب لازم دارید.

---

## ۱. ساخت مخزن مجزا

```bash
# روی گیت‌هاب: New repository → AetherDesktop → Public → بدون README
git init AetherDesktop && cd AetherDesktop
# محتوای این اسکلت را اینجا کپی کنید
git add .
git commit -m "feat: Aether Desktop 1.0.0 scaffold"
git branch -M main
git remote add origin https://github.com/<YOUR-ORG>/AetherDesktop.git
git push -u origin main
```

❌ مخزن اندروید را دست نزنید. این دو مخزن فقط یک چیز مشترک دارند:
هستهٔ `CluvexStudio/Aether` که هر دو مستقلاً و خودکار سینک می‌کنند.

---

## ۲. مجوز نوشتن برای Actions (اجباری)

`Settings → Actions → General → Workflow permissions`

- ☑️ **Read and write permissions**
- ☑️ Allow GitHub Actions to create and approve pull requests

بدون این، مرحلهٔ انتشار Release با خطای `403` رد می‌شود.
هیچ توکن دستی‌ای لازم نیست؛ `GITHUB_TOKEN` خودکار ساخته می‌شود.

---

## ۳. اتصال هسته (دو روش — یکی را انتخاب کنید)

**الف) submodule (توصیه‌شده)**
```bash
git submodule add https://github.com/CluvexStudio/Aether native/aether
git -C native/aether checkout v1.7.0
git add .gitmodules native/aether && git commit -m "chore: vendor core v1.7.0"
```

**ب) vendor کامل** — دقیقاً مثل مخزن اندروید: محتوای `native/aether` را
از همان مخزن کپی کنید و فایل `CORE_VERSION` را روی `1.7.0` بگذارید.

در هر دو حالت، `scripts/sync-core.sh` از این به بعد خودش هسته را بالا می‌برد.

---

## ۴. آیکون — دقیقاً همان آیکون اندروید

آیکون اندروید وکتور است (`ic_launcher_foreground.xml` + `ic_launcher_background.xml`)، پس
بدون هیچ افت کیفیتی به ویندوز منتقل می‌شود:

```bash
# ۱) دو وکتور را روی هم رندر کنید (۱۰۲۴×۱۰۲۴)
npx @tauri-apps/cli icon assets/icon-1024.png
```
خروجی خودکار در `src-tauri/icons/` قرار می‌گیرد: `icon.ico` (چندرزولوشنی،
شامل ۲۵۶×۲۵۶ برای Explorer)، PNG‌های مورد نیاز و تصاویر ویزارد.

تصاویر ویزارد نصب (BMP است، نه PNG — Inno Setup فقط BMP می‌فهمد):
```bash
magick assets/icon-1024.png -resize 55x58!   -background "#0A0E1A" -flatten BMP3:installer/wizard-small.bmp
magick assets/wizard.png    -resize 164x314! -background "#0A0E1A" -flatten BMP3:installer/wizard-large.bmp
```

---

## ۵. یک‌بار تنظیم: GUID نصب‌کننده

در `installer/aether.iss` مقدار `MyAppId` را **یک‌بار** با یک GUID تازه جایگزین کنید
(`New-Guid` در PowerShell) و **دیگر هرگز تغییرش ندهید**.

این GUID در ویندوز دقیقاً همان نقشی را دارد که پایداری keystore در اندروید
داشت: اگر عوض شود، کاربران به‌جای ارتقا، یک نصب دوم موازی خواهند داشت.

---

## ۶. (اختیاری) امضای کد برای عبور از SmartScreen

اگر گواهی Code Signing (OV/EV) دارید:

`Settings → Secrets and variables → Actions → New repository secret`

| نام | مقدار |
|---|---|
| `WINDOWS_PFX_BASE64` | `base64 -w0 cert.pfx` |
| `WINDOWS_PFX_PASSWORD` | رمز فایل pfx |

اگر تعریف نکنید، پایپ‌لاین بدون خطا این مرحله را رد می‌کند (`if: env.SIGN_PFX != ''`).

---

## ۷. اجرای اولین بیلد

```bash
git push origin main          # ← nightly (pre-release)
```
یا برای انتشار رسمی:
```bash
git tag v1.0.0 && git push origin v1.0.0
```

در `Actions` جریان را ببینید. ترتیب مراحل:

```
sync-core ─┐
           ├─ build (x64) ─┐
           └─ build (x86) ─┴─ release
```

خروجی نهایی در `Releases`:

```
Aether-Setup-1.0.0-x64.exe
Aether-Setup-1.0.0-x86.exe
Aether-Portable-1.0.0-x64.zip
Aether-Portable-1.0.0-x86.zip
SHA256SUMS.txt
```

---

## ۸. توسعهٔ محلی (اختیاری)

```powershell
npm ci
./scripts/build-engine.ps1 -Target x86_64-pc-windows-msvc
./scripts/fetch-wintun.ps1 -ArchDir bin/amd64
./scripts/stage-xray.ps1 -Arch x64   # هستهٔ Xray برای «کانفیگ‌های سفارشی» (اختیاری)
npm run tauri dev
```

---

## ۹. چک‌لیست عیب‌یابی

| نشانه | علت | درمان |
|---|---|---|
| `403` در مرحلهٔ Publish | مجوز workflow روی read است | مرحلهٔ ۲ |
| `ISCC.exe not found` | Inno Setup روی runner نیست | مرحلهٔ `Ensure Inno Setup 6` خودکار نصبش می‌کند |
| بیلد x86 می‌شکند ولی x64 سالم است | وابستگی نیتیو فقط ۶۴بیتی | در `Cargo.toml` هسته فیچر را مشروط کنید |
| Setup نصب می‌شود ولی اپ بالا نمی‌آید | WebView2 غایب | `PrepareToInstall` در `aether.iss` خودکار نصبش می‌کند |
| تونل وصل نمی‌شود | برنامه بدون Administrator اجرا شده | Wintun نیاز به ارتقای دسترسی دارد |
