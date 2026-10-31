// =============================================================================
//  صفحهٔ اصلی — پورت از `ui/HomeScreen.kt` + `ConnectButton.kt` + `ConnectionCard.kt`
// -----------------------------------------------------------------------------
//  ۱.۲.۴ — دو تغییری که این فایل را بازنویسی کرد، هر دو از مخزن موبایل ۱.۲.۹:
//
//  ۱) **بلوک اطلاعات اتصال یک کارت شد.** پیش از این، وضعیت/آی‌پی/ترافیک/متا
//     چهار سطح شناور جدا بودند. حالا همه فرزندِ یک کارت‌اند — منطقش کامل در
//     `views/connectioncard.js` است و همین‌جا فقط ساخته و رنگ‌آمیزی می‌شود.
//
//  ۲) **تیک رفت؛ A آمد.** حالت متصل دیگر آیکون Bolt نشان نمی‌دهد، بلکه نشانِ
//     خود اِتِر است: همان A آیکون برنامه، روشن، اسکن‌شده و در حال چرخش در رمپ
//     لهجه‌های برنامه (`ui/aethermark.js`). این نشان **فقط** در حالت متصل ساخته
//     می‌شود و در هر گذارِ دیگری حلقهٔ فریمش لغو می‌شود، پس دکمهٔ بی‌کار و
//     مشغول دقیقاً همان هزینهٔ قبلی را دارند.
//
//  نمایش نور، فقط روی کارت است. در موبایل هم حلقهٔ نور یک بار دور دکمه گذاشته
//  شد و برداشته شد: دو نمایش نور روی یک صفحه برای چشم با هم می‌جنگند. دکمه
//  هالهٔ نبض‌دار و کمانِ مشغول خودش را نگه می‌دارد.
// =============================================================================

import { app, onChange, toggleConnection, accentFor } from '../main.js'
import { t } from '../i18n.js'
import { createConnectionCard, isRedundantCaption } from './connectioncard.js'
import { createPresetSelector } from '../ui/presets.js'
import { startAetherMark } from '../ui/aethermark.js'
import { homeAnimationsEnabled, onHomeAnimationsChange } from '../ui/feedback.js'

const BUSY_STATES = ['STARTING_ENGINE', 'CONNECTING', 'VERIFYING', 'RECONNECTING', 'DISCONNECTING']

// همان دو آیکون متریالِ ConnectButton.kt — PowerSettingsNew / Autorenew.
// حالت سوم (Bolt) حذف شد: جایش را AetherMark گرفت.
const ICON_POWER =
  '<svg viewBox="0 0 24 24" width="52" height="52" aria-hidden="true"><path d="M12 3v9" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/><path d="M6.5 6.8a8 8 0 1 0 11 0" stroke="currentColor" stroke-width="2.2" fill="none" stroke-linecap="round"/></svg>'
const ICON_RENEW =
  '<svg viewBox="0 0 24 24" width="52" height="52" aria-hidden="true"><path d="M12 5a7 7 0 0 1 6.3 4" stroke="currentColor" stroke-width="2.2" fill="none" stroke-linecap="round"/><path d="M18.6 4.6V9h-4.4" stroke="currentColor" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 19a7 7 0 0 1-6.3-4" stroke="currentColor" stroke-width="2.2" fill="none" stroke-linecap="round"/><path d="M5.4 19.4V15h4.4" stroke="currentColor" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>'

/** عنوان وضعیت — همان رشته‌های strings.xml. */
function titleFor(state) {
  return {
    DISCONNECTED: t('Disconnected'),
    STARTING_ENGINE: t('Starting engine…'),
    CONNECTING: t('Connecting…'),
    VERIFYING: t('Verifying connection…'),
    CONNECTED: t('Connected'),
    RECONNECTING: t('Reconnecting…'),
    DISCONNECTING: t('Disconnecting…'),
    FAILED: t('Connection failed'),
  }[state] ?? state
}

/** زیرنویس وضعیت — همان رشته‌های StatusLine.kt.
 *
 * ۱.۲.۵: پیام‌های سمت Rust از `t()` می‌گذرند. پیش از این خامِ انگلیسی نشان
 * داده می‌شدند، و چون `t()` وقتی ترجمه‌ای نباشد همان کلید را برمی‌گرداند،
 * این تغییر هیچ پیامِ موجودی را عوض نمی‌کند — فقط ترجمه‌شدن را ممکن می‌کند.
 *
 * درصدِ تور جداگانه می‌آید تا جمله همین‌جا و به زبانِ کاربر ساخته شود؛ یک
 * «Reaching the Tor network… 45%» که از Rust بیاید، هیچ کلیدِ ترجمه‌ای ندارد. */
/** ۱.۴.۰: پیام‌هایی که از Rust با درصد می‌آیند («Reaching the Tor network… 45%»)
 * ابتدا با الگوی `{p}%` ترجمه می‌شوند تا جمله به زبان کاربر و با همان عدد ساخته
 * شود؛ اگر الگویی نبود، `t()` خودش از راه `numbered()` تلاش می‌کند. */
export function translateDetail(detail) {
  if (typeof detail !== 'string' || !detail) return ''
  const m = detail.match(/^(.*?)(\d{1,3})%(.*)$/s)
  if (m) {
    const pattern = `${m[1]}{p}%${m[3]}`
    const hit = t(pattern)
    if (hit !== pattern) return hit.replace('{p}', m[2])
  }
  return t(detail)
}

function captionFor(snapshot) {
  switch (snapshot.state) {
    case 'DISCONNECTED': return t('Tap to connect securely')
    case 'CONNECTED': return t('Tap to disconnect')
    case 'FAILED': return t(snapshot.error || 'Something went wrong')
    case 'VERIFYING': return t('Verifying connection…')
    default:
      if (typeof snapshot.torPercent === 'number') {
        return t('Reaching the Tor network… {p}%').replace('{p}', String(snapshot.torPercent))
      }
      return snapshot.detail ? translateDetail(snapshot.detail) : ''
  }
}

/** ۱.۴.۰-ui: زیرنویسی که عیناً همان عنوان است («در حال اتصال…» دو بار) حذف می‌شود. */
export function dedupeCaption(title, caption) {
  return isRedundantCaption(title, caption) ? '' : caption
}

export function renderHome() {
  const root = document.createElement('div')
  root.className = 'view view--home'
  root.innerHTML = `
    <!-- ۱.۴.۰-mobile: عنوان و شعار در هدر موبایل هستند؛ اینجا فقط برای صفحه‌خوان
         می‌ماند و با mobile.css پنهان است (عنوان تکراری بالای کارت اتصال). -->
    <div class="hero" hidden aria-hidden="true">
      <h1 class="hero__title">${t('Aether')}</h1>
      <p class="hero__tagline">${t('Freedom, in one tap')}</p>
    </div>

    <div class="connect-wrap">
      <span class="connect__halo" id="halo"></span>
      <button class="connect" id="connect" type="button" aria-live="polite">
        <svg class="connect__arc" viewBox="0 0 100 100" aria-hidden="true">
          <circle cx="50" cy="50" r="47" fill="none" stroke="currentColor" stroke-width="2.5"
                  stroke-linecap="round" stroke-dasharray="73.8 221.4"/>
        </svg>
        <!-- هستهٔ جمعیِ نرم پشت نشان، تا گلیف از دیسک بیرون بتابد و صاف
             رویش نچسبد — همان Canvas(CORE) در ConnectButton.kt. -->
        <span class="connect__core" id="ccore" aria-hidden="true"></span>
        <span class="connect__icon" id="cicon">${ICON_POWER}</span>
        <canvas class="connect__mark" id="cmark" aria-hidden="true" hidden></canvas>
      </button>
    </div>

    <!-- v1.2.0: نشان محافظت WebRTC — نتیجهٔ سنجش واقعی، نه ادعای تزئینی.
         بیرون کارت می‌ماند چون یک هشدار امنیتی است، نه یک واقعیتِ اتصال. -->
    <p class="shield" id="shield" hidden><span class="shield__dot"></span><span id="shield-text"></span></p>
  `

  root.prepend(createPresetSelector())
  const card = createConnectionCard()
  root.appendChild(card.node)

  root.querySelector('#connect').addEventListener('click', toggleConnection)

  const markCanvas = root.querySelector('#cmark')
  const iconEl = root.querySelector('#cicon')
  let stopMark = null
  const spinAnims = []

  const paint = ({ snapshot: current }) => {
    // بوت قبل از اولین snapshotِ هسته: حالتِ قطع، نه خطا.
    const snapshot = current ?? { state: 'DISCONNECTED' }
    const accent = accentFor(snapshot.state)
    const busy = BUSY_STATES.includes(snapshot.state)
    const connected = snapshot.state === 'CONNECTED'

    const btn = root.querySelector('#connect')
    btn.style.setProperty('--accent', accent)
    btn.classList.toggle('is-busy', busy)
    btn.classList.toggle('is-on', connected)
    btn.classList.toggle('is-error', snapshot.state === 'FAILED')
    root.querySelector('#halo').classList.toggle('is-on', connected)

    // تعویض مود — فقط وقتی مود واقعاً عوض شده، تا انیمیشن ریست نشود و تا
    // نشان در هر snapshot (پنج بار در ثانیه) از اول متولد نشود.
    const mode = busy ? 'busy' : connected ? 'on' : 'idle'
    if (btn.dataset.mode !== mode) {
      btn.dataset.mode = mode

      for (const a of spinAnims.splice(0)) a.cancel()
      if (stopMark) {
        stopMark()
        stopMark = null
      }

      if (connected) {
        // نشان جای آیکون را می‌گیرد؛ حلقهٔ فریمش همین‌جا شروع می‌شود و در
        // گذار بعدی لغو می‌شود.
        iconEl.hidden = true
        markCanvas.hidden = false
        stopMark = startAetherMark(markCanvas, { animated: homeAnimationsEnabled() })
      } else {
        markCanvas.hidden = true
        iconEl.hidden = false
        iconEl.innerHTML = busy ? ICON_RENEW : ICON_POWER
        // ریشهٔ مشکل تکرارشوندهٔ ۲: چرخش مشغول را با Web Animations API
        // می‌رانیم. انیمیشن‌های سادهٔ CSS وقتی ویندوز prefers-reduced-motion
        // گزارش می‌کند (افکت‌ها خاموش / ماشین مجازی / RDP) سراسری بی‌اثر
        // می‌شوند و همین بود که کمان و فلش‌ها یخ‌زده به نظر می‌رسیدند.
        // چرخش دکمهٔ «در حال اتصال» همیشه فعال است؛ فقط Glow پس‌زمینه با تنظیم خاموش می‌شود.
        if (busy) {
          const spin = [
            { transform: 'translateZ(0) rotate(0deg)' },
            { transform: 'translateZ(0) rotate(360deg)' },
          ]
          const arcEl = root.querySelector('.connect__arc')
          if (arcEl && arcEl.animate) {
            spinAnims.push(arcEl.animate(spin, { duration: 1100, iterations: Infinity }))
          }
          if (iconEl.animate) {
            spinAnims.push(iconEl.animate(spin, { duration: 1400, iterations: Infinity }))
          }
        }
      }
    }

    // کارت خودش را رنگ می‌کند؛ عنوان و زیرنویس از همین‌جا می‌روند تا رشته‌ها
    // یک منبع داشته باشند.
    card.paint(snapshot, {
      busy,
      title: titleFor(snapshot.state),
      caption: dedupeCaption(titleFor(snapshot.state), captionFor(snapshot)),
    })

    // نشان محافظت WebRTC — سه حالت: در حال سنجش / محافظت‌شده / نشتی.
    const shield = root.querySelector('#shield')
    shield.hidden = !connected
    if (connected) {
      const leak = snapshot.webrtcLeak
      const shieldState = leak === true ? 'leak' : leak === false ? 'safe' : 'unknown'
      shield.dataset.state = shieldState
      root.querySelector('#shield-text').textContent =
        shieldState === 'leak'
          ? t('WebRTC is leaking your real IP')
          : shieldState === 'safe'
            ? t('WebRTC protected — no IP leak')
            : t('Checking for WebRTC leaks…')
    }
  }

  // نماها کَش می‌شوند و در تعویض تب فقط جدا/وصل می‌شوند (main.js). پس حلقه‌های
  // فریم باید با پنهان‌شدن نما بخوابند، وگرنه کارتِ نامرئی تا پایان عمر برنامه
  // شصت فریم در ثانیه می‌کشد.
  root.__onHide = () => {
    if (stopMark) {
      stopMark()
      stopMark = null
    }
    // مود را باطل کن تا بازگشت به تب، نشان را از نو بسازد.
    root.querySelector('#connect').dataset.mode = ''
    card.stop()
  }

  root.__onShow = () => {
    card.start()
    // رنگ‌آمیزی فوری با وضعیت فعلی: جریان وضعیت فقط وقتی چیزی عوض شود
    // امیت می‌کند، پس بازگشت به تب به خودی خود هیچ فریمی نمی‌سازد و نشان
    // متصل دیگر برنمی‌گشت.
    paint(app)
  }

  paint(app)
  onChange(paint, root)
  // تعویض سوییچ «انیمیشن‌های صفحهٔ اصلی» بی‌درنگ اعمال شود: مود باطل و دوباره رنگ‌آمیزی.
  // نما کَش و هنگام تعویض تب از DOM جدا می‌شود؛ پس مشترک نمی‌ماند-نمی‌رود: مود باطل
  // می‌شود و اگر نما دیده می‌شود همین حالا، وگرنه `__onShow` از نو رنگ‌آمیزی می‌کند.
  onHomeAnimationsChange(() => {
    root.querySelector('#connect').dataset.mode = ''
    if (root.isConnected) paint(app)
  })
  return root
}
