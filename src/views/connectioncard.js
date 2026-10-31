// =============================================================================
//  پورت ۱:۱ از `ui/components/ConnectionCard.kt` — بلوکِ پایینیِ صفحهٔ اصلی.
// -----------------------------------------------------------------------------
//  تا نسخهٔ ۱.۲.۳ دسکتاپ، ناحیهٔ زیر دکمهٔ پاور چهار سطحِ شناورِ جدا بود —
//  متن وضعیت، نشان آی‌پی، سنجهٔ ترافیک و ردیف پروتکل/اندپوینت/تأخیر — هر یک
//  با رنگ، شعاع و padding خودش (`.ipbadge`, `.meta`, `.traffic` در app.css).
//  روی یک پنجره شبیه شلختگی خوانده می‌شد و هیچ‌چیز آن‌ها را به هم وصل نمی‌کرد.
//
//  حالا یک کارتِ گلس‌مورفیک واحد است، با یک نظام رنگ و یک سلسله‌مراتب عمودی
//  ثابت — دقیقاً همان هفت گام مخزن موبایل:
//
//    ۱. وضعیت اتصال   (درشت، mint، با یک سطر آرام «برای قطع لمس کنید»)
//    ۲. تایمر نشست    («مدت اتصال» + HH:MM:SS با چهرهٔ مونو/دیجیتال)
//    ۳. پیل آی‌پی سرور (برچسب + پرچم کشور + نشانی)
//    ۴. نوار سرعت      (نرخ زندهٔ دانلود/آپلود و مجموع نشست)
//    ۵. اسلاید پروتکل  (تمام‌عرض)
//    ۶. اسلاید اندپوینت (تمام‌عرض)
//    ۷. اسلاید تأخیر   (تمام‌عرض، همراه متر زندهٔ قدرت پینگ)
//
//  هیچ‌چیز بیرون بلوک شناور نیست: هر زیربخش، فرزندِ همان کارت است و از همان
//  پالت کشیده می‌شود.
//
//  رنگ‌ها عمداً از توکن‌های تم گرفته نمی‌شوند و در `app.css` به همان مقادیر
//  برند پین شده‌اند (navy عمیق #070B14، لهجهٔ mint #3EDBB0، یک سطح شیشهٔ
//  اسلیت برای همه‌چیزِ درونش) — همان دلیل موبایل: کارت باید در هر تمی مثل
//  اِتِر به نظر برسد.
//
//  یک اسلاید در هر واقعیت. سه گام آخر در نسخهٔ موبایل قبلاً یک نوار سه‌ستونی
//  بودند و `WIREGUARD → PSIPHON` یا یک `ip:port` هرگز در یک‌سومِ عرض جا
//  نمی‌شد؛ برچسبی که مقدارش خوانده نمی‌شود تزئین است. اینجا هم هر کدام تمام
//  عرض کارت را دارند: برچسب چپ، مقدار راست.
// =============================================================================

import { flagHtml } from '../flags.js'
import { t } from '../i18n.js'
import {
  FRAME_CAPS,
  GlowCycle,
  drawGlowCycle,
  fitCanvas,
  frameLoop,
  roundRectPath,
  trackSize,
  TWO_PI,
} from '../ui/glowcycle.js'
import { homeAnimationsEnabled } from '../ui/feedback.js'

const CARD_RADIUS = 26
const IDLE_ACCENT = '#5B93FF'
const ERROR_ACCENT = '#FF5C7A'
const AETHER_MINT = '#3EDBB0'

// ---- تنظیم متر پینگ -------------------------------------------------------
// آستانه‌های درجه و رمپِ ارتفاع میله‌ها با هم اعلام می‌شوند تا خوانندهٔ بعدی
// ببیند که قرار است بر هم منطبق باشند: EXCELLENT هم سقفِ رمپ ارتفاع است و
// FAIR کفِ آن، پس مرزِ mint/کهربایی در رنگ و مرزِ Good/Fair در برچسب، به
// جای تصادف، *ساختاراً* یک عددند. این همان اشکالی است که در موبایل دو جدولِ
// آستانهٔ مستقل ساخته بود و هر خواندن بین ۱۶۱ تا ۱۸۹ میلی‌ثانیه، میلهٔ سبز
// زیر کلمهٔ «متوسط» نشان می‌داد.
const PING_EXCELLENT_MS = 80
const PING_GOOD_MS = 190
const PING_FAIR_MS = 320
const PING_BEST_MS = PING_EXCELLENT_MS
const PING_WORST_MS = 400

// >>> AETHER-APP-PATCH tor-has-its-own-ping-scale
// ۱.۲.۵ — مقیاس به خطِ لوله بستگی دارد.
//
// اعداد بالا برای یک هاپ تا لبهٔ WARP نوشته شده‌اند. تور سه هاپ دارد
// (با پل چهار)؛ کفِ فیزیکیِ آن دویست و خرده‌ای میلی‌ثانیه است و لاگِ ۱۷
// سپتامبر هم همین را می‌گوید: `session floor 247 ms`. با مقیاسِ تونل،
// هر خواندنِ سالمی در تور «Poor» می‌شد — در تصویرِ کاربر ۳۹۷ms زیرِ
// کلمهٔ Poor نشسته بود در حالی که برای تورِ پل‌دار خواندنِ خوبی است.
// کارت دروغ نمی‌گوید: عدد همان عدد است، فقط با معیارِ خودِ همین مسیر
// قضاوت می‌شود.
const PING_BANDS_TUNNEL = {
  excellent: PING_EXCELLENT_MS,
  good: PING_GOOD_MS,
  fair: PING_FAIR_MS,
  best: PING_BEST_MS,
  worst: PING_WORST_MS,
}
const PING_BANDS_TOR = {
  excellent: 250,
  good: 450,
  fair: 800,
  best: 250,
  worst: 1200,
}

/** کدام مقیاس به این خطِ لوله می‌خورد؟ `null` و ناشناخته = مقیاسِ تونل. */
export function pingBandsFor(protocol) {
  return typeof protocol === 'string' && protocol.toLowerCase().includes('tor')
    ? PING_BANDS_TOR
    : PING_BANDS_TUNNEL
}
// <<< AETHER-APP-PATCH tor-has-its-own-ping-scale
const PING_BARS = 26
const PING_BAR_GAP = 3
/** سقف پهنای هر میله — رجوع به توضیح در `paintWave`. */
const PING_BAR_MAX_W = 11
const PING_WAVE_MS = 1500
const PING_FAIR = '#FFB43C'
const PING_POOR = '#FF5C7A'
const CARD_TEXT_DIM = 'rgba(255,255,255,0.34)'

const DASH = '\u2014'

// AETHER-APP-PATCH 1.4.0 smart-label: `SMART` is a planning marker, not a transport.
// If the backend label still carries it, use the first compact form (winning
// transport) when available, otherwise drop the marker and show the pipeline name.
export function resolveProtocolLabel(snapshot){
  const raw = snapshot?.protocol
  if (raw == null || raw === '') return DASH
  if (!/\bSMART\b/i.test(raw)) return raw
  const compact = Array.isArray(snapshot?.protocolCompact) ? snapshot.protocolCompact : []
  const alt = compact.find(x => typeof x === 'string' && x.trim() && !/\bSMART\b/i.test(x))
  if (alt) return alt
  const stripped = raw.replace(/\s*\(\s*SMART\s*\)/ig, '').replace(/\bSMART\b/ig, '').replace(/\s{2,}/g, ' ').trim()
  return stripped || raw
}

/**
 * متن را فقط وقتی می‌نویسد که عوض شده باشد.
 *
 * مقدارِ نوشته‌شده روی خودِ گره یادداشت می‌شود و نه با `el.textContent` مقایسه —
 * خواندنِ `textContent` خودش مرورگر را وادار می‌کند متنِ زیردرخت را از نو بسازد،
 * که همان چیزی است که می‌خواستیم از آن پرهیز کنیم.
 */
// >>> AETHER-APP-PATCH custom-configs
/**
 * زنجیرهٔ کانفیگِ سفارشی (`VLESS → Aether(WireGuard) → Psiphon`) در یک خط.
 *
 * Rust شکل‌ها را از بلند به کوتاه می‌فرستد (`protocolCompact`): کامل، بی‌پرانتزِ
 * ترابری، با پیکان‌های چسبیده. اولین شکلی که جا شود نشان داده می‌شود؛ اگر هیچ‌کدام
 * جا نشد، کوتاه‌ترین با فونتِ کوچک‌تر. متنِ کامل همیشه در `title` می‌ماند.
 */
function fitChain(node, options) {
  if (!node) return
  const list = Array.isArray(options) ? options.filter(Boolean) : []
  if (!list.length) {
    if (node.__aetherFit) {
      node.__aetherFit = null
      node.classList.remove('ccard__slide-v--tight')
      node.removeAttribute('title')
    }
    return
  }
  const key = `${list.join('\u0001')}@${node.clientWidth}`
  if (node.__aetherFit === key) return
  node.__aetherFit = key
  node.classList.remove('ccard__slide-v--tight')
  let chosen = list[list.length - 1]
  for (const option of list) {
    node.textContent = option
    if (node.scrollWidth <= node.clientWidth) { chosen = option; break }
  }
  node.textContent = chosen
  // `setText` همان برچسبِ کامل (`snapshot.protocol` = `list[0]`) را می‌بیند و
  // شکلِ کوتاه‌شده را با آن بازنویسی نمی‌کند.
  node.__aetherText = list[0]
  if (node.scrollWidth > node.clientWidth) node.classList.add('ccard__slide-v--tight')
  node.title = list[0]
}
// <<< AETHER-APP-PATCH custom-configs

function setText(el, value) {
  if (!el) return
  const next = String(value)
  if (el.__aetherText === next) return
  el.__aetherText = next
  el.textContent = next
}

function formatBytes(v) {
  if (v < 1024) return `${Math.round(v)} B`
  const kb = v / 1024
  if (kb < 1024) return `${kb.toFixed(1)} KB`
  const mb = kb / 1024
  if (mb < 1024) return `${mb.toFixed(1)} MB`
  return `${(mb / 1024).toFixed(2)} GB`
}

function formatRate(v) {
  return `${formatBytes(v)}/s`
}

/** `HH:MM:SS` — همان `String.format(Locale.US, "%02d:%02d:%02d", …)`. */
function formatClock(totalSecs) {
  const s = Math.max(0, Math.floor(totalSecs))
  const pad = (x) => String(x).padStart(2, '0')
  return `${pad(Math.floor(s / 3600))}:${pad(Math.floor((s % 3600) / 60))}:${pad(s % 60)}`
}

/**
 * تنها درجه‌ای که یک خواندنِ تأخیر دارد. رنگ *و* برچسب هر دو از همین می‌آیند.
 */
export function pingGrade(connected, ms, bands = PING_BANDS_TUNNEL) {
  if (!connected) return 'offline'
  if (ms == null || ms < 0) return 'measuring'
  if (ms <= bands.excellent) return 'excellent'
  if (ms <= bands.good) return 'good'
  if (ms <= bands.fair) return 'fair'
  return 'poor'
}

function pingTint(grade) {
  switch (grade) {
    case 'excellent':
    case 'good':
      return AETHER_MINT
    case 'fair':
      return PING_FAIR
    case 'poor':
      return PING_POOR
    default:
      return CARD_TEXT_DIM
  }
}

function pingQualityLabel(grade) {
  switch (grade) {
    case 'excellent':
      return t('Excellent')
    case 'good':
      return t('Good')
    case 'fair':
      return t('Fair')
    case 'poor':
      return t('Poor')
    case 'measuring':
      return t('Measuring…')
    default:
      return t('Offline')
  }
}

/**
 * رمپ پیوستهٔ *ارتفاع* میله‌ها: ۱ = عالی، ۰ = بی‌استفاده.
 *
 * جدا از [pingGrade] نگه داشته شده چون یک انیمیشن مقدار پیوسته می‌خواهد؛ ولی
 * دیگر چیزی را تصمیم نمی‌گیرد که یک *کلمه* هم تصمیم می‌گیرد.
 */
export function pingStrength(connected, ms, bands = PING_BANDS_TUNNEL) {
  if (!connected || ms == null || ms < 0) return 0
  if (ms <= bands.best) return 1
  if (ms >= bands.worst) return 0.08
  return 1 - (ms - bands.best) / (bands.worst - bands.best)
}

/**
 * کارت را می‌سازد.
 *
 * @returns `{ node, paint(snapshot), destroy() }` — `paint` را جریان وضعیت
 *   صدا می‌زند و `destroy` هر دو حلقهٔ فریم را واقعاً لغو می‌کند.
 */
/** 1.4.0-r5: «در حال اتصال…» / «در حال راستی‌آزمایی…» هرگز دو بار زیر هم نمی‌آیند.
 *  زیرنویس حذف می‌شود اگر با عنوان یکی باشد، یا کوتاه‌تر و پیشوندِ عنوان باشد
 *  («در حال راستی‌آزمایی…» در برابر «در حال راستی‌آزمایی اتصال…»). */
const normStatusText = (v) => String(v ?? '').replace(/[.…\s\u200c]+/g, ' ').trim().toLowerCase()
export function isRedundantCaption(title, caption) {
  const a = normStatusText(title)
  const b = normStatusText(caption)
  if (!b) return true
  return a === b || a.startsWith(b)
}

export function createConnectionCard() {
  const node = document.createElement('section')
  node.className = 'ccard'
  node.innerHTML = `
    <canvas class="ccard__edge" aria-hidden="true"></canvas>
    <div class="ccard__body">
      <div class="ccard__status">
        <p class="ccard__title" id="cc-title">${t('Disconnected')}</p>
        <p class="ccard__caption" id="cc-caption">${t('Tap to connect securely')}</p>
      </div>

      <div class="ccard__timer">
        <span class="ccard__timer-k">${t('Connected for')}</span>
        <span class="ccard__timer-v ltr" dir="ltr" id="cc-clock">00:00:00</span>
      </div>

      <div class="ccard__pill ltr" dir="ltr" id="cc-pill">
        <span class="ccard__pill-k" id="cc-ip-label">${t('Your IP')}</span>
        <span class="ccard__pill-flag" id="cc-ip-flag">${flagHtml(null)}</span>
        <span class="ccard__pill-v" id="cc-ip-value">${t('Checking IP…')}</span>
      </div>

      <div class="ccard__speeds">
        <div class="ccard__speed">
          <span class="ccard__speed-badge ccard__speed-badge--down" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                 stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 5v13M6.5 12.5 12 18l5.5-5.5"/>
            </svg>
          </span>
          <span class="ccard__speed-text">
            <span class="ccard__speed-rate ltr" dir="ltr" id="cc-rx-rate">0 B/s</span>
            <span class="ccard__speed-total">${t('Total')} <bdi id="cc-rx-total">0 B</bdi></span>
          </span>
        </div>
        <span class="ccard__divider" aria-hidden="true"></span>
        <div class="ccard__speed">
          <span class="ccard__speed-badge ccard__speed-badge--up" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor"
                 stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 19V6M6.5 11.5 12 6l5.5 5.5"/>
            </svg>
          </span>
          <span class="ccard__speed-text">
            <span class="ccard__speed-rate ltr" dir="ltr" id="cc-tx-rate">0 B/s</span>
            <span class="ccard__speed-total">${t('Total')} <bdi id="cc-tx-total">0 B</bdi></span>
          </span>
        </div>
      </div>

      <div class="ccard__slide">
        <span class="ccard__slide-k">${t('Protocol')}</span>
        <span class="ccard__slide-v ltr" dir="ltr" id="cc-proto">${DASH}</span>
      </div>

      <div class="ccard__slide ccard__slide--stack">
        <div class="ccard__slide-row">
          <span class="ccard__slide-k">${t('Latency')}</span>
          <span class="ccard__slide-v ltr" dir="ltr" id="cc-latency">${DASH}</span>
        </div>
        <div class="ccard__ping">
          <div class="ccard__ping-head">
            <span class="ccard__ping-k">${t('Ping strength')}</span>
            <span class="ccard__ping-q" id="cc-ping-q">${t('Offline')}</span>
          </div>
          <canvas class="ccard__ping-wave" id="cc-wave" aria-hidden="true"></canvas>
        </div>
      </div>
    </div>
  `

  const el = (id) => node.querySelector(`#${id}`)
  const edge = node.querySelector('.ccard__edge')
  const wave = el('cc-wave')

  // ---- وضعیتِ زندهٔ ترسیم ------------------------------------------------
  let accent = IDLE_ACCENT
  // آخرین لهجه‌ای که واقعاً روی گره نوشته شد — نوشتنِ یک متغیرِ CSS با همان
  // مقدارِ قبلی، بازمحاسبهٔ سبکِ کلِ زیردرخت را به‌دنبال دارد.
  let paintedAccent = null
  let connected = false
  // چرخهٔ نور: فقط وقتی متصل‌ایم ساخته می‌شود — بی‌هیچ اشتراکِ فریم در حالت
  // قطع، همان قاعدهٔ `if (connected) rememberGlowCycle() else null`.
  let cycle = null
  // آخرین خواندنِ *خوب*. حالت‌های گذار مقدار null می‌دهند و باور کردنشان
  // باعث می‌شد مقدار تأخیر و متر، هر چند ثانیه یک‌بار به «…» پلک بزنند.
  let lastMs = -1
  // ارتفاع میله‌ها به مقدار تازه سُر می‌خورد و نمی‌پرد (tween 700ms موبایل).
  let level = 0
  let levelTarget = 0
  let levelAt = performance.now()
  // مقیاسِ پینگِ نشستِ جاری — با هر رندر از برچسبِ خطِ لوله تازه می‌شود.
  let bands = PING_BANDS_TUNNEL

  // دستگیرهٔ دو حلقهٔ فریم، و «نما روی صفحه است؟».
  //
  // پیش از `trackSize` اعلام می‌شوند و نه پایین‌تر: جایی که `ResizeObserver`
  // نیست (هارنس‌های jsdom در `tests/`)، `trackSize` پاسخِ خودش را همان لحطهٔ
  // ساخته‌شدن و همگام صدا می‌زند، و آن پاسخ به `requestWaveFrame` می‌رسد.
  // با اعلامِ پایین‌تر، همان پاسخ در ناحیهٔ مردهٔ `let` می‌افتاد و با ReferenceError
  // می‌مرد — همان جایی که در بازنویسیِ این پرونده یک بار شکست.
  let stopEdge = null
  let stopWave = null
  let visible = false

  // نرخ لحظه‌ای از دلتای بایت‌ها روی ساعت یکنواخت — یک جهش ساعت دیواری
  // نباید بتواند یک اسپایک جعلی بسازد.
  let lastRx = -1
  let lastTx = -1
  let lastSampleAt = 0

  // ---- لبهٔ کارت -----------------------------------------------------------
  // یک تابش نرم درونی، یک حاشیهٔ مویی، و — تا وقتی متصل‌ایم — نور متحرک،
  // یک رنگ در هر دور.
  //
  // ۱.۲.۵-perf: هندسه و گرادیان بین فریم‌ها **کَش** می‌شوند. هیچ‌کدام به زمان
  // وابسته نیست — مسیر فقط به اندازهٔ کارت بستگی دارد و گرادیان به اندازه و
  // رنگِ لهجه — ولی هر فریم از نو ساخته می‌شدند: یک `Path2D` و یک
  // `CanvasGradient` تازه، شصت بار در ثانیه، که هم تخصیص است و هم فشارِ مداوم
  // روی جمع‌آورِ حافظه.
  let edgePath = null
  let edgePerimeter = 0
  let edgeGrad = null
  let edgeGradKey = ''

  const edgeSize = trackSize(node, () => { edgePath = null; edgeGrad = null })

  const drawEdgeFrame = (now) => {
    edgeSize.poll(now)
    const width = edgeSize.width
    const height = edgeSize.height
    if (width <= 0 || height <= 0) return
    const ctx = edge.getContext('2d')
    // تغییرِ اندازهٔ بافرِ canvas خودش محتوا را پاک می‌کند و ترنسفورم را
    // بازمی‌نشاند، پس هندسهٔ کَش‌شده هم باید دور ریخته شود.
    if (fitCanvas(edge, width, height)) edgePath = null
    ctx.clearRect(0, 0, width, height)

    const hairline = 1
    // نور متحرک کمی پهن‌تر از حاشیهٔ ساختاری کشیده می‌شود: در ۱ پیکسل، هستهٔ
    // آن بین دو پیکسل دستگاه می‌افتد و ضدپله‌گذاری آن را به خطی گل‌آلود پهن
    // می‌کند. ۱.۵ بیشتر اوقات روی مرز پیکسل می‌نشیند و مثل رشتهٔ نور تیز
    // خوانده می‌شود.
    const lightStroke = 1.5
    if (!edgePath) {
      const built = roundRectPath(width, height, CARD_RADIUS, hairline / 2)
      edgePath = built.path
      edgePerimeter = built.perimeter
      edgeGrad = null
    }

    const gradKey = `${width}\u00d7${height}\u00d7${accent}`
    if (!edgeGrad || edgeGradKey !== gradKey) {
      edgeGrad = ctx.createRadialGradient(
        width / 2, 0, 0,
        width / 2, 0, width * 0.95,
      )
      edgeGrad.addColorStop(0, hexAlpha(accent, 0.10))
      edgeGrad.addColorStop(1, hexAlpha(accent, 0))
      edgeGradKey = gradKey
    }
    ctx.fillStyle = edgeGrad
    ctx.fill(edgePath)

    ctx.strokeStyle = hexAlpha(accent, cycle ? 0.16 : 0.10)
    ctx.lineWidth = hairline
    ctx.setLineDash([])
    ctx.stroke(edgePath)

    if (cycle) drawGlowCycle(ctx, edgePath, edgePerimeter, cycle, lightStroke)
  }

  // ---- متر قدرت پینگ ------------------------------------------------------
  // فضای خالیِ اسلاید تأخیر، خودِ اندازه‌گیری را نشان می‌دهد: موجی رونده از
  // میله‌های گرد که ارتفاع، روشنایی و رنگش کیفیت آخرین کاوش را دنبال می‌کند.
  // سرعتِ حرکت عمداً ثابت است: در موبایل مشتق‌کردنش از تأخیر باعث می‌شد spec
  // در هر کاوش عوض شود و موج هر چهار ثانیه یک‌بار به‌چشم بپرد.
  //
  // ۱.۲.۵-perf — دو چیز عوض شد و هیچ‌کدام ظاهر را عوض نمی‌کند:
  //
  //   * چیدمانِ ردیف (پهنای میله، گام، مبدأ) روی تغییرِ اندازه حساب می‌شود و
  //     نه در هر فریم؛ همان چهار تقسیمِ ساده بود، ولی کنارش یک
  //     `getBoundingClientRect()` می‌نشست که مرورگر را وادار به محاسبهٔ
  //     چیدمان می‌کرد.
  //   * حلقه وقتی چیزی برای نشان‌دادن نیست **می‌ایستد**. در حالت قطع، ارتفاعِ
  //     میله‌ها صفر است و موج حرکت نمی‌کند (`phase = 0`)، پس هر فریم دقیقاً
  //     همان تصویرِ فریمِ قبل را می‌کشید — ۲۶ مستطیل گردگوشه، شصت بار در ثانیه،
  //     برای تصویری که تکان نمی‌خورد. سنجهٔ `bench/count-card-ops.mjs` همین را
  //     نشان داد: کارتِ قطع ۳۲۲ فراخوانِ canvas در هر فریم داشت، در برابر ۳۶۶
  //     در حالت متصل.
  let waveLayout = null

  const waveSize = trackSize(wave, () => {
    waveLayout = null
    // اندازه تازه شد، و ممکن است حلقه ایستاده باشد (حالتِ قطع). بدون این یک
    // فریم، متر در اولین نمایش خالی می‌ماند: `ResizeObserver` فقط پس از
    // اتصالِ نود به سند آتش می‌کند و تا آن لحطه عرض و ارتفاع صفر بوده‌اند، پس
    // `drawWaveFrame` زود برمی‌گشت و دیگر هیچ‌کس صدایش نمی‌زد.
    requestWaveFrame()
  })

  const layoutWave = (boxWidth, boxHeight) => {
    const gap = PING_BAR_GAP
    // ۱.۲.۴-p4 — میله‌ها سقف پهنا دارند و ردیف وسط‌چین می‌شود.
    //
    // پیش از این پهنا فقط تقسیمِ عرضِ کارت بر ۲۶ بود، پس هر پیکسلی که کارت
    // پهن‌تر می‌شد مستقیماً به میله‌ها می‌رفت و دایره‌های موبایل روی دسکتاپ به
    // کپسولِ کشیده تبدیل می‌شدند. ۱۱ پیکسل همان پهنایی است که ۲۶ میله در کارت
    // گوشی دارند؛ سقف می‌گذاریم و نه مقدار ثابت، تا در پنجرهٔ باریک باز هم جا شود.
    const barWidth = Math.min(PING_BAR_MAX_W, (boxWidth + gap) / PING_BARS - gap)
    if (barWidth <= 0) return null
    const pitch = barWidth + gap
    const rowWidth = PING_BARS * pitch - gap
    return {
      width: boxWidth,
      height: boxHeight,
      barWidth,
      pitch,
      originX: (boxWidth - rowWidth) / 2,
      radius: barWidth / 2,
      floorH: boxHeight * 0.16,
    }
  }

  const drawWaveFrame = (now) => {
    waveSize.poll(now)
    const boxWidth = waveSize.width
    const boxHeight = waveSize.height
    if (boxWidth <= 0 || boxHeight <= 0) return
    const ctx = wave.getContext('2d')
    fitCanvas(wave, boxWidth, boxHeight)
    ctx.clearRect(0, 0, boxWidth, boxHeight)

    // میان‌یابی ساعت‌محور به سمت هدف — معادل animateFloatAsState(tween(700)).
    const dt = Math.min(1, (now - levelAt) / 700)
    levelAt = now
    level += (levelTarget - level) * dt

    if (!waveLayout) waveLayout = layoutWave(boxWidth, boxHeight)
    const L = waveLayout
    if (!L) return

    const grade = pingGrade(connected, lastMs, bands)
    const tint = pingTint(grade)
    const phase = connected ? (now % PING_WAVE_MS) / PING_WAVE_MS : 0

    for (let i = 0; i < PING_BARS; i++) {
      const x = i / (PING_BARS - 1)
      // دو هارمونیک در دو جهت مخالف: قلهٔ موج هرگز ثابت نمی‌ماند و الگو به
      // شکلی تکرار نمی‌شود که چشم رویش قفل کند.
      const a = 0.5 + 0.5 * Math.sin(TWO_PI * (2.0 * x - phase))
      const b = 0.5 + 0.5 * Math.sin(TWO_PI * (3.7 * x + 1.6 * phase))
      const w = 0.58 * a + 0.42 * b
      const h = L.floorH + (boxHeight - L.floorH) * level * w
      const top = (boxHeight - h) / 2
      const left = L.originX + i * L.pitch
      const alpha = 0.30 + 0.70 * w * (0.25 + 0.75 * level)

      ctx.fillStyle = hexAlpha(tint, Math.min(1, Math.max(0, alpha)))
      roundBar(ctx, left, top, L.barWidth, h, L.radius)
    }

    // تصویرِ ساکن، حلقهٔ ساکن. آخرین فریم پیش از ایستادن همان فریمِ صافِ حالتِ
    // قطع است، پس چیزی نیمه‌کشیده روی صفحه نمی‌ماند؛ `paint` هر وقت لازم شود
    // دوباره حلقه را راه می‌اندازد.
    if (waveIsIdle()) stopWaveLoop()
  }

  /** موج چیزی برای نشان‌دادن ندارد؟ (قطع، و میله‌ها به صفر رسیده‌اند) */
  function waveIsIdle() {
    return !connected && level < 0.004 && levelTarget < 0.004
  }

  /**
   * یک فریمِ تک، وقتی حلقه ایستاده ولی تصویر باید تازه شود.
   *
   * `function` و نه `const`: این دو تابع از پاسخِ `trackSize` صدا زده می‌شوند که
   * ممکن است بالاتر از اینجا بیفتد؛ اعلامِ `function` بالا می‌رود و مستقل از
   * ترتیبِ سطرها کار می‌کند.
   */
  function requestWaveFrame() {
    if (stopWave || !visible) return
    drawWaveFrame(performance.now())
  }

  // حلقه‌های فریم، قابل شروع و توقف.
  //
  // نماها در `main.js` کَش می‌شوند و تعویض تب فقط جدا/وصلشان می‌کند؛ اگر این دو
  // حلقه به عمر *نما* گره نخورند، کارتِ نامرئی تا پایان عمر برنامه شصت فریم در
  // ثانیه می‌کشد — همان هزینهٔ پس‌زمینه‌ای که ۱.۲.۳ برای امیت‌کردن snapshotِ
  // بی‌تغییر می‌داد و ریشه‌اش کنده شد.
  //
  // ۱.۲.۵-perf: حلقهٔ موج علاوه بر این، *به‌خودیِ‌خود* هم می‌ایستد. `visible`
  // یادش می‌ماند که نما روی صفحه است یا نه، وگرنه یک `paint` که در غیبتِ تب
  // برسد، حلقهٔ ایستاده را روی تبِ نامرئی از نو راه می‌انداخت.
  // (اعلامِ سه متغیر بالاتر است — دلیلش همانجا نوشته شده.)

  const stopWaveLoop = () => {
    if (stopWave) { stopWave(); stopWave = null }
  }

  const startWaveLoop = () => {
    if (!visible || stopWave) return
    // ساعتِ میان‌یابی از سرِ ایستادن ادامه پیدا کند، نه از لحظهٔ توقف: وگرنه
    // اولین `dt` بعد از بیدارشدن به ۱ می‌رسد و میله‌ها به هدف می‌پرند.
    levelAt = performance.now()
    stopWave = frameLoop(drawWaveFrame, FRAME_CAPS.wave)
  }

  function start() {
    visible = true
    if (!stopEdge) stopEdge = frameLoop(drawEdgeFrame, FRAME_CAPS.edge)
    if (!waveIsIdle()) startWaveLoop()
    else drawWaveFrame(performance.now())
  }

  function stop() {
    visible = false
    if (stopEdge) { stopEdge(); stopEdge = null }
    stopWaveLoop()
  }

  /**
   * یک بار رنگ‌آمیزی از روی یک snapshot.
   *
   * سرعت‌ها *فقط* اینجا نمونه‌برداری می‌شوند و نه در حلقهٔ فریم: نرخ باید از
   * دلتای بایت‌های واقعیِ موتور بیاید، و موتور هر ۲۰۰ میلی‌ثانیه یک snapshot
   * می‌فرستد.
   *
   * ۱.۲.۵-perf — هر نوشتن روی DOM از `setText` می‌گذرد و فقط وقتی انجام می‌شود
   * که مقدار **واقعاً** عوض شده باشد. پیش از این هر رسیدنِ snapshot حدود پانزده
   * `textContent` و چهار `innerHTML` می‌نوشت، پنج بار در ثانیه، در حالی که
   * بیشترشان در طولِ یک نشست هرگز عوض نمی‌شوند (`cc-proto`،
   * برچسبِ آی‌پی). یک نوشتنِ بی‌تغییر روی `textContent` هم مرورگر را وادار به
   * بازمحاسبهٔ سبک و چیدمانِ همان زیردرخت می‌کند، و `innerHTML` علاوه بر آن
   * HTML را از نو parse می‌کند.
   */
  function paint(snapshot, opts) {
    const busy = !!(opts && opts.busy)
    const failed = snapshot.state === 'FAILED'
    const wasConnected = connected
    connected = snapshot.state === 'CONNECTED'
    accent = failed ? ERROR_ACCENT : connected ? AETHER_MINT : IDLE_ACCENT

    // نمایش و صدا: نور متحرک لبه فقط وقتی انیمیشن‌های صفحهٔ اصلی روشن‌اند (موبایل: LocalHomeAnimationsEnabled).
    const glowOn = connected && homeAnimationsEnabled()
    if (glowOn && !cycle) cycle = new GlowCycle()
    if (!glowOn && cycle) cycle = null

    if (accent !== paintedAccent) {
      paintedAccent = accent
      node.style.setProperty('--cc-accent', accent)
    }
    node.classList.toggle('is-on', connected)
    node.classList.toggle('is-error', failed)

    // ۱. وضعیت
    const title = el('cc-title')
    // پاک‌سازی + گارد بازرندر: setText فقط وقتی متن واقعاً عوض شده `textContent`
    // را می‌نویسد (جایگزین کامل فرزندان، نه افزودن)، و زیرنویسِ هم‌متن با عنوان
    // خالی می‌شود تا «در حال اتصال…» دو بار زیر هم نیفتد.
    const captionText = isRedundantCaption(opts.title, opts.caption) ? '' : opts.caption
    setText(title, opts.title)
    if (title.style.color !== accent) title.style.color = accent
    setText(el('cc-caption'), captionText)

    // ۲. تایمر — در حالت قطع، خاموش و کم‌رنگ می‌ماند و صفر نشان می‌دهد؛
    //    ردیف هرگز از کارت حذف نمی‌شود تا ارتفاع کارت نلرزد.
    const clock = el('cc-clock')
    setText(clock, formatClock(connected ? snapshot.uptimeSecs : 0))
    clock.classList.toggle('is-dim', !connected)

    // ۳. پیل آی‌پی
    const info = snapshot.ipInfo
    el('cc-ip-value').title = info ? [info.ip, info.alternateIp].filter(Boolean).join(' · ') : ''
    const viaTunnel = !!(info && info.viaTunnel)
    setText(el('cc-ip-label'), viaTunnel ? t('Server IP') : t('Your IP'))
    const pill = el('cc-pill')
    pill.classList.toggle('is-tunnel', viaTunnel)
    const flagBox = el('cc-ip-flag')
    // پرچم SVG درون‌ساخت است چون ویندوز فونت ایموجی پرچم ندارد و کد کشور
    // به‌صورت دو حرف («DE») رندر می‌شد.
    flagBox.hidden = !info
    // پرچم تنها جایی است که `innerHTML` می‌ماند (یک SVG است، نه متن) — پس با
    // کدِ کشور مقایسه می‌شود تا در هر snapshot از نو parse نشود.
    const flagKey = info ? String(info.countryCode ?? '') : ''
    if (info && flagBox.dataset.cc !== flagKey) {
      flagBox.dataset.cc = flagKey
      flagBox.innerHTML = flagHtml(info.countryCode)
    }
    setText(el('cc-ip-value'), busy
      ? t('Checking IP…')
      : info
        ? info.ip
        : snapshot.ipLoading
          ? t('Checking IP…')
          : t('IP unavailable'))

    // ۴. سرعت‌ها
    if (connected) {
      const now = performance.now()
      if (lastSampleAt > 0 && now > lastSampleAt && lastRx >= 0) {
        const seconds = (now - lastSampleAt) / 1000
        const rx = Math.max(0, (snapshot.rxBytes - lastRx) / seconds)
        const tx = Math.max(0, (snapshot.txBytes - lastTx) / seconds)
        setText(el('cc-rx-rate'), formatRate(rx))
        setText(el('cc-tx-rate'), formatRate(tx))
      }
      lastRx = snapshot.rxBytes
      lastTx = snapshot.txBytes
      lastSampleAt = now
      setText(el('cc-rx-total'), formatBytes(snapshot.rxBytes))
      setText(el('cc-tx-total'), formatBytes(snapshot.txBytes))
    } else {
      lastRx = -1
      lastTx = -1
      lastSampleAt = 0
      setText(el('cc-rx-rate'), '0 B/s')
      setText(el('cc-tx-rate'), '0 B/s')
      setText(el('cc-rx-total'), '0 B')
      setText(el('cc-tx-total'), '0 B')
    }

    // ۵–۷. اسلایدهای متا
    // AETHER-APP-PATCH 1.4.0 smart-label: never show the generic `(SMART)` marker —
    // prefer the compact label (which carries the winning transport) or strip it.
    setText(el('cc-proto'), connected ? resolveProtocolLabel(snapshot) : DASH)
    // AETHER-APP-PATCH custom-configs: زنجیرهٔ کانفیگِ سفارشی کوتاه می‌شود تا جا شود.
    fitChain(el('cc-proto'), connected ? snapshot.protocolCompact : null)
    // ردیف «Endpoint» از کارت حذف شد (۱.۳.۰): دیگر کاربردی نداشت و فضا را برای بقیه آزاد می‌کند.

    lastMs = !connected ? -1 : snapshot.latencyMs != null ? snapshot.latencyMs : lastMs
    setText(el('cc-latency'), !connected
      ? DASH
      : lastMs >= 0
        ? `${lastMs} ms`
        : '\u2026')

    // مقیاسِ پینگ از خطِ لولهٔ همین نشست می‌آید — پیش از هر قضاوتی روی عدد.
    bands = pingBandsFor(connected ? snapshot.protocol : null)

    const grade = pingGrade(connected, lastMs, bands)
    const quality = el('cc-ping-q')
    setText(quality, pingQualityLabel(grade))
    const qColour = connected ? pingTint(grade) : CARD_TEXT_DIM
    if (quality.style.color !== qColour) quality.style.color = qColour
    levelTarget = pingStrength(connected, lastMs, bands)

    // موج باید بدود؟ هر گذاری که چیزی برای نشان‌دادن می‌سازد، حلقهٔ ایستاده را
    // بیدار می‌کند — وصل‌شدن، و همچنین قطع‌شدن (میله‌ها باید *به‌نرمی* بخوابند
    // و نه یک‌دفعه ناپدید شوند).
    if (!waveIsIdle() || wasConnected !== connected) startWaveLoop()
  }

  start()

  return { node, paint, start, stop }
}

/** مستطیل گردگوشه با شعاع بریده‌شده — معادل `drawRoundRect` سمت Compose. */
function roundBar(ctx, x, y, w, h, r) {
  const radius = Math.min(r, w / 2, h / 2)
  ctx.beginPath()
  ctx.moveTo(x + radius, y)
  ctx.lineTo(x + w - radius, y)
  ctx.arcTo(x + w, y, x + w, y + radius, radius)
  ctx.lineTo(x + w, y + h - radius)
  ctx.arcTo(x + w, y + h, x + w - radius, y + h, radius)
  ctx.lineTo(x + radius, y + h)
  ctx.arcTo(x, y + h, x, y + h - radius, radius)
  ctx.lineTo(x, y + radius)
  ctx.arcTo(x, y, x + radius, y, radius)
  ctx.closePath()
  ctx.fill()
}

/**
 * `#RRGGBB` را با آلفا به `rgba()` تبدیل می‌کند.
 *
 * عمداً و نه `color-mix()`: این رنگ‌ها داخل canvas مصرف می‌شوند، و canvas
 * توابع رنگ CSS را حساب نمی‌کند — یک رشتهٔ نامعتبر در `fillStyle` بی‌صدا
 * نادیده گرفته می‌شود و نتیجه‌اش کارتی است بدون هیچ نور.
 */
function hexAlpha(hex, alpha) {
  if (hex.startsWith('rgba')) return hex
  const n = parseInt(hex.slice(1), 16)
  const r = (n >> 16) & 0xff
  const g = (n >> 8) & 0xff
  const b = n & 0xff
  return `rgba(${r},${g},${b},${Math.min(1, Math.max(0, alpha))})`
}
