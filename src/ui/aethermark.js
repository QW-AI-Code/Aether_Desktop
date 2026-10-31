// =============================================================================
//  پورت ۱:۱ از `ui/components/AetherMark.kt` — نشانِ حالتِ متصل: A زندهٔ اِتِر.
// -----------------------------------------------------------------------------
//  چرا این جای تیک را می‌گیرد
//
//  تیک می‌گفت «انجام شد». همان گلیفی است که هر فرم وقتی یک ایمیل را قبول
//  می‌کند نشان می‌دهد، هر برنامهٔ دیگری هم برای همان کار از آن استفاده می‌کند،
//  و هیچ چیزی درباره‌ی این نمی‌گوید که *کدام* تونل بالا است. نشانی که وقتی
//  تونل ترافیک می‌برد به این دکمه می‌آید، نشان خودِ برنامه است: همان A که روی
//  آیکون برنامه و در صفحهٔ انتشار است.
//
//  هندسه دقیقاً از آیکون برنامه آمده — همان دو فهرست مختصات
//  `ic_launcher_foreground.xml`. اگر روزی آیکون بازطراحی شد، تنها چیزی که
//  باید عوض شود همین دو آرایه است و انیمیشن دست‌نخورده روی آن سوار می‌ماند.
//
//  هزینه: یک canvas و پنج ساعت. هر مقدار انیمیشن‌شده *داخل* حلقهٔ ترسیم
//  خوانده می‌شود، پس یک فریم فقط یک redraw است. صدا زدنش هم فقط در حالت
//  متصل اتفاق می‌افتد، بنابراین صفحهٔ قطع‌شده به هیچ فریمی مشترک نمی‌شود.
// =============================================================================

import { FRAME_CAPS, TWO_PI, fitCanvas, frameLoop, trackSize } from './glowcycle.js'

// ------------------------------------------------------------------ هندسه

/**
 * A، در نمای ۱۰۸×۱۰۸ آیکون برنامه.
 * مسیر ۱: `M54,20 L82,86 L66,86 L54,54 L42,86 L26,86 Z`
 */
const MARK_OUTLINE = [54, 20, 82, 86, 66, 86, 54, 54, 42, 86, 26, 86]

/** مسیر ۲، کانترِ زیر رأس: `M54,44 L64,70 L44,70 Z`. */
const MARK_COUNTER = [54, 44, 64, 70, 44, 70]

// جعبهٔ گلیف داخل آن نما. عمداً ثابت نوشته شده و محاسبه نمی‌شود تا نگاشت
// پایدار و واضح بماند: x از ۲۶ تا ۸۲، y از ۲۰ تا ۸۶.
const BOX_LEFT = 26
const BOX_TOP = 20
const BOX_WIDTH = 56
const BOX_HEIGHT = 66

/**
 * رمپ لهجه‌ای که نشان در آن می‌چرخد: لهجه‌های خودِ برنامه، به ترتیب فام، تا
 * هر دو گام همسایه باشند و هیچ گذاری از رنگ گل‌آلود عبور نکند.
 */
const MARK_COLORS = [
  [0x3e, 0xdb, 0xb0], // mint برند — همان لهجهٔ «متصل» در تمام برنامه
  [0x35, 0xd0, 0xe8], // فیروزه‌ای
  [0x5b, 0x93, 0xff], // آبی — رنگ کنشِ اصلی
  [0x9b, 0x8c, 0xff], // بنفش — لهجهٔ هوش مصنوعی
  [0xff, 0x7a, 0xd9], // ارکیده
  [0xff, 0xc6, 0x5c], // کهربایی
]

const EDGE_LAYERS = [
  [3.4, 0.10],
  [2.1, 0.22],
  [1.0, 0.88],
]

/** میلی‌ثانیه به‌ازای هر رنگ رمپ. کند: این فضاسازی است، نه فلاش. */
const HUE_STEP_MS = 3400
const SWEEP_MS = 2600
const SCAN_MS = 2050
const BREATH_MS = 1500
const REVEAL_MS = 760

function lerpChannel(a, b, k) {
  return Math.round(a + (b - a) * k)
}

function mix(a, b, k) {
  return [lerpChannel(a[0], b[0], k), lerpChannel(a[1], b[1], k), lerpChannel(a[2], b[2], k)]
}

const WHITE = [255, 255, 255]

function rgba(c, alpha) {
  const a = Math.min(1, Math.max(0, alpha))
  return `rgba(${c[0]},${c[1]},${c[2]},${a})`
}

/** رمپ را پیوسته میان‌یابی می‌کند؛ [phase] بر حسب دور است، پس `floor` گام است. */
function cycleColour(phase) {
  const size = MARK_COLORS.length
  const step = ((Math.floor(phase) % size) + size) % size
  const next = (step + 1) % size
  return mix(MARK_COLORS[step], MARK_COLORS[next], phase - Math.floor(phase))
}

/**
 * دو مسیر را می‌سازد تا canvas فعلی را پر کنند، با حفظ نسبت آیکون و کمی
 * حاشیه تا بلوم لبهٔ نئون با جعبهٔ چیدمان بریده نشود.
 */
function buildMark(width, height) {
  const scale = Math.min(width / BOX_WIDTH, height / BOX_HEIGHT) * 0.94
  const dx = (width - BOX_WIDTH * scale) / 2
  const dy = (height - BOX_HEIGHT * scale) / 2
  const mapX = (x) => dx + (x - BOX_LEFT) * scale
  const mapY = (y) => dy + (y - BOX_TOP) * scale

  const build = (coords) => {
    const path = new Path2D()
    for (let i = 0; i < coords.length; i += 2) {
      const x = mapX(coords[i])
      const y = mapY(coords[i + 1])
      if (i === 0) path.moveTo(x, y)
      else path.lineTo(x, y)
    }
    path.closePath()
    return path
  }

  return { outline: build(MARK_OUTLINE), counter: build(MARK_COUNTER) }
}

// ------------------------------------------------------------------ لایه‌ها

/** هاله‌ای که نشان در آن نشسته است. جمعی، پس دیسک زیرش را بالا می‌آورد. */
function drawHalo(ctx, w, h, colour, intensity) {
  const radius = Math.min(w, h) * 0.62
  const cx = w / 2
  const cy = h * 0.56
  const grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, radius)
  grad.addColorStop(0, rgba(colour, 0.34 * intensity))
  grad.addColorStop(1, rgba(colour, 0))
  ctx.save()
  ctx.globalCompositeOperation = 'lighter'
  ctx.fillStyle = grad
  ctx.beginPath()
  ctx.arc(cx, cy, radius, 0, TWO_PI)
  ctx.fill()
  ctx.restore()
}

/**
 * پُرکنندهٔ بدنه: رنگ همین دور در رأس، رنگ *بعدی* در پاها.
 *
 * دو استاپ از یک رمپ و نه «رنگ به شفاف»: حرفی که پایینش محو شود جای پایش را
 * روی دیسک از دست می‌دهد، و همین گرادیان دورنگ است که چرخه را در خودِ گلیف
 * دیدنی می‌کند، نه فقط در هالهٔ آن.
 */
function drawBody(ctx, w, h, colour, ahead) {
  const grad = ctx.createLinearGradient(0, 0, 0, h)
  grad.addColorStop(0, rgba(mix(colour, WHITE, 0.22), 0.95))
  grad.addColorStop(0.5, rgba(colour, 0.80))
  grad.addColorStop(1, rgba(ahead, 0.62))
  ctx.fillStyle = grad
  ctx.fillRect(0, 0, w, h)
}

/**
 * شبکهٔ خطوط مویی: خط‌های تیرهٔ نازک روی پُرکننده، با رانش آرام.
 *
 * تیره و نه روشن، و فقط ۱۴٪ کدر: این بافتی است که نشان را شبیه نمایشگری
 * می‌کند که خوانده می‌شود، و لحظه‌ای که آن‌قدر روشن شود که خودش دیده شود،
 * دیگر بافت نیست و راه‌راه است.
 *
 * # ۱.۲.۵-perf — یک `fillRect` جای بیست‌وشش تا
 *
 * الگو ثابت است و فقط *جابه‌جا* می‌شود؛ پس یک‌بار روی یک canvas کوچکِ `۱×gap`
 * کشیده می‌شود و بعد به‌عنوان `CanvasPattern` تکرار می‌شود. رانش با `translate`
 * روی همان الگو می‌آید — دقیقاً همان تصویر، با یک فراخوانِ پُرکردن به‌جای یکی
 * برای هر خط.
 *
 * الگو روی خودِ canvas کَش می‌شود و نه سراسری: یک `CanvasPattern` به context
 * سازنده‌اش گره خورده است.
 */
function hairlinePattern(ctx, canvas, gap, thickness) {
  if (canvas.__aetherHairline !== undefined) return canvas.__aetherHairline
  // نبودِ `document` (هارنس‌های بی‌مرورگرِ `tests/`) یا نبودِ `createPattern`
  // یعنی همان حلقهٔ قبلی اجرا می‌شود. `null` هم کَش می‌شود تا در هر فریم دوباره
  // تلاش نشود.
  let pattern = null
  try {
    if (typeof document !== 'undefined' && typeof ctx.createPattern === 'function') {
      const tile = document.createElement('canvas')
      tile.width = 1
      tile.height = gap
      const tctx = tile.getContext('2d')
      if (tctx) {
        tctx.fillStyle = 'rgba(0,0,0,0.14)'
        tctx.fillRect(0, 0, 1, thickness)
        pattern = ctx.createPattern(tile, 'repeat')
      }
    }
  } catch {
    pattern = null
  }
  canvas.__aetherHairline = pattern
  return pattern
}

function drawHairlines(ctx, canvas, w, h, scan) {
  const gap = 5
  const drift = scan * gap
  const thickness = 1
  const pattern = hairlinePattern(ctx, canvas, gap, thickness)
  if (pattern) {
    ctx.save()
    ctx.translate(0, drift - gap)
    ctx.fillStyle = pattern
    ctx.fillRect(0, 0, w, h + gap)
    ctx.restore()
    return
  }
  ctx.fillStyle = 'rgba(0,0,0,0.14)'
  for (let y = -gap + drift; y < h; y += gap) {
    ctx.fillRect(0, y, w, thickness)
  }
}

/**
 * هایلایت متحرک. عمداً از محور خارج چرخانده شده: جاروی افقی یا عمودی روی یک
 * گلیف متقارن شبیه خطای رندر است، جاروی مورب شبیه نور.
 */
function drawSweepLight(ctx, w, h, phase, pulse) {
  const band = w * 0.42
  const travel = -band + phase * (w + 2 * band)
  ctx.save()
  ctx.globalCompositeOperation = 'lighter'
  ctx.translate(w / 2, h / 2)
  ctx.rotate((-22 * Math.PI) / 180)
  ctx.translate(-w / 2, -h / 2)
  const grad = ctx.createLinearGradient(travel - band / 2, 0, travel + band / 2, 0)
  grad.addColorStop(0, 'rgba(255,255,255,0)')
  grad.addColorStop(0.5, `rgba(255,255,255,${0.38 * pulse})`)
  grad.addColorStop(1, 'rgba(255,255,255,0)')
  ctx.fillStyle = grad
  ctx.fillRect(-w / 2, -h / 2, w * 2, h * 2)
  ctx.restore()
}

/** نوار اسکن، از پایین به بالا، با یک خط هستهٔ روشن در مرکزش. */
function drawScanBar(ctx, w, h, phase, colour, pulse) {
  const height = h * 0.16
  const top = h + height - phase * (h + 2 * height)
  ctx.save()
  ctx.globalCompositeOperation = 'lighter'
  const grad = ctx.createLinearGradient(0, top, 0, top + height)
  grad.addColorStop(0, 'rgba(255,255,255,0)')
  grad.addColorStop(0.5, rgba(mix(colour, WHITE, 0.45), 0.50 * pulse))
  grad.addColorStop(1, 'rgba(255,255,255,0)')
  ctx.fillStyle = grad
  ctx.fillRect(0, top, w, height)
  const core = 1.5
  ctx.fillStyle = `rgba(255,255,255,${0.30 * pulse})`
  ctx.fillRect(0, top + height / 2 - core / 2, w, core)
  ctx.restore()
}

/**
 * لبهٔ نئون: سه قلمِ جمعیِ درجه‌بندی‌شده، پهن‌ترین و کم‌رنگ‌ترین اول.
 * سرِ گرد *و* اتصال گرد — اتصال تیز روی این حرف در رأس سوزن می‌سازد.
 */
function drawEdge(ctx, outline, colour, pulse) {
  const base = 1.6
  ctx.save()
  ctx.globalCompositeOperation = 'lighter'
  ctx.lineCap = 'round'
  ctx.lineJoin = 'round'
  const tint = mix(colour, WHITE, 0.25)
  for (const [widthScale, alphaScale] of EDGE_LAYERS) {
    ctx.strokeStyle = rgba(tint, alphaScale * pulse)
    ctx.lineWidth = base * widthScale
    ctx.stroke(outline)
  }
  ctx.restore()
}

/**
 * مثلث کانتر: مسیر دوم آیکون، به‌عنوان هستهٔ نشان.
 *
 * ضربان تندترِ خودش را دارد (فاز اسکن با نرخ دوبرابر) تا گلیف کنار ریتم
 * بیرونی یک ریتم درونی هم داشته باشد — تفاوت «حرفی با نور روی آن» و «حرفی که
 * چیزی درونش می‌دود».
 */
function drawCounter(ctx, counter, colour, pulse, scan) {
  const beat = 0.55 + 0.45 * Math.abs(Math.sin(scan * TWO_PI))
  ctx.save()
  ctx.globalCompositeOperation = 'lighter'
  ctx.fillStyle = rgba(mix(colour, WHITE, 0.55), 0.42 + 0.38 * beat * pulse)
  ctx.fill(counter)
  ctx.strokeStyle = `rgba(255,255,255,${0.22 * beat})`
  ctx.lineWidth = 1.2
  ctx.lineCap = 'round'
  ctx.lineJoin = 'round'
  ctx.stroke(counter)
  ctx.restore()
}

/** خط روشنی که موجِ ظهور پشتش می‌سازد، فقط تا وقتی موج در حال اجراست. */
function drawBuildLine(ctx, w, y, colour, entered) {
  const fade = Math.min(1, Math.max(0, 1 - entered))
  const thickness = 2
  const grad = ctx.createLinearGradient(0, 0, w, 0)
  grad.addColorStop(0, 'rgba(255,255,255,0)')
  grad.addColorStop(0.5, rgba(mix(colour, WHITE, 0.6), 0.85 * fade))
  grad.addColorStop(1, 'rgba(255,255,255,0)')
  ctx.save()
  ctx.globalCompositeOperation = 'lighter'
  ctx.fillStyle = grad
  ctx.fillRect(0, y - thickness / 2, w, thickness)
  ctx.restore()
}

// ------------------------------------------------------------------- عمومی

/**
 * نشان را روی [canvas] زنده می‌کند و تابعی برمی‌گرداند که آن را متوقف کند.
 *
 * فراخوان باید این را *فقط* در حالت متصل صدا بزند و خروجی‌اش را در گذار به
 * هر حالت دیگری اجرا کند؛ همان قراردادی که `ConnectButton.kt` با «این
 * composable فقط در حالت متصل وجود دارد» داشت.
 */
export function startAetherMark(canvas, { animated = true } = {}) {
  // ورودِ یک‌باره. از صفر شروع می‌شود چون اولین فریمِ این نشان، همان لحظه‌ای
  // است که تونل بالا آمده — اتصال یک رخداد است و یکی می‌ارزد.
  const bornAt = performance.now()

  // ۱.۲.۵-perf — دو مسیرِ گلیف بین فریم‌ها کَش می‌شوند.
  //
  // `buildMark` فقط به اندازهٔ canvas بستگی دارد، ولی در هر فریم صدا زده
  // می‌شد: دو `Path2D` تازه، شصت بار در ثانیه، برای هندسه‌ای که تا تغییرِ
  // اندازهٔ پنجره ثابت است. اندازه هم دیگر با `getBoundingClientRect()` در
  // حلقهٔ فریم خوانده نمی‌شود — آن فراخوان مرورگر را وادار به محاسبهٔ چیدمان
  // می‌کرد؛ حالا `trackSize` خبر می‌دهد.
  let paths = null
  const size = trackSize(canvas, () => { paths = null })

  let stopLoop = null
  stopLoop = frameLoop((frameNow) => {
    size.poll(frameNow)
    const w = size.width || canvas.clientWidth
    const h = size.height || canvas.clientHeight
    if (w <= 0 || h <= 0) return
    // تغییرِ بافرِ canvas ترنسفورم را بازمی‌نشاند ولی مسیرها در مختصاتِ CSS
    // ساخته می‌شوند، پس تنها چیزی که مسیرها را باطل می‌کند تغییرِ w/h است —
    // و آن از `trackSize` می‌آید.
    fitCanvas(canvas, w, h)
    const ctx = canvas.getContext('2d')

    // animated=false (انیمیشن‌های صفحهٔ اصلی خاموش): همان `AetherMark(animated=false)` موبایل —
    // یک فریمِ ثابتِ کاملاً ظاهرشده، بدون موج ورود و بدون حلقه.
    const now = animated ? frameNow : 0
    const age = animated ? now - bornAt : REVEAL_MS
    const huePhase = (now / HUE_STEP_MS) % MARK_COLORS.length
    const colour = cycleColour(huePhase)
    const ahead = cycleColour(huePhase + 0.45)
    const sweep = (now % SWEEP_MS) / SWEEP_MS
    const scan = (now % SCAN_MS) / SCAN_MS
    const breathT = (now % (2 * BREATH_MS)) / BREATH_MS
    const tri = breathT <= 1 ? breathT : 2 - breathT
    const pulse = 0.74 + 0.26 * (tri * tri * (3 - 2 * tri))
    // easing نرم روی موجِ ظهور، مثل FastOutSlowIn سمت اندروید.
    const linear = Math.min(1, age / REVEAL_MS)
    const entered = linear * linear * (3 - 2 * linear)

    ctx.clearRect(0, 0, w, h)
    if (entered <= 0.001) return

    if (!paths) paths = buildMark(w, h)
    const { outline, counter } = paths

    // ۱. هاله‌ای که گلیف در آن نشسته، پشت همه‌چیز و بیرون از کلیپ تا بتواند
    //    از لبه‌های حرف بیرون بزند.
    drawHalo(ctx, w, h, colour, pulse * entered)

    // ۲. هر چیزی که *داخل* حرف است، از پایین به بالا پاک‌روبی می‌شود.
    const wipeTop = h * (1 - entered)
    ctx.save()
    ctx.beginPath()
    ctx.rect(0, wipeTop, w, h - wipeTop)
    ctx.clip()
    ctx.save()
    ctx.clip(outline)
    drawBody(ctx, w, h, colour, ahead)
    drawHairlines(ctx, canvas, w, h, scan)
    drawSweepLight(ctx, w, h, sweep, pulse)
    drawScanBar(ctx, w, h, scan, colour, pulse)
    ctx.restore()

    // ۳. لبهٔ نئون: روی ناحیهٔ پاک‌روبی‌شده کشیده می‌شود ولی هرگز به خودِ حرف
    //    کلیپ نمی‌شود، تا بلومش نور به نظر بیاید و نه حاشیه.
    drawEdge(ctx, outline, colour, pulse)
    drawCounter(ctx, counter, colour, pulse, scan)
    ctx.restore()

    // ۴. خط ساخت: فقط تا وقتی موج در حال اجراست.
    if (entered < 0.999) drawBuildLine(ctx, w, wipeTop, colour, entered)
    if (!animated && stopLoop) stopLoop()
  }, FRAME_CAPS.mark)

  // نشان در هر گذارِ غیرِ متصل لغو می‌شود، پس ناظرِ اندازه هم باید همان‌جا آزاد
  // شود: یک `ResizeObserver` که کسی جمعش نکند، بعد از چند بار وصل و قطع تبدیل
  // به چند ناظرِ زنده روی یک canvas می‌شود.
  return () => {
    stopLoop()
    size.stop()
  }
}
