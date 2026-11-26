// =============================================================================
//  src/ai.js — لایهٔ هوش مصنوعی سمت کاربر
//  پورت از ui/ai/AiState.kt + AiHintIcon.kt (Compose → DOM)
// =============================================================================
//
//  # این فایل مالکِ چه چیزی است
//
//  یک snapshot از سمت Rust (`aether://ai`)، و دو چیزی که هر صفحهٔ تنظیمات لازم
//  دارد: دکمهٔ ✨ کنار هر گزینه، و حبابِ توضیحی که باز می‌کند. حالتِ واقعی —
//  کلید، مدل، تاریخ چت، نتیجهٔ مشاور — **اینجا زندگی نمی‌کند**؛ در `ai_session.rs`
//  زندگی می‌کند و اینجا فقط بازتاب داده می‌شود. دلیلش همان دلیل `app.snapshot`
//  است: دو منبعِ حقیقت برای «کلید هست یا نه» یعنی صفحه‌ای که می‌گوید آماده است و
//  دکمه‌ای که رد می‌کند.
//
//  # چرا دکمهٔ ✨ یک تابع است و نه یک کامپوننت در هر صفحه
//
//  در a2 هر ردیف تنظیمات یک ✨ دارد. کپی‌کردن آن منطق در هر ردیف یعنی چهل نسخه
//  از همان چهار حالت دروازه، و تضمینِ اینکه یکی‌شان وقتی تونل پایین است به‌جای
//  پیام درست، یک خطای خام نشان بدهد.

import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { t, getLang, tAiError } from './i18n.js'
import { askInChat } from './ui/nav.js'

// ---------------------------------------------------------------- حالت

/** بازتابِ `AiSnapshot` سمت Rust. تا اولین رخداد، شکلِ خالیِ امن. */
export const ai = {
  gate: 'NO_KEY',
  gateCode: 'NO_KEY',
  hasKey: false,
  tunnelConnected: false,
  keyHint: '',
  models: [],
  selectedModel: '',
  modelNumber: 0,
  busy: false,
  error: null,
  errorKind: null,
  messages: [],
  advisor: null,
  /** نتیجهٔ آخرین تست اتصال — بازتابِ `AiProbe` در `ai_session.rs`. */
  probe: { state: 'IDLE', modelCount: 0, via: '', message: '' },
}

const listeners = new Set()

/** مثل `onChange` در main.js: شنونده مالِ گرهی است که رنگش می‌کند. */
export function onAiChange(fn, owner = null) {
  const entry = { fn, owner }
  listeners.add(entry)
  return () => listeners.delete(entry)
}

function emitAi() {
  for (const l of listeners) {
    if (l.owner && !l.owner.isConnected) continue
    l.fn(ai)
  }
}

function absorb(next) {
  // An AI event is newer than any snapshot request already in flight.
  ++refreshSeq
  Object.assign(ai, next)
  emitAi()
}

/**
 * درِ پشتیِ تست: همان چیزی که رخدادِ `aether://ai` می‌کند، بدون Tauri.
 *
 * صادر می‌شود چون هارنسِ jsdom باید بتواند snapshotهای واقعیِ Rust را بازی کند
 * (`probe.state = OK/FAILED`) و ببیند رابط چه نشان می‌دهد؛ هیچ کدِ محصولی آن را
 * صدا نمی‌زند.
 */
export const applyAiSnapshot = absorb

/** یک بار در بوت صدا زده می‌شود. */
export async function initAi() {
  // Subscribe before reading the initial state so a connection transition during
  // startup cannot be overwritten by an older DISCONNECTED snapshot.
  await listen('aether://ai', (event) => absorb(event.payload))
  await refreshAi()
}

/**
 * >>> AETHER-APP-PATCH ai-gate-follows-tunnel (1.3.0)
 *
 * دروازهٔ هوش مصنوعی (`gateCode`) به حالت تونل وابسته است، ولی Rust فقط بعد از
 * کارهای خودِ دستیار `aether://ai` می‌فرستاد — نه وقتی تونل وصل/قطع می‌شد. نتیجه:
 * کاربر وصل می‌شد و چت همچنان «تونل وصل نیست» نشان می‌داد. این تابع snapshot را
 * دوباره می‌گیرد؛ main.js آن را با هر تغییر حالت اتصال و هر ذخیرهٔ پروفایل صدا
 * می‌زند. پاسخ‌های قدیمی‌تر از درخواست بعدی دور ریخته می‌شوند.
 */
let refreshSeq = 0
export async function refreshAi() {
  const seq = ++refreshSeq
  try {
    const next = await invoke('ai_snapshot')
    if (seq === refreshSeq && next && typeof next === 'object') absorb(next)
  } catch (e) {
    console.error('ai_snapshot refresh failed', e)
  }
}
// <<< AETHER-APP-PATCH ai-gate-follows-tunnel

// ------------------------------------------------------------- دروازه

/**
 * جمله‌ای که به کاربر گفته می‌شود، و *کارِ* درست برای رفعش.
 *
 * هر حالت یک کنشِ مشخص دارد و هیچ‌کدام «مشکلی پیش آمد» نیست. این کل تفاوتِ یک
 * قابلیتِ قابل‌استفاده و یک قابلیتِ خراب است: کاربری که روی اِتِرِ تنها وصل است
 * باید بشنود «حالت را به Aether → Psiphon عوض کن»، نه اینکه حدس بزند.
 */
export function gateMessage(code = ai.gateCode) {
  switch (code) {
    case 'READY':
      return null
    case 'NO_KEY':
      return t('Add your Gemini API key to use the assistant.')
    case 'NO_MODEL':
      return t('No model has been discovered for this key yet.')
    case 'DISCONNECTED':
      return t('The assistant needs the tunnel to be connected — Google is not reachable otherwise.')
    case 'WRONG_MODE':
      return t('Switch the connection to Aether → Psiphon: Google refuses the Cloudflare WARP addresses that Aether alone exits from.')
    default:
      return t('The assistant is not available right now.')
  }
}

/**
 * جمله‌ای که برای یک شکست به کاربر گفته می‌شود.
 *
 * از `errorKind` ساخته می‌شود و نه از متنِ گوگل: پیامِ خامِ REST انگلیسیِ فنی است
 * («API key not valid. Pass a valid API key.») و در یک رابط فارسی، دقیقاً همان
 * چیزی است که کاربر را می‌فرستد سراغِ حدس‌زدن. متنِ خام هم پرت نمی‌شود — زیر
 * جملهٔ ترجمه‌شده به‌عنوان جزئیات می‌ماند.
 */
export function failureText(kind) {
  switch (kind) {
    case 'BAD_KEY':
      return t('Google rejected this key. Check it in AI Studio, or paste it again.')
    case 'RATE_LIMIT':
      return t('The free quota for this key is used up for now. Try again later.')
    case 'NO_SUCH_MODEL':
      return t('This key cannot use the selected model. Discover the models again.')
    case 'TRANSPORT':
      return t('The request never reached Google. Check the tunnel and try again.')
    case 'SERVER_ERROR':
      return t('Google failed on its own side. This is not your connection — try again.')
    case 'PROTOCOL':
      return t('Google sent back something this app could not read.')
    case 'TRUNCATED':
      return t('The answer was cut off before it finished.')
    case 'BLOCKED':
      return t('The model returned no answer.')
    default:
      return t('The request failed.')
  }
}

export function aiReady() {
  return ai.gateCode === 'READY' && !ai.busy
}

/**
 * خطِ خلاصهٔ زیرِ دکمهٔ «تست اتصال به API» — پورت از `AiPages.kt`.
 *
 * ترتیب شرط‌ها اهمیت دارد: «در حال تست» بر همه چیز مقدم است، و دروازهٔ بسته بر
 * نتیجهٔ کهنه، چون تستی که دیروز با تونلِ بالا سبز شده بود دربارهٔ تونلِ پایینِ
 * فعلی هیچ چیزی نمی‌گوید.
 */
export function probeSummary() {
  const probe = ai.probe ?? {}
  if (probe.state === 'RUNNING' || ai.busy) return t('Testing…')
  const blocked = ai.hasKey ? gateMessage() : null
  if (blocked && ai.gateCode !== 'NO_MODEL') return blocked
  if (probe.state === 'OK') {
    return t('Working — {0} model(s) available through {1}')
      .replace('{0}', String(probe.modelCount ?? 0))
      .replace('{1}', probe.via || 'Aether')
  }
  if (probe.state === 'FAILED') {
    return t('Not working: {0}').replace('{0}', probe.message ? tAiError(probe.message) : '')
  }
  return t('Checks the key and lists the models it may use')
}

// ------------------------------------------------------- آیکن و حبابِ توضیح

const SPARKLE =
  '<svg viewBox="0 0 24 24" width="15" height="15" aria-hidden="true">' +
  '<path d="M12 3l1.7 4.6L18 9.3l-4.3 1.7L12 15.6l-1.7-4.6L6 9.3l4.3-1.7z" fill="currentColor"/>' +
  '<path d="M18.5 14.5l.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8z" fill="currentColor" opacity=".65"/>' +
  '</svg>'

/**
 * دکمهٔ ✨ برای یک گزینهٔ تنظیمات.
 *
 * @param {{title: string, subtitle?: string, value?: () => string}} topic
 *
 * `value` یک **تابع** است و نه یک رشته، عمداً: ردیف‌های تنظیمات یک بار ساخته و
 * کَش می‌شوند (رجوع به `BUILT` در main.js)، پس مقداری که در زمان ساخت خوانده
 * شود تا همیشه یخ می‌زند و توضیحِ «مقدارِ فعلی‌اش X است» به‌آرامی دروغ می‌شود.
 */
export function aiHintButton(topic) {
  const btn = document.createElement('button')
  btn.type = 'button'
  btn.className = 'aihint'
  btn.innerHTML = SPARKLE
  btn.setAttribute('aria-label', t('Ask the assistant about this setting'))
  btn.title = t('Ask the assistant about this setting')
  btn.addEventListener('click', (event) => {
    event.preventDefault()
    event.stopPropagation()
    openExplain(btn, topic)
  })
  // دکمه با دروازه هم‌گام می‌ماند: با تونلِ پایین کم‌رنگ می‌شود ولی **حذف
  // نمی‌شود**، چون کلیک‌کردنش همان جایی است که کاربر یاد می‌گیرد چرا در دسترس
  // نیست. یک آیکن که ناپدید می‌شود، هیچ چیزی توضیح نمی‌دهد.
  const sync = () => btn.classList.toggle('is-muted', ai.gateCode !== 'READY')
  onAiChange(sync, btn)
  sync()
  return btn
}

let openBubble = null

function closeBubble() {
  openBubble?.remove()
  openBubble = null
}

document.addEventListener('click', (event) => {
  if (openBubble && !openBubble.contains(event.target) && !event.target.closest('.aihint')) {
    closeBubble()
  }
})
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') closeBubble()
})

async function openExplain(anchor, topic) {
  closeBubble()
  const bubble = document.createElement('div')
  bubble.className = 'aibubble'
  bubble.setAttribute('role', 'dialog')
  bubble.innerHTML =
    '<div class="aibubble__head"><span class="aibubble__title"></span>' +
    '<button type="button" class="aibubble__close" aria-label="' + t('Close') + '">×</button></div>' +
    '<div class="aibubble__body"></div>'
  bubble.querySelector('.aibubble__title').textContent = topic.title
  const body = bubble.querySelector('.aibubble__body')
  // پاسخ مدل ترجمه‌شده نیست و می‌تواند انگلیسی برگردد؛ جهت را از محتوای خودش
  // بگیرد، نه از زبان رابط.
  body.dir = 'auto'
  bubble.querySelector('.aibubble__close').addEventListener('click', closeBubble)
  document.body.appendChild(bubble)
  openBubble = bubble
  place(bubble, anchor)

  const blocked = gateMessage()
  if (blocked) {
    body.className = 'aibubble__body is-blocked'
    body.textContent = blocked
    return
  }

  body.innerHTML = '<span class="aibubble__spin"></span>'
  try {
    const text = await invoke('ai_explain', {
      lang: getLang(),
      title: topic.title,
      subtitle: topic.subtitle ?? '',
      value: topic.value ? String(topic.value()) : '',
    })
    // حباب ممکن است در این فاصله بسته شده باشد یا کاربر روی ✨ دیگری زده باشد:
    // نوشتن در گرهی که دیگر روی صفحه نیست، پاسخِ یک پرسشِ رهاشده را داخل حبابِ
    // یک پرسش دیگر می‌گذاشت.
    if (openBubble !== bubble) return
    body.className = 'aibubble__body'
    body.textContent = text
    // پایک **فقط** زیر یک پاسخِ واقعی می‌آید: زیر یک خطا، «متوجه نشدید؟» پرسشِ
    // اشتباهی است — کاربر خوب هم متوجه شده، جواب نگرفته.
    bubble.appendChild(askFooter(topic, text))
  } catch (e) {
    if (openBubble !== bubble) return
    body.className = 'aibubble__body is-error'
    body.textContent = tAiError(e)
  }
}

/**
 * پایکِ حبابِ ✨: «متوجه نشدید؟ از دستیار بپرسید».
 *
 * # چه چیزی به چت منتقل می‌شود
 *
 * عنوانِ تنظیم و **خودِ توضیحی که کاربر همین حالا خوانده**، نه فقط عنوان. بدون
 * متن، دستیار در چت همان توضیح را از صفر تولید می‌کند و کاربر دو بار همان جواب
 * را می‌گیرد؛ با متن، پرسش تبدیل می‌شود به «این را ساده‌تر بگو»، که همان چیزی
 * است که کاربر روی این دکمه می‌خواهد. پورت از `ai_explain_ask_chat` در
 * `AiCommon.kt`.
 */
function askFooter(topic, explanation) {
  const foot = document.createElement('div')
  foot.className = 'aibubble__foot'
  const btn = document.createElement('button')
  btn.type = 'button'
  btn.className = 'aibubble__ask'
  btn.innerHTML = SPARKLE + '<span></span>'
  btn.querySelector('span').textContent = t('Did not understand? Ask the assistant')
  btn.addEventListener('click', () => {
    const question = t('Explain this more simply: “{0}”. This is what the app told me: {1}')
      .replace('{0}', topic.title)
      .replace('{1}', explanation)
    closeBubble()
    askInChat(question)
  })
  foot.appendChild(btn)
  return foot
}

/**
 * حباب را کنار دکمه می‌گذارد و داخل پنجره نگه می‌دارد.
 *
 * `position: fixed` با مختصات از `getBoundingClientRect`، و نه یک عنصرِ درونیِ
 * `position: absolute`: ردیف‌های تنظیمات داخل یک کارتِ اسکرول‌شونده با
 * `overflow: hidden` هستند و یک حبابِ درونی از لبهٔ همان کارت بریده می‌شد.
 */
function place(bubble, anchor) {
  const a = anchor.getBoundingClientRect()
  const width = Math.min(320, window.innerWidth - 24)
  bubble.style.width = `${width}px`
  let left = a.left + a.width / 2 - width / 2
  left = Math.max(12, Math.min(left, window.innerWidth - width - 12))
  bubble.style.left = `${left}px`
  const below = window.innerHeight - a.bottom
  if (below > 190) {
    bubble.style.top = `${a.bottom + 8}px`
  } else {
    bubble.style.bottom = `${window.innerHeight - a.top + 8}px`
  }
}

// ------------------------------------------------------------- کنش‌ها
//
// هر کدام یک `invoke` نازک‌اند. خطاها پرت می‌شوند تا فراخوان تصمیم بگیرد کجا
// نشان داده شوند؛ ولی snapshot از سمت Rust در هر حال می‌رسد، پس اسپینرها بدون
// اینکه اینجا کاری بکنند پایین می‌آیند.

export const setApiKey = (key) => invoke('ai_set_key', { key })
export const selectModel = (id) => invoke('ai_select_model', { id })
export const refreshModels = () => invoke('ai_refresh_models')
/** «تست اتصال به API» — همان رفت‌وبرگشتِ کشفِ مدل، با نتیجهٔ ماندگار در `ai.probe`. */
export const testKey = () => invoke('ai_test_key')
export const sendChat = (text) => invoke('ai_send_chat', { lang: getLang(), text })
export const runAdvisor = () => invoke('ai_advise', { lang: getLang() })
/** «تلاش مجدد» روی یک حبابِ شکست‌خورده. */
export const retryMessage = (id) => invoke('ai_retry', { lang: getLang(), id })
/** یکی از پیام‌های خودِ کاربر را بازنویسی می‌کند و دوباره می‌پرسد. */
export const editMessage = (id, text) => invoke('ai_edit_message', { lang: getLang(), id, text })
/** حذفِ گروهی — یک رفت‌وبرگشت برای هر تعداد پیام. */
export const deleteMessages = (ids) => invoke('ai_delete_messages', { ids })
/** پاسخِ در راه را رها می‌کند. رجوع به `AiSession::stop` در سمت Rust. */
export const stopChat = () => invoke('ai_stop')
/**
 * تنظیماتی که یک پاسخ پیشنهاد کرده را می‌نویسد — دکمهٔ «اعمال».
 *
 * فهرستِ `[کلید, مقدار]`ِ چیزهایی که واقعاً نشستند را برمی‌گرداند. می‌تواند خالی
 * باشد، وقتی تنظیمات از قبل همان بوده‌اند.
 */
export const applyChanges = (id) => invoke('ai_apply_changes', { id })
export const clearChat = () => invoke('ai_clear_chat')
export const dismissAiError = () => invoke('ai_dismiss_error')
export const dismissAdvisor = () => invoke('ai_dismiss_advisor')
