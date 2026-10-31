// =============================================================================
//  Aether Windows — پوستهٔ کاربری (۱.۴.۰-mobile: قاب موبایلی ۳۹۰×۸۲۰)
//  پورت یک‌به‌یک از ui/ مخزن اندروید (Jetpack Compose → DOM).
// =============================================================================
import { onConnectionState } from './ui/feedback.js'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWindow } from '@tauri-apps/api/window'

import { renderHome } from './views/home.js'
import { renderSettings, renderTunnelSettings } from './views/settings.js'
import { renderAssistant } from './views/assistant.js'
import { renderChat } from './views/chat.js'
import { renderDiagnostics } from './views/diagnostics.js'
import { renderShare } from './views/share.js'
import { renderAbout } from './views/about.js'

import { t, applyLang, getLang, setLangPersister, adoptStoredLang } from './i18n.js'
import { initAi, refreshAi } from './ai.js'
// AETHER-APP-PATCH whats-new
import { maybeShowWhatsNew } from './ui/whatsnew.js'
import { setTabRouter } from './ui/nav.js'
import { syncLoginCode } from './ui/logincode.js'
import { icon } from './ui/icons.js'

// --- وضعیت سراسری ------------------------------------------------------
export const app = {
  snapshot: {
    state: 'DISCONNECTED',
    detail: '',
    error: null,
    endpoint: null,
    protocol: null,
    latencyMs: null,
    uptimeSecs: 0,
    rxBytes: 0,
    txBytes: 0,
    shareSocks: null,
    shareHttp: null,
    // ۱.۵.۰ — اشتراک LAN: off | waiting | ready | portBusy، آدرس‌ها و اتصال‌ها.
    shareStatus: 'off',
    shareTargets: [],
    shareClients: 0,
    // ۱.۵.۰ — هسته منتظرِ کدِ ورودِ Zero Trust است (دیالوگ سراسری).
    loginCode: null,
    ipInfo: null,
    ipLoading: true,
    // v1.2.0 — سنجش نشتی WebRTC: null = هنوز سنجیده نشده.
    webrtcLeak: null,
    leakGuard: false,
    torPercent: null,
  },
  profile: null,
  tab: 'home',
  listeners: new Set(),
}

// A repaint listener is owned by the DOM node it paints. Detached owners are
// skipped instead of being torn down, which is what lets a view be cached and
// re-attached rather than rebuilt from scratch on every tab switch.
export function onChange(fn, owner = null) {
  const entry = { fn, owner }
  app.listeners.add(entry)
  return () => app.listeners.delete(entry)
}

export function emit() {
  for (const l of app.listeners) {
    if (l.owner && !l.owner.isConnected) continue
    l.fn(app)
  }
}

/**
 * یک تنظیم را ذخیره می‌کند.
 *
 * # چرا اول خوانده می‌شود و بعد نوشته
 *
 * `set_profile` **کلِ** پروفایل را می‌گیرد و نه یک تغییر. پس نوشتن روی کپیِ
 * محلی یعنی هر فیلدی که این کپی از آن بی‌خبر است، با مقدارِ کهنه‌اش بازنویسی
 * می‌شود. تا وقتی هر نوشتنی از خودِ رابط شروع می‌شد این بی‌ضرر بود؛ مسیرهای
 * هوش مصنوعی که در Rust می‌نویسند، این فرض را شکستند: کاربر تغییرِ دستیار را
 * اعمال می‌کرد، بعد یک تنظیمِ بی‌ربط را عوض می‌کرد، و تغییرِ دستیار بی‌صدا
 * برمی‌گشت.
 *
 * حالا مرجع، همیشه سمت Rust است: پروفایلِ فعلی خوانده می‌شود، تغییر روی همان
 * می‌نشیند، و همان نوشته می‌شود. رخدادِ `aether://profile` هم هست، ولی این
 * تابع به رسیدنِ آن **تکیه نمی‌کند** — یک رخدادِ ازدست‌رفته نباید به از‌دست‌رفتنِ
 * تنظیمات ترجمه شود.
 *
 * فیلدهای محرمانه از این قاعده مستثنا نیستند و لازم هم نیست باشند:
 * `get_profile` آن‌ها را برنمی‌گرداند (رشتهٔ خالی) و `set_profile` رشتهٔ خالی را
 * «دست نزن» تفسیر می‌کند، پس رازِ این نشست با یک خواندن پاک نمی‌شود.
 */
export async function saveProfile(patch) {
  let base = app.profile
  try {
    base = await invoke('get_profile')
  } catch (e) {
    // خواندن شکست خورد: با کپیِ محلی جلو می‌رویم، چون نوشتنِ تنظیمِ کاربر مهم‌تر
    // از تازه‌بودنِ بقیهٔ فیلدهاست — ولی *گفته* می‌شود.
    console.error('get_profile before save failed; writing on the local copy', e)
  }
  app.profile = { ...base, ...patch }
  await invoke('set_profile', { profile: app.profile })
  // ai-gate-follows-tunnel: عوض‌شدن بک‌اند دروازهٔ هوش مصنوعی (WRONG_MODE) را عوض می‌کند.
  refreshAi()
  emit()
}

/**
 * درِ پشتیِ تست برای رخدادِ `aether://profile` — بدونِ Tauri.
 *
 * هیچ کدِ محصولی صدایش نمی‌زند؛ هارنسِ jsdom با آن همان چیزی را بازی می‌کند که
 * Rust پس از نوشتنِ پروفایل می‌فرستد.
 */
export function applyProfileSnapshot(profile) {
  app.profile = profile
  dropProfileViews()
  emit()
}

export async function toggleConnection() {
  if (!app.profile) return
  try {
    await invoke('toggle_connection')
  } catch (e) {
    app.snapshot.error = String(e)
    emit()
  }
}

// --- رنگ حالت — دقیقاً همان قانون ConnectButton.kt --------------------
export function accentFor(state) {
  if (state === 'CONNECTED') return '#3EDBB0'
  if (state === 'FAILED') return '#FF5C7A'
  return '#5B93FF'
}

// --- متن حالت — همان رشته‌های strings.xml -----------------------------
export const STATE_LABEL = {
  DISCONNECTED: 'Disconnected',
  STARTING_ENGINE: 'Starting engine…',
  CONNECTING: 'Connecting…',
  VERIFYING: 'Verifying…',
  CONNECTED: 'Connected',
  RECONNECTING: 'Reconnecting…',
  DISCONNECTING: 'Disconnecting…',
  FAILED: 'Connection failed',
}

export function formatBytes(n) {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  return `${(n / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

export function formatUptime(secs) {
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  const pad = (x) => String(x).padStart(2, '0')
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`
}

// --- نوار ۲۸ پیکسلی ویندوز (decorations: false) ------------------------
// ۱.۴.۰-mobile: فقط کمینه و بستن. بیشینه‌سازی حذف شد — پنجره قاب موبایلی است
// (`maximizable: false` در tauri.conf.json هم Win+↑ را می‌بندد).
const ICON_MINIMIZE = icon('minimize', 12)
const ICON_CLOSE = icon('close', 12)

// ۱.۴.۰-ui: Material Rounded، یکسان با نسخهٔ موبایل
const NAV_ICONS = {
  home: icon('home'),
  advanced: icon('settings'),
  assistant: icon('assistant'),
  chat: icon('chat'),
  diagnostics: icon('bug_report'),
  share: icon('wifi'),
  about: icon('info'),
}

function wireWinbar() {
  const win = getCurrentWindow()
  const minBtn = document.querySelector('.twin--min')
  const closeBtn = document.querySelector('.twin--close')
  if (minBtn) minBtn.innerHTML = ICON_MINIMIZE
  if (closeBtn) closeBtn.innerHTML = ICON_CLOSE
  const bar = document.querySelector('.winbar')
  bar?.addEventListener('mousedown', (e) => {
    if (e.button !== 0 || e.target.closest('.twin')) return
    win.startDragging()
  })
  // دابل‌کلیک دیگر بزرگ نمی‌کند — فقط جلویش گرفته می‌شود.
  bar?.addEventListener('dblclick', (e) => e.preventDefault())
  minBtn?.addEventListener('click', () => win.minimize())
  closeBtn?.addEventListener('click', () => win.close())
}

// --- کشوی ناوبری ---------------------------------------------------------
function drawerEls() {
  return {
    drawer: document.getElementById('drawer'),
    backdrop: document.getElementById('drawer-backdrop'),
    menuBtn: document.getElementById('menu-btn'),
  }
}

export function isDrawerOpen() {
  return document.getElementById('drawer')?.classList.contains('is-open') ?? false
}

export function openDrawer() {
  const { drawer, backdrop, menuBtn } = drawerEls()
  if (!drawer) return
  drawer.classList.add('is-open')
  drawer.setAttribute('aria-hidden', 'false')
  if (backdrop) { backdrop.hidden = false; backdrop.classList.add('is-open') }
  menuBtn?.setAttribute('aria-expanded', 'true')
  document.body.classList.add('drawer-open')
  drawer.querySelector('.drawer__item.is-active, .drawer__item')?.focus?.()
}

export function closeDrawer() {
  const { drawer, backdrop, menuBtn } = drawerEls()
  if (!drawer) return
  drawer.classList.remove('is-open')
  drawer.setAttribute('aria-hidden', 'true')
  if (backdrop) { backdrop.classList.remove('is-open'); backdrop.hidden = true }
  menuBtn?.setAttribute('aria-expanded', 'false')
  document.body.classList.remove('drawer-open')
}

export function toggleDrawer() {
  if (isDrawerOpen()) closeDrawer()
  else openDrawer()
}

function wireDrawer() {
  const { drawer, backdrop, menuBtn } = drawerEls()
  menuBtn?.addEventListener('click', toggleDrawer)
  backdrop?.addEventListener('click', closeDrawer)
  for (const b of drawer?.querySelectorAll('.drawer__item') ?? []) {
    b.addEventListener('click', () => {
      closeDrawer()
      showTab(b.dataset.tab)
    })
  }
  for (const b of document.querySelectorAll('.mobile-header__action')) {
    b.addEventListener('click', () => showTab(b.dataset.tab))
  }
  document.getElementById('back-btn')?.addEventListener('click', () => goBack())
}

// --- مسیریابی تب‌ها (در اندروید باتم‌شیت بود، در دسکتاپ ریل کناری) --
const VIEWS = {
  home: renderHome,
  advanced: renderSettings,
  tunnel: renderTunnelSettings,
  assistant: renderAssistant,
  chat: renderChat,
  diagnostics: renderDiagnostics,
  share: renderShare,
  about: renderAbout,
}

// Built views, kept by tab.
//
// Root cause of the slow menu: every tab click threw the old view's DOM away and
// rebuilt the next one from strings — and "Advanced" means 56 country rows, each
// with an inline SVG flag, plus a fresh `core_caps` IPC round trip, every single
// time. Views are built once and re-attached after that, so switching a tab is a
// single `appendChild`. `emit()` already skips detached owners, so a cached view
// costs nothing while it is off screen.
const BUILT = new Map()
let mounted = null

// A view may expose lifecycle hooks on its root node; only the diagnostics panel
// needs them (it polls the log while visible and must stop when it is not).
function renderTab() {
  const host = document.getElementById('view')
  if (mounted && mounted.parentElement === host) {
    mounted.__onHide?.()
    host.removeChild(mounted)
  }
  let node = BUILT.get(app.tab)
  if (!node) {
    node = VIEWS[app.tab](app)
    BUILT.set(app.tab, node)
  }
  host.replaceChildren(node)
  mounted = node
  node.__onShow?.()
  for (const b of document.querySelectorAll('.drawer__item')) {
    b.classList.toggle('is-active', b.dataset.tab === app.tab)
  }
  document.body.dataset.tab = app.tab
  syncHeader()
  // v14 — یک آپدیت را که وقتی این تب پنهان بود از دست رفت، همین‌جا برمی‌گردانیم.
  //
  // `emit()` هر listenerی را که مالکش هنوز `isConnected` نیست رد می‌کند —
  // دقیقاً همان چیزی که این تب را تا این لحظه ارزان نگه می‌داشت. مشکل این بود
  // که هیچ‌کس، درست در لحظه‌ای که یک نودِ کش‌شده دوباره متصل می‌شود، این
  // رد‌شده‌ها را دوباره صدا نمی‌زد؛ یک `emit()` که *وسطِ* غیبتِ این تب اتفاق
  // می‌افتاد (مثلاً `saveProfile` از تبِ Settings) برای همیشه گم می‌شد و تنها
  // با رخداد بعدیِ `emit` (که مقدارِ *آن لحظه* را می‌داد، نه لزوماً مقدارِ درست
  // برای این ردیف) جایش پر می‌شد. همین‌جا، بعد از اتصالِ دوبارهٔ نود، یک
  // `emit()` تازه تضمین می‌کند هر چیزی که این تب نشان می‌دهد با `app.profile`/
  // `app.snapshot` *همین الان* یکی است — نه با آخرین باری که این تب دیده شد.
  emit()
  // A tab may be opened after a missed event while it was detached; consult
  // Rust's current tunnel state before presenting the chat gate or model list.
  if (app.tab === 'chat' || app.tab === 'assistant') refreshAi()
}

// Drops a cached view so the next visit rebuilds it. Used by panels whose markup
// depends on the profile (revealing a section, switching endpoint mode).
export function refreshTab(tab = app.tab) {
  const node = BUILT.get(tab)
  if (node === mounted) mounted = null
  BUILT.delete(tab)
  if (tab === app.tab) renderTab()
}

/// Tabs whose MARKUP is built from the profile.
///
/// Only one, and that is the point: `advanced.js` reads `app.profile` while it
/// builds its controls and never subscribes to `onChange`. Combined with the
/// view cache above, a profile that Rust writes -- the assistant applying a
/// change, Smart Auto lowering the noize, `reset_profile` -- left the built
/// panel showing the OLD value for the rest of the session. The hub row updated
/// (it has an `onChange`), so the row said one thing and the control under it
/// said another.
const PROFILE_TABS = ['advanced', 'tunnel', 'share']

/// A rebuild pending because the user is typing. See [`dropProfileViews`].
let profileTabStale = false

/// True while the caret sits in an editable control inside [node].
function editingInside(node) {
  const active = document.activeElement
  if (!active || active === document.body || !node.contains(active)) return false
  return active.matches('input, textarea, select, [contenteditable="true"]')
}

/// Throws away the profile-built views so the next paint reads the new profile.
///
/// The one case that must NOT rebuild immediately is a user typing into the
/// panel (a bridge line, a team name): a snapshot arriving mid-keystroke would
/// replace the field under the caret and eat the edit. There the rebuild is
/// deferred to the next time the tab is shown.
function dropProfileViews() {
  for (const tab of PROFILE_TABS) {
    const node = BUILT.get(tab)
    if (!node) continue
    if (node === mounted && editingInside(node)) {
      profileTabStale = true
      continue
    }
    if (node === mounted) refreshTab(tab)
    else BUILT.delete(tab)
  }
}

/// Switches tab. The drawer, the header shortcuts and the jsdom harness go
/// through here, so the cache invalidation cannot be true on one path and
/// false on the other.
///
/// ۱.۴.۰-mobile — ناوبری پشته‌ای: هر تبِ غیر از خانه یک زیرصفحهٔ تمام‌صفحه است
/// که روی پشته می‌نشیند؛ «بازگشت»، Esc و Alt+Left آن را برمی‌دارند. خانه همیشه
/// کفِ پشته است و خودش هرگز دکمهٔ بازگشت ندارد.
export const navStack = []

export function showTab(tab, { push = true } = {}) {
  if (!(tab in VIEWS)) return
  if (!app.profile && tab !== 'home') return
  if (tab === 'home') navStack.length = 0
  else if (push && app.tab !== tab) {
    const i = navStack.indexOf(app.tab)
    if (i >= 0) navStack.length = i
    if (app.tab !== 'home') navStack.push(app.tab)
  }
  app.tab = tab
  if (profileTabStale && PROFILE_TABS.includes(tab)) {
    profileTabStale = false
    BUILT.delete(tab)
    if (mounted && BUILT.get(tab) === undefined) mounted = null
  }
  renderTab()
}

/** یک پله عقب. اگر چیزی روی پشته نباشد، به خانه برمی‌گردد. */
export function goBack() {
  if (isDrawerOpen()) { closeDrawer(); return true }
  if (app.tab === 'home') return false
  const prev = navStack.pop() ?? 'home'
  showTab(prev, { push: false })
  return true
}

const HEADER_TITLES = { home: 'Aether', advanced: 'Settings', tunnel: 'Tunnel settings', assistant: 'Assistant', chat: 'Chat', diagnostics: 'Diagnostics', share: 'Share over LAN', about: 'About' }

function syncHeader() {
  const header = document.getElementById('mobile-header')
  if (!header) return
  const atHome = app.tab === 'home'
  header.classList.toggle('is-sub', !atHome)
  const menuBtn = document.getElementById('menu-btn')
  const backBtn = document.getElementById('back-btn')
  if (menuBtn) menuBtn.hidden = !atHome
  if (backBtn) backBtn.hidden = atHome
  const title = document.getElementById('header-title')
  const tagline = document.getElementById('header-tagline')
  if (title) title.textContent = t(HEADER_TITLES[app.tab] ?? 'Aether')
  if (tagline) { tagline.textContent = t('Freedom, in one tap'); tagline.hidden = !atHome }
  for (const b of document.querySelectorAll('.mobile-header__action')) {
    b.classList.toggle('is-active', b.dataset.tab === app.tab)
  }
}

function wireKeys() {
  document.addEventListener('keydown', (e) => {
    if (e.defaultPrevented) return
    if (e.key === 'Escape') {
      if (isDrawerOpen()) { e.preventDefault(); closeDrawer(); return }
      // Esc داخل فیلدها را به خودشان واگذار می‌کنیم (بستن dropdown و…)
      if (e.target instanceof HTMLElement && e.target.matches('input, textarea, select, [contenteditable="true"]')) return
      if (goBack()) e.preventDefault()
      return
    }
    if (e.altKey && e.key === 'ArrowLeft') {
      if (goBack()) e.preventDefault()
    }
  })
}

// --- راه‌اندازی ---------------------------------------------------------
const NAV_LABELS = { home: 'Home', advanced: 'Settings', tunnel: 'Tunnel settings', assistant: 'Aether AI', chat: 'Chat with Gemini', diagnostics: 'Diagnostics & logs', share: 'Share VPN', about: 'About' }
// ۱.۴.۰-ui: زیرنویس هر آیتم کشو — همان متن‌های Android (strings.xml).
const NAV_SUBS = {
  assistant: 'Gemini inside the app: explain, optimize and chat',
  chat: 'Ask anything, or say what should change',
  advanced: 'Connection, apps, security and troubleshooting',
  diagnostics: 'Live status of every part of the tunnel',
  share: 'Use this computer as a proxy for other devices',
  about: 'Makers, links and what changed in this version',
}

// retranslate the chrome (drawer items + header) for the active language.
function translateChrome() {
  for (const b of document.querySelectorAll('.drawer__item')) {
    const label = t(NAV_LABELS[b.dataset.tab] ?? b.dataset.tab)
    b.innerHTML =
      '<span class="drawer__icon">' + (NAV_ICONS[b.dataset.tab] ?? '') + '</span>' +
      '<span class="drawer__text"><span class="drawer__label"></span><span class="drawer__sub"></span></span>' +
      '<span class="drawer__chev">' + icon('chevron', 18) + '</span>'
    b.querySelector('.drawer__label').textContent = label
    const sub = NAV_SUBS[b.dataset.tab]
    b.querySelector('.drawer__sub').textContent = sub ? t(sub) : ''
    b.title = label
  }
  const menuBtn = document.getElementById('menu-btn')
  if (menuBtn) { menuBtn.innerHTML = icon('menu', 24); menuBtn.setAttribute('aria-label', t('Menu')) }
  const backBtn = document.getElementById('back-btn')
  if (backBtn) { backBtn.innerHTML = icon('arrow_back', 24); backBtn.setAttribute('aria-label', t('Back')) }
  const hdrAssistant = document.getElementById('hdr-assistant')
  if (hdrAssistant) { hdrAssistant.innerHTML = icon('assistant', 22); hdrAssistant.setAttribute('aria-label', t('Assistant')); hdrAssistant.title = t('Assistant') }
  const hdrTune = document.getElementById('hdr-tune')
  if (hdrTune) { hdrTune.innerHTML = icon('tune', 22); hdrTune.setAttribute('aria-label', t('Tunnel settings')); hdrTune.title = t('Tunnel settings') }
  const dTitle = document.querySelector('.drawer__title')
  if (dTitle) dTitle.textContent = t('Aether')
  const dTag = document.querySelector('.drawer__tagline')
  if (dTag) dTag.textContent = t('Freedom, in one tap')
  syncHeader()
}

// v8: re-render chrome + current tab after a language change.
export function rerender() {
  translateChrome()
  // A language change invalidates every built view, not just the visible one.
  for (const [tab, node] of BUILT) {
    if (node === mounted) mounted = null
    BUILT.delete(tab)
  }
  renderTab()
}

async function boot() {
  applyLang()
  wireWinbar()
  wireDrawer()
  wireKeys()
  translateChrome()
  // درِ ناوبری برای بقیهٔ ماژول‌ها — رجوع به مستند `src/ui/nav.js` برای اینکه
  // چرا این ثبت است و نه یک import مستقیم به `renderTab`.
  setTabRouter((tab) => {
    if (!(tab in VIEWS)) return
    showTab(tab)
  })

  // Paint a tiny, dependency-free shell immediately. Rendering a full view
  // before profile IPC caused the advanced view to do expensive work twice.
  const host = document.getElementById('view')
  host.innerHTML = '<div class="boot-skeleton" role="status" aria-busy="true"></div>'
  host.firstElementChild.textContent = t('Preparing Aether…')
  // Shell first, before any IPC, engine staging or listener registration.
  // Defer hydration by one task so the browser can present this frame.
  await new Promise(resolve => setTimeout(resolve, 0))
  await invoke('startup_ready')

  // Fetch initial state in parallel instead of serializing two IPC round trips.
  // ui-lang-on-disk: زبان از prefs.json سمت Rust هم خوانده می‌شود (همان رفت‌وبرگشت موازی).
  setLangPersister((lang) => invoke('set_ui_lang', { lang }))
  const [profile, snapshot, storedLang] = await Promise.all([
    invoke('get_profile'),
    invoke('get_snapshot'),
    invoke('get_ui_lang').catch(() => null),
  ])
  app.profile = profile
  app.snapshot = snapshot
  // نمایش و صدا: حالتِ آغازین فقط پایهٔ سیاست صدا است (شروع برنامه بی‌صدا).
  onConnectionState(snapshot?.state)
  if (storedLang === 'fa' || storedLang === 'en') {
    if (adoptStoredLang(storedLang)) translateChrome()
  } else {
    // اولین اجرا بعد از این نسخه: انتخابِ فعلیِ localStorage را به دیسک منتقل کن.
    invoke('set_ui_lang', { lang: getLang() }).catch(() => {})
  }

  // پروفایلی که خودِ Rust نوشته — مسیرهای هوش مصنوعی. بی این، صفحهٔ تنظیمات
  // مقدارِ پیش از اعمال را نشان می‌داد و کاربر نتیجه می‌گرفت که «اعمال نشد».
  await listen('aether://profile', (event) => {
    if (event.payload) applyProfileSnapshot(event.payload)
  })

  // جریان زندهٔ وضعیت — معادل StateFlow در اندروید (هر ۲۰۰ میلی‌ثانیه).
  let lastAccent = null
  // ai-gate-follows-tunnel: حالت اتصالی که دروازهٔ هوش مصنوعی آخرین بار با آن سنجیده شد.
  let lastGateState = app.snapshot?.state ?? null
  await listen('aether://state', (event) => {
    app.snapshot = event.payload
    onConnectionState(app.snapshot?.state)
    if (app.snapshot?.state !== lastGateState) {
      lastGateState = app.snapshot?.state ?? null
      refreshAi()
    }
    // فقط وقتی رنگ واقعاً عوض شده بنویس — نوشتن مداوم متغیر CSS روی <html>
    // هر ۲۰۰ms باعث style-recalc کل صفحه و گیرکردن انیمیشن کمان می‌شد.
    const accent = accentFor(app.snapshot.state)
    if (accent !== lastAccent) {
      lastAccent = accent
      document.documentElement.style.setProperty('--accent', accent)
    }
    syncLoginCode(app.snapshot?.loginCode)
    emit()
  })

  // جریان وضعیت هوش مصنوعی. عمداً `await` نمی‌شود و در `Promise.all` بالا هم
  // نیست: صفحهٔ خانه به آن نیازی ندارد و انتظار برایش اولین رنگ‌آمیزی را عقب
  // می‌انداخت. صفحهٔ دستیار به‌محض رسیدن اولین snapshot خودش را می‌سازد.
  initAi().catch((error) => console.error('AI layer unavailable', error))

  // Repaint the already-visible shell with the real state once IPC returns.
  renderTab()
  syncLoginCode(app.snapshot?.loginCode)
  emit()

  // >>> AETHER-APP-PATCH whats-new (1.3.0)
  // پنجرهٔ «تازه‌ها»: اولین اجرا بعد از نصب یا ارتقا (تا وقتی کاربر برای همین
  // نسخه «دیگر نمایش نده» را بزند). بعد از اولین رنگ‌آمیزی، تا شروع را کند نکند.
  maybeShowWhatsNew().catch((error) => console.error('What\'s new dialog unavailable', error))
  // <<< AETHER-APP-PATCH whats-new
}

export const bootReady = boot().catch((error) => {
  console.error('Aether UI bootstrap failed', error)
  const host = document.getElementById('view')
  if (host) {
    host.replaceChildren()
    const error = document.createElement('p')
    error.className = 'boot-error'
    error.setAttribute('role', 'alert')
    error.textContent = t('Aether could not finish loading. Please restart the app.')
    const retry = document.createElement('button')
    retry.className = 'btn btn--primary'
    retry.textContent = t('Retry')
    retry.onclick = () => window.location.reload()
    host.append(error, retry)
  }
})
