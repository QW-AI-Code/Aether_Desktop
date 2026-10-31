// =============================================================================
//  src/views/settings.js — منوی تنظیمات
//  پورت از ui/settings/SettingsMenuScreen.kt + SettingsRow.kt (تصویر a2)
// =============================================================================
//
//  # شکل صفحه
//
//  یک هاب با گروه‌های نام‌دار، و هر ردیف یک زیرصفحه. کنترل‌های زیرصفحه از
//  `renderAdvanced(sections)` می‌آیند و اینجا بازنویسی **نمی‌شوند** — دلیلش در
//  خودِ advanced.js نوشته شده: دو نسخه از یک کنترل یعنی روزی که یکی درست شود و
//  دیگری نه.
//
//  # ✨ کجاست
//
//  دو جا، مثل a2: روی ردیف هاب (پرسش دربارهٔ کل گروه) و روی هر تک‌گزینه در
//  زیرصفحه. دومی با خواندن برچسب و راهنمای همان `.field` ساخته می‌شود و نه با
//  یک فهرست دستی کنار فهرست کنترل‌ها: فهرست دوم بی‌صدا از قالب عقب می‌ماند و
//  گزینه‌های تازه بی‌✨ می‌مانند.

import { app, onChange, refreshTab, emit, STATE_LABEL } from '../main.js'
import { renderAdvanced } from './advanced.js'
import { aiHintButton, refreshAi } from '../ai.js'
import { t, getLang } from '../i18n.js'
import { invoke } from '@tauri-apps/api/core'
// AETHER-APP-PATCH custom-configs
import { renderCustomConfigs, customConfigsValue, refreshCustomConfigs } from './customconfigs.js'
// AETHER-APP-PATCH whats-new
import { renderAnnouncements, MEGAPHONE } from './announcements.js'
import { renderCleanIpSettings } from './cleanip.js'
import {
  homeAnimationsEnabled, setHomeAnimationsEnabled,
  connectionSoundsEnabled, setConnectionSoundsEnabled,
} from '../ui/feedback.js'

const CHEVRON =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 5l7 7-7 7"/></svg>'
const ARROW_BACK =
  '<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="M11 6l-6 6 6 6"/></svg>'

const ICON = {
  layers: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/></svg>',
  bolt: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><path d="M13 3L5 14h6l-1 7 8-11h-6z"/></svg>',
  dns: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="3.5" y="4.5" width="17" height="6" rx="2"/><rect x="3.5" y="13.5" width="17" height="6" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>',
  link: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M10 14a4 4 0 0 1 0-5.7l2-2a4 4 0 0 1 5.7 5.7l-1 1"/><path d="M14 10a4 4 0 0 1 0 5.7l-2 2A4 4 0 0 1 6.3 12l1-1"/></svg>',
  shield: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><path d="M12 3l7 3v5.5c0 4.3-2.9 7.7-7 9.5-4.1-1.8-7-5.2-7-9.5V6z"/></svg>',
  badge: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><path d="M12 3l2.4 1.7 2.9-.2.9 2.8 2.3 1.8-1.1 2.7 1.1 2.7-2.3 1.8-.9 2.8-2.9-.2L12 21l-2.4-1.7-2.9.2-.9-2.8L3.5 15l1.1-2.7L3.5 9.6l2.3-1.8.9-2.8 2.9.2z"/></svg>',
  apps: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="4" y="4" width="6.5" height="6.5" rx="1.6"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.6"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.6"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.6"/></svg>',
  globe: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.4 2.3 2.4 14.7 0 17M12 3.5c-2.4 2.3-2.4 14.7 0 17"/></svg>',
  custom: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M8 7h-2a3 3 0 0 0 0 6h2"/><path d="M16 7h2a3 3 0 0 1 0 6h-2"/><path d="M9 10h6"/><path d="M12 15v5M9.5 17.5h5"/></svg>',
  reset: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M4 12a8 8 0 1 1 2.6 5.9"/><path d="M4 5.5V12h6"/></svg>',
}

// نگاشت نامِ کوتاهِ مقدارها به همان برچسب‌هایی که در کنترل نشان داده می‌شوند.
// یک منوی تنظیمات که مقدار فعلی را با نام داخلی (`AETHER_PSIPHON`) نشان بدهد،
// کاربر را مجبور می‌کند برای خواندنِ وضعیت وارد زیرصفحه شود.
const VALUE_LABEL = {
  AETHER: 'Aether', AETHER_PSIPHON: 'Aether \u2192 Psiphon',
  TOR: 'Tor', AETHER_TOR: 'Aether \u2192 Tor',
  TOR_PSIPHON: 'Tor \u2192 Psiphon', TOR_AETHER: 'Tor \u2192 Aether',
  SMART: 'Smart', MASQUE: 'MASQUE', WIREGUARD: 'WireGuard', GOOL: 'WARP\u00d72', MIM: 'MASQUE\u00d72',
  OFF: 'Off', LIGHT: 'Light', FIREWALL: 'Firewall', BALANCED: 'Balanced',
  GFW: 'GFW', AGGRESSIVE: 'Aggressive',
  INCLUDE: 'Only these apps', EXCLUDE: 'All except these',
}

const label = (raw) => (raw ? (['AETHER', 'TOR'].includes(raw) ? VALUE_LABEL[raw] : t(VALUE_LABEL[raw] ?? raw)) : '')

/**
 * گروه‌ها و ردیف‌ها — آینهٔ `ai_topic.rs::Group` تا توضیحی که دستیار می‌دهد و
 * جایی که کاربر گزینه را می‌بیند از هم واگرا نشوند.
 *
 * `sections` نام قطعه‌هایی است که زیرصفحه از advanced.js می‌گیرد. `value` تابع
 * است، نه رشته: هاب کَش می‌شود و مقدارِ خوانده‌شده در زمان ساخت یخ می‌زد.
 */
const CLOUD = '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M7 18a4 4 0 0 1-.6-7.96A5.5 5.5 0 0 1 17 8.5a4.75 4.75 0 0 1 .5 9.5z"/></svg>'

// ۱.۴.۰-mobile: ترتیب گروه‌ها مطابق SettingsMenuScreen.kt نسخهٔ موبایل:
// Tunnel → Custom configs → Connection safety → Application
const GROUPS = [
  {
    title: 'Tunnel',
    rows: [
      {
        id: 'connection', icon: ICON.layers, sections: ['connection'],
        title: 'Connection',
        subtitle: 'Network backend, exit country, protocol and scanning',
        value: (p) => label(p.backend || 'AETHER'),
      },
      {
        id: 'transport', icon: ICON.bolt, sections: ['transport'],
        title: 'Transport & anti-DPI',
        subtitle: 'Obfuscation, endpoint, MTU and anti-DPI',
        value: (p) => label(p.noize),
      },
      {
        id: 'dns', icon: ICON.dns, sections: ['dns'],
        title: 'DNS & routing rules',
        subtitle: 'Resolvers inside the tunnel, block and bypass lists',
        value: (p) => ((p.dns || []).length ? `${(p.dns || []).length}` : ''),
      },
      {
        id: 'upstream', icon: ICON.link, sections: ['upstream'],
        title: 'Upstream proxy (chaining)',
        subtitle: 'Dial out through a proxy already running on this PC',
        value: (p) => ((p.upstream || '').trim() ? t('On') : ''),
      },
      {
        id: 'tls', icon: ICON.bolt, sections: ['tls'],
        title: 'TLS fingerprint & API',
        subtitle: 'Server names, certificate checks and TLS handshake details (core 2.4.0)',
        value: () => '',
      },
    ],
  },
  // >>> AETHER-APP-PATCH custom-configs (mobile 1.5.0 `CustomConfigsPage`)
  // زیرصفحهٔ خودش را دارد (`render`)، نه بخش‌های advanced.js: کانفیگ‌ها عضوِ
  // پروفایل نیستند و در انبارِ مهرشدهٔ جداگانه می‌مانند.
  {
    title: 'Custom configs',
    rows: [
      {
        id: 'custom', icon: ICON.custom, sections: [], render: () => renderCustomConfigs(),
        title: 'Custom configs',
        subtitle: 'Your own VLESS, VMess, Trojan, Shadowsocks, SOCKS, WireGuard or npvt server, alone or chained',
        value: () => customConfigsValue(),
      },
      // موبایل ۱.۶.۰: «Clean IP scan settings» درست بعد از Custom configs می‌آید و
      // زیرصفحهٔ مستقل خودش را دارد (تنظیمات اسکن به پروفایل تونل ربطی ندارد).
      {
        id: 'cleanip', icon: CLOUD, sections: [], render: () => renderCleanIpSettings(),
        title: 'Clean IP scan settings',
        subtitle: 'Scan profile, manual ping and the automatic scan for your own configs',
        value: () => '',
      },
    ],
  },
  // <<< AETHER-APP-PATCH custom-configs
  {
    title: 'Connection safety',
    rows: [
      {
        id: 'safety', icon: ICON.shield, sections: ['safety'],
        title: 'Kill switch & leak protection',
        subtitle: 'What happens the moment the tunnel drops',
        value: (p) => (p.killSwitch ? t('On') : t('Off')),
      },
      {
        id: 'zerotrust', icon: ICON.badge, sections: ['zerotrust'],
        title: 'Zero Trust',
        subtitle: 'Join a Cloudflare organisation instead of plain WARP',
        value: (p) => ((p.team || '').trim() ? p.team.trim() : ''),
      },
    ],
  },
  // موبایل ۱.۶.۰ `DisplayAndSoundGroup`: دو سوییچ مستقیماً در هاب (بدون زیرصفحه).
  // `rows` خالی است تا ROWS/SETTINGS_ROWS و تست‌های زیرصفحه دست نخورند.
  { title: 'Display and sound', rows: [], displaySound: true },
  {
    title: 'Application',
    rows: [
      {
        id: 'apps', icon: ICON.apps, sections: ['apps'],
        title: 'Apps & LAN sharing',
        subtitle: 'Which programs use the tunnel, and who else may',
        value: (p) => label(p.splitMode),
      },
      {
        id: 'language', icon: ICON.globe, sections: ['language'],
        title: 'Language',
        subtitle: 'Interface language',
        value: () => (getLang() === 'fa' ? 'فارسی' : 'English'),
      },
      // >>> AETHER-APP-PATCH whats-new (mobile 1.5.0 `AnnouncementsPage`)
      // زیرصفحهٔ خودش را دارد (`render`): بایگانیِ پیام‌ها عضوِ پروفایل نیست.
      {
        id: 'announcements', icon: MEGAPHONE, sections: [], render: () => renderAnnouncements(),
        controlless: true, // فقط خواندنی؛ tests/settings-smoke.mjs کنترل نمی‌خواهد
        title: 'Messages & announcements',
        subtitle: "What's new in this version and the connection guide, any time",
        value: () => '',
      },
      // <<< AETHER-APP-PATCH whats-new
    ],
  },
]


const ROWS = GROUPS.flatMap((g) => g.rows)

// ------------------------------------------------------------ نوار اطلاع

/**
 * همان نوار آبیِ بالای a2 — ولی متنش با حقیقتِ نسخهٔ دسکتاپ خوانده می‌شود.
 *
 * در موبایل نوشته «برای تغییر، قطع کنید» چون آنجا گزینه‌ها قفل می‌شوند. اینجا
 * قفل نمی‌شوند: تغییر ذخیره می‌شود و هسته آن را در استارت بعدی می‌خواند. پس
 * جملهٔ موبایل اینجا دروغ بود و متن همان کاری را می‌گوید که واقعاً می‌افتد.
 */
function noticeBar() {
  const bar = document.createElement('div')
  bar.className = 'setnotice'
  bar.innerHTML = '<span class="setnotice__icon">i</span><span class="setnotice__text"></span>'
  const text = bar.querySelector('.setnotice__text')
  const sync = () => {
    const live = app.snapshot.state !== 'DISCONNECTED'
    bar.hidden = !live
    if (live) {
      text.textContent = t('The tunnel is running. Changes are saved now and handed to the engine the next time it starts — reconnect to apply them.')
    }
  }
  onChange(sync, bar)
  sync()
  return bar
}

// ---------------------------------------------------------------- هاب

function hubRow(row, go) {
  const el = document.createElement('div')
  el.className = 'setrow'
  // شناسهٔ پایدارِ ردیف: تست‌ها نباید به «شمارهٔ ردیف» تکیه کنند؛ با افزودنِ ردیفی
  // مثل cleanip شمارهٔ ردیف‌های بعدی جابه‌جا می‌شود و تست صفحهٔ دیگری را باز می‌کند.
  if (row.id) el.dataset.row = row.id
  el.innerHTML =
    `<span class="setrow__icon">${row.icon}</span>` +
    '<span class="setrow__text"><span class="setrow__title"></span><span class="setrow__sub"></span></span>' +
    '<span class="setrow__value"></span>' +
    `<span class="setrow__chev">${CHEVRON}</span>`
  el.querySelector('.setrow__title').textContent = t(row.title)
  el.querySelector('.setrow__sub').textContent = t(row.subtitle)

  const value = el.querySelector('.setrow__value')
  const sync = () => { value.textContent = row.value(app.profile ?? {}) }
  onChange(sync, el)
  sync()

  // ✨ پیش از chevron تزریق می‌شود تا ترتیبِ a2 حفظ شود، و کلیکش داخل خودش
  // stopPropagation دارد (در ai.js) تا ردیف را باز نکند.
  el.insertBefore(
    aiHintButton({ title: t(row.title), subtitle: t(row.subtitle), value: () => row.value(app.profile ?? {}) }),
    el.querySelector('.setrow__chev'),
  )

  // ردیف یک div است و نه button: یک button نمی‌تواند button دیگری (✨) را در
  // خود جای بدهد و مرورگر ساختار را بی‌صدا خراب می‌کند. نقشِ دسترسی‌پذیری
  // دستی داده می‌شود تا صفحه‌خوان و کلید Enter مثل دکمه کار کنند.
  el.tabIndex = 0
  el.setAttribute('role', 'button')
  el.addEventListener('click', () => go(row))
  el.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      go(row)
    }
  })
  return el
}

/** ردیف هابِ دارای سوییچ (نمایش و صدا). مقدار از feedback.js خوانده و همان‌جا ذخیره می‌شود. */
function switchRow(title, subtitle, read, write) {
  const el = document.createElement('div')
  el.className = 'setrow setrow--switch'
  el.innerHTML =
    '<span class="setrow__text"><span class="setrow__title"></span><span class="setrow__sub"></span></span>' +
    '<button type="button" class="switch" role="switch"><span class="switch__knob"></span></button>'
  el.querySelector('.setrow__title').textContent = t(title)
  el.querySelector('.setrow__sub').textContent = t(subtitle)
  const sw = el.querySelector('.switch')
  const paint = () => {
    const on = read()
    sw.classList.toggle('is-on', on)
    sw.setAttribute('aria-checked', String(on))
  }
  paint()
  sw.setAttribute('aria-label', t(title))
  const flip = () => { write(!read()); paint() }
  sw.addEventListener('click', (e) => { e.stopPropagation(); flip() })
  el.addEventListener('click', flip)
  el.insertBefore(
    aiHintButton({ title: t(title), subtitle: t(subtitle), value: () => (read() ? t('On') : t('Off')) }),
    sw,
  )
  return el
}

function resetRow() {
  const el = document.createElement('div')
  el.className = 'setrow setrow--danger'
  el.tabIndex = 0
  el.setAttribute('role', 'button')
  el.innerHTML =
    `<span class="setrow__icon">${ICON.reset}</span>` +
    '<span class="setrow__text"><span class="setrow__title"></span><span class="setrow__sub"></span></span>'
  el.querySelector('.setrow__title').textContent = t('Reset all settings to defaults')
  el.querySelector('.setrow__sub').textContent = t('Every setting goes back to its default, including endpoint ranges, routing rules and enrolment details.')
  el.appendChild(aiHintButton({
    title: t('Reset all settings to defaults'),
    subtitle: t('Every setting goes back to its default, including endpoint ranges, routing rules and enrolment details.'),
  }))
  const run = async () => {
    // بازنشانی برگشت‌ناپذیر است و در a2 هم دیالوگ تأیید دارد.
    if (!window.confirm(t('Reset every setting to its default?'))) return
    app.profile = await invoke('reset_profile')
    refreshAi() // ai-gate-follows-tunnel: بک‌اند پیش‌فرض ممکن است دروازه را عوض کند
    refreshTab(app.tab === 'tunnel' ? 'tunnel' : 'advanced')
  }
  el.addEventListener('click', run)
  el.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); run() }
  })
  return el
}

// ------------------------------------------------------------ زیرصفحه

/**
 * ✨ را به هر گزینهٔ یک زیرصفحه می‌چسباند.
 *
 * عنوان از `.field__label` و توضیح از **اولین** `.field__hint` خوانده می‌شود؛
 * فیلدهایی که فقط راهنمای متنی‌اند (بدون برچسب و کنترل) رد می‌شوند، چون آن‌ها
 * خودشان توضیح‌اند و ✨ روی یک پاراگراف توضیح، چیزی برای پرسیدن ندارد.
 */
function decorateFields(root) {
  for (const field of root.querySelectorAll('.field')) {
    // The built-in verification card has the mobile info/title/switch header.
    if (field.classList.contains('field--verify')) continue
    const labelEl = field.querySelector('.field__label')
    if (!labelEl) continue
    if (field.querySelector('.aihint')) continue
    const hint = field.querySelector('.field__hint')
    // `.fdrop` (انتخابگر کشور با پرچم) هم شمرده می‌شود؛ جا افتادنش یعنی ✨ کنار
    // «کشور خروج» مقدار فعلی را به دستیار نمی‌داد و پاسخ کورکورانه می‌شد.
    const control = field.querySelector('.seg, .select, .switch, .input, .fdrop')
    const head = document.createElement('div')
    head.className = 'field__head'
    // برچسب داخل یک ردیف با ✨ می‌رود تا آیکن هم‌تراز عنوان بنشیند و نه کنارِ
    // کنترل — همان چیدمانی که در a2 است.
    labelEl.replaceWith(head)
    head.appendChild(labelEl)
    head.appendChild(aiHintButton({
      title: labelEl.textContent.trim(),
      subtitle: hint ? hint.textContent.trim() : '',
      value: () => readControl(control),
    }))
  }
}

/** مقدار *فعلی* یک کنترل، از خودِ DOM — همان چیزی که کاربر می‌بیند. */
function readControl(control) {
  if (!control) return ''
  if (control.classList.contains('seg')) {
    return control.querySelector('.seg__item.is-active')?.textContent.trim() ?? ''
  }
  if (control.classList.contains('select')) {
    return control.options?.[control.selectedIndex]?.textContent.trim() ?? control.value ?? ''
  }
  if (control.classList.contains('fdrop')) {
    return control.querySelector('.fdrop__btn .fdrop__name')?.textContent.trim() ?? ''
  }
  if (control.classList.contains('switch')) {
    return control.classList.contains('is-on') ? t('On') : t('Off')
  }
  return control.value ?? ''
}

function subPage(row, back) {
  const page = document.createElement('div')
  page.className = 'view view--settings'

  const bar = document.createElement('div')
  bar.className = 'setpage__head'
  const backBtn = document.createElement('button')
  backBtn.type = 'button'
  backBtn.className = 'setpage__back'
  backBtn.innerHTML = ARROW_BACK
  backBtn.setAttribute('aria-label', t('Back'))
  backBtn.addEventListener('click', back)
  const title = document.createElement('h2')
  title.className = 'setpage__title'
  title.textContent = t(row.title)
  bar.append(backBtn, title)
  page.appendChild(bar)
  page.appendChild(noticeBar())

  const panel = row.render ? row.render() : renderAdvanced(row.sections)
  decorateFields(panel)
  page.appendChild(panel)
  return page
}

// -------------------------------------------------------------- صفحه

// کدامیک زیرصفحه باز بود.
//
// این متغیر بیرون از تابع زندگی می‌کند چون **باید** از بازساختِ تب جان سالم
// ببرد: چند گزینه (نام تیم، روش ورود، حالت endpoint، split) بعد از ذخیره
// `refreshTab('advanced')` صدا می‌زنند تا فیلدهای وابسته‌شان عوض شوند، و بدون
// این، کاربری که وسط تایپِ نام تیم است به هاب پرت می‌شد.
const OPEN_BY = { advanced: null, tunnel: null }

// ۱.۴.۰-ui: صفحهٔ اختصاصی «تنظیمات تونل» (دکمهٔ Tune در هدر) — فقط ردیف‌های
// تونل به ترتیب نسخهٔ موبایل + کارت قرمز بازنشانی؛ هاب عمومی باز نمی‌شود.
const TUNNEL_ROW_IDS = ['connection', 'custom', 'cleanip', 'transport', 'dns', 'upstream', 'tls']

export function renderSettings() {
  return buildSettings('advanced')
}

export function renderTunnelSettings() {
  return buildSettings('tunnel')
}

function buildSettings(mode) {
  const groups = mode === 'tunnel'
    ? [{ title: 'Tunnel', rows: TUNNEL_ROW_IDS.map((id) => ROWS.find((r) => r.id === id)).filter(Boolean) }]
    : GROUPS
  const rowsHere = groups.flatMap((g) => g.rows)
  const root = document.createElement('div')
  root.className = 'view view--settings'

  // ناوبری درون‌تبی: تب کَش می‌شود، پس هاب یک بار ساخته و نگه داشته می‌شود و
  // زیرصفحه در همان میزبان جا عوض می‌کند. با `refreshTab` هم مسیر به هاب
  // برمی‌گردد، که همان رفتار دکمهٔ back سیستمی در موبایل است.
  const host = document.createElement('div')
  const hub = document.createElement('div')
  hub.className = 'sethub'

  // v14 — ریشهٔ باگ: هاب و هر زیرصفحه در همین یک تب زنده می‌مانند و با
  // `replaceChildren` جا عوض می‌کنند؛ نودی که همین الان جایش را به دیگری داد
  // از DOM جدا می‌شود و `emit()` (در main.js) هر listenerِ متعلق به یک مالکِ
  // جداشده را بی‌صدا رد می‌کند. یعنی وقتی کاربر داخل «Transport & anti-DPI»
  // چیزی را عوض می‌کرد، `saveProfile` را صدا می‌زد و آن `emit()` را هم اجرا
  // می‌کرد، ولی ردیفِ هاب دقیقاً همان لحظه از DOM جدا بود و آن emit را از دست
  // می‌داد؛ برگشتن به هاب فقط همان نودِ قدیمی (با مقدارِ قبل از تغییر) را
  // دوباره وصل می‌کرد، بدون هیچ resync‌ای — پس ردیف «Off» می‌ماند در حالی که
  // `app.profile.noize` واقعاً «Light» بود (تصویرهای a1/a2). فراخوانیِ `emit()`
  // همین‌جا، بعد از هر تعویض، تضمین می‌کند نودی که تازه دوباره متصل شد فوراً
  // با آخرین پروفایل هم‌گام شود — نه فقط با رخدادِ بعدیِ تصادفی.
  const show = (node) => { host.replaceChildren(node); emit() }
  const goHub = () => { OPEN_BY[mode] = null; show(hub) }
  const go = (row) => { OPEN_BY[mode] = row.id; show(subPage(row, goHub)) }

  // ۱.۴.۰-mobile: عنوان هاب در هدر موبایل است؛ اینجا پنهان می‌ماند (mobile.css).
  const title = document.createElement('h2')
  title.className = 'setpage__title setpage__title--hub'
  title.textContent = t('Tunnel settings')
  title.hidden = true
  hub.appendChild(title)
  hub.appendChild(noticeBar())

  for (const group of groups) {
    const head = document.createElement('h3')
    head.className = 'sethub__group'
    head.textContent = t(group.title)
    hub.appendChild(head)
    const card = document.createElement('div')
    card.className = 'sethub__card'
    for (const row of group.rows) card.appendChild(hubRow(row, go))
    if (group.displaySound) {
      card.appendChild(switchRow('Home screen animations',
        'Turn off the moving home-screen effects on weaker PCs. The live ping meter stays animated.',
        homeAnimationsEnabled, setHomeAnimationsEnabled))
      card.appendChild(switchRow('Connection sounds',
        'Play a short cue when connected or disconnected.',
        connectionSoundsEnabled, setConnectionSoundsEnabled))
    }
    hub.appendChild(card)
  }

  const danger = document.createElement('div')
  danger.className = 'sethub__card sethub__card--danger'
  danger.appendChild(resetRow())
  hub.appendChild(danger)

  // AETHER-APP-PATCH custom-configs: مقدارِ ردیفِ هاب از انبارِ کانفیگ‌ها.
  refreshCustomConfigs()

  const reopen = OPEN_BY[mode] ? rowsHere.find((r) => r.id === OPEN_BY[mode]) : null
  if (reopen) show(subPage(reopen, goHub))
  else show(hub)
  root.appendChild(host)
  return root
}

export { ROWS as SETTINGS_ROWS }
