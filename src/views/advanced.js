// پورت از ui/AdvancedPanel.kt (+ SegmentedSelector.kt ، DropdownSelector.kt ، LtrInput.kt ، AppPickerDialog.kt)
// توجه: گزینهٔ Proxy Mode عمداً حذف شده — در ویندوز کاربردی ندارد.
// v8:
//   * پروتکل «Auto» به «Smart» تغییر نام داد — دقیقاً هم‌نام نسخهٔ موبایل.
//   * انتخاب زبان برنامه (English/فارسی) + دکمهٔ «بازنشانی به تنظیمات پیش‌فرض».
import { invoke } from '@tauri-apps/api/core'
import { app, saveProfile, rerender, refreshTab, onChange } from '../main.js'
import { t, getLang, setLang, LANGS } from '../i18n.js'
import { flagHtml } from '../flags.js'
import { toast } from '../ui/toast.js'
import { openModal, modalButton, modalNote, confirmModal } from '../ui/modal.js'

// v11 (هستهٔ 1.7.0):
//   * پروکسی بالادست (--upstream) — زنجیره‌کردن اِتِر پشت یک VPN/پروکسی دیگر.
//   * تطبیق قواعد دامنه‌ای از روی نام واقعی میزبان (SNI/Host) پشت Wintun.
//   * ثبت دوبارهٔ خودکار هویتی که Cloudflare دیگر قبولش ندارد.
// v12 (۱.۲.۳) — بک‌اند ترابرد، پورت مستقیم از model/TransportBackend.kt.
// «Aether → Psiphon» خروجی را با یک IP هاستینگ عادی عوض می‌کند و هاپ اول را
// روی ترابرد مبهم‌سازی‌شدهٔ اِتِر نگه می‌دارد. حالت تک‌هاپیِ Psiphon عمداً وجود
// ندارد: نمی‌توانست هاپ اول خودش را رد کند.
// v13 (۱.۲.۵ / هستهٔ 2.0.0) — چهار حالت تور، عیناً `TransportBackend.entries`
// موبایل و به همان ترتیب. هر کدام کاری می‌کند که بقیه نمی‌کنند، پس هیچ‌یک
// «همان قبلی با یک گزینهٔ بیشتر» نیست؛ توضیحِ هر کدام در BACKEND_HELP است.
const BACKENDS = [
  ['AETHER', 'Aether'],
  ['AETHER_PSIPHON', 'Aether \u2192 Psiphon'],
  ['TOR', 'Tor'],
  ['AETHER_TOR', 'Aether \u2192 Tor'],
  ['TOR_PSIPHON', 'Tor \u2192 Psiphon'],
  ['TOR_AETHER', 'Tor \u2192 Aether'],
]

// توضیحِ زیرِ انتخابگر، برای هر بک‌اند جدا — پورت از `backendHelp` موبایل.
// تا ۱.۲.۴ اینجا یک جملهٔ ثابت بود که فقط دربارهٔ Psiphon حرف می‌زد؛ با شش
// بک‌اند، آن یک جمله برای چهارتایشان حرفِ نادرست می‌شد.
const BACKEND_HELP = {
  // این دو از `backend_help_aether` و `backend_help_chained` موبایل می‌آیند.
  // تا ۱.۲.۴ یک جملهٔ واحد برای هر دو بود؛ حالا که توضیح به بک‌اند وابسته است،
  // آن جمله وقتی «Aether» انتخاب بود هم دربارهٔ سایفون حرف می‌زد.
  AETHER: 'One hop through the bundled Aether/WARP engine. Fastest.',
  AETHER_PSIPHON: 'Two hops: Aether connects first, then Psiphon tunnels through it. Your exit IP becomes Psiphon\u2019s, so sites that block Aether/WARP addresses open again.',
  TOR: 'Tor alone, without the Aether tunnel. Your exit is a Tor exit node and your traffic passes three relays, which is the slowest and the most private of the modes. Tor has to reach the Tor network by itself here, so it uses bridges when it is blocked.',
  AETHER_TOR: 'Two hops: Aether connects first, then Tor is built INSIDE that tunnel. The network you are on sees only Aether\u2019s obfuscated transport, never Tor \u2014 so this is the mode to use where Tor is blocked. Your exit is a Tor exit node.',
  TOR_PSIPHON: 'Three hops: Tor first, then Psiphon dialled through it. Your exit IP is Psiphon\u2019s, reached from a Tor address, so sites that block Tor exit nodes open again while your own address stays behind Tor. The slowest mode.',
  TOR_AETHER: 'The reverse chain: Tor first, then the Aether tunnel built INSIDE it. Your exit is a WARP address \u2014 the same as plain Aether \u2014 but the network you are on sees only Tor, and cannot tell that a VPN tunnel exists at all. Use it where Cloudflare/WARP itself is blocked or throttled but Tor still gets through. Carries normal UDP, unlike the Tor-exit modes.',
}

// حالت‌هایی که تور در آن‌ها هست — آینهٔ `uses_tor` و `tor_mode` در profile.rs.
const TOR_BACKENDS = ['TOR', 'AETHER_TOR', 'TOR_PSIPHON', 'TOR_AETHER']
const usesTor = (b) => TOR_BACKENDS.includes(b || 'AETHER')
// در زنجیرهٔ عادی، تور از داخلِ تونل زنگ می‌زند: شبکهٔ محلی هرگز آن را
// نمی‌بیند، پس پل و کشورِ پل بی‌معنی‌اند.
const torChained = (b) => b === 'AETHER_TOR'
const torReverse = (b) => b === 'TOR_AETHER'

const TOR_BRIDGES = [
  ['AUTO', 'Automatic'],
  ['ALWAYS', 'Always'],
  ['OFF', 'Off'],
]

// همان فهرست transport/TorCountries.kt — کشورهایی که bridgedb برایشان پل دارد.
const TOR_COUNTRIES = [
  ['', 'Detect automatically'], ['ir', 'Iran'], ['ru', 'Russia'], ['cn', 'China'],
  ['tm', 'Turkmenistan'], ['by', 'Belarus'], ['eg', 'Egypt'], ['sa', 'Saudi Arabia'],
  ['ae', 'United Arab Emirates'], ['tr', 'T\u00fcrkiye'],
]

// صبر برای مسیر مستقیم، پیش از رفتن به پل‌ها. صفر = همان ۷۵ ثانیهٔ خود موتور.
const TOR_DIRECT_PRESETS = [0, 20, 45, 120, 240]

// همان کدهای transport/ExitRegions.kt و src-tauri/src/exit_regions.rs.
// ⚠ Psiphon این را فیلتر سخت می‌داند؛ اگر کشور سرور نداشته باشد سمت Rust
// خودکار به خروجی automatic برمی‌گردد.
const EXIT_REGIONS = [
  ['', 'Automatic'], ['AE', 'United Arab Emirates'], ['AR', 'Argentina'], ['AT', 'Austria'],
  ['AU', 'Australia'], ['BE', 'Belgium'], ['BG', 'Bulgaria'], ['BR', 'Brazil'],
  ['CA', 'Canada'], ['CH', 'Switzerland'], ['CL', 'Chile'], ['CO', 'Colombia'],
  ['CY', 'Cyprus'], ['CZ', 'Czechia'], ['DE', 'Germany'], ['DK', 'Denmark'],
  ['EE', 'Estonia'], ['ES', 'Spain'], ['FI', 'Finland'], ['FR', 'France'],
  ['GB', 'United Kingdom'], ['GR', 'Greece'], ['HK', 'Hong Kong'], ['HR', 'Croatia'],
  ['HU', 'Hungary'], ['IE', 'Ireland'], ['IL', 'Israel'], ['IN', 'India'],
  ['IS', 'Iceland'], ['IT', 'Italy'], ['JP', 'Japan'], ['KR', 'South Korea'],
  ['LT', 'Lithuania'], ['LU', 'Luxembourg'], ['LV', 'Latvia'], ['MD', 'Moldova'],
  ['MX', 'Mexico'], ['MY', 'Malaysia'], ['NL', 'Netherlands'], ['NO', 'Norway'],
  ['NZ', 'New Zealand'], ['PH', 'Philippines'], ['PL', 'Poland'], ['PT', 'Portugal'],
  ['RO', 'Romania'], ['RS', 'Serbia'], ['SE', 'Sweden'], ['SG', 'Singapore'],
  ['SK', 'Slovakia'], ['TH', 'Thailand'], ['TR', 'Turkey'], ['TW', 'Taiwan'],
  ['UA', 'Ukraine'], ['US', 'United States'], ['VN', 'Vietnam'], ['ZA', 'South Africa'],
]

const PROTOCOLS = [
  ['SMART', 'Smart'],
  ['MASQUE', 'MASQUE'],
  ['WIREGUARD', 'WireGuard'],
  ['GOOL', 'WARP×2'],
  ['MIM', 'MASQUE×2'],
]
const GOOL_MODES = [
  ['MODERN', 'Modern (MASQUE)'],
  ['CLASSIC', 'Classic (WireGuard)'],
]
const SCAN_MODES = [
  ['TURBO', 'Turbo'],
  ['BALANCED', 'Balanced'],
  ['THOROUGH', 'Thorough'],
  ['STEALTH', 'Stealth'],
  ['IRONCLAD', 'Ironclad'],
]
const IP_VERSIONS = [['V4', 'IPv4'], ['V6', 'IPv6'], ['BOTH', 'Both']]
const NOIZE = [
  ['OFF', 'Off'], ['LIGHT', 'Light'], ['FIREWALL', 'Firewall'],
  ['BALANCED', 'Balanced'], ['GFW', 'GFW'], ['AGGRESSIVE', 'Aggressive'],
]
const ENDPOINT_MODES = [
  ['AUTO', 'Automatic'],
  ['MANUAL_PEER', 'Manual peer'],
  ['MANUAL_RANGE', 'Manual range'],
]
const SPLIT_MODES = [['OFF', 'Off'], ['INCLUDE', 'Only these apps'], ['EXCLUDE', 'All except these']]
const MTU_PRESETS = [1280, 1380, 1420, 1500]
// ۱.۴.۰ (MTU دستی): مقداری که کاربر تایپ کرده و جزو پیش‌تنظیم‌ها نیست هم باید
// در فهرست بماند؛ وگرنه <select> هیچ گزینه‌ای را انتخاب‌شده نشان نمی‌داد و
// نخستین `change` بی‌صدا یک پیش‌تنظیم را جای مقدار کاربر می‌نشاند.
function mtuOptions(current) {
  const values = [...MTU_PRESETS]
  const n = Number(current)
  if (Number.isFinite(n) && n > 0 && !values.includes(n)) values.push(n)
  return values.sort((a, b) => a - b).map((v) => [String(v), String(v)])
}
const KEEPALIVE_PRESETS = [0, 10, 25, 45]
const RECONNECT_ATTEMPTS = Array.from({ length: 18 }, (_, i) => i + 3)

// v10 — هستهٔ 1.5.0: روش‌های ورود Zero Trust (همان گزینه‌های موبایل/هسته).
const ACCESS_MODES = [
  ['OFF', 'Off'],
  ['EMAIL', 'Email code'],
  ['SERVICE_TOKEN', 'Service token'],
  ['TOKEN', 'Access token'],
]

// v11 — آینهٔ دقیق parse_upstream در profile.rs (و upstream.rs هسته).
// فقط برای بازخورد زنده به کاربر است؛ تصمیم نهایی همیشه سمت Rust گرفته می‌شود.
export function parseUpstream(raw) {
  const value = (raw || '').trim()
  if (!value) return null
  const at = value.indexOf('://')
  const scheme = at === -1 ? 'socks5' : value.slice(0, at).toLowerCase()
  const rest = at === -1 ? value : value.slice(at + 3)
  let kind
  if (['socks5', 'socks5h', 'socks'].includes(scheme)) kind = 'socks5'
  else if (['http', 'https'].includes(scheme)) kind = 'http'
  else return null

  const cut = rest.lastIndexOf('@')
  let endpoint = cut === -1 ? rest : rest.slice(cut + 1)
  endpoint = endpoint.replace(/\/+$/, '')

  let host
  let port
  if (endpoint.startsWith('[')) {
    const end = endpoint.indexOf(']')
    if (end === -1 || endpoint[end + 1] !== ':') return null
    host = endpoint.slice(1, end)
    port = endpoint.slice(end + 2)
  } else {
    const colon = endpoint.lastIndexOf(':')
    if (colon === -1) return null
    host = endpoint.slice(0, colon)
    port = endpoint.slice(colon + 1)
  }
  if (!host || !/^[0-9]{1,5}$/.test(port)) return null
  const number = Number(port)
  if (number < 1 || number > 65535) return null
  return { kind, host, port: number }
}

function segmented(label, key, options, current) {
  return `
    <section class="field">
      <span class="field__label">${label}</span>
      <div class="seg" role="radiogroup" data-key="${key}">
        ${options.map(([v, tx]) => `
          <button type="button" role="radio" class="seg__item ${current === v ? 'is-active' : ''}"
                  data-value="${v}" aria-checked="${current === v}">${t(tx)}</button>`).join('')}
      </div>
    </section>`
}

function dropdown(label, key, options, current) {
  return `
    <section class="field field--row">
      <span class="field__label">${label}</span>
      <select class="select" data-key="${key}">
        ${options.map(([v, tx]) => `<option value="${v}" ${current === v ? 'selected' : ''}>${t(tx)}</option>`).join('')}
      </select>
    </section>`
}

// v1.2.3 — انتخابگر کشور خروج با پرچم.
//
// ریشهٔ مشکل: این فیلد یک `<select>` بومی بود و `<option>` بومی هیچ‌وقت
// نمی‌تواند SVG (یا هر المان دیگری) داخلش داشته باشد، پس فهرست کشورها فقط
// اسم بود — درست همان چیزی که کاربر دید — در حالی که نسخهٔ موبایل کنار هر
// کشور پرچمش را دارد. اموجی پرچم هم راه‌حل نیست: ویندوز فونت
// regional-indicator ندارد و «DE» را دو حرف خام رندر می‌کند (همان چیزی که
// `flags.js` برای نشان IP حلش کرده بود).
//
// پس یک listbox واقعی جای `<select>` را می‌گیرد: هر ردیف = پرچم SVG درون‌خطی
// + نام کشور، ردیف «Automatic» یک کرهٔ زمین می‌گیرد تا تنها ردیف بی‌نشان
// نباشد (عیناً قاعدهٔ ExitRegions.kt). ناوبری کیبورد کامل است، وگرنه یک
// select بومی را با یک div بی‌دسترسی عوض کرده بودیم.
function flagRow(cc, label) {
  return `<span class="fdrop__flag">${flagHtml(cc)}</span><span class="fdrop__name">${label}</span>`
}

const CARET =
  '<svg class="fdrop__caret" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 10l5 5 5-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'

function flagDropdown(label, key, options, current) {
  const index = Math.max(0, options.findIndex(([v]) => v === current))
  const [value] = options[index]
  return `
    <section class="field field--row">
      <span class="field__label">${label}</span>
      <div class="fdrop" data-key="${key}" data-value="${value}">
        <button type="button" class="fdrop__btn" aria-haspopup="listbox" aria-expanded="false"
                aria-label="${label}">
          ${flagRow(value, t(options[index][1]))}${CARET}
        </button>
        <ul class="fdrop__menu" role="listbox" tabindex="-1" aria-label="${label}" hidden>
          ${options.map(([v, tx]) => `
            <li class="fdrop__item ${v === value ? 'is-selected' : ''}" role="option"
                data-value="${v}" aria-selected="${v === value}">${flagRow(v, t(tx))}</li>`).join('')}
        </ul>
      </div>
    </section>`
}

// سیم‌کشی انتخابگر: باز/بسته، کیبورد، تایپ‌اِهد، و کلیک بیرون.
// شنوندهٔ سطح-سند فقط تا وقتی منو باز است زنده می‌ماند، پس بازرندرهای پیاپی
// این نما هیچ شنوندهٔ سرگردانی جا نمی‌گذارند.
function wireFlagDropdowns(root, onPick) {
  root.querySelectorAll('.fdrop').forEach((drop) => {
    const btn = drop.querySelector('.fdrop__btn')
    const menu = drop.querySelector('.fdrop__menu')
    const items = Array.from(menu.querySelectorAll('.fdrop__item'))
    let typed = ''
    let typedAt = 0

    const activeIndex = () => {
      const at = items.findIndex((i) => i.classList.contains('is-active'))
      return at === -1 ? items.findIndex((i) => i.classList.contains('is-selected')) : at
    }
    const setActive = (at) => {
      const next = Math.max(0, Math.min(items.length - 1, at))
      items.forEach((i, n) => i.classList.toggle('is-active', n === next))
      items[next].scrollIntoView({ block: 'nearest' })
    }
    const onOutside = (e) => {
      if (!drop.contains(e.target)) close()
    }
    const open = () => {
      if (!menu.hidden) return
      menu.hidden = false
      drop.classList.add('is-open')
      btn.setAttribute('aria-expanded', 'true')
      // اگر پایین جا نیست، منو بالای دکمه باز می‌شود: در انتهای صفحهٔ
      // «پیشرفته» فهرست ۵۶ ردیفی وگرنه از پایینِ ناحیهٔ اسکرول می‌زد بیرون.
      const box = drop.getBoundingClientRect()
      const room = window.innerHeight - box.bottom
      menu.classList.toggle('is-above', room < Math.min(264, menu.scrollHeight + 12) && box.top > room)
      setActive(activeIndex() === -1 ? 0 : activeIndex())
      menu.focus()
      document.addEventListener('pointerdown', onOutside, true)
    }
    function close() {
      if (menu.hidden) return
      menu.hidden = true
      drop.classList.remove('is-open')
      btn.setAttribute('aria-expanded', 'false')
      document.removeEventListener('pointerdown', onOutside, true)
    }
    const pick = async (item) => {
      const value = item.dataset.value
      items.forEach((i) => {
        const on = i === item
        i.classList.toggle('is-selected', on)
        i.setAttribute('aria-selected', String(on))
      })
      drop.dataset.value = value
      btn.innerHTML = `${flagRow(value, item.querySelector('.fdrop__name').textContent)}${CARET}`
      close()
      btn.focus()
      await onPick(drop.dataset.key, value)
    }

    btn.addEventListener('click', () => (menu.hidden ? open() : close()))
    btn.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        open()
      }
    })
    items.forEach((item) => {
      item.addEventListener('click', () => pick(item))
      item.addEventListener('mousemove', () => setActive(items.indexOf(item)))
    })
    menu.addEventListener('keydown', (e) => {
      switch (e.key) {
        case 'ArrowDown': e.preventDefault(); setActive(activeIndex() + 1); break
        case 'ArrowUp': e.preventDefault(); setActive(activeIndex() - 1); break
        case 'Home': e.preventDefault(); setActive(0); break
        case 'End': e.preventDefault(); setActive(items.length - 1); break
        case 'PageDown': e.preventDefault(); setActive(activeIndex() + 8); break
        case 'PageUp': e.preventDefault(); setActive(activeIndex() - 8); break
        case 'Enter':
        case ' ': {
          e.preventDefault()
          const at = activeIndex()
          if (at >= 0) pick(items[at])
          break
        }
        case 'Escape': e.preventDefault(); close(); btn.focus(); break
        case 'Tab': close(); break
        default:
          // تایپ‌اِهد: با ۵۶ کشور، پیمایش با فلش تنها آزاردهنده است.
          if (e.key.length === 1 && /\S/.test(e.key)) {
            const now = Date.now()
            typed = now - typedAt > 900 ? e.key : typed + e.key
            typedAt = now
            const needle = typed.toLowerCase()
            const hit = items.findIndex((i) =>
              i.querySelector('.fdrop__name').textContent.toLowerCase().startsWith(needle))
            if (hit !== -1) setActive(hit)
          }
      }
    })
  })
}

function toggle(label, key, hint, on) {
  return `
    <section class="field field--row">
      <div>
        <span class="field__label">${label}</span>
        ${hint ? `<span class="field__hint">${hint}</span>` : ''}
      </div>
      <button type="button" class="switch ${on ? 'is-on' : ''}" data-key="${key}" role="switch" aria-checked="${on}">
        <span class="switch__knob"></span>
      </button>
    </section>`
}

// security-audit-1.3.0 (S-07): profile values (some written by the AI advisor) are escaped.
function escHtml(v) {
  return String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')
}

function textField(label, key, value, placeholder, opts = {}) {
  const type = opts.secret ? 'password' : 'text'
  const hint = opts.hint ? `<span class=\"field__hint\">${opts.hint}</span>` : ''
  return `
    <section class="field">
      <span class="field__label">${label}</span>
      <input class="input ltr" dir="ltr" type="${type}" data-key="${key}" value="${escHtml(value)}" placeholder="${placeholder}" ${opts.secret ? 'autocomplete="off"' : ''}>
      ${hint}
    </section>`
}

// v10: تری‌ایریای چندخطی برای فهرست‌ها (routing/dns) — هر خط یک قاعده.
function listArea(label, key, values, placeholder, hint) {
  return `
    <section class="field">
      <span class="field__label">${label}</span>
      <textarea class="input input--area ltr" dir="ltr" data-key="${key}"
        placeholder="${placeholder}">${escHtml((values || []).join('\n'))}</textarea>
      ${hint ? `<span class=\"field__hint\">${hint}</span>` : ''}
    </section>`
}

// =============================================================================
//  >>> AETHER-APP-PATCH connection-page-a1-a2 (1.3.0)
//  صفحهٔ «اتصال» مطابق a1/a2 موبایل (`ConnectionPage` در SettingsScreen.kt):
//    * گروه «بک‌اند شبکه»: یک کارت با دو ردیفِ انتخاب (بک‌اند، کشور خروجی) که
//      هر کدام یک برگهٔ پایینی (a1) باز می‌کنند — به‌جای نوار قطعه‌ای شش‌تایی.
//    * گروه «هسته»: پروتکل به شکل شبکهٔ کاشی دوستونه با تیک (a2) + یادداشتِ i،
//      حالت اسکن به شکل ردیف انتخاب، نسخهٔ IP به شکل کاشی.
//  کنترل‌ها همان `.seg[data-key] .seg__item` قبلی‌اند، پس ذخیره، ✨، گیتِ هسته
//  و تست‌ها همان سیم‌کشیِ موجود را می‌گیرند؛ فقط چیدمان عوض شده است.
// =============================================================================
const PICK_ICON = {
  layers: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/></svg>',
  globe: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.4 2.3 2.4 14.7 0 17M12 3.5c-2.4 2.3-2.4 14.7 0 17"/></svg>',
  speed: '<svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M4.5 17a8.5 8.5 0 1 1 15 0"/><path d="M12 13l4-4"/><circle cx="12" cy="13" r="1.2" fill="currentColor"/></svg>',
}
const PICK_CHEV =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 5l7 7-7 7"/></svg>'
const PICK_CHECK =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>'
const NOTE_ICON =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><circle cx="12" cy="12" r="9" fill="currentColor"/><path d="M12 11v5.5M12 7.6v.1" stroke="#0B111D" stroke-width="2.2" stroke-linecap="round"/></svg>'

/** برچسبِ گروه بالای کارت (آبی و کوچک) — `GroupCaption` موبایل. */
const groupCaption = (text) => `<h3 class="sethub__group scard__caption">${text}</h3>`
/** متنِ زیرِ کارت — `GroupFooter` موبایل. */
const groupFooter = (text) => `<p class="scard__footer">${text}</p>`

/** ردیفِ انتخاب + برگهٔ پایینی (a1). `flags` کنار هر گزینه پرچم می‌نشاند. */
function pickRow(key, title, icon, options, current, opts = {}) {
  const index = Math.max(0, options.findIndex(([v]) => v === current))
  const [value, text] = options[index]
  const flag = (v) => (opts.flags ? `<span class="seg__flag">${flagHtml(v)}</span>` : '')
  const off = !!opts.disabled
  return `
    <section class="field field--pick ${off ? 'is-disabled' : ''}" data-pick="${key}">
      <div class="pick" role="button" tabindex="${off ? -1 : 0}" aria-haspopup="dialog"
           aria-disabled="${off}" data-open="${key}">
        <span class="pick__icon">${icon}</span>
        <span class="pick__text">
          <span class="field__label">${title}</span>
          
        </span>
        <span class="pick__value">${flag(value)}<span class="pick__value-text">${key === 'backend' ? escHtml(text) : t(text)}</span></span>
        <span class="pick__chev">${PICK_CHEV}</span>
      </div>
      ${opts.summary ? `<p class="field__hint pick__summary">${opts.summary}</p>` : ''}
      <div class="sheet" hidden>
        <div class="sheet__scrim"></div>
        <div class="sheet__panel" role="dialog" aria-modal="true" aria-label="${title}">
          <span class="sheet__handle" aria-hidden="true"></span>
          <h3 class="sheet__title">${title}</h3>
          ${options.length >= 10 ? `<input type="search" class="sheet__search" dir="auto" autocomplete="off" spellcheck="false" placeholder="${t('Search country')}" aria-label="${t('Search country')}">` : ''}
          <div class="seg seg--sheet" role="radiogroup" data-key="${key}">
            ${options.map(([v, tx]) => `
              <button type="button" role="radio" class="seg__item ${v === value ? 'is-active' : ''}"
                      data-value="${v}" data-en="${escHtml(String(tx))}" aria-checked="${v === value}" ${off ? 'disabled' : ''}>
                ${flag(v)}<span class="seg__text" ${key === 'backend' ? 'dir="ltr"' : ''}>${key === 'backend' ? escHtml(tx) : t(tx)}</span><span class="seg__check">${PICK_CHECK}</span>
              </button>`).join('')}
          </div>
        </div>
      </div>
    </section>`
}

/** یادداشتِ i زیر یک کنترل — `SettingsNoticeRow` موبایل. */
const noteRow = (text, extra = '') =>
  `<div class="pnote" ${extra}><span class="pnote__icon">${NOTE_ICON}</span><span class="pnote__text">${text}</span></div>`

/** کاشی‌های دوستونه با تیک (a2). گزینهٔ آخرِ تک، تمام‌عرض می‌شود. */
function tileGrid(label, key, options, current, opts = {}) {
  const off = !!opts.disabled
  return `
    <section class="field field--tiles ${off ? 'is-disabled' : ''}">
      <span class="field__label">${label}</span>
      <div class="seg seg--grid ${options.length % 2 ? 'seg--odd' : ''} ${opts.cards ? 'seg--cards' : ''}" role="radiogroup" data-key="${key}">
        ${options.map(([v, tx]) => `
          <button type="button" role="radio" class="seg__item ${current === v ? 'is-active' : ''}"
                  data-value="${v}" aria-checked="${current === v}" ${off ? 'disabled' : ''}>
            <span class="seg__text">${t(tx)}</span><span class="seg__check">${PICK_CHECK}</span>
          </button>`).join('')}
      </div>
      ${typeof opts.notes === 'object' && opts.notes !== null ? noteRow(opts.notes[current] || '') : (opts.notes ?? '')}
    </section>`
}

// باز/بستنِ برگه‌ها، و هم‌گام‌کردنِ ردیف با انتخاب. ذخیره را همان شنوندهٔ عمومیِ
// `.seg__item` انجام می‌دهد؛ اینجا فقط چیدمان.
function wirePicks(root) {
  root.querySelectorAll('.field--pick').forEach((field) => {
    const row = field.querySelector('.pick')
    const sheet = field.querySelector('.sheet')
    const items = Array.from(sheet.querySelectorAll('.seg__item'))
    const onKey = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); close(); row.focus() }
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault()
        const at = items.indexOf(document.activeElement)
        const vis = items.filter((i) => !i.hidden)
        if (!vis.length) return
        const at2 = vis.indexOf(document.activeElement)
        vis[at2 === -1 ? 0 : (at2 + (e.key === 'ArrowDown' ? 1 : -1) + vis.length) % vis.length].focus()
      }
    }
    const open = () => {
      if (field.classList.contains('is-disabled') || !sheet.hidden) return
      sheet.hidden = false
      if (search) { search.value = ''; items.forEach((i) => { i.hidden = false }) }
      requestAnimationFrame(() => sheet.classList.add('is-open'))
      document.addEventListener('keydown', onKey, true)
      if (search) { search.focus(); return }
      ;(items.find((i) => i.classList.contains('is-active')) ?? items[0])?.focus()
    }
    function close() {
      if (sheet.hidden) return
      sheet.classList.remove('is-open')
      sheet.hidden = true
      document.removeEventListener('keydown', onKey, true)
    }
    row.addEventListener('click', open)
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open() }
    })
    // جستجو در گزینه‌ها (کشور): هم نام نمایشی/ترجمه‌شده، هم کد و هم متن اصلی.
    const search = sheet.querySelector('.sheet__search')
    if (search) {
      search.addEventListener('input', () => {
        const q = search.value.trim().toLowerCase()
        for (const it of items) {
          const hay = `${it.dataset.value} ${it.dataset.en || ''} ${it.textContent}`.toLowerCase()
          it.hidden = !!q && !hay.includes(q)
        }
      })
      search.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowDown') { e.preventDefault(); items.find((i) => !i.hidden)?.focus() }
      })
    }
    sheet.querySelector('.sheet__scrim').addEventListener('click', close)
    items.forEach((item) => item.addEventListener('click', () => {
      if (item.disabled) return
      const value = row.querySelector('.pick__value')
      const flag = item.querySelector('.seg__flag')
      value.innerHTML = `${flag ? flag.outerHTML : ''}<span class="pick__value-text"></span>`
      value.querySelector('.pick__value-text').textContent = item.querySelector('.seg__text').textContent
      items.forEach((x) => {
        x.classList.toggle('is-active', x === item)
        x.setAttribute('aria-checked', String(x === item))
      })
      close()
      row.focus()
    }))
  })
  // یادداشتِ «هوشمند» فقط وقتی پروتکل Smart است.
  const smartNote = root.querySelector('#smart-note')
  if (smartNote) {
    root.querySelectorAll('.seg[data-key="protocol"] .seg__item').forEach((b) => {
      b.addEventListener('click', () => { smartNote.hidden = b.dataset.value !== 'SMART' })
    })
  }
}
// <<< AETHER-APP-PATCH connection-page-a1-a2

// Cached promise for `core_caps` — see the call site at the bottom of this file.
let CAPS_ONCE = null

// =============================================================================
//  بخش‌های تنظیمات
// =============================================================================
//
//  چرا این پنل به قطعه‌های نام‌دار شکسته شد: منوی تنظیماتِ موبایل (a2) هر گروه
//  را در صفحهٔ خودش نشان می‌دهد، و راه ساده‌اش این بود که آن صفحه‌ها کنترل‌های
//  خودشان را از نو بسازند. آن راه یعنی دو نسخه از هر کنترل و دو سیم‌کشیِ ذخیره،
//  و روزی که یکی از دو نسخه ثابت شود و دیگری نه. پس همان یک قالب و همان یک
//  سیم‌کشی می‌ماند و `renderAdvanced` می‌تواند زیرمجموعه‌ای از آن را بدهد.
const SECTIONS = {
  language: (p) => segmented(t('Language'), '__lang', LANGS, getLang()),

  // connection-page-a1-a2: چیدمانِ a2 — دو گروهِ کارت‌دار، ردیف‌های برگه‌ای و کاشی‌ها.
  connection: (p) => {
    const backend = p.backend || 'AETHER'
    const external = ['AETHER_PSIPHON', 'TOR_PSIPHON'].includes(backend)
    const torExit = usesTor(backend) && !torReverse(backend)
    const exitSummary = torExit
      ? t('Tor chooses its own exit node, and a new one per circuit. No setting can pin it to a country.')
      : external
        ? t('Psiphon treats this as a hard region filter. If it cannot establish there, the app retries automatically with an automatic exit.')
        : t('Aether/WARP chooses its own anycast exit.')
    // بدون تونل WARP (دو حالتِ تنها-تور) پروتکل، اسکن و نسخهٔ IP بی‌معنی‌اند.
    const noWarp = backend === 'TOR' || backend === 'TOR_PSIPHON'
    const protoNotes = [
      torReverse(backend) ? noteRow(t('Fixed to MASQUE over HTTP/2 in this mode. Tor carries TCP only and WARP\u2019s WireGuard endpoints answer on UDP alone, so the engine refuses WireGuard and WARP\u00d72 here.')) : '',
      noWarp ? noteRow(t('There is no WARP tunnel in this mode: Tor carries the traffic by itself, so the protocol, scan mode and IP version are not used.')) : '',
      noteRow(t('Smart tries the protocols one at a time, starting with the one most likely to work on this network, and keeps the first one that passes the self-test.'),
        `id="smart-note" ${p.protocol === 'SMART' && !noWarp && !torReverse(backend) ? '' : 'hidden'}`),
    ].join('')
    return `
    <section class="field" id="tor-caps-note" hidden>
      <span class="field__hint" id="tor-caps-note-text"></span>
    </section>
    <div class="scard-group">
      ${groupCaption(t('Network backend'))}
      <div class="sethub__card scard">
        ${pickRow('backend', t('Network backend'), PICK_ICON.layers, BACKENDS, backend)}
        ${pickRow('exitRegion', t('Exit country'), PICK_ICON.globe, EXIT_REGIONS, p.exitRegion || '',
          { flags: true, summary: exitSummary, disabled: !external })}
      </div>
      ${groupFooter(t(BACKEND_HELP[backend] ?? BACKEND_HELP.AETHER))}
    </div>
    ${usesTor(backend) ? `
    <div class="scard-group">
      ${groupCaption(t('Tor'))}
      <div class="sethub__card scard scard--fields">${SECTIONS.tor(p)}</div>
      ${groupFooter(t('Tor carries TCP only \u2014 in every app, on every platform. Aether answers DNS over TCP inside Tor and drops other UDP, so QUIC-capable apps fall back to TCP. That is normal and nothing is leaking: dropped UDP goes nowhere, least of all around Tor. Expect noticeably higher latency, and expect the first connect to take a while \u2014 Tor downloads its directory before it can build a circuit.'))}
    </div>` : ''}
    <div class="scard-group">
      <div class="sethub__card scard scard--fields">
        <section class="field field--verify">
          <div class="verify__row">
            <span class="pick__icon" aria-hidden="true">${NOTE_ICON}</span>
            <span class="field__label">${t('Verify connection')}</span>
            <button type="button" class="switch ${p.verifyConnection !== false ? 'is-on' : ''}" data-key="verifyConnection" role="switch" aria-checked="${p.verifyConnection !== false}"><span class="switch__knob"></span></button>
          </div>
          <span class="field__hint">${t('Default on for all six built-in modes. Turning off skips optional initial connection checks, not engine startup, Tor bootstrap, exit-IP lookup or ongoing health monitoring.')}</span>
        </section>
      </div>
    </div>
    <div class="scard-group">
      ${groupCaption(t('Core'))}
      <div class="sethub__card scard">
        <div class="scard__block">
          ${tileGrid(t('Protocol'), 'protocol', PROTOCOLS, p.protocol, { disabled: noWarp || torReverse(backend), notes: protoNotes })}
        </div>
        ${!noWarp && !torReverse(backend) ? `
        <div class="scard__block">
          ${tileGrid(t('Gool mode'), 'goolMode', GOOL_MODES, p.goolMode || 'MODERN', {
            cards: true,
            notes: {
              MODERN: t('Modern: WireGuard inside MASQUE, the core 2.4.0 default.'),
              CLASSIC: t('Classic: the older WireGuard-inside-WireGuard mode.')
            }
          })}
        </div>` : ''}
        ${pickRow('scanMode', t('Scan mode'), PICK_ICON.speed, SCAN_MODES, p.scanMode, { disabled: noWarp })}
        <div class="scard__block">
          ${tileGrid(t('IP version'), 'ipVersion', IP_VERSIONS, p.ipVersion, { disabled: noWarp })}
        </div>
      </div>
    </div>`
  },

  // v13 — گروه تور، پورت از بخش Tor در SettingsScreen.kt. فقط وقتی رندر
  // می‌شود که حالتِ انتخابی واقعاً تور داشته باشد: گروهی که همیشه آنجاست و
  // همیشه غیرفعال، تنها پنل را شلوغ می‌کند.
  tor: (p) => `
    <div id="v20-tor">
    ${dropdown(t('Bridges'), 'torBridges', TOR_BRIDGES, p.torBridges || 'AUTO')}
    <section class="field">
      <span class="field__hint">${torChained(p.backend)
        ? t('Not needed in this mode: Tor is dialled through the Aether tunnel, so the network you are on never sees it.')
        : t('How Tor reaches the network when it is blocked.')}</span>
    </section>
    ${torChained(p.backend) ? '' : `
    ${dropdown(t('Bridge country'), 'torCountry', TOR_COUNTRIES, (p.torCountry || '').trim().toLowerCase())}
    <section class="field">
      <span class="field__hint">${t('Which country bridgedb hands out bridges for. Detection asks the network where you are, which is the request most likely to fail here.')}</span>
    </section>
    ${dropdown(t('Bootstrap patience'), 'torDirectSecs',
      TOR_DIRECT_PRESETS.map((v) => [String(v), v === 0 ? t('Automatic (75 s)') : t('{0} seconds').replace('{0}', String(v))]),
      String(p.torDirectSecs ?? 0))}
    <section class="field">
      <span class="field__hint">${t('How long Tor tries the direct path before falling back to bridges. Shorten it where Tor is definitely blocked.')}</span>
    </section>
    ${listArea(t('Own bridge lines'), 'torBridgeLines', (p.torBridgeLines || '').split('\n').filter(Boolean),
      'obfs4 192.0.2.55:38114 &lt;FINGERPRINT&gt; cert=… iat-mode=0',
      t('One per line, in the format bridges.torproject.org hands out. Leave empty to use the bridges the app fetches for your country. A line naming a transport the app does not ship is ignored.'))}`}
    ${textField(t('Reachability check'), 'torCheck', p.torCheck, 'check.torproject.org:443', {
      hint: t('The address Tor must reach before the bootstrap counts as working. Change it only if bootstrap keeps failing on a Tor that seems fine \u2014 the default target is itself blocked on some networks.'),
    })}
    <section class="field">
      <span class="field__hint">${t('Tor carries TCP only \u2014 in every app, on every platform. Aether answers DNS over TCP inside Tor and drops other UDP, so QUIC-capable apps fall back to TCP. That is normal and nothing is leaking: dropped UDP goes nowhere, least of all around Tor. Expect noticeably higher latency, and expect the first connect to take a while \u2014 Tor downloads its directory before it can build a circuit.')}</span>
    </section>
    </div>`,

  transport: (p) => `
    ${dropdown(t('Noize'), 'noize', NOIZE, p.noize)}
    ${dropdown(t('Endpoint'), 'endpointMode', ENDPOINT_MODES, p.endpointMode)}
    <div id="endpoint-extra">
      ${p.endpointMode === 'MANUAL_PEER' ? textField(t('Peer address'), 'manualPeer', p.manualPeer, '1.2.3.4:443') : ''}
      ${p.endpointMode === 'MANUAL_RANGE' ? textField(t('Address range'), 'manualRange', p.manualRange, '162.159.192.0/24') : ''}
    </div>
    ${dropdown('MTU', 'mtu', mtuOptions(p.mtu), String(p.mtu))}
    ${textField(t('Custom MTU'), 'mtu', String(p.mtu), '1280-9000', { hint: t('Safe range: 1280 to 9000 bytes. Lower it if connections stall.') })}
    ${dropdown(t('Keepalive'), 'keepalive', KEEPALIVE_PRESETS.map((v) => [String(v), v === 0 ? t('Off') : `${v}s`]), String(p.keepalive))}
    ${toggle(t('Quick reconnect'), 'quickReconnect', t('Reconnect instantly after a drop'), p.quickReconnect)}
    ${toggle(t('Only reuse a fast endpoint'), 'fastEndpointOnly', t('Quick reconnect skips the scan for the last endpoint that worked. With this on it is also checked for speed, and a slow one is replaced by a fresh scan instead of halving your download and upload for the whole session.'), p.fastEndpointOnly)}
    ${toggle(t('MASQUE over HTTP/2'), 'masqueHttp2', t('Helps on networks that block HTTP/3'), p.masqueHttp2)}
    ${toggle(t('Packet fragmentation'), 'fragment', t('Splits the handshake to evade filtering'), p.fragment)}
    ${toggle(t('Encrypted Client Hello'), 'ech', t('Hide the destination name (SNI) from DPI'), p.ech)}
    ${p.ech ? textField(t('ECHConfigList (base64, optional)'), 'echConfig', p.echConfig || '', 'base64...', { hint: t('Leave empty to let the engine fetch one. Paste a base64 ECHConfigList to use it instead — useful where fetching the default one is what your network blocks. Naming a different domain, as v2rayNG does, needs an engine change and is not possible here.') }) : ''}`,

  safety: (p) => `
    ${toggle(t('Kill switch'), 'killSwitch', t('Block browser traffic if the tunnel drops'), p.killSwitch)}
    ${toggle(t('IPv6 leak protection'), 'ipv6Protection', t('Keep the IPv6 default route protected or block it safely'), p.ipv6Protection)}
    ${dropdown(t('Automatic reconnect attempts'), 'reconnectAttempts', RECONNECT_ATTEMPTS.map((v) => [String(v), `${v}`]), String(p.reconnectAttempts ?? 3))}`,

  apps: (p) => `
    ${toggle(t('Share over LAN'), 'lanShare', t('Let other devices on your network use this tunnel'), p.lanShare)}
    ${dropdown(t('Split tunneling'), 'splitMode', SPLIT_MODES, p.splitMode)}
    <section class="field" id="split-apps" ${p.splitMode === 'OFF' ? 'hidden' : ''}>
      <span class="field__label">${t('Applications')}</span>
      <textarea class="input input--area ltr" dir="ltr" data-key="splitApps"
        placeholder="chrome.exe&#10;telegram.exe">${escHtml((p.splitApps || []).join('\n'))}</textarea>
      <span class="field__hint">${t('One executable name per line.')}</span>
    </section>`,

  zerotrust: (p) => `
    <section class="field" id="caps-note" hidden>
      <span class="field__hint" id="caps-note-text"></span>
    </section>
    <div id="v15-zt">
    ${textField(t('Team name'), 'team', p.team, t('your-team'), { hint: t('Connect as a managed device of a Cloudflare Zero Trust organization. Leave empty for normal WARP.') })}
    <div id="zt-extra" ${(p.team || '').trim() ? '' : 'hidden'}>
      ${segmented(t('Sign-in method'), 'accessMode', ACCESS_MODES, p.accessMode)}
      <div id="zt-fields">
        ${p.accessMode === 'EMAIL' ? textField(t('Access email'), 'accessEmail', p.accessEmail, 'user@example.com', { hint: t('A one-time code is sent to this mailbox on connect.') }) : ''}
        ${p.accessMode === 'SERVICE_TOKEN' ? textField('Access ID', 'accessId', p.accessId, 'xxxxxxxx.access', {}) : ''}
        ${p.accessMode === 'SERVICE_TOKEN' ? textField('Access Secret', 'accessSecret', '', '••••••', { secret: true, hint: t('Stored in memory only — never written to disk.') }) : ''}
        ${p.accessMode === 'TOKEN' ? textField('Access Token (JWT)', 'accessToken', '', '••••••', { secret: true, hint: t('Stored in memory only — never written to disk.') }) : ''}
        ${p.accessMode === 'TOKEN' ? '<span class="field__hint zt__tokencheck" id="zt-token-check"></span>' : ''}
      </div>
      ${toggle(t('Gateway proxy'), 'gateway', t('Route HTTP/HTTPS through your organization\'s Gateway (adds a hop and logs browsing)'), p.gateway)}
    </div>
    <section class="field zt__member">
      <span class="field__label">${t('Membership')}</span>
      <div id="zt-member"></div>
    </section>
    </div>
    <div id="v17-identity">
    <h3 class="view__subtitle">${t('Account identity')}</h3>
    ${toggle(t('Replace a refused identity'), 'reprovision', t('If Cloudflare stops accepting the saved device, register a fresh one instead of handshaking a tunnel that carries no traffic'), p.reprovision !== false)}
    </div>`,

  dns: (p) => `
    <div id="v15-dns">
    <h3 class="view__subtitle">DNS</h3>
    ${listArea(t('In-tunnel DNS servers'), 'dns', p.dns, '1.1.1.1&#10;9.9.9.9', t('Resolvers used inside the tunnel. Empty = engine defaults.'))}
    </div>
    <div id="v14-smart">
    <h3 class="view__subtitle">${t('Smart lists')}</h3>
    ${toggle(t('Bypass Iranian sites'), 'bypassIran', t('Iranian sites (.ir and Iranian IP ranges) open directly on this Windows PC only; shared devices stay in the tunnel.'), !!p.bypassIran)}
    <section class="field" ${p.bypassIran ? '' : 'hidden'} id="smart-iran-note">
      <span class="field__hint" id="smart-iran-count"></span>
    </section>
    ${toggle(t('Block ads and trackers'), 'blockAds', t('Blocks ad and tracker domains (HaGeZi Light list, refreshed weekly through the tunnel).'), !!p.blockAds)}
    <section class="field" ${p.blockAds ? '' : 'hidden'} id="smart-ads-note">
      <span class="field__hint" id="smart-ads-count"></span>
    </section>
    </div>
    <div id="v15-routing">
    <h3 class="view__subtitle">${t('Routing rules')}</h3>
    ${listArea(t('Blocked destinations'), 'routeBlock', p.routeBlock, 'ads.example.com&#10;203.0.113.0/24', t('One rule per line — domain, IP or CIDR. These connections are refused.'))}
    ${listArea(t('Direct destinations'), 'routeDirect', p.routeDirect, 'bank-domain.ir&#10;192.168.0.0/16', t('One rule per line. These bypass the tunnel — for banking apps, LAN services and domestic sites.'))}
    <div id="v17-sniff">
    ${toggle(t('Match domain rules by real host name'), 'routeSniff', t('Reads the name from the first bytes (TLS SNI or HTTP Host), so domain rules keep working even though Windows hands the tunnel an IP address'), p.routeSniff !== false)}
    </div>
    </div>`,

  upstream: (p) => `
    <div id="v17-upstream">
    ${textField(t('Proxy address'), 'upstream', p.upstream, 'socks5://127.0.0.1:1080', { hint: t('Aether dials out through this proxy — use it to chain behind another VPN or proxy already running on this PC. Empty = direct.') })}
    <section class="field">
      <span class="field__hint" id="upstream-note"></span>
    </section>
    </div>`,


  // ۱.۴.۰ / هستهٔ 2.4.0 — اثرانگشت TLS و مسیر API. همه‌ی مقادیر خالی = پیش‌فرض
  // هسته (چیزی فرستاده نمی‌شود)؛ سمت Rust مقادیر را پاک‌سازی می‌کند.
  tls: (p) => `
    <div id="v24-tls">
    <h3 class="view__subtitle">${t('Server names (SNI)')}</h3>
    ${textField(t('MASQUE server name'), 'masqueSni', p.masqueSni, 'www.cloudflare.com', { hint: t('The name the MASQUE handshakes put in their ClientHello. Empty = core default.') })}
    ${textField(t('API address'), 'apiAddress', p.apiAddress, '203.0.113.5:443', { hint: t('Send the calls to the WARP API to this IP or name instead of the default. Empty = default.') })}
    ${textField(t('API server name (SNI)'), 'apiSni', p.apiSni, 'example.com', { hint: t('The server name the ClientHello of those API calls sends.') })}
    ${textField(t('API host'), 'apiHost', p.apiHost, 'api.cloudflareclient.com', { hint: t('The HTTP host of those API calls.') })}
    <h3 class="view__subtitle">${t('Certificate checks')}</h3>
    ${toggle(t('Verify the MASQUE gateway certificate'), 'tlsVerify', t('Hold the gateway certificate to the pins the core carries. Always on with Zero Trust.'), !!p.tlsVerify)}
    ${textField(t('Trust anchor IDs'), 'tlsTrustAnchors', p.tlsTrustAnchors, '11129.9.1:11129.9.4', { hint: t('Dotted IDs separated by a colon. Empty = none.') })}
    ${segmented(t('Certificate compression'), 'tlsCertCompression', [['', 'Off'], ['brotli', 'brotli'], ['zlib', 'zlib'], ['zstd', 'zstd']], ['', 'brotli', 'zlib', 'zstd'].includes(p.tlsCertCompression) ? p.tlsCertCompression : '')}
    <h3 class="view__subtitle">${t('TLS fingerprint')}</h3>
    ${textField(t('TLS 1.2 cipher suites'), 'tlsCiphers', p.tlsCiphers, 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256', { hint: t('Names separated by a colon. Empty = Chrome default.') })}
    ${textField(t('TLS 1.3 cipher suites'), 'tls13Ciphers', p.tls13Ciphers, 'TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256', { hint: t('Standard names separated by a colon, in order. Empty = Chrome default.') })}
    ${textField(t('TLS groups'), 'tlsGroups', p.tlsGroups, 'P-256:X25519:P-384', { hint: t('Groups in order. Empty = core default.') })}
    ${textField(t('Key shares'), 'tlsKeyShares', p.tlsKeyShares, 'X25519MLKEM768:X25519', { hint: t('Groups that get a key share; each must be one of the TLS groups. Empty = Chrome default.') })}
    ${textField(t('Signature algorithms'), 'tlsSigalgs', p.tlsSigalgs, 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256', { hint: t('BoringSSL names separated by a colon. Empty = core default.') })}
    ${segmented(t('ALPS'), 'tlsAlps', [['', 'Off'], ['new', 'New'], ['old', 'Old']], ['new', 'old'].includes(p.tlsAlps) ? p.tlsAlps : '')}
    ${textField(t('Server padding (bytes)'), 'tlsServerPadding', p.tlsServerPadding, '6000', { hint: t('Bytes of padding asked of the server, 0 to 65535. Empty = none.') })}
    ${toggle(t('Disable GREASE'), 'disableGrease', t('Leave out the GREASE values Chrome sends.'), !!p.disableGrease)}
    ${toggle(t('GREASE signature algorithm'), 'enableGreaseSigalgs', t('Put a GREASE value first among the signature algorithms, as Chrome does.'), !!p.enableGreaseSigalgs)}
    ${toggle(t('ECH GREASE'), 'enableEchGrease', t('Send a GREASE ECH extension when no ECH key is offered.'), !!p.enableEchGrease)}
    ${toggle(t('Disable OCSP stapling'), 'disableOcspStapling', t('Leave out the status_request extension.'), !!p.disableOcspStapling)}
    ${toggle(t('Disable SCT'), 'disableSct', t('Leave out the signed_certificate_timestamp extension.'), !!p.disableSct)}
    ${toggle(t('Disable session tickets'), 'disableSessionTicket', t('Leave out the session_ticket extension.'), !!p.disableSessionTicket)}
    ${toggle(t('Disable extension permutation'), 'disableExtensionPermutation', t('Keep one fixed order of the extensions instead of Chrome\'s per-handshake shuffle.'), !!p.disableExtensionPermutation)}
    <section class="field"><span class="field__hint" id="tls24-note"></span></section>
    </div>`,

}

/**
 * کنترل‌های بخش‌های نام‌بُرده را می‌سازد و سیم‌کشی می‌کند.
 *
 * @param {string[]} sections کلیدهایی از `SECTIONS`.
 *
 * نمای یک‌تکهٔ قدیمی حذف شد و این تابع فقط زیرمجموعه می‌دهد: منوی a2 تنها
 * مصرف‌کننده است و نگه‌داشتن یک صفحهٔ تختِ موازی یعنی دو مسیر به یک گزینه —
 * دو جایی که کاربر باید بگردد و دو چیدمانی که باید هم‌گام بمانند.
 */
export function renderAdvanced(sections) {
  const p = app.profile
  const root = document.createElement('div')
  root.className = 'view view--advanced'
  root.innerHTML = sections.map((key) => SECTIONS[key](p)).join('\n')

  // --- سیم‌کشی — هر تغییر فوراً ذخیره می‌شود (مثل DataStore در اندروید)
  root.querySelectorAll('.seg__item').forEach((b) => {
    b.addEventListener('click', async () => {
      const key = b.closest('.seg').dataset.key
      // زبان برنامه عضو profile نیست؛ جدا ذخیره و کل پوسته دوباره رندر می‌شود.
      if (key === '__lang') {
        setLang(b.dataset.value)
        rerender()
        return
      }
      await saveProfile({ [key]: b.dataset.value })
      b.closest('.seg').querySelectorAll('.seg__item').forEach((x) => {
        x.classList.toggle('is-active', x === b)
        x.setAttribute('aria-checked', String(x === b))
      })
      // v10: تغییر روش ورود Zero Trust فیلدهای متفاوتی می‌خواهد — بازرندر.
      // v13: عوض شدن بک‌اند هم — گروه تور می‌آید/می‌رود، توضیحِ بک‌اند و
      // متنِ کشورِ خروجی عوض می‌شود، و در زنجیرهٔ برعکس انتخابگر پروتکل
      // دلیلِ قفل‌بودنش را می‌نویسد. بدون بازرندر، پنل حرفِ حالتِ قبلی را می‌زد.
      if (key === 'accessMode' || key === 'backend' || key === 'goolMode') {
        refreshTab(app.tab === 'tunnel' ? 'tunnel' : 'advanced')
      }
    })
  })

  root.querySelectorAll('.select').forEach((s) => {
    s.addEventListener('change', async () => {
      const key = s.dataset.key
      const raw = s.value
      const value = ['mtu', 'keepalive', 'reconnectAttempts', 'torDirectSecs'].includes(key)
        ? Number(raw)
        : raw
      await saveProfile({ [key]: value })
      if (key === 'endpointMode' || key === 'splitMode') {
        refreshTab(app.tab === 'tunnel' ? 'tunnel' : 'advanced')
      }
    })
  })

  wirePicks(root)

  wireFlagDropdowns(root, async (key, value) => {
    await saveProfile({ [key]: value })
  })

  root.querySelectorAll('.switch').forEach((tg) => {
    tg.addEventListener('click', async () => {
      const on = !tg.classList.contains('is-on')
      tg.classList.toggle('is-on', on)
      tg.setAttribute('aria-checked', String(on))
      await saveProfile({ [tg.dataset.key]: on })
      // ECH فیلدِ ECHConfigList را نشان/پنهان می‌کند؛ دو کلیدِ فهرستِ هوشمند
      // زیرنویسِ شمارش و هشدارِ اشتراک را. بدون بازرندر، پنل حالتِ قبلی را می‌گفت.
      if (['ech', 'bypassIran', 'blockAds', 'lanShare'].includes(tg.dataset.key)) {
        refreshTab(app.tab === 'tunnel' ? 'tunnel' : 'advanced')
      }
    })
  })

  // v11 — پیام زندهٔ پروکسی بالادست: مقدار نامعتبر را هسته بی‌صدا دور
  // می‌ریزد، پس همین‌جا به کاربر گفته می‌شود. پروکسی HTTP هم UDP حمل
  // نمی‌کند، پس تنها MASQUE روی HTTP/2 از آن رد می‌شود.
  const upstreamNote = () => {
    const el = root.querySelector('#upstream-note')
    const input = root.querySelector('[data-key="upstream"]')
    if (!el || !input) return
    const raw = input.value.trim()
    if (!raw) {
      el.textContent = ''
      return
    }
    const parsed = parseUpstream(raw)
    if (!parsed) {
      el.textContent = t('That is not a proxy address Aether can use. Expected socks5://host:port or http://host:port — the port is required.')
      return
    }
    el.textContent =
      parsed.kind === 'http'
        ? t('An HTTP proxy cannot carry UDP, so MASQUE is switched to HTTP/2 automatically and WireGuard / WARP×2 will not pass through it. Use a SOCKS5 proxy for those.')
        : t('SOCKS5 with UDP support carries every protocol: MASQUE, WireGuard and WARP×2.')
  }
  upstreamNote()

  root.querySelectorAll('.input').forEach((i) => {
    i.addEventListener('input', () => {
      if (i.dataset.key === 'upstream') upstreamNote()
      // ۱.۵.۰: بررسیِ زندهٔ توکنِ عضویت زیرِ همان فیلد.
      if (i.dataset.key === 'accessToken') ztTokenCheck(root, i.value).catch(() => {})
    })
    i.addEventListener('change', async () => {
      const key = i.dataset.key
      // ورودیِ بی‌کلید (مثلاً کدِ ورودِ Zero Trust) هرگز در پروفایل نوشته نمی‌شود.
      if (!key) return
      // v10: فیلدهای فهرستی — هر خط یک مقدار (مثل splitApps).
      const LIST_KEYS = ['splitApps', 'routeBlock', 'routeDirect', 'dns']
      // `torBridgeLines` هم چندخطی است ولی در پروفایل یک رشتهٔ واحد می‌ماند —
      // همان‌طور که در موبایل هست، چون سَنیتایزرِ سمت Rust خط‌به‌خط پارس و
      // اعتبارسنجی می‌کند و شکستنِ آن به آرایه، آن اعتبارسنجی را دور می‌زد.
      let value = LIST_KEYS.includes(key)
        ? i.value.split('\n').map((x) => x.trim()).filter(Boolean)
        : key === 'torBridgeLines'
          ? i.value.split('\n').map((x) => x.trim()).filter(Boolean).join('\n')
          : i.value.trim()
      if (key === 'mtu') {
        const num = parseInt(value, 10)
        if (!isNaN(num)) value = Math.max(1280, Math.min(9000, num))
      }
      await saveProfile({ [key]: value })
      // v10: پاک/پر شدن نام تیم، بخش Zero Trust را نشان/پنهان می‌کند.
      if (key === 'team') {
        refreshTab(app.tab === 'tunnel' ? 'tunnel' : 'advanced')
      }
      if (key === 'accessEmail' || key === 'accessId' || key === 'accessSecret') ztRefresh(root).catch(() => {})
      // سخت‌سازی امنیتی: مقدار محرمانه بعد از ذخیره از DOM پاک می‌شود تا
      // در اسکرین‌شات/بازرسی DOM نماند (ذخیره فقط در حافظهٔ بک‌اند است).
      if (key === 'accessSecret' || key === 'accessToken') {
        i.value = ''
        i.placeholder = '•••••• (saved)'
        if (key === 'accessToken') ztTokenCheck(root, null).catch(() => {})
      }
    })
  })

  // v10: قابلیت‌سنجی هسته — اگر هستهٔ همراه قدیمی‌تر از 1.5.0 باشد (مثلاً
  // وقتی کاربر نسخهٔ هسته را در پایپ‌لاین پین کرده)، این بخش‌ها غیرفعال و
  // با توضیح نشان داده می‌شوند تا کاربر تنظیمی را پر نکند که بی‌اثر است.
  // خطای این فراخوانی هرگز صفحه را نمی‌شکند.
  // The bundled core cannot change while the app is running, so this is asked
  // for once per launch. It used to be an IPC round trip plus a disk read on
  // every single render of this panel.
  // هر دو ناهمگام‌اند و جدا از رندر اجرا می‌شوند؛ شکستِ هرکدام (IPC ناموجود،
  // پاسخِ خالی) هرگز نباید به یک rejection بی‌صاحب و شکستنِ صفحه برسد.
  smartCounts(root).catch(() => {})
  ztRefresh(root).catch(() => {})
  ztTokenCheck(root, null).catch(() => {})
  // اتصال بالا/پایین شد: دکمه‌های ورود و عضویت فعال/غیرفعال می‌شوند.
  let ztWasIdle = ztIdle()
  onChange(() => {
    const idle = ztIdle()
    if (idle === ztWasIdle) return
    ztWasIdle = idle
    ztRefresh(root).catch(() => {})
  }, root)

  CAPS_ONCE ??= invoke('core_caps')
  CAPS_ONCE
    .then((caps) => {
      const gate = (id, enabled) => {
        const el = root.querySelector(id)
        if (!el || enabled) return
        el.querySelectorAll('input, textarea, button, select').forEach((c) => {
          c.disabled = true
        })
        el.style.opacity = '0.45'
      }
      gate('#v15-zt', caps.zeroTrust)
      gate('#v15-routing', caps.routing)
      gate('#v15-dns', caps.customDns)
      // v11: قابلیت‌های هستهٔ 1.7.0 جداگانه گیت می‌شوند.
      gate('#v17-upstream', caps.upstream)
      // هستهٔ 2.4.0 — گزینه‌های TLS/API روی هستهٔ قدیمی‌تر غیرفعال و توضیح‌دار.
      gate('#v24-tls', caps.tls24)
      if (!caps.tls24) {
        const n = root.querySelector('#tls24-note')
        if (n) n.textContent = t('The TLS and API options need engine core 2.4.0 or newer. The bundled core is older, so they are disabled.')
      }
      gate('#v17-sniff', caps.routeSniff)
      gate('#v17-identity', caps.routeSniff)
      // v13 — تور از هستهٔ 2.0.0. اگر هستهٔ همراه قدیمی‌تر باشد، بک‌اندهای تور
      // انتخاب‌شدنی‌اند ولی بی‌اثر: profile.rs فلگ‌هایشان را نمی‌فرستد. پس
      // همان‌جا گفته می‌شود، نه بعد از یک اتصالِ ساکتاً معمولی.
      if (!caps.tor) {
        root.querySelectorAll('.seg[data-key="backend"] .seg__item').forEach((b) => {
          if (usesTor(b.dataset.value)) {
            b.disabled = true
            b.style.opacity = '0.45'
          }
        })
        gate('#v20-tor', false)
        const note = root.querySelector('#tor-caps-note')
        const text = root.querySelector('#tor-caps-note-text')
        if (note && text) {
          text.textContent = t('The Tor modes need engine core 2.0.0 or newer. The bundled core is older, so they are disabled.')
          note.hidden = false
        }
      }
      const missing15 = !caps.zeroTrust || !caps.routing || !caps.customDns
      const missing17 = !caps.upstream || !caps.routeSniff
      if (missing15 || missing17) {
        const note = root.querySelector('#caps-note')
        const text = root.querySelector('#caps-note-text')
        if (note && text) {
          text.textContent = missing15
            ? t('These features need engine core 1.5.0 or newer. The bundled core is older, so they are disabled.')
            : t('The upstream proxy, host-name routing and identity replacement need engine core 1.7.0 or newer. The bundled core is older, so they are disabled.')
          note.hidden = false
        }
      }
    })
    .catch(() => {})

  return root
}

// =============================================================================
//  ۱.۴.۰ — فهرست‌های هوشمند: شمارِ ردیف‌ها زیرِ دو کلید
// =============================================================================
async function smartCounts(root) {
  const iran = root.querySelector('#smart-iran-count')
  const ads = root.querySelector('#smart-ads-count')
  if (!iran && !ads) return
  let c
  try {
    c = await invoke('smart_list_counts')
  } catch {
    return
  }
  // پاسخِ خالی (هستهٔ قدیمی، یا هارنسِ تست که برای هر IPC ناشناخته null
  // برمی‌گرداند) یعنی شماری برای نشان‌دادن نیست — نه اینکه صفحه بشکند.
  if (!c || typeof c !== 'object') return
  const num = (v) => (Number.isFinite(Number(v)) ? String(Number(v)) : '0')
  const when = (secs) => (secs ? new Date(secs * 1000).toLocaleDateString(getLang() === 'fa' ? 'fa-IR' : 'en-US') : t('built-in copy'))
  if (iran) {
    iran.textContent = t('{0} Iranian IP ranges and {1} domains · updated {2}')
      .replace('{0}', num(c.iranCidrs)).replace('{1}', num(c.iranDomains)).replace('{2}', when(c.iranRefreshedAt))
  }
  if (ads) {
    ads.textContent = t('{0} ad and tracker domains · updated {1}')
      .replace('{0}', num(c.adDomains)).replace('{1}', when(c.adsRefreshedAt))
  }
}

// =============================================================================
//  ۱.۵.۰ — Zero Trust: اول ورود، بعد اتصال (پورت از ZeroTrustMembership.kt)
// =============================================================================
//
//  عضویتِ این دستگاه بدون ورود دیده می‌شود (`zt_membership`). ورود با کدِ
//  ایمیلی در یک دیالوگ انجام می‌شود و نتیجه‌اش مهرشده، وابسته به همان تیم و
//  نشانی، برای اتصالِ بعدی می‌ماند. وضعیت هرگز خودِ توکن را حمل نمی‌کند. ورود از
//  مسیرِ مستقیم انجام می‌شود، پس وقتی تونل بالا یا در حالِ بالا آمدن است
//  دکمه‌ها غیرفعال‌اند — همان «اول قطع کنید» موبایل.
const ZT_IDLE_STATES = ['DISCONNECTED', 'IDLE', 'FAILED', undefined, null, '']
const ZT_RESEND_COOLDOWN_MS = 30_000
const ZT_MAX_CODE_ATTEMPTS = 3

const ztFill = (text, ...values) => values.reduce((s, v, i) => s.replace(`{${i}}`, String(v)), text)
const ztIdle = () => ZT_IDLE_STATES.includes(app.snapshot?.state)

/** متنِ یک `ZtProblem` (یا رشتهٔ خطای خام). */
function ztProblemText(problem, host = '') {
  if (!problem || typeof problem !== 'object') return t(String(problem ?? ''))
  const h = problem.host || host
  switch (problem.kind) {
    case 'badTeam': return t('That team name is not valid. Use just the name, for example acme.')
    case 'badEmail': return t('That e-mail address is not complete.')
    case 'noEmailCode': return t('This organization does not offer sign-in with an e-mailed code. Ask its administrator, or use a service token or an enrolment token instead.')
    case 'noNonce': return t('The code was sent, but Cloudflare\u2019s answer lacked what the sign-in needs. Try again; if it keeps happening, the sign-in page has changed.')
    case 'refused': return ztFill(t('Cloudflare refused the request (HTTP {0}). Check the team name, and that this address is allowed to join.'), problem.status ?? 0)
    case 'noToken': return ztFill(t('Not accepted (HTTP {0}). Check the client ID and secret, and that the service token is allowed to enrol devices (Service Auth).'), problem.status ?? 0)
    case 'network': return ztFill(t('Could not reach {0} ({1}). Check the connection and try again. If Cloudflare is only reachable through your upstream proxy, skip signing in here: the code asked for while connecting goes through that proxy.'), h, problem.detail || '')
    case 'expiredOnArrival': return t('Cloudflare issued a token that is already expired. Check that this PC\u2019s date and time are correct, then sign in again.')
    case 'storeFailed': return t('Signed in, but this PC could not store the result securely, so nothing was saved.')
    case 'noSession': return t('Ask for a code first.')
    case 'busy': return t('Disconnect first: the running tunnel is using this membership.')
    default: return t(String(problem.detail || problem.kind || ''))
  }
}

/** «تا … دیگر معتبر است» — دقیقه / ساعت / روز. */
function ztExpiryLine(secondsLeft) {
  if (secondsLeft == null) return t('The sign-in carries no expiry date.')
  if (secondsLeft < 60) return t('The sign-in expires in under a minute.')
  if (secondsLeft < 3600) return ztFill(t('The sign-in is valid for {0} more minute(s): connect before then.'), Math.floor(secondsLeft / 60))
  if (secondsLeft < 86400) return ztFill(t('The sign-in is valid for {0} more hour(s).'), Math.floor(secondsLeft / 3600))
  return ztFill(t('The sign-in is valid for {0} more day(s).'), Math.floor(secondsLeft / 86400))
}

/** یک ردیفِ عمل: دکمه + توضیح زیرش. */
function ztActionRow(id, label, desc, { kind = '', disabled = false } = {}) {
  return `
    <div class="zt__action">
      <button type="button" class="btn btn--small ${kind}" id="${id}" ${disabled ? 'disabled' : ''}>${label}</button>
      <span class="field__hint" id="${id}-desc">${desc}</span>
    </div>`
}

function ztNotice(text, kind = '') {
  return `<p class="zt__notice ${kind}">${escHtml(text)}</p>`
}

/** بررسیِ توکنِ عضویتِ چسبانده‌شده — همان دو بررسی‌ای که موتور می‌کند. */
async function ztTokenCheck(root, raw) {
  const el = root.querySelector('#zt-token-check')
  if (!el) return
  let r = null
  try {
    r = await invoke('zt_inspect_token', { raw: raw ?? null })
  } catch {
    r = null
  }
  const verdict = r?.verdict || 'empty'
  const days = r?.secondsLeft == null ? null : Math.floor(r.secondsLeft / 86400)
  let text
  switch (verdict) {
    case 'malformed': text = t('This does not look like a token. Copy the whole value that follows token= on the enrolment page.'); break
    case 'expired': text = t('This token has expired. Sign in again and paste a fresh one.'); break
    case 'usable':
      text = r?.secondsLeft == null
        ? t('Token looks valid. It carries no expiry date.')
        : days === 0
          ? t('Token looks valid but expires in under a day.')
          : ztFill(t('Token looks valid, expires in {0} day(s).'), days)
      break
    default: text = ztFill(t('Sign in at https://{0}.cloudflareaccess.com/warp in a browser, then copy the value that follows token= and paste it here. Or pick E-mail code above to sign in inside the app instead.'), (app.profile?.team || '').trim() || 'team')
  }
  el.textContent = text
  el.classList.toggle('is-error', verdict === 'malformed' || verdict === 'expired')
}

let ztGeneration = 0

async function ztRefresh(root) {
  const box = root.querySelector('#zt-member')
  if (!box) return
  const gen = ++ztGeneration
  const p = app.profile || {}
  const team = (p.team || '').trim()
  if (!team) {
    box.innerHTML = ztNotice(t('Enter the team name above to sign in or to see whether this device is already a member.'))
    return
  }
  if (!box.innerHTML.trim()) box.innerHTML = ztNotice(t('Checking this device\u2019s membership\u2026'))

  let m = null
  try {
    m = await invoke('zt_membership')
  } catch {
    m = null
  }
  if (gen !== ztGeneration) return
  if (!m || typeof m !== 'object') m = { team, enrolled: false }
  const shownTeam = m.team || team
  const editable = typeof m.editable === 'boolean' ? m.editable : ztIdle()

  if (m.enrolled) {
    box.innerHTML =
      ztNotice(ztFill(t('This device is already a member of {0}. Connecting needs no sign-in.'), shownTeam), 'is-ok') +
      ztActionRow('zt-remove', t('Remove this device\u2019s membership'),
        editable
          ? t('Deletes the saved membership for this team only. The next connect joins again. Use it after your organization removed this device, or to join as someone else.')
          : t('Disconnect to sign in or to change the membership.'),
        { kind: 'btn--danger', disabled: !editable })
    box.querySelector('#zt-remove')?.addEventListener('click', async () => {
      const ok = await confirmModal({
        title: t('Remove the membership?'),
        body: ztFill(t('This PC\u2019s saved identity in {0} is deleted, and the next connect joins the organization again as a new device. Personal WARP and other teams are not touched. This cannot be undone.'), shownTeam),
        ok: t('Remove'),
        cancel: t('Cancel'),
        danger: true,
      })
      if (!ok) return
      // در لحظهٔ عمل سنجیده می‌شود، نه وقتی دیالوگ باز شد.
      if (!ztIdle()) {
        toast(t('Disconnect first: the running tunnel is using this membership.'))
        return
      }
      try {
        await invoke('zt_forget_membership')
        toast(t('Membership removed. The next connect joins again.'))
      } catch (e) {
        toast(ztProblemText(e))
      }
      ztRefresh(root)
    })
    return
  }

  switch (p.accessMode) {
    case 'EMAIL': {
      let st = null
      try {
        st = await invoke('zt_status')
      } catch {
        st = null
      }
      if (gen !== ztGeneration) return
      if (!st || typeof st !== 'object') st = { state: 'none' }
      const email = (p.accessEmail || '').trim()
      const emailReady = /.+@.+\..+/.test(email)
      let status
      let kind = ''
      switch (st.state) {
        case 'ready':
          status = ztFill(t('Signed in as {0}. The next connect joins this device without asking for a code.'), st.email || email) +
            '\n' + ztExpiryLine(st.secondsLeft)
          kind = 'is-ok'
          break
        case 'expired':
          status = t('Your sign-in has expired. Sign in again before connecting, or the code is asked for while connecting.')
          kind = 'is-warn'
          break
        case 'otherProfile':
          status = ztFill(t('The saved sign-in is for {0} in team {1}, not the address and team above. It will not be used: sign in again.'), st.email || '', st.team || '')
          kind = 'is-warn'
          break
        default:
          status = t('Not signed in yet. Sign in now and the connect will not stop to ask for a code. If you skip this, the code is asked for while connecting.')
      }
      const hasRecord = !!st.hasRecord || ['ready', 'expired', 'otherProfile'].includes(st.state)
      let html = ztNotice(status, kind)
      html += ztActionRow('zt-signin-btn', hasRecord ? t('Sign in again') : t('Sign in'),
        !editable
          ? t('Disconnect to sign in or to change the membership.')
          : !emailReady
            ? t('Enter your work e-mail above first.')
            : t('Your organization e-mails a one-time code to the address above, you type it here, and the result is kept encrypted on this PC for the next connect.'),
        { kind: 'btn--primary', disabled: !editable || !emailReady })
      if (hasRecord) {
        html += ztActionRow('zt-signout', t('Forget this sign-in'),
          t('Deletes the saved sign-in from this PC. A membership this device already has is not affected.'),
          { kind: 'btn--ghost', disabled: !editable })
      }
      box.innerHTML = html
      box.querySelector('#zt-signin-btn')?.addEventListener('click', () => {
        ztSignInDialog(root, p.team, shownTeam, email, m.host)
      })
      box.querySelector('#zt-signout')?.addEventListener('click', async () => {
        try {
          await invoke('zt_forget')
          toast(t('Sign-in forgotten.'))
        } catch (e) {
          toast(ztProblemText(e))
        }
        ztRefresh(root)
      })
      break
    }
    case 'SERVICE_TOKEN': {
      const complete = typeof m.serviceComplete === 'boolean'
        ? m.serviceComplete
        : !!((p.accessId || '').trim())
      const idleText = !editable
        ? t('Disconnect to sign in or to change the membership.')
        : !complete
          ? t('Enter both the client ID and the client secret first.')
          : t('Asks your organization for an enrolment token exactly as the engine will when connecting. Nothing is stored.')
      box.innerHTML =
        ztNotice(t('Not a member yet. The next connect joins with the service token above, without you.')) +
        ztActionRow('zt-svc-test', t('Test the service token'), idleText, { disabled: !editable || !complete })
      const btn = box.querySelector('#zt-svc-test')
      const desc = box.querySelector('#zt-svc-test-desc')
      btn?.addEventListener('click', async () => {
        btn.disabled = true
        desc.classList.remove('is-error', 'is-ok')
        desc.textContent = t('Testing\u2026')
        try {
          await invoke('zt_test_service_token')
          desc.textContent = t('Accepted: the organization issued an enrolment token for this service token.')
          desc.classList.add('is-ok')
        } catch (e) {
          desc.textContent = ztProblemText(e)
          desc.classList.add('is-error')
        } finally {
          btn.disabled = !ztIdle()
        }
      })
      break
    }
    case 'TOKEN':
      box.innerHTML = ztNotice(t('Not a member yet. The next connect joins with the enrolment token above.'))
      break
    default:
      box.innerHTML = ''
  }
}

/** دیالوگِ ورود با کدِ ایمیلی (ZeroTrustSignInDialog موبایل). */
function ztSignInDialog(root, rawTeam, team, email, host) {
  let step = { kind: 'sending' }
  let timer = null
  let closed = false
  const modal = openModal({ title: ztFill(t('Sign in to {0}'), team), onEscape: () => cancel() })

  const finish = () => {
    if (closed) return
    closed = true
    if (timer) clearInterval(timer)
    modal.close()
    ztRefresh(root)
  }
  const cancel = () => {
    invoke('zt_cancel').catch(() => {})
    finish()
  }

  const codeInput = document.createElement('input')
  codeInput.className = 'input ltr modal__code'
  codeInput.dir = 'ltr'
  codeInput.type = 'text'
  codeInput.inputMode = 'numeric'
  codeInput.autocomplete = 'one-time-code'
  codeInput.maxLength = 12
  codeInput.placeholder = t('Login code')
  codeInput.setAttribute('aria-label', t('Login code'))

  const retryable = (problem) => !['badTeam', 'badEmail', 'noEmailCode'].includes(problem?.kind)

  const render = () => {
    if (closed) return
    modal.body.replaceChildren()
    modal.actions.replaceChildren()
    const cancelBtn = modalButton(t('Cancel'), 'btn--ghost', cancel)
    if (step.kind === 'sending') {
      modal.body.append(modalNote(ztFill(t('Asking your organization to e-mail a code to {0}\u2026'), email), 'is-busy'))
      const confirm = modalButton(t('Sign in'), 'btn--primary')
      confirm.disabled = true
      modal.actions.append(cancelBtn, confirm)
      return
    }
    if (step.kind === 'failed') {
      modal.body.append(modalNote(ztProblemText(step.problem, host), 'is-error'))
      const again = retryable(step.problem)
        ? modalButton(t('Try again'), 'btn--primary', requestCode)
        : modalButton(t('Close'), 'btn--primary', cancel)
      modal.actions.append(cancelBtn, again)
      return
    }
    // code / busy
    const code = step.kind === 'busy' ? step.from : step
    const busy = step.kind === 'busy'
    const exhausted = code.rejected >= ZT_MAX_CODE_ATTEMPTS
    modal.body.append(modalNote(ztFill(t('A one-time code was e-mailed to {0}. Type it here to sign in.'), email)))
    if (code.resent) modal.body.append(modalNote(t('A new code is on its way. Only the newest code works.')))
    const warning = code.problem
      ? ztProblemText(code.problem, host)
      : exhausted
        ? t('That code was not accepted either. Ask for a new code and try again.')
        : code.rejected > 0
          ? ztFill(t('That code was not accepted. Attempt {0} of {1}.'), code.rejected + 1, ZT_MAX_CODE_ATTEMPTS)
          : null
    if (warning) modal.body.append(modalNote(warning, 'is-error'))
    codeInput.disabled = busy || exhausted
    modal.body.append(codeInput)
    if (busy) {
      modal.body.append(modalNote(step.resending ? t('Asking for a new code\u2026') : t('Checking the code\u2026'), 'is-busy'))
    } else {
      const wait = Math.ceil((ZT_RESEND_COOLDOWN_MS - (Date.now() - code.sentAt)) / 1000)
      const resend = modalButton(
        wait > 0 ? ztFill(t('New code possible in {0} seconds'), wait) : t('Send a new code'),
        'btn--ghost modal__link',
        resendCode,
      )
      resend.disabled = wait > 0
      resend.dataset.role = 'resend'
      modal.body.append(resend)
    }
    const confirm = modalButton(t('Sign in'), 'btn--primary', submit)
    confirm.disabled = busy || exhausted || !codeInput.value.trim()
    confirm.dataset.role = 'confirm'
    modal.actions.append(cancelBtn, confirm)
    if (!busy && !exhausted) setTimeout(() => codeInput.focus(), 0)
  }

  codeInput.addEventListener('input', () => {
    const confirm = modal.actions.querySelector('[data-role="confirm"]')
    if (confirm && step.kind === 'code') {
      confirm.disabled = !codeInput.value.trim() || step.rejected >= ZT_MAX_CODE_ATTEMPTS
    }
  })
  codeInput.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') submit()
  })

  async function requestCode() {
    step = { kind: 'sending' }
    codeInput.value = ''
    render()
    try {
      await invoke('zt_request_code')
      step = { kind: 'code', rejected: 0, sentAt: Date.now(), resent: false, problem: null }
    } catch (e) {
      step = { kind: 'failed', problem: e }
    }
    render()
  }

  async function submit() {
    if (step.kind !== 'code') return
    const current = step
    const typed = codeInput.value.trim()
    if (!typed || current.rejected >= ZT_MAX_CODE_ATTEMPTS) return
    step = { kind: 'busy', from: current, resending: false }
    render()
    try {
      await invoke('zt_submit_code', { code: typed })
      toast(t('Signed in. Connect now to join the organization.'))
      finish()
      return
    } catch (e) {
      if (e?.kind === 'rejected') {
        codeInput.value = ''
        step = { ...current, rejected: current.rejected + 1, problem: null, resent: false }
      } else if (e?.kind === 'expiredOnArrival' || e?.kind === 'storeFailed') {
        step = { kind: 'failed', problem: e }
      } else {
        step = { ...current, problem: e, resent: false }
      }
    }
    render()
  }

  async function resendCode() {
    if (step.kind !== 'code') return
    const current = step
    step = { kind: 'busy', from: current, resending: true }
    render()
    try {
      await invoke('zt_resend_code')
      codeInput.value = ''
      step = { ...current, rejected: 0, sentAt: Date.now(), problem: null, resent: true }
    } catch (e) {
      step = { ...current, problem: e, resent: false }
    }
    render()
  }

  // ساعتِ مکثِ «ارسال کد تازه» — فقط برچسب همان دکمه به‌روز می‌شود.
  timer = setInterval(() => {
    if (step.kind !== 'code') return
    const btn = modal.body.querySelector('[data-role="resend"]')
    if (!btn) return
    const wait = Math.ceil((ZT_RESEND_COOLDOWN_MS - (Date.now() - step.sentAt)) / 1000)
    btn.disabled = wait > 0
    btn.textContent = wait > 0 ? ztFill(t('New code possible in {0} seconds'), wait) : t('Send a new code')
  }, 1000)

  requestCode()
}
