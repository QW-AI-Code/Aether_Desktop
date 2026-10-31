// =============================================================================
//  src/ui/whatsnew.js — پنجرهٔ «تازه‌ها» (What's New / First-Launch modal)
//
//  # کِی باز می‌شود
//  نسخهٔ فعلی (`news_state.version` = نسخهٔ Cargo) با نسخهٔ «ساکت‌شده» مقایسه
//  می‌شود. نصبِ تازه (چیزی ذخیره نشده) و ارتقا (نسخهٔ دیگری ذخیره شده) هر دو
//  پنجره را خودکار باز می‌کنند. تا وقتی کاربر با تیکِ «دیگر این پیام را نمایش
//  نده» نبندد، در اجراهای بعدیِ همان نسخه هم باز می‌شود؛ تیک فقط برای **همین**
//  نسخه است و آپدیتِ بعدی پیامش را دوباره نشان می‌دهد.
//
//  # کجا ذخیره می‌شود
//  `prefs.json` سمتِ Rust (فرمان‌های `news_state` / `news_mark`) — همان دلیلِ
//  ui-lang-on-disk. `localStorage` فقط پشتیبان است، برای وقتی IPC در دسترس
//  نیست (هارنسِ jsdom یا `vite` بدون Tauri).
// =============================================================================

import { invoke } from '@tauri-apps/api/core'
import { announcementFor } from '../news/announcements.js'
import { openSupportDialog, supportSuppressed } from './support.js'

const LS_LAST = 'aether.news.lastLaunched'
const LS_SUPPRESSED = 'aether.news.suppressed'

const CLOSE_ICON =
  '<svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6L6 18"/></svg>'

const lsGet = (k) => { try { return localStorage.getItem(k) } catch { return null } }
const lsSet = (k, v) => { try { localStorage.setItem(k, v) } catch { /* ignore */ } }

/** تصمیمِ خالص (در tests/whatsnew.mjs آزموده می‌شود). */
export function shouldShowNews(version, suppressed) {
  return !!version && suppressed !== version
}

async function readState() {
  try {
    const s = await invoke('news_state')
    if (s && s.version) {
      return {
        version: s.version,
        // اگر فایل هنوز چیزی ندارد ولی localStorage دارد، تیکِ کاربر گم نشود.
        suppressed: s.suppressed ?? lsGet(LS_SUPPRESSED),
      }
    }
  } catch { /* بدون Tauri */ }
  try {
    const info = await invoke('about_info')
    if (info?.appVersion) return { version: info.appVersion, suppressed: lsGet(LS_SUPPRESSED) }
  } catch { /* بدون Tauri */ }
  return { version: null, suppressed: lsGet(LS_SUPPRESSED) }
}

function mark(version, suppress) {
  lsSet(LS_LAST, version)
  if (suppress) lsSet(LS_SUPPRESSED, version)
  invoke('news_mark', { suppress }).catch(() => {})
}

/**
 * در شروعِ برنامه یک بار صدا زده می‌شود (main.js، بعد از اولین رندر).
 * @returns {Promise<boolean>} آیا پنجره باز شد
 */
export async function maybeShowWhatsNew() {
  const { version, suppressed } = await readState()
  if (!version) return false
  if (!shouldShowNews(version, suppressed)) {
    mark(version, false)
    return false
  }
  openWhatsNew({
    announcement: announcementFor(version),
    showDontShowAgain: true,
    onClose: (dontShowAgain) => {
      mark(version, dontShowAgain)
      // یادداشت حمایت از سازندهٔ هسته، بلافاصله پس از بستن «تازه‌ها».
      if (!supportSuppressed()) openSupportDialog({ showDontShowAgain: true })
    },
  })
  return true
}

/**
 * خودِ پنجره. از آرشیوِ تنظیمات هم با `showDontShowAgain: false` باز می‌شود.
 *
 * عمداً با کلیکِ بیرونِ کارت بسته نمی‌شود (یک کلیکِ اشتباه نباید راهنمای
 * طولانی را بیندازد) — همان قاعدهٔ `modal.js`. Escape، دکمهٔ بستن و «متوجه
 * شدم» هر سه می‌بندند و وضعیتِ چک‌باکس را تحویل می‌دهند.
 */
export function openWhatsNew({ announcement, showDontShowAgain = true, onClose = () => {} }) {
  document.querySelector('.news')?.remove()

  const root = document.createElement('div')
  root.className = 'news'
  root.setAttribute('role', 'dialog')
  root.setAttribute('aria-modal', 'true')
  root.setAttribute('aria-labelledby', 'news-title')
  root.setAttribute('dir', 'rtl')
  root.setAttribute('lang', 'fa')

  root.innerHTML = `
    <div class="news__card">
      <div class="news__head">
        <div class="news__headtext">
          <div class="news__title" id="news-title">📢 تازه‌های نسخهٔ <span dir="ltr" class="news__ver"></span></div>
          <div class="news__sub">پیام‌ها و اطلاعیه‌های اتر</div>
        </div>
        <button type="button" class="news__close" aria-label="بستن" title="بستن">${CLOSE_ICON}</button>
      </div>
      <div class="news__body" tabindex="0">
        <div class="announcement-content" dir="rtl"></div>
      </div>
      <div class="news__foot">
        <label class="news__check"${showDontShowAgain ? '' : ' hidden'}>
          <input type="checkbox" class="news__checkbox" />
          <span>دیگر این پیام را نمایش نده</span>
        </label>
        <button type="button" class="news__ok">متوجه شدم</button>
      </div>
    </div>`

  root.querySelector('.news__ver').textContent = announcement.version
  root.querySelector('.announcement-content').innerHTML = announcement.html
  const checkbox = root.querySelector('.news__checkbox')

  let closed = false
  const close = () => {
    if (closed) return
    closed = true
    document.removeEventListener('keydown', onKey, true)
    root.remove()
    onClose(showDontShowAgain && checkbox.checked)
  }
  const onKey = (ev) => {
    if (ev.key === 'Escape') {
      ev.preventDefault()
      ev.stopPropagation()
      close()
    }
  }
  document.addEventListener('keydown', onKey, true)
  root.querySelector('.news__close').addEventListener('click', close)
  root.querySelector('.news__ok').addEventListener('click', close)

  document.body.append(root)
  root.querySelector('.news__ok').focus({ preventScroll: true })
  return { root, close }
}
