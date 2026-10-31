// کلاس‌هایی که در JS/HTML استفاده می‌شوند ولی در هیچ CSSی تعریف نشده‌اند.
//
// دقیقاً همان اشکالی که فیلد کلید API را بی‌استایل کرده بود: `field__input` هرگز
// تعریف نشده بود و کسی متوجه نمی‌شد، چون یک input بی‌قاعده هم *چیزی* نشان می‌دهد.
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

const files = []
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p)
    else if (/\.(js|html)$/.test(name)) files.push(p)
  }
}
walk('src')

const css = ['src/styles/app.css', 'src/styles/tokens.css', 'src/styles/chat.css', 'src/styles/mobile.css', 'src/styles/parity.css']
  .map((f) => readFileSync(f, 'utf8'))
  .join('\n')
const cssClasses = new Set()
for (const m of css.matchAll(/\.(-?[_a-zA-Z][\w-]*)/g)) cssClasses.add(m[1])

// کلاس‌هایی که عمداً بی‌قاعده‌اند: قلابِ ظرف یا modifier که فقط برای انتخابگرهای
// JS و تست وجود دارند. فهرست صریح است تا مورد تازه سروصدا کند.
const ALLOWED = new Set([
  'view--advanced', 'view--diagnostics', 'view--share', 'checks--env',
  'scard-group', 'scard', 'scard--fields', 'scard__block', 'scard__caption', 'scard__footer',
  'field--pick', 'pick', 'pick__icon', 'pick__text', 'pick__value', 'pick__value-text', 'pick__chev',
  'sheet', 'sheet__scrim', 'sheet__panel', 'sheet__handle', 'sheet__title', 'is-open',
  'field--tiles', 'seg--grid', 'seg--sheet', 'seg--odd', 'seg__flag', 'seg__text', 'seg__check',
  'pnote', 'pnote__icon', 'pnote__text',
  'model-item', 'model-tier', 'model-description',
  'sethub', 'twin--min', 'drawer-open',
  // Semantic button roles; all visual rules come from mobile-header__btn.
  'mobile-header__menu', 'mobile-header__back', 'mobile-header__action',
])

const used = new Map()
for (const f of files) {
  const src = readFileSync(f, 'utf8')
  const add = (raw, line) => {
    for (const cls of raw.split(/\s+/).filter(Boolean)) {
      if (/[${}(]/.test(cls)) continue
      if (!used.has(cls)) used.set(cls, [])
      used.get(cls).push(`${f}:${line}`)
    }
  }
  src.split('\n').forEach((line, i) => {
    for (const m of line.matchAll(/class(?:Name)?\s*=\s*['"`]([^'"`${}]+)['"`]/g)) add(m[1], i + 1)
    for (const m of line.matchAll(/class="([^"${}]+)"/g)) add(m[1], i + 1)
    for (const m of line.matchAll(/classList\.(?:add|toggle)\(\s*'([^']+)'/g)) add(m[1], i + 1)
  })
}

const missing = [...used.entries()].filter(([cls]) => !cssClasses.has(cls) && !ALLOWED.has(cls))
if (!missing.length) {
  console.log('OK — هر کلاسِ استفاده‌شده یا در CSS تعریف شده یا صریحاً مجاز است.')
  process.exit(0)
}
console.log(`${missing.length} کلاس بدون قاعدهٔ CSS:`)
for (const [cls, where] of missing.sort()) {
  console.log(`  .${cls}  <-  ${[...new Set(where)].slice(0, 3).join(', ')}`)
}
process.exit(1)
