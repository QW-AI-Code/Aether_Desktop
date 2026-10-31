// هر پیام خطای npvs.rs / import.rs باید ترجمهٔ فارسی داشته باشد.
import fs from 'fs'
const i18n = fs.readFileSync('src/i18n.js', 'utf8')
const rs = fs.readFileSync('src-tauri/src/custom/npvs.rs', 'utf8') + fs.readFileSync('src-tauri/src/custom/import.rs', 'utf8') + fs.readFileSync('src-tauri/src/custom/npvo.rs', 'utf8')
const msgs = new Set([...rs.matchAll(/\bbad\("([^"]+)"\)/g)].map((m) => m[1]))
for (const m of rs.matchAll(/invalid\("((?:binary NPVS|unsupported file type)[^"]*)"\)/g)) msgs.add(m[1])
const miss = [...msgs].filter((k) => !i18n.includes(`'${k.replace(/'/g, "\\'")}':`))
if (miss.length) { console.error('missing fa:', miss); process.exit(1) }
console.log(`PASS: ${msgs.size} NPVS/import error messages have Persian translations`)
