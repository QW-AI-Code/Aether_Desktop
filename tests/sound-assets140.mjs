// صدای اتصال/قطع باید بایت‌به‌بایت همان فایل‌های موبایل باشد.
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
const want = {
  'src/assets/sfx_connect.ogg': '1aee0ca5816a076993cd04bd44f5f8a6011ec060177768a547952827eeb3df0c',
  'src/assets/sfx_disconnect.ogg': '1967953f680fd8b8c390cdf11853357e5c7f1985b4a8b5e0ec65c1c2e868c8ac',
}
let bad = 0
for (const [f, h] of Object.entries(want)) {
  const got = createHash('sha256').update(readFileSync(f)).digest('hex')
  if (got !== h) { console.error('MISMATCH', f, got); bad++ }
}
const conf = readFileSync('src-tauri/tauri.conf.json', 'utf8')
if (!conf.includes('autoplay-policy=no-user-gesture-required')) { console.error('autoplay flag missing'); bad++ }
if (bad) process.exit(1)
console.log('sound-assets140: ok')
