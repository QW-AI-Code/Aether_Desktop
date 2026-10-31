// Parse every first-party JS module, including files not imported by smoke tests.
// --check never executes application code and needs no DOM or Tauri runtime.
import { readdirSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name)
    return entry.isDirectory() ? walk(path) : /\.(?:js|mjs)$/.test(path) ? [path] : []
  })
}
const files = [...walk('src'), ...walk('tests'), ...walk('bench'), 'vite.config.js']
let failures = 0
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' })
  if (result.error || result.status !== 0) {
    console.error(`FAIL: ${file}\n${result.stderr || result.error || result.stdout}`)
    failures++
  }
}
if (failures) process.exit(1)
console.log(`JS SYNTAX OK: ${files.length} first-party modules parsed`)
