// pure-logic check of chainbuilder.js without its UI imports
import { readFileSync } from 'node:fs'
let src = readFileSync('src/ui/chainbuilder.js', 'utf8')
src = src.replace(/^import .*$/gm, '').replace(/export function renderChainBuilder[\s\S]*$/, '')
const mod = await import('data:text/javascript,' + encodeURIComponent(src + '\nconst t=(s)=>s;'))
const { allChains, options, complete, target, modeChain, MODES, BACKEND_CHAINS, currentChain, lengthNeedsConfig } = mod
const assert = (c, m) => { if (!c) { console.error('FAIL', m); process.exit(1) } }
assert(allChains().length === 21, 'all chains = 6 + 15 ' + allChains().length)
for (const c of allChains()) { const tg = target(c); assert(tg, 'target ' + c); if (tg.mode) assert(modeChain(tg.mode).join() === c.join(), 'mode ' + c); else assert(BACKEND_CHAINS[tg.backend].join() === c.join(), 'backend ' + c) }
assert(options([], 1, 0).sort().join() === 'AETHER,CONFIG,TOR', 'opts1')
assert(options(['CONFIG'], 2, 1).sort().join() === 'AETHER,PSIPHON,TOR', 'opts2')
assert(complete(['TOR'], 3, ['TOR', 'AETHER']).join() === 'TOR,AETHER,CONFIG', 'complete')
assert(target(['PSIPHON']) === null, 'psiphon alone')
assert(target(['CONFIG', 'PSIPHON']).backend === null && target(['CONFIG','PSIPHON']).mode === 'CONFIG_PSIPHON', 'config psiphon')
assert(currentChain('TOR_AETHER', false, 'SOLO').join() === 'TOR,AETHER', 'current')
assert(complete(['AETHER'], 2, ['AETHER']).join() === 'AETHER,PSIPHON', 'no config added (aether)')
assert(!complete(['TOR'], 2, ['TOR']).includes('CONFIG'), 'no config added (tor)')
assert(complete(['CONFIG'], 2, ['CONFIG']).join() === 'CONFIG,AETHER', 'config kept when chosen')
assert(complete(['AETHER'], 1, ['AETHER', 'TOR']).join() === 'AETHER', 'shrink')
assert(lengthNeedsConfig(3) && !lengthNeedsConfig(2) && !lengthNeedsConfig(1), 'needs config')
console.log('chainbuilder logic OK')
