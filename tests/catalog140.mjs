// Boundary / grouping regressions against the real 1.4.0 UI helpers.
import assert from 'node:assert/strict'
import { JSDOM } from 'jsdom'
const dom=new JSDOM('<div id="view"></div>',{url:'http://localhost/',pretendToBeVisual:true})
for (const k of ['window','document','HTMLElement','localStorage'])globalThis[k]=k==='window'?dom.window:dom.window[k]
globalThis.requestAnimationFrame=(fn)=>setTimeout(fn,0)
globalThis.cancelAnimationFrame=clearTimeout
window.__TAURI_INTERNALS__={invoke:async(cmd)=>cmd==='plugin:event|listen'?1:null,transformCallback:(x)=>x,metadata:{currentWindow:{label:'main'},currentWebview:{label:'main',windowLabel:'main'}}}
const {pingClass,catalogRows,pingText}=await import('../src/views/customconfigs.js')
let passed=0
function test(name,fn){fn();passed++;console.log('  ok   '+name)}
for(const [ms,cls] of [[0,'is-good'],[149,'is-good'],[150,'is-slow'],[300,'is-slow'],[301,'is-bad'],[-1,'is-muted'],[NaN,'is-muted'],[Infinity,'is-muted']])test(`ping boundary ${ms}`,()=>assert.equal(pingClass({ms}),cls))
test('pending ping does not inherit previous success',()=>assert.equal(pingClass({ms:42,pending:true}),'is-wait'))
test('missing ping is neutral',()=>assert.equal(pingClass(null),'is-muted'))
const configs=[{id:'a',name:'A',format:'URI',groupId:'user:1'},{id:'b',name:'B',format:'NPVT',groupId:'user:1'},{id:'c',name:'C',format:'JSON'},{id:'d',name:'D',format:'NPVT'}]
const pings=new Map([['a',{ms:650}],['b',{ms:142}],['c',{ms:-1}],['d',{ms:300}]])
test('All sorts valid pings ascending and failures last',()=>assert.deepEqual(catalogRows(configs,'all',pings).map(c=>c.id),['b','d','a','c']))
test('Npvt family excludes manually owned NPVT configs',()=>assert.deepEqual(catalogRows(configs,'format:npvt',pings).map(c=>c.id),['d']))
test('V2Ray family excludes NPVT and manual ownership',()=>assert.deepEqual(catalogRows(configs,'format:v2ray',pings).map(c=>c.id),['c']))
test('named group membership survives family grouping',()=>assert.deepEqual(catalogRows(configs,'user:1',pings).map(c=>c.id),['b','a']))
test('sorting never mutates stored config order',()=>assert.deepEqual(configs.map(c=>c.id),['a','b','c','d']))
test('missing groups do not leak other configs',()=>assert.deepEqual(catalogRows(configs,'user:missing',pings),[]))
test('network error has meaningful fallback label',()=>assert.match(pingText({ms:-1,label:'No response'}),/-1/))
console.log(`ALL OK — ${passed} catalog regressions`)
window.close();process.exit(0)
