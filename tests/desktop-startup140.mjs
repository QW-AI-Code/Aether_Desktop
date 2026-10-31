// Real DOM/boot regression. Pending backend is intentionally not resolved until shell is asserted.
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import {JSDOM} from 'jsdom'
const dom=new JSDOM(readFileSync('src/index.html','utf8'),{url:'http://localhost/',pretendToBeVisual:true})
for(const k of ['window','document','HTMLElement','localStorage'])globalThis[k]=k==='window'?dom.window:dom.window[k]
globalThis.requestAnimationFrame=fn=>setTimeout(fn,0);globalThis.cancelAnimationFrame=clearTimeout
localStorage.setItem('aether.lang','fa')
let ready;const gate=new Promise(resolve=>{ready=resolve});const calls=[]
window.__TAURI_INTERNALS__={invoke:async(cmd,args)=>{
 calls.push([cmd,args]);if(cmd==='startup_ready')return gate
 if(cmd==='get_profile')return {backend:'AETHER',protocol:'SMART'}
 if(cmd==='get_snapshot')return {state:'DISCONNECTED',uptimeSecs:0,rxBytes:0,txBytes:0}
 if(cmd==='preset_state')return {activeId:'default',presets:[{id:'default',name:'Default'}]}
 if(cmd==='news_state')return {version:'1.4.0',suppressed:'1.4.0'}
 if(cmd==='plugin:event|listen')return 1
 return null
},transformCallback:x=>x,metadata:{currentWindow:{label:'main'},currentWebview:{label:'main',windowLabel:'main'}}}
const main=await import('../src/main.js')
await new Promise(resolve=>setTimeout(resolve,10))
assert(document.querySelector('.boot-skeleton[role=status]'),'shell exists with backend still pending')
assert(!calls.some(([c])=>c==='get_profile'),'no state read races background initialization')
assert(!document.querySelector('#connect'),'no connection control races startup')
ready();await main.bootReady
assert(document.querySelector('#connect'),'Home hydrates after real ready contract')
await new Promise(resolve=>setTimeout(resolve,0))
assert.equal(document.querySelector('.presets__trigger').textContent,'پیش‌فرض')
assert(!document.querySelector('.boot-skeleton'))
const source=readFileSync('src-tauri/src/leakguard.rs','utf8')
assert(source.includes('const CHROMIUM_POLICY_NAME: &str = "WebRtcIPHandling";'))
assert(!source.includes('WebRtcIPHandlingPolicy'))
console.log('PASS: static first paint, blocked backend shell, readiness ordering, Home hydration, Persian Default, exact WebRTC policy')
dom.window.close();process.exit(0)
