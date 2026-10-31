// UI/UX a1–a7: catalog regression tests. No native IPC or network.
import assert from 'node:assert/strict'
import { JSDOM } from 'jsdom'
const dom=new JSDOM('<div id="view"></div>',{url:'http://localhost/',pretendToBeVisual:true})
for (const k of ['window','document','HTMLElement','localStorage'])globalThis[k]=k==='window'?dom.window:dom.window[k]
globalThis.requestAnimationFrame=fn=>setTimeout(fn,0)
globalThis.cancelAnimationFrame=clearTimeout
window.__TAURI_INTERNALS__={invoke:async cmd=>cmd==='plugin:event|listen'?1:null,transformCallback:x=>x,metadata:{currentWindow:{label:'main'},currentWebview:{label:'main',windowLabel:'main'}}}
const {catalogRows,catalogTabs}=await import('../src/views/customconfigs.js')
const {setLang,t}=await import('../src/i18n.js')
const state={configs:[{id:'a',name:'A',format:'URI',groupId:'user:one'},{id:'b',name:'B',format:'NPVT'}],groups:[{id:'user:one',name:'One'}],tabNames:{},hiddenTabs:[],subscriptions:[{id:'sub:one',name:'Subscription 1',configIds:['a']},{id:'sub:two',name:'Subscription 2',configIds:['b']}]}
assert.deepEqual(catalogTabs(state).map(g=>g.id),['all','format:npvt','user:one'])
assert(!catalogTabs(state).some(g=>g.id.startsWith('sub:')),'feeds are sources, not host-named tabs')
assert.deepEqual(catalogRows(state.configs,'format:v2ray').map(c=>c.id),[],'manual configs do not create parallel family rows')
assert.deepEqual(catalogRows(state.configs,'user:one').map(c=>c.id),['a'])
assert.equal(catalogRows(state.configs,'all').length,2)
state.hiddenTabs=['all'];assert.equal(catalogTabs(state)[0].id,'all','All cannot be hidden')
state.tabNames['user:one']='Renamed';assert.equal(catalogTabs(state).at(-1).name,'Renamed')
const pairs=[['Use this config','استفاده از این کانفیگ'],['Test ping','تست پینگ'],['Paste one or more links, a JSON config or a subscription address','یک یا چند لینک، کانفیگ JSON یا آدرس اشتراک را وارد کنید'],['Paste from clipboard','جای‌گذاری از کلیپ‌بورد'],['Import now','اکنون وارد کن'],['Keepalive','زنده‌نگه‌داشتن اتصال (Keepalive)'],['Encrypted Client Hello','کلاینت‌هلو رمزنگاری‌شده (ECH)'],['your-team','نام-سازمان-شما']]
setLang('fa');for(const [key,value] of pairs)assert.equal(t(key),value)
setLang('en');for(const [key] of pairs)assert.equal(t(key),key,'English language remains supported')
console.log('PASS: exclusive manual ownership, no subscription tabs, permanent All, renamed manual tab, all 8 Persian translations, English fallbacks')
window.close();process.exit(0)
