import assert from 'node:assert/strict'
import {JSDOM} from 'jsdom'
const dom=new JSDOM('<div id="view"></div>',{url:'http://localhost/',pretendToBeVisual:true})
for(const k of ['window','document','HTMLElement','localStorage'])globalThis[k]=k==='window'?dom.window:dom.window[k]
globalThis.requestAnimationFrame=fn=>setTimeout(fn,0);globalThis.cancelAnimationFrame=clearTimeout
const calls=[];const cc={enabled:false,mode:'SOLO',modeLabel:'Config',activeId:null,modes:[],max:500,configs:[],groups:[{id:'user:manual',name:'Manual'}],subscriptions:[],tabNames:{},hiddenTabs:[]}
window.__TAURI_INTERNALS__={invoke:async(cmd,args)=>{
 calls.push([cmd,args]);if(cmd==='plugin:event|listen')return 1
 if(cmd==='get_profile')return {backend:'AETHER',protocol:'SMART'}
 if(cmd==='get_snapshot')return {state:'DISCONNECTED',uptimeSecs:0,rxBytes:0,txBytes:0}
 if(cmd==='news_state')return {version:'1.4.0',suppressed:'1.4.0'}
 if(cmd==='cc_state')return cc
 if(cmd==='cc_subscription_save'||cmd==='cc_import_text'){
  const id='config-'+cc.configs.length
  cc.configs.push({id,name:id,format:'URI',groupId:args.groupId||null,server:'example.invalid:443',chainLabel:'VLESS',locked:false,expired:false})
  if(cmd==='cc_subscription_save')cc.subscriptions.push({id:'sub:one',name:'worker.example.workers.dev',configIds:[id]})
  return {...cc,added:1,addedIds:[id]}
 }
 return null
},transformCallback:x=>x,metadata:{currentWindow:{label:'main'},currentWebview:{label:'main',windowLabel:'main'}}}
const main=await import('../src/main.js');await main.bootReady
const {renderCustomConfigs,refreshCustomConfigs,catalogTabs}=await import('../src/views/customconfigs.js')
const tick=()=>new Promise(r=>setTimeout(r,0))
document.querySelector('#view').replaceChildren(renderCustomConfigs());await refreshCustomConfigs();await tick()
const tab=id=>[...document.querySelectorAll('.cc-tab')].find(el=>el.textContent.includes(id))
const button=text=>[...document.querySelectorAll('.chat__modal button')].find(b=>b.textContent===text)
tab('Manual').querySelector('.cc-tab__pick').click()
tab('All').querySelector('.cc-tab-edit__btn').click()
assert(!button('Delete'));assert(button('Add config'));button('Cancel').click()
// Editor belongs to Manual even when All is currently selected.
tab('All').querySelector('.cc-tab__pick').click()
tab('Manual').querySelector('.cc-tab-edit__btn').click();assert(button('Delete'));button('Add config').click();button('Link or text').click()
document.querySelector('.cc-paste').value='https://worker.example.workers.dev/sub'
// A late tab change must not steal an in-flight import destination.
tab('All').querySelector('.cc-tab__pick').click();button('Import now').click();await tick();await tick()
assert.equal(calls.find(([cmd])=>cmd==='cc_subscription_save')[1].groupId,'user:manual')
assert.equal(cc.configs[0].groupId,'user:manual')
assert.deepEqual(catalogTabs(cc).map(t=>t.id),['all','user:manual'])
assert(!document.querySelector('.cc-tab__close'))
// All imports go to the standard V2Ray family, never to the source hostname.
tab('All').querySelector('.cc-tab__pick').click();document.querySelector('.cc-add').click();button('Link or text').click()
document.querySelector('.cc-paste').value='vless://fixture@example.invalid:443'
button('Import now').click();await tick();await tick()
assert.equal(calls.find(([cmd])=>cmd==='cc_import_text')[1].groupId,null)
assert.deepEqual(catalogTabs(cc).map(t=>t.id),['all','format:v2ray','user:manual'])
assert(!document.querySelector('.cc-tabs').textContent.includes('workers.dev'))
assert(!calls.some(([cmd])=>cmd==='cc_move'),'ownership is one atomic import, not a follow-up move')
console.log('PASS: All editor protection, manual editor direct import, captured async destination, subscription source isolation, standard family routing, no close buttons, atomic IPC')
dom.window.close();process.exit(0)
