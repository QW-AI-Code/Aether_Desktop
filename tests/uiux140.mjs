// Real Chromium layout regressions, with test-only IPC fixtures (no network).
// Run after web:build. Screenshots/reports go to $QA_DIR or validation/uiux140.
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { createServer } from 'node:http'
import { readFile, mkdir, writeFile } from 'node:fs/promises'
import { join, resolve, extname } from 'node:path'
import puppeteer from 'puppeteer-core'
const dist = resolve(process.env.DIST_DIR || 'dist-web')
const out = resolve(process.env.QA_DIR || 'validation/uiux140')
await mkdir(out, {recursive:true})
const mime = {'.html':'text/html','.js':'text/javascript','.css':'text/css','.png':'image/png','.ttf':'font/ttf'}
const server = createServer(async(req,res)=>{
  try { const file=join(dist,decodeURIComponent(req.url.split('?')[0])==='/'?'index.html':decodeURIComponent(req.url.split('?')[0]));res.setHeader('Content-Type',mime[extname(file)]||'application/octet-stream');res.end(await readFile(file)) }
  catch {res.statusCode=404;res.end()}
})
await new Promise(r=>server.listen(0,'127.0.0.1',r))
let browser
const report=[]
try {
 browser=await puppeteer.launch({ignoreDefaultArgs:['--hide-scrollbars'],executablePath:[process.env.CHROME, '/usr/local/bin/chromium', '/usr/bin/chromium', '/usr/bin/google-chrome', 'C:/Program Files/Google/Chrome/Application/chrome.exe'].filter(Boolean).find(p=>existsSync(p)),args:['--no-sandbox','--disable-dev-shm-usage']})
 const baseline = process.env.BASELINE === '1'
 for(const [width,height,lang] of [[390,820,'fa'],[360,720,'fa'],[760,900,'fa'],[390,820,'en']]) {
  const context=await browser.createBrowserContext();const page=await context.newPage();await page.setViewport({width,height,deviceScaleFactor:1})
  const errors=[];page.on('pageerror',e=>errors.push(String(e)))
  await page.evaluateOnNewDocument((lang)=>{
   localStorage.setItem('aether.lang',lang)
   const profile={backend:'AETHER_PSIPHON',exitRegion:'',protocol:'SMART',scanMode:'BALANCED',ipVersion:'V4',noize:'OFF',endpointMode:'AUTO',manualPeer:'',manualRange:'',mtu:1280,keepalive:0,quickReconnect:true,masqueHttp2:false,fragment:false,ech:false,lanShare:false,killSwitch:true,ipv6Protection:true,reconnectAttempts:5,splitMode:'OFF',splitApps:[],dns:['1.1.1.1'],routeBlock:[],routeDirect:[],routeSniff:true,upstream:'',reprovision:true,team:'',accessMode:'EMAIL',verifyConnection:true}
   const configs=Array.from({length:12},(_,i)=>({id:String(i),name:i===0?'🔒 @Broz_time < کانفیگ سفارشی با نام بلند '+ 'آزمایش '.repeat(4):`${i+1} - VLESS - Domain : 2086`,server:i===0?'very-long-subdomain-'.repeat(5)+'.example.com:2086':'www.speedtest.net:2086',format:i<8?'URI':'NPVT',chainLabel:i<8?'VLESS':'Npvt',locked:i>=8,expired:false,note:'',groupId:null}))
   const cc={enabled:false,mode:'SOLO',modeLabel:'Config',activeId:'0',modes:[{id:'SOLO',label:'VLESS',hops:1}],configs,groups:[...Array.from({length:5},(_,i)=>({id:`user:${i}`,name:lang==='fa'?`گروه آزمایش ${i+1}`:`Test ${i+1}`}))],tabNames:{},hiddenTabs:JSON.parse(localStorage.getItem('qa-hidden')||'[]'),subscriptions:[{id:'sub:one',name:'subscription.example.invalid',count:4,configIds:['0','1','2','3']},{id:'sub:two',name:'Second subscription',count:2,configIds:['4','5']}]}
   window.__cc=cc
   window.__calls=[];window.__events={}
   window.__TAURI_INTERNALS__={
    invoke:async(cmd,args)=>{
     window.__calls.push([cmd,args])
     if(cmd==='plugin:event|listen'){window.__events[args.event]=args.handler;return 1}
     if(cmd==='preset_state')return {activeId:'default',presets:[{id:'default',name:'Default'},{id:'work',name:lang==='fa'?'کار':'Work'}]}
     if(cmd==='get_ui_lang')return lang
     if(cmd==='get_profile')return {...profile}
     if(cmd==='set_profile'){Object.assign(profile,args.profile||args.patch||{});return {...profile}}
     if(cmd==='get_snapshot')return {state:'DISCONNECTED',detail:'Tap to connect',protocol:'SMART',latencyMs:null,uptimeSecs:0,rxBytes:0,txBytes:0}
     if(cmd==='core_caps')return {zeroTrust:true,routing:true,customDns:true,upstream:true,routeSniff:true,tor:true,coreVersion:'2.4.0'}
     if(cmd==='news_state')return {version:'1.4.0',suppressed:'1.4.0'}
     if(cmd==='ai_snapshot')return {gate:'NO_KEY',gateCode:'NO_KEY',hasKey:false,messages:[],models:[],probe:{state:'IDLE'}}
     if(cmd==='cc_state'||cmd==='cc_select')return cc
     if(cmd==='cc_tab_delete'){
      if(args.id==='all')return cc
      cc.configs=cc.configs.filter(c=>args.id.startsWith('user:')?c.groupId!==args.id:c.groupId || ((args.id==='format:npvt')!==(c.format==='NPVT')))
      cc.groups=cc.groups.filter(g=>g.id!==args.id)
      return cc
     }
     if(cmd==='cc_subscription_refresh')return cc
     if(cmd==='cc_tab_save'){cc.tabNames[args.id]=args.name;return cc}
     if(cmd==='cc_ping')return {id:args.id,ms:42}
     if(cmd==='cc_import_text')return cc
     if(cmd==='cc_ping_all')return {results:configs.map((c,i)=>({id:c.id,ms:150+i*30}))}
     if(cmd==='zt_status')return {member:false}
     return null
    },transformCallback:cb=>cb,metadata:{currentWindow:{label:'main'},currentWebview:{label:'main',windowLabel:'main'}}
   }
  },lang)
  const wait=()=>new Promise(r=>setTimeout(r,100))
  const click=async sel=>{await page.waitForSelector(sel);await page.evaluate(s=>document.querySelector(s).click(),sel);await wait()}
  const shot=async name=>{await page.evaluate(()=>document.fonts.ready);await wait();await page.screenshot({path:join(out,`${width}-${lang}-${name}.png`)})}
  // CI-robust navigation: the hub rows are located by position, so wait until the
  // whole hub is really mounted (not just the first rows), click, and verify that the
  // sub-page rendered. A click that lands while the view is being (re)built is retried
  // instead of burning the full 30 s selector timeout; on final failure the page errors
  // and the visible DOM are printed so the CI log shows the real cause.
  const gotoSettings=async()=>{
   await page.waitForFunction(()=>!!document.querySelector('.drawer__item[data-tab="advanced"]'))
   await page.evaluate(()=>document.querySelector('.drawer__item[data-tab="advanced"]').click());await wait()
  }
  const open=async id=>{
   let last
   for(let attempt=0;attempt<4;attempt++){
    try{
     if(await page.$('.setpage__back'))await click('.setpage__back')
     if(!await page.$('.setrow'))await gotoSettings()
     // Stable row id (data-row), never a position: inserting a hub row (e.g. cleanip) must not
     // silently open a different sub-page.
     await page.waitForSelector(`.sethub .setrow[data-row="${id}"]`,{timeout:10000})
     await page.evaluate(id=>{document.querySelector(`.sethub .setrow[data-row="${id}"]`).click();document.querySelector('main').scrollTop=0},id);await wait()
     await page.waitForSelector(id==='custom'?'.ccfg':'.setpage__back',{timeout:8000})
     return
    }catch(e){last=e;await wait()}
   }
   const dom=await page.evaluate(()=>(document.querySelector('main')?.innerText||'').slice(0,400)).catch(()=> '')
   console.error('open('+id+') failed. page errors:',errors,'\nmain text:',dom)
   throw last
  }
  await page.goto(`http://127.0.0.1:${server.address().port}/`,{waitUntil:'networkidle0'})
  await shot('home-profiles')
  await click('.presets__trigger');await shot('profile-menu-cards');await page.keyboard.press('Escape')
  await click('.drawer__item[data-tab="advanced"]');await open('custom')
  await shot('a1-chain-health')
  if(!baseline){
   const layout=await page.evaluate(()=>{
    const box=s=>{const r=document.querySelector(s).getBoundingClientRect();return {x:r.x,y:r.y,w:r.width,h:r.height,right:r.right}}
    return {hint:box('.cc-chain__summary'),row:box('.cc-pick'),icon:box('.cc-health__icon'),head:box('.cc-health-card .field__head'),chip:box('.cc-health__chip')}
   })
   assert(layout.hint.w>width*.65,'full-width chain hint');assert(layout.hint.y>=layout.row.y+layout.row.h-1,'help below row')
   if(lang==='fa')assert(layout.icon.x>layout.head.x&&layout.head.x>layout.chip.x,'RTL icon → label → chip')
   else assert(layout.icon.x<layout.head.x&&layout.head.x<layout.chip.x,'LTR icon → label → chip')
   assert.equal(Math.round(layout.icon.w),32,'no oversized icon flex')
   assert.equal(await page.$$('.cc-subscriptions,.cc-subscription').then(a=>a.length),0)
   assert.equal(await page.$$('.cc-tab__close').then(a=>a.length),0,'deletion only inside editor')
   assert(!await page.$eval('.cc-tabs',el=>el.textContent.includes('subscription.example.invalid')),'no domain/subscription tabs')
   await page.select('#cc-health','60');await wait()
   assert(await page.evaluate(()=>window.__calls.some(([cmd,a])=>cmd==='set_profile'&&a.profile?.customHealthSecs===60)))
   await page.select('#cc-health','300')
  }
  await page.$eval('.cc-tabs',el=>el.scrollIntoView({block:'start'}));await shot('a4-tabs')
  if(!baseline){
   const tabs=await page.$('.cc-tabs');const rect=await tabs.boundingBox()
   assert.equal(await tabs.evaluate(el=>getComputedStyle(el).scrollbarWidth),'thin','tab scrollbar must not be hidden')
   assert.notEqual(await tabs.evaluate(el=>getComputedStyle(el,'::-webkit-scrollbar').display),'none','legacy hidden-scrollbar rule removed')
   const before=await tabs.evaluate(el=>el.scrollLeft)
   const x=rect.x+rect.width*.5,y=rect.y+rect.height*.5
   await page.mouse.move(x,y);await page.mouse.down();await page.mouse.move(x+(lang==='fa'?120:-120),y,{steps:12});await page.mouse.up();await wait()
   const after=await tabs.evaluate(el=>el.scrollLeft);assert(Math.abs(after-before)>50,'mouse drag changes strip offset')
   assert.equal(await page.$$('.chat__modal').then(a=>a.length),0,'drag cannot open edit/delete')
   await page.mouse.move(x,y);await page.mouse.wheel({deltaY:200});await wait()
   assert.notEqual(await tabs.evaluate(el=>el.scrollLeft),after,'wheel scroll changes strip offset')
   await shot('a4-tabs-dragged')
   await tabs.evaluate(el=>el.scrollLeft=0)
  }
  await click('.ccfg__actions');await shot('a2-config-menu')
  if(!baseline&&lang==='fa'){
   const text=await page.$eval('.chat__modal',el=>el.textContent);assert(text.includes('استفاده از این کانفیگ')&&text.includes('تست پینگ'))
  }
  await page.keyboard.press('Escape');await click('.cc-add');await click('.mlist .mbtn');await shot('a3-import')
  if(!baseline&&lang==='fa'){
   assert.equal(await page.$eval('.cc-paste',el=>el.placeholder),'یک یا چند لینک، کانفیگ JSON یا آدرس اشتراک را وارد کنید')
   const txt=await page.$eval('.chat__modal',el=>el.textContent);assert(txt.includes('جای‌گذاری از کلیپ‌بورد')&&txt.includes('اکنون وارد کن'))
  }
  if(!baseline){
   await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{readText:async()=> 'vless://fixture@example.invalid:443'}}))
   await click('.mclip');assert.equal(await page.$eval('.cc-paste',el=>el.value),'vless://fixture@example.invalid:443')
   assert.equal(await page.$eval('.cc-paste',el=>getComputedStyle(el).direction),'ltr','technical links remain LTR')
   await click('.chat__modalrow .btn--primary')
   assert(await page.evaluate(()=>window.__calls.some(([cmd])=>cmd==='cc_import_text')))
  } else await page.keyboard.press('Escape')
  await page.$eval('.cc-ping-all',el=>el.scrollIntoView({block:'start'}));await shot('a5-subscription-strip-removed')
  if(!baseline){
   // All: rename/import allowed, deletion absent.
   await click('.cc-tab:first-child .cc-tab-edit__btn')
   assert.equal(await page.$$('.chat__modalrow .btn--danger').then(a=>a.length),0)
   assert(await page.evaluate(()=>[...document.querySelectorAll('.chat__modalrow button')].some(b=>b.textContent=== (document.documentElement.lang==='fa'?'افزودن کانفیگ':'Add config'))))
   await page.keyboard.press('Escape')
   // Format editor, then a separate destructive confirmation. Escape commits nothing.
   await click('.cc-tab:nth-child(2) .cc-tab-edit__btn');await shot('tab-editor-danger-import')
   await click('.chat__modalrow .btn--danger');await shot('tab-delete-confirmation');await page.keyboard.press('Escape')
   assert.equal(await page.$$('.ccfg').then(a=>a.length),12)
   await click('.cc-tab:nth-child(2) .cc-tab-edit__btn');await click('.chat__modalrow .btn--danger');await click('.chat__modalrow .btn--danger')
   assert.equal(await page.$$('.ccfg').then(a=>a.length),4,'format cascade removes ungrouped V2Ray configs')
   assert.equal(await page.$$('.cc-tab__close').then(a=>a.length),0)
  }
  await open('transport')
  await page.$eval('[data-key="keepalive"]',el=>el.scrollIntoView({block:'center'}));await shot('a6-keepalive')
  if(!baseline&&lang==='fa')assert((await page.$eval('[data-key="keepalive"]',el=>el.closest('section').textContent)).includes('زنده‌نگه‌داشتن اتصال (Keepalive)'))
  await page.$eval('[data-key="ech"]',el=>el.scrollIntoView({block:'center'}));await shot('a6-ech')
  if(!baseline&&lang==='fa')assert((await page.$eval('[data-key="ech"]',el=>el.closest('section').textContent)).includes('کلاینت‌هلو رمزنگاری‌شده (ECH)'))
  await open('zerotrust');await shot('a7-zero-trust')
  if(!baseline&&lang==='fa')assert.equal(await page.$eval('[data-key="team"]',el=>el.placeholder),'نام-سازمان-شما')
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'no horizontal page overflow')
  assert.deepEqual(errors,[])
  report.push({width,height,lang,status:baseline?'BASELINE_CAPTURE':'PASS',ipc:'test fixture, not Windows native',consoleErrors:errors})
  console.log(`${baseline?'CAPTURE':'PASS'} ${width}×${height} ${lang}: a1–a7, drag/wheel, deletion, localization`)
  await context.close()
 }
 await writeFile(join(out,'report.json'),JSON.stringify(report,null,2))
} finally {if(browser)await browser.close();await new Promise(r=>server.close(r))}
