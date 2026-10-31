// Real Chromium layout regressions, with test-only IPC fixtures (no network).
// Run after web:build. Screenshots/reports go to $QA_DIR or validation/ui-parity.
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { createServer } from 'node:http'
import { readFile, mkdir, writeFile } from 'node:fs/promises'
import { join, resolve, extname } from 'node:path'
import puppeteer from 'puppeteer-core'
const dist = resolve('dist-web')
const out = resolve(process.env.QA_DIR || 'validation/ui-parity')
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
 browser=await puppeteer.launch({executablePath:[process.env.CHROME, '/usr/local/bin/chromium', '/usr/bin/chromium', '/usr/bin/google-chrome', 'C:/Program Files/Google/Chrome/Application/chrome.exe'].filter(Boolean).find(p=>existsSync(p)),args:['--no-sandbox','--disable-dev-shm-usage']})
 for(const [width,height,lang] of [[390,820,'fa'],[360,720,'fa'],[760,900,'fa'],[390,820,'en']]) {
  const page=await browser.newPage();await page.setViewport({width,height,deviceScaleFactor:1})
  const errors=[];page.on('pageerror',e=>errors.push(String(e)))
  await page.evaluateOnNewDocument((lang)=>{
   localStorage.setItem('aether.lang',lang)
   const profile={backend:'AETHER_PSIPHON',exitRegion:'',protocol:'SMART',scanMode:'BALANCED',ipVersion:'V4',noize:'OFF',endpointMode:'AUTO',manualPeer:'',manualRange:'',mtu:1280,keepalive:0,quickReconnect:true,masqueHttp2:false,fragment:false,ech:false,lanShare:false,killSwitch:true,ipv6Protection:true,reconnectAttempts:5,splitMode:'OFF',splitApps:[],dns:['1.1.1.1'],routeBlock:[],routeDirect:[],routeSniff:true,upstream:'',reprovision:true,team:'',accessMode:'EMAIL',verifyConnection:true}
   const configs=Array.from({length:12},(_,i)=>({id:String(i),name:i===0?'🔒 @Broz_time < کانفیگ سفارشی با نام بلند '+ 'آزمایش '.repeat(4):`${i+1} - VLESS - Domain : 2086`,server:i===0?'very-long-subdomain-'.repeat(5)+'.example.com:2086':'www.speedtest.net:2086',format:i<8?'URI':'NPVT',chainLabel:i<8?'VLESS':'Npvt',locked:i>=8,expired:false,note:'',groupId:null}))
   const cc={enabled:false,mode:'SOLO',modeLabel:'Config',activeId:'0',modes:[{id:'SOLO',label:'VLESS',hops:1}],configs,groups:[{id:'user:test',name:'test'}],tabNames:{},subscriptions:[]}
   window.__calls=[];window.__events={}
   window.__TAURI_INTERNALS__={
    invoke:async(cmd,args)=>{
     window.__calls.push([cmd,args])
     if(cmd==='plugin:event|listen'){window.__events[args.event]=args.handler;return 1}
     if(cmd==='get_ui_lang')return lang
     if(cmd==='get_profile')return {...profile}
     if(cmd==='set_profile'){Object.assign(profile,args.profile||args.patch||{});return {...profile}}
     if(cmd==='get_snapshot')return {state:'DISCONNECTED',detail:'Tap to connect',protocol:'SMART',latencyMs:null,uptimeSecs:0,rxBytes:0,txBytes:0}
     if(cmd==='core_caps')return {zeroTrust:true,routing:true,customDns:true,upstream:true,routeSniff:true,tor:true,coreVersion:'2.4.0'}
     if(cmd==='news_state')return {version:'1.4.0',suppressed:'1.4.0'}
     if(cmd==='ai_snapshot')return {gate:'NO_KEY',gateCode:'NO_KEY',hasKey:false,messages:[],models:[],probe:{state:'IDLE'}}
     if(cmd==='cc_state'||cmd==='cc_select')return cc
     if(cmd==='cc_ping_all')return {results:configs.map((c,i)=>({id:c.id,ms:150+i*30}))}
     if(cmd==='zt_status')return {member:false}
     return null
    },transformCallback:cb=>cb,metadata:{currentWindow:{label:'main'},currentWebview:{label:'main',windowLabel:'main'}}
   }
  },lang)
  await page.goto(`http://127.0.0.1:${server.address().port}/`,{waitUntil:'networkidle0'})
  const click=async sel=>{await page.evaluate(s=>document.querySelector(s).click(),sel);await new Promise(r=>setTimeout(r,70))}
  await click('.drawer__item[data-tab="advanced"]')
  const open=async(id)=>{
   if(await page.$('.setpage__back'))await click('.setpage__back')
   await page.evaluate(id=>{
    // Stable row id (data-row), not a position and not translated copy.
    document.querySelector(`.setrow[data-row="${id}"]`).click();document.querySelector('main').scrollTop=0
   },id)
   await page.evaluate(()=>document.fonts.ready);await new Promise(r=>setTimeout(r,100))
  }
  const shot=async(name)=>{await page.evaluate(()=>new Promise(r=>requestAnimationFrame(()=>requestAnimationFrame(r))));if((width===390||width===360)&&lang==='fa')await page.screenshot({path:join(out,`${name}${width===360?'-360':''}.png`)})}
  const noOverflow=async(label)=>{
   const data=await page.evaluate(()=>{
    const m=document.querySelector('main');return {page:document.documentElement.scrollWidth,viewport:innerWidth,main:m.scrollWidth,mainClient:m.clientWidth}
   });assert(data.page<=data.viewport+1,label+' page overflow');assert(data.main<=data.mainClient+1,label+' main overflow');return data
  }
  const aligned=async()=>page.evaluate(()=>[...document.querySelectorAll('.field__head')].filter(el=>el.getBoundingClientRect().height).map(el=>{
   const label=el.querySelector('.field__label').getBoundingClientRect(),ai=el.querySelector('.aihint').getBoundingClientRect(),r=el.getBoundingClientRect()
   return {horizontal:getComputedStyle(el).flexDirection==='row',contained:ai.left>=r.left-1&&ai.right<=r.right+1,align:getComputedStyle(el.querySelector('.field__label')).textAlign}
  }))
  await open('connection')
  assert.equal(await page.$$eval('[data-key="verifyConnection"]',es=>es.length),1)
  assert(await page.evaluate(()=>document.querySelector('[data-key="verifyConnection"]').getBoundingClientRect().top<document.querySelector('[data-key="protocol"]').getBoundingClientRect().top))
  assert.equal(await page.$eval('[data-key="protocol"] [data-value="MIM"] .seg__text',el=>el.textContent),'MASQUE×2')
  assert(await page.$eval('.pick__summary',el=>el.clientWidth>250))
  assert.equal(await page.$eval('.pick__chev',el=>getComputedStyle(el).transform),lang==='fa'?'matrix(-1, 0, 0, 1, 0, 0)':'none')
  await shot('connection');await noOverflow('connection')
  await page.$eval('[data-key="protocol"]',el=>el.scrollIntoView({block:'center'}));await shot('protocol')
  await page.evaluate(()=>document.querySelector('main').scrollTop=0)
  await click('[data-open="backend"]');await new Promise(r=>setTimeout(r,350))
  assert.deepEqual(await page.$$eval('[data-key="backend"] .seg__text',es=>es.map(e=>e.textContent)),['Aether','Aether → Psiphon','Tor','Aether → Tor','Tor → Psiphon','Tor → Aether'])
  await shot('backend-sheet');await page.keyboard.press('Escape')
  await click('[data-key="verifyConnection"]')
  assert(await page.evaluate(()=>window.__calls.some(([cmd,args])=>cmd==='set_profile'&&args.profile?.verifyConnection===false)))
  await open('transport');assert.equal(await page.$$eval('[data-key="verifyConnection"]',es=>es.length),0);await shot('transport')
  for(const id of ['dns','apps','safety','zerotrust']) {
   await open(id);await noOverflow(id)
   const heads=await aligned();assert(heads.every(h=>h.horizontal&&h.contained),id+' headings/AI')
   if(lang==='fa')assert(heads.every(h=>['right','start'].includes(h.align)))
   await shot(id)
  }
  await open('custom');await page.waitForSelector('.ccfg');await noOverflow('custom')
  assert.equal(await page.$$eval('.cc-list-title',es=>es.length),0)
  assert(await page.$eval('.cc-table-scroll',el=>el.scrollWidth<=el.clientWidth+1))
  assert(await page.evaluate(()=>document.querySelector('.cc-ping-all').getBoundingClientRect().top>=document.querySelector('.cc-table-scroll').getBoundingClientRect().bottom))
  assert(await page.evaluate(()=>{const a=document.querySelector('.cc-add').getBoundingClientRect(),b=document.querySelector('.cc-new-tab').getBoundingClientRect();return Math.abs(a.top-b.top)<1&&Math.abs(a.height-b.height)<1}))
  assert(await page.$eval('.ccfg__server',el=>!el.closest('.ccfg__meta')))
  await page.$eval('.cc-tabs-bar',el=>el.scrollIntoView({block:'start'}));await shot('custom-table')
  await click('.cc-ping-all');assert(await page.evaluate(()=>window.__calls.some(([cmd])=>cmd==='cc_ping_all')))
  assert(await page.$$eval('.ccfg__ping', els=>els.length===12 && els.every(el=>el.scrollWidth<=el.clientWidth+1)))
  assert(await page.$$eval('.ccfg__actions', els=>els.every(el=>{const r=el.getBoundingClientRect(),p=el.closest('.cc-table-scroll').getBoundingClientRect();return r.left>=p.left&&r.right<=p.right})))
  await page.$eval('.cc-ping-all',el=>el.scrollIntoView({block:'end'}));await shot('custom-ping')
  await click('.cc-add')
  if(lang==='fa'){
   const text=await page.$eval('.modal',el=>el.textContent).catch(()=>page.evaluate(()=>document.body.textContent))
   assert(text.includes('لینک یا متن')&&text.includes('وارد کردن فایل'))
  }
  await shot('add-modal');await page.keyboard.press('Escape');assert(await page.$('.cc-table-scroll'), 'Escape must not navigate away from the config page')
  await click('.cc-tab-edit__btn');if(lang==='fa')assert.equal(await page.$eval('.mfield > span',el=>el.textContent),'نام')
  await shot('edit-tab-modal');await page.keyboard.press('Escape')
  await click('#menu-btn');await new Promise(r=>setTimeout(r,250));assert.equal(await page.$$('.drawer__logo').then(a=>a.length),0);await shot('drawer')
  assert.deepEqual(errors,[])
  report.push({width,height,lang,status:'PASS',consoleErrors:errors})
  console.log(`PASS ${width}×${height} ${lang}: connection, backend, verification, transport, DNS, apps, safety, Zero Trust, config table, ping, modals, drawer`)
  await page.close()
 }
 await writeFile(join(out,'report.json'),JSON.stringify(report,null,2))
} finally {if(browser)await browser.close();await new Promise(r=>server.close(r))}
