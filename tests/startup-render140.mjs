// Real Chromium first paint while native initialization stays pending; no Windows timing claim.
import assert from 'node:assert/strict'
import {existsSync} from 'node:fs'
import {createServer} from 'node:http'
import {readFile,mkdir,writeFile} from 'node:fs/promises'
import {resolve,join,extname} from 'node:path'
import puppeteer from 'puppeteer-core'
const dist=resolve('dist-web'),out=resolve(process.env.QA_DIR||'validation/startup140');await mkdir(out,{recursive:true})
const server=createServer(async(req,res)=>{try {const path=join(dist,req.url==='/'?'index.html':req.url.split('?')[0]);res.setHeader('Content-Type',({'.html':'text/html','.js':'text/javascript','.css':'text/css','.png':'image/png','.ttf':'font/ttf'})[extname(path)]||'application/octet-stream');res.end(await readFile(path))}catch{res.statusCode=404;res.end()}})
await new Promise(r=>server.listen(0,'127.0.0.1',r));let browser
try {
 browser=await puppeteer.launch({executablePath:[process.env.CHROME,'/usr/local/bin/chromium','/usr/bin/chromium'].filter(Boolean).find(p=>existsSync(p)),args:['--no-sandbox','--disable-dev-shm-usage']})
 const page=await browser.newPage();await page.setViewport({width:390,height:820})
 await page.evaluateOnNewDocument(()=>{
  localStorage.setItem('aether.lang','fa');window.__calls=[]
  window.__TAURI_INTERNALS__={invoke:async(cmd,args)=>{
   window.__calls.push(cmd)
   if(cmd==='startup_ready')return new Promise((resolve,reject)=>{window.__releaseStartup=resolve;window.__failStartup=reject})
   if(cmd==='get_profile')return {backend:'AETHER',protocol:'SMART'}
   if(cmd==='get_snapshot')return {state:'DISCONNECTED',uptimeSecs:0,rxBytes:0,txBytes:0}
   if(cmd==='preset_state')return {activeId:'default',presets:[{id:'default',name:'Default'}]}
   if(cmd==='news_state')return {version:'1.4.0',suppressed:'1.4.0'}
   if(cmd==='plugin:event|listen')return 1
   return null
  },transformCallback:x=>x,metadata:{currentWindow:{label:'main'},currentWebview:{label:'main',windowLabel:'main'}}}
 })
 const url=`http://127.0.0.1:${server.address().port}/`
 await page.goto(url,{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>!!window.__releaseStartup)
 await page.waitForFunction(()=>performance.getEntriesByType('paint').length>0)
 const metric=await page.evaluate(()=>({paint:performance.getEntriesByType('paint').map(p=>({name:p.name,ms:p.startTime})),stateReads:window.__calls.filter(c=>['get_profile','get_snapshot'].includes(c)),shell:!!document.querySelector('.boot-skeleton')}))
 assert(metric.shell);assert.equal(metric.stateReads.length,0);assert(metric.paint.find(p=>p.name==='first-contentful-paint').ms<1000,'local Chromium FCP under 1s')
 await page.screenshot({path:join(out,'startup-pending-fa.png')})
 await page.evaluate(()=>window.__releaseStartup());await page.waitForSelector('#connect');assert.equal(await page.$eval('.presets__trigger',e=>e.textContent),'پیش‌فرض')
 await page.goto(url,{waitUntil:'domcontentloaded'});await page.waitForFunction(()=>!!window.__failStartup);await page.evaluate(()=>window.__failStartup('Injected initialization failure'))
 await page.waitForSelector('.boot-error');assert.equal(await page.$eval('#view button',e=>e.textContent),'تلاش مجدد');await page.screenshot({path:join(out,'startup-error-retry-fa.png')})
 await writeFile(join(out,'startup-metrics.json'),JSON.stringify({...metric,environment:'Linux Chromium; IPC gated fixture; not Windows WebView2 cold-start timing',readyHydration:'PASS',errorRetry:'PASS'},null,2))
 console.log('PASS: pending shell, measured local FCP, no IPC readiness race, hydration, actionable startup error',JSON.stringify(metric.paint))
}finally{if(browser)await browser.close();await new Promise(r=>server.close(r))}
