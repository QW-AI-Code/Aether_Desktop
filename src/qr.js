// Pure local QR decoding. No camera permission, remote upload, or eval.
// 1.4.0: multi-scale + contrast-normalised + centre-crop decoding so QR codes
// pasted from dark/light themed screenshots, scaled images or busy pages decode.
import jsQR from 'jsqr'
export const QR_MAX_BYTES=10*1024*1024
export const QR_MAX_PIXELS=20_000_000
export const QR_MAX_CONTENT_BYTES=2*1024*1024
// Scales tried in order (full first, then shrink, then grow for tiny codes).
export const QR_SCALES=[1.0,0.75,0.5,1.25,1.5]
// jsQR only knows these values; 'attemptBoth' covers light-on-dark codes.
const INVERSION='attemptBoth'

function assertDims(data,width,height){
 if(!Number.isInteger(width)||!Number.isInteger(height)||width<1||height<1||width*height>QR_MAX_PIXELS||data.length!==width*height*4)throw new Error('Invalid QR image dimensions')
}
function toClamped(data){return data instanceof Uint8ClampedArray?data:new Uint8ClampedArray(data)}
function finish(text){
 if(!text?.trim())return null
 if(new TextEncoder().encode(text).length>QR_MAX_CONTENT_BYTES)throw new Error('QR content is too large')
 return text
}
function tryDecode(data,width,height){
 try{const qr=jsQR(data,width,height,{inversionAttempts:INVERSION});return qr?.data?.trim()?qr.data:null}catch{return null}
}
// Grayscale + contrast stretch (2nd..98th percentile → 0..255). Returns a new RGBA buffer.
export function normalizeContrast(data,width,height){
 const n=width*height,gray=new Uint8ClampedArray(n),hist=new Uint32Array(256)
 for(let i=0,p=0;i<n;i++,p+=4){const g=(data[p]*299+data[p+1]*587+data[p+2]*114+500)/1000|0;gray[i]=g;hist[g]++}
 const lowCut=n*0.02,highCut=n*0.98;let lo=0,hi=255,acc=0
 for(let v=0;v<256;v++){acc+=hist[v];if(acc>=lowCut){lo=v;break}}
 acc=0;for(let v=255;v>=0;v--){acc+=hist[v];if(acc>=n-highCut){hi=v;break}}
 if(hi-lo<16)return null // already flat/uniform — stretching would only amplify noise
 const out=new Uint8ClampedArray(n*4),span=hi-lo
 for(let i=0,p=0;i<n;i++,p+=4){let v=((gray[i]-lo)*255/span)|0;v=v<0?0:v>255?255:v;out[p]=out[p+1]=out[p+2]=v;out[p+3]=255}
 return out
}
// Nearest/bilinear-free resample that works without a DOM (tests run in Node).
export function resamplePixels(data,width,height,scale){
 const w=Math.max(1,Math.round(width*scale)),h=Math.max(1,Math.round(height*scale))
 if(w===width&&h===height)return{data,width,height}
 if(w*h>QR_MAX_PIXELS)return null
 const out=new Uint8ClampedArray(w*h*4)
 if(scale<1){ // box-filter downscale keeps module edges cleaner than nearest
  const fx=width/w,fy=height/h
  for(let y=0;y<h;y++){const y0=y*fy|0,y1=Math.min(height,Math.max(y0+1,(y+1)*fy|0))
   for(let x=0;x<w;x++){const x0=x*fx|0,x1=Math.min(width,Math.max(x0+1,(x+1)*fx|0));let r=0,g=0,b=0,c=0
    for(let yy=y0;yy<y1;yy++){let p=(yy*width+x0)*4;for(let xx=x0;xx<x1;xx++,p+=4){r+=data[p];g+=data[p+1];b+=data[p+2];c++}}
    const o=(y*w+x)*4;out[o]=r/c;out[o+1]=g/c;out[o+2]=b/c;out[o+3]=255}}
 }else{
  for(let y=0;y<h;y++){const sy=Math.min(height-1,y*height/h|0)
   for(let x=0;x<w;x++){const sx=Math.min(width-1,x*width/w|0),p=(sy*width+sx)*4,o=(y*w+x)*4;out[o]=data[p];out[o+1]=data[p+1];out[o+2]=data[p+2];out[o+3]=255}}
 }
 return{data:out,width:w,height:h}
}
export function centerCrop(data,width,height,fraction=0.7){
 const w=Math.max(1,Math.round(width*fraction)),h=Math.max(1,Math.round(height*fraction))
 if(w===width&&h===height)return null
 const x0=(width-w)>>1,y0=(height-h)>>1,out=new Uint8ClampedArray(w*h*4)
 for(let y=0;y<h;y++)out.set(data.subarray(((y0+y)*width+x0)*4,((y0+y)*width+x0+w)*4),y*w*4)
 return{data:out,width:w,height:h}
}
function* variants(data,width,height){
 // Pass 1: raw at every scale. Pass 2: contrast-normalised at every scale.
 // Pass 3: centre crop (raw + normalised) at 1.0 and 1.5.
 for(const s of QR_SCALES){const r=resamplePixels(data,width,height,s);if(r)yield r}
 const norm=normalizeContrast(data,width,height)
 if(norm)for(const s of QR_SCALES){const r=resamplePixels(norm,width,height,s);if(r)yield r}
 const crop=centerCrop(data,width,height)
 if(crop){
  yield crop
  const up=resamplePixels(crop.data,crop.width,crop.height,1.5);if(up)yield up
  const cn=normalizeContrast(crop.data,crop.width,crop.height)
  if(cn){yield{data:cn,width:crop.width,height:crop.height};const cu=resamplePixels(cn,crop.width,crop.height,1.5);if(cu)yield cu}
 }
}
export function decodeQrPixels(data,width,height){
 assertDims(data,width,height)
 const src=toClamped(data)
 for(const v of variants(src,width,height)){
  const text=tryDecode(v.data,v.width,v.height)
  if(text!==null)return finish(text)
 }
 throw new Error('No QR code found in image')
}
// 1.4.0-r5: the CSP has no `blob:` in img-src, so `new Image()` on an object URL
// was blocked inside the app and every picked photo failed with "Could not read QR
// image". createImageBitmap(file) never touches the CSP; a data: URL (allowed) is
// the fallback. Transparent PNGs are flattened onto white first, otherwise the
// transparent pixels (0,0,0,0) read as black and swallow the code.
function loadDataUrl(file){
 return new Promise((resolve,reject)=>{
  const r=new FileReader()
  r.onerror=()=>reject(new Error('Could not read QR image'))
  r.onload=()=>{const i=new Image();i.onload=()=>resolve(i);i.onerror=()=>reject(new Error('Could not read QR image'));i.src=r.result}
  r.readAsDataURL(file)
 })
}
async function loadBitmap(file){
 if(typeof createImageBitmap==='function'){
  try{return await createImageBitmap(file)}catch{/* fall through to data: URL */}
 }
 return loadDataUrl(file)
}
export async function decodeQrFile(file){
 if(file.size>QR_MAX_BYTES)throw new Error('QR image is larger than 10 MB')
 const image=await loadBitmap(file)
 try{
  const w=image.naturalWidth||image.width,h=image.naturalHeight||image.height
  if(w*h>QR_MAX_PIXELS||w<1||h<1)throw new Error('Invalid QR image dimensions')
  const canvas=document.createElement('canvas');canvas.width=w;canvas.height=h
  const ctx=canvas.getContext('2d',{willReadFrequently:true})
  ctx.fillStyle='#fff';ctx.fillRect(0,0,w,h);ctx.drawImage(image,0,0)
  return decodeQrPixels(ctx.getImageData(0,0,w,h).data,w,h)
 }finally{if(typeof image.close==='function')image.close()}
}
