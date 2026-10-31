import assert from 'node:assert/strict'
import qrcode from 'qrcode-generator'
import {decodeQrPixels,QR_MAX_PIXELS} from '../src/qr.js'
const text='vless://11111111-2222-3333-4444-555555555555@server.invalid:443#qr'
const qr=qrcode(0,'M');qr.addData(text);qr.make();const n=qr.getModuleCount(),scale=5,margin=4,w=(n+2*margin)*scale
const rgba=new Uint8ClampedArray(w*w*4);rgba.fill(255)
for(let y=0;y<w;y++)for(let x=0;x<w;x++){const a=Math.floor(y/scale)-margin,b=Math.floor(x/scale)-margin;if(a>=0&&b>=0&&a<n&&b<n&&qr.isDark(a,b)){const i=(y*w+x)*4;rgba[i]=rgba[i+1]=rgba[i+2]=0}}
assert.equal(decodeQrPixels(rgba,w,w),text);console.log('  ok   QR image decodes full config locally')
const inverted=new Uint8ClampedArray(rgba);for(let i=0;i<inverted.length;i+=4)for(let k=0;k<3;k++)inverted[i+k]=255-inverted[i+k]
assert.equal(decodeQrPixels(inverted,w,w),text);console.log('  ok   inverted QR decodes')
assert.throws(()=>decodeQrPixels(new Uint8ClampedArray(4),QR_MAX_PIXELS,2));console.log('  ok   excessive QR dimensions rejected')
assert.throws(()=>decodeQrPixels(new Uint8ClampedArray(100*100*4).fill(255),100,100),/No QR/);console.log('  ok   absent QR rejected')
console.log('ALL OK — QR image tests')
