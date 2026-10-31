import fs from 'fs'
const src = fs.readFileSync('src/i18n.js', 'utf8')
const need = [...fs.readFileSync('src/views/cleanip.js','utf8').matchAll(/\bt\(\s*'((?:\\.|[^'\\])*)'/g)].map(m=>m[1].replace(/\\'/g,"'")).filter(k=>/\s/.test(k)&&!k.includes('\\u'))
const miss = need.filter(k => !src.includes(`'${k}':`) && !src.includes(`"${k}":`) && !src.includes(`'${k.replace(/'/g,"\\'")}':`))
if (miss.length) { console.error('missing fa:', miss); process.exit(1) }
console.log('PASS: all cleanip.js strings have Persian translations (' + need.length + ')')
