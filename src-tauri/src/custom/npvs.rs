//! NPVS v5 wire-compatible port of mobile NpvsCodec.kt (1.6.0).
//! Authentication before unlock; device-bound exports fail closed. Never logs plaintext.
use super::{npvt::{self, Decoded, Tables}, parser::ImportError};
use chacha20poly1305::{aead::{Aead, Payload}, ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
const MAX: usize = 2 * 1024 * 1024;
type R<T> = Result<T, ImportError>;
fn bad(s: &str) -> ImportError { ImportError::Invalid(s.into()) }
fn cut(b: &[u8], p: usize, n: usize) -> R<&[u8]> { b.get(p..p.checked_add(n).ok_or_else(||bad("NPVS length overflow"))?).ok_or_else(||bad("truncated NPVS payload")) }
fn u16at(b: &[u8], p: usize) -> R<usize> { let s=cut(b,p,2)?;Ok(u16::from_be_bytes([s[0],s[1]]) as usize) }
fn u32at(b: &[u8], p: usize) -> R<usize> { let s=cut(b,p,4)?;let n=u32::from_be_bytes(s.try_into().unwrap()) as usize; if n>MAX { return Err(bad("NPVS length exceeds limit")); } Ok(n) }
fn open(key: &[u8], nonce: &[u8], blob: &[u8], aad: &[u8]) -> R<Zeroizing<Vec<u8>>> {
 if key.len()!=32 || nonce.len()!=12 || blob.len()<16 {return Err(bad("bad NPVS cipher parameters"));}
 ChaCha20Poly1305::new_from_slice(key).map_err(|_|bad("bad NPVS key"))?
 .decrypt(Nonce::from_slice(nonce),Payload{msg:blob,aad}).map(Zeroizing::new).map_err(|_|bad("NPVS authentication failed"))
}
fn hkdf(dek: &[u8], salt: &[u8], info: &[u8]) -> R<Zeroizing<[u8;32]>> {
 let mut key=Zeroizing::new([0;32]);Hkdf::<Sha256>::new(Some(salt),dek).expand(info,&mut *key).map_err(|_|bad("NPVS key derivation failed"))?;Ok(key)
}
fn text(b: &[u8]) -> R<&str> { std::str::from_utf8(b).map_err(|_|bad("NPVS field is not UTF-8")) }
fn decode_sentinels(s: &str) -> R<String> {
 let mut out=String::new();let mut rest=s;
 while let Some(i)=rest.find("npvs1:") {
  out.push_str(&rest[..i]);rest=&rest[i+6..];
  let n=rest.bytes().take_while(|c|c.is_ascii_alphanumeric() || b"+/=_-".contains(c)).count();
  if n==0 {out.push_str("npvs1:");continue;}
  let bytes=npvt::decode_base64(&rest[..n]).ok_or_else(||bad("bad NPVS sentinel encoding"))?;
  out.push_str(text(&bytes)?);rest=&rest[n..];
 }
 out.push_str(rest);Ok(out)
}
fn substitute(v: &Value, fields: &BTreeMap<usize,Zeroizing<Vec<u8>>>, depth: usize) -> R<Value> {
 if depth>48 {return Err(bad("NPVS config nesting is too deep"));}
 Ok(match v {
  Value::Object(o)=>Value::Object(o.iter().map(|(k,v)|Ok((k.clone(),substitute(v,fields,depth+1)?))).collect::<R<_>>()?),
  Value::Array(a)=>Value::Array(a.iter().map(|v|substitute(v,fields,depth+1)).collect::<R<_>>()?),
  Value::Number(n) if n.as_u64().is_some()=>{
   let b=fields.get(&(n.as_u64().unwrap() as usize)).ok_or_else(||bad("NPVS field is missing"))?;
   let raw=text(b)?;let parsed=serde_json::from_str::<Value>(raw).ok();
   let s=match parsed {Some(Value::String(s))=>s,Some(Value::Number(n))=>n.to_string(),Some(Value::Bool(b))=>b.to_string(),_=>raw.trim().to_string()};
   Value::String(decode_sentinels(&s)?)
  },_=>v.clone()
 })
}
pub fn decode(bytes: &[u8], tables: &Tables, password: Option<&str>) -> R<Decoded> {
 if bytes.len()<9 || bytes.len()>MAX || !bytes.starts_with(b"NPVS") {return Err(bad("truncated NPVS header"));}
 if bytes[4]!=5 {return Err(bad("unsupported NPVS envelope version"));}
 let hl=u32at(bytes,5)?;if hl<135 {return Err(bad("truncated NPVS compact header"));}
 let h=cut(bytes,9,hl)?;if h[0]!=1 {return Err(bad("unsupported NPVS compact header"));}
 let method=h[50];let recipients=u16at(h,51)?;if recipients>1024 {return Err(bad("too many NPVS recipients"));}
 let mut off=53+recipients*125;
 let (salt,wrap,iterations)=match method {
  1=>{let it=u32at(h,off)?;if !(1..=2_000_000).contains(&it) {return Err(bad("unsupported NPVS password work factor"));}
   let s=cut(h,off+4,16)?;let w=cut(h,off+20,60)?;off+=80;(s,w,it)},
  2=>{if u16at(h,off)?!=2 {return Err(bad("bad NPVS app-key block"));}
   let s=cut(h,off+2,16)?;let w=cut(h,off+18,60)?;off+=78;(s,w,0)},
  0=>return Err(bad("NPVS recipient-bound config requires its owner's device key")),
  _=>return Err(bad("unsupported NPVS unlock method"))
 };
 let ml=u32at(h,off)?;if off+4+ml!=h.len() {return Err(bad("invalid NPVS metadata length"));}
 let meta=cut(h,off+4,ml)?;let prefix=cut(h,0,off)?;
 let bo=9+hl;let nonce=cut(bytes,bo,12)?;let bl=u32at(bytes,bo+12)?;let body=cut(bytes,bo+16,bl)?;
 if bo+16+bl+64!=bytes.len() {return Err(bad("invalid NPVS body length"));}
 let creator=VerifyingKey::from_sec1_bytes(cut(h,17,33)?).map_err(|_|bad("NPVS creator signature is invalid"))?;
 let sig=Signature::from_slice(&bytes[bytes.len()-64..]).map_err(|_|bad("NPVS creator signature is invalid"))?;
 creator.verify(&bytes[..bytes.len()-64],&sig).map_err(|_|bad("NPVS creator signature is invalid"))?;
 let mut kdk=Zeroizing::new([0u8;32]);
 if method==1 {
  let pw=password.filter(|p|!p.is_empty()).ok_or(ImportError::Password{wrong:false})?;
  pbkdf2::pbkdf2_hmac::<Sha256>(pw.as_bytes(),salt,iterations as u32,&mut *kdk);
 } else {
  let mut input=[0u32;16];for (i,c) in input.iter_mut().enumerate(){*c=salt[i] as u32;}
  let a=Zeroizing::new(tables.encrypt_block(&input).map(|v|v as u8));
  let mut sha=Sha256::new();sha.update(b"npvtunnel/appkey/v2 ");sha.update(&*a);sha.update(cut(h,1,16)?);kdk.copy_from_slice(&sha.finalize());
 }
 let dek=open(&*kdk,&wrap[..12],&wrap[12..],salt).map_err(|e|if method==1 {ImportError::Password{wrong:true}} else {e})?;
 if dek.len()!=32 {return Err(bad("invalid NPVS content key"));}
 let mk=hkdf(&dek,nonce,b"NPVS-v5/metadata")?;
 let mb=open(&*mk,nonce,meta,prefix)?;
 let metadata:Value=serde_json::from_slice(&mb).map_err(|_|bad("invalid NPVS metadata"))?;
 let policy=metadata.get("policy").and_then(Value::as_object).ok_or_else(||bad("NPVS policy missing"))?;
 let att=policy.get("attestationLevel").and_then(Value::as_str).unwrap_or("");
 if !att.is_empty() && att!="NONE" {return Err(bad("NPVS device attestation is not supported"));}
 if body.len()<38 || !body.starts_with(b"NPF\x01") {return Err(bad("invalid NPVS NPF body"));}
 let cid=cut(body,4,32)?;let count=u16at(body,36)?;if !(1..=8192).contains(&count){return Err(bad("invalid NPVS field count"));}
 let mut fields=BTreeMap::new();let mut p=38;
 for _ in 0..count {
  let seq=u16at(body,p)?;let flags=u16at(body,p+2)?;let len=u16at(body,p+4)?;p+=6;
  if flags!=0 || fields.contains_key(&seq) || len<16 {return Err(bad("unsupported or duplicate NPVS field"));}
  let blob=cut(body,p,len)?;p+=len;let seqbe=(seq as u16).to_be_bytes();
  let mut info=b"NPV-fields-v1/field/".to_vec();info.extend(seqbe);let key=hkdf(&dek,cid,&info)?;
  let mut aad=b"NPV-fields-v1/record/".to_vec();aad.extend(cid);aad.extend(seqbe);aad.extend(((len-16) as u32).to_be_bytes());
  fields.insert(seq,open(&*key,&[0;12],blob,&aad)?);
 }
 if p+32!=body.len() {return Err(bad("invalid NPVS NPF trailer length"));}
 let spec:Value=serde_json::from_slice(fields.get(&65535).ok_or_else(||bad("NPVS config table missing"))?).map_err(|_|bad("invalid NPVS config table"))?;
 let configs=spec.get("configs").and_then(Value::as_array).ok_or_else(||bad("NPVS configs missing"))?;
 if configs.is_empty() || configs.len()>500 {return Err(bad("invalid NPVS config count"));}
 let mut servers=Vec::new();for c in configs {
  let mut v=substitute(c,&fields,0)?;
  let o=v.as_object_mut().ok_or_else(||bad("NPVS server is not an object"))?;
  if !o.get("v2rayProfile").map(Value::is_object).unwrap_or(false) || o.contains_key("lockConfig") {return Err(bad("unsupported NPVS server or nested lock policy"));}
  o.insert("type".into(),json!("V2RAY"));servers.push(v);
 }
 let expiry=policy.get("expiresAt").and_then(Value::as_str).unwrap_or("");
 if !expiry.is_empty() && super::parser::parse_expiry(expiry)<=0 {return Err(bad("invalid NPVS expiry"));}
 let msg=["displayMessage","customServerMessage"].iter().filter_map(|k|policy.get(*k).and_then(Value::as_str)).filter(|s|!s.trim().is_empty()).collect::<Vec<_>>().join("\n");
 let lock=json!({"isLocked":true,"expiryDate":expiry,"onlyMobileNetwork":policy.get("onlyMobileNetwork").and_then(Value::as_bool).unwrap_or(false),"message":msg});
 Ok(Decoded{version:1,servers:Value::Array(servers).to_string(),lock:lock.to_string()})
}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn malformed_fails_closed(){ for b in [b"NPVS".as_slice(),b"NPVS\x05\xff\xff\xff\xff",b"NPVS\x04\0\0\0\0"] { assert!(decode(b,npvt::tables(),None).is_err()); } }
 #[test] fn sentinels(){assert_eq!(decode_sentinels("x npvs1:aGVsbG8=!").unwrap(),"x hello!");}
}

#[cfg(test)] mod envelope_tests {
 use super::*;
 use p256::ecdsa::{signature::Signer,SigningKey};
 fn seal(k:&[u8],n:&[u8],p:&[u8],a:&[u8])->Vec<u8>{ChaCha20Poly1305::new_from_slice(k).unwrap().encrypt(Nonce::from_slice(n),Payload{msg:p,aad:a}).unwrap()}
 pub(super) fn fixture(password:Option<&str>,expiry:&str,mobile:bool)->Vec<u8>{
  let signing=SigningKey::from_slice(&[1u8;32]).unwrap();let creator=signing.verifying_key().to_encoded_point(true);
  let cid=[1u8;16];let salt=[2u8;16];let nonce=[3u8;12];let dek=[4u8;32];let wn=[5u8;12];let content=[6u8;32];
  let tables=npvt::Tables::parse(include_bytes!("gen2-wb.bin")).unwrap();let mut kdk=[0u8;32];
  if let Some(pw)=password {pbkdf2::pbkdf2_hmac::<Sha256>(pw.as_bytes(),&salt,100,&mut kdk);}else{
   let block=tables.encrypt_block(&[2u32;16]).map(|v|v as u8);let mut sha=Sha256::new();sha.update(b"npvtunnel/appkey/v2 ");sha.update(block);sha.update(cid);kdk.copy_from_slice(&sha.finalize());
  }
  let mut prefix=vec![1];prefix.extend(cid);prefix.extend(creator.as_bytes());prefix.push(if password.is_some(){1}else{2});prefix.extend(0u16.to_be_bytes());
  if password.is_some(){prefix.extend(100u32.to_be_bytes());}else{prefix.extend(2u16.to_be_bytes());}
  prefix.extend(salt);prefix.extend(wn);prefix.extend(seal(&kdk,&wn,&dek,&salt));
  let meta=json!({"policy":{"attestationLevel":"NONE","expiresAt":expiry,"onlyMobileNetwork":mobile,"displayMessage":"Synthetic"}}).to_string();
  let mk=hkdf(&dek,&nonce,b"NPVS-v5/metadata").unwrap();let sealed=seal(&*mk,&nonce,meta.as_bytes(),&prefix);
  let mut header=prefix;header.extend((sealed.len() as u32).to_be_bytes());header.extend(sealed);
  let fields=[(1u16,"\"Synthetic\""),(2,"\"server.invalid\""),(3,"5"),(4,"\"npvs1:NDQz\""),(5,"\"11111111-2222-3333-4444-555555555555\""),(6,"\"tcp\""),(7,"\"none\""),(65535,r#"{"configs":[{"name":1,"v2rayProfile":{"server":2,"configType":3,"serverPort":4,"password":5,"network":6,"security":7}}]}"#)];
  let mut body=b"NPF\x01".to_vec();body.extend(content);body.extend((fields.len() as u16).to_be_bytes());
  for(seq,plain)in fields {let mut info=b"NPV-fields-v1/field/".to_vec();info.extend(seq.to_be_bytes());let key=hkdf(&dek,&content,&info).unwrap();let mut aad=b"NPV-fields-v1/record/".to_vec();aad.extend(content);aad.extend(seq.to_be_bytes());aad.extend((plain.len() as u32).to_be_bytes());let c=seal(&*key,&[0;12],plain.as_bytes(),&aad);body.extend(seq.to_be_bytes());body.extend(0u16.to_be_bytes());body.extend((c.len() as u16).to_be_bytes());body.extend(c);}
  body.extend([0;32]);let mut env=b"NPVS\x05".to_vec();env.extend((header.len() as u32).to_be_bytes());env.extend(header);env.extend(nonce);env.extend((body.len() as u32).to_be_bytes());env.extend(body);
  let sig:Signature=signing.sign(&env);env.extend(sig.to_bytes());env
 }
 #[test] fn appkey_locked_import(){let b=fixture(None,"",false);let cs=super::super::parser::parse_bytes(&b,super::super::ConfigSource::File,None,1).unwrap();assert_eq!(cs.len(),1);let c=&cs[0];assert!(c.locked && !c.mobile_only);assert!(c.raw.is_empty()&&c.server.is_empty());assert!(c.outbound.contains("server.invalid")&&c.outbound.contains("443"));}
 #[test] fn password_policy(){let b=fixture(Some("correct"),"",false);assert!(matches!(npvt::decode_bytes(&b,None),Err(ImportError::Password{wrong:false})));assert!(matches!(npvt::decode_bytes(&b,Some("wrong")),Err(ImportError::Password{wrong:true})));assert!(npvt::decode_bytes(&b,Some("correct")).is_ok());}
 #[test] fn expiry_enforced(){let b=fixture(None,"2020-01-01",false);let r=super::super::parser::parse_bytes(&b,super::super::ConfigSource::File,None,1_800_000_000_000);assert!(r.is_err());}
 #[test] fn tamper_truncate_overflow(){let b=fixture(None,"",false);let mut bad=b.clone();*bad.last_mut().unwrap()^=1;let mut length=b.clone();length[5]=127;for v in [bad,length,b[..b.len()-1].to_vec(),[b.clone(),vec![0]].concat()] {assert!(npvt::decode_bytes(&v,None).is_err());}}
}

#[cfg(test)]mod mobile_policy_tests {use super::*;#[test]fn mobile_only_rejected_on_windows(){let bytes=super::envelope_tests::fixture(None,"",true);assert!(super::super::parser::parse_bytes(&bytes,super::super::ConfigSource::File,None,1).is_err());}}

/// Interop with an envelope written by an independent implementation of the mobile
/// wire format (`testdata/make_npvs.py`, HMAC-based HKDF, PBKDF2 unlock, Persian text,
/// two servers, numeric field references and an `npvs1:` sentinel).
#[cfg(test)]
mod interop_tests {
    use super::*;
    const FILE: &[u8] = include_bytes!("testdata/synthetic_pw.npvs");
    const PW: &str = "pw-سلام";
    fn parse(b: &[u8], pw: Option<&str>) -> Result<Vec<super::super::CustomConfig>, ImportError> {
        super::super::parser::parse_bytes(b, super::super::ConfigSource::File, pw, 1)
    }
    #[test] fn independent_envelope_decodes_to_two_locked_servers() {
        let cs = parse(FILE, Some(PW)).unwrap();
        assert_eq!(cs.len(), 2);
        assert!(cs[0].name.starts_with("سرور آزمایشی ۱"), "{}", cs[0].name);
        assert!(cs[1].name.starts_with("سرور آزمایشی ۲"), "{}", cs[1].name);
        assert!(cs.iter().all(|c| c.locked && c.raw.is_empty() && c.server.is_empty()));
        assert!(cs[0].outbound.contains("one.example.invalid") && cs[0].outbound.contains("443"));
        assert!(cs[1].outbound.contains("two.example.invalid") && cs[1].outbound.contains("8443"));
    }
    #[test] fn password_prompt_and_wrong_password() {
        assert!(matches!(parse(FILE, None), Err(ImportError::Password { wrong: false })));
        assert!(matches!(parse(FILE, Some("nope")), Err(ImportError::Password { wrong: true })));
    }
    #[test] fn any_single_byte_flip_is_rejected() {
        for i in (0..FILE.len()).step_by(7) {
            let mut b = FILE.to_vec(); b[i] ^= 1;
            assert!(parse(&b, Some(PW)).is_err(), "flip at {i} was accepted");
        }
    }
    #[test] fn truncation_and_trailing_bytes_are_rejected() {
        for n in [0, 4, 8, 9, 100, FILE.len() - 1] { assert!(parse(&FILE[..n], Some(PW)).is_err(), "len {n}"); }
        assert!(parse(&[FILE, &[0]].concat(), Some(PW)).is_err());
    }
}
