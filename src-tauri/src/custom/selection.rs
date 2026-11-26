//! Freshness and hysteresis shared by UI ping, session startup and periodic group selection.
use super::{store::State, realdelay::{Delay,Verdict}};
use std::{collections::BTreeMap,sync::{Mutex,OnceLock},time::{Instant,Duration}};
#[derive(Clone)]pub struct Report {pub ms:i64,pub at:Instant,pub ok:bool}
fn cache()->&'static Mutex<BTreeMap<String,Report>>{static C:OnceLock<Mutex<BTreeMap<String,Report>>>=OnceLock::new();C.get_or_init(||Mutex::new(BTreeMap::new()))}
pub fn record(rows:&[Delay]) {let mut c=cache().lock().unwrap_or_else(|p|p.into_inner());for r in rows{c.insert(r.id.clone(),Report{ms:r.ms,at:Instant::now(),ok:r.status==Verdict::Ok});}if c.len()>1000{c.retain(|_,r|r.at.elapsed()<Duration::from_secs(120));}}
pub fn group_configs(s:&State)->Vec<super::CustomConfig>{let group=s.active_id.as_ref().and_then(|id|s.membership.get(id));s.configs.iter().filter(|c|s.membership.get(&c.id)==group && !c.is_expired(super::now_millis()) && !c.mobile_only).cloned().collect()}
pub fn choose(s:&State,reports:&BTreeMap<String,Report>,now:Instant)->Option<String>{choose_with(s,reports,now,50,5)}
/// 1.5.0 (same version): the threshold is a parameter. Steady health checks keep
/// 50 ms / 20 %; a run the user asked for ("Test all") or the run after a network
/// change uses 20 ms / 10 %, because the user wants the fastest server now.
pub fn choose_with(s:&State,reports:&BTreeMap<String,Report>,now:Instant,min_gain:i64,divisor:i64)->Option<String>{
 let valid:Vec<_>=group_configs(s).into_iter().filter(|c|reports.get(&c.id).map(|r|r.ok&&r.ms>=1&&now.checked_duration_since(r.at).map(|d|d<=Duration::from_secs(120)).unwrap_or(false)).unwrap_or(false)).collect();
 let best=valid.iter().min_by_key(|c|(reports[&c.id].ms,&c.id))?;
 if let Some(current)=valid.iter().find(|c|Some(&c.id)==s.active_id.as_ref()) {let old=reports[&current.id].ms;let next=reports[&best.id].ms;if old-next<min_gain.max(old/divisor.max(1)){return Some(current.id.clone());}}
 Some(best.id.clone())
}
pub fn cached_choice(s:&State)->Option<String>{choose(s,&cache().lock().unwrap_or_else(|p|p.into_inner()),Instant::now())}
/// Same as [`cached_choice`] with the eager (manual-test) threshold.
pub fn cached_choice_eager(s:&State)->Option<String>{choose_with(s,&cache().lock().unwrap_or_else(|p|p.into_inner()),Instant::now(),20,10)}

static MANUAL_RUN:std::sync::atomic::AtomicBool=std::sync::atomic::AtomicBool::new(false);
/// A "Test all" run just finished: the live session should switch to the fastest server.
pub fn mark_manual_run(){MANUAL_RUN.store(true,std::sync::atomic::Ordering::SeqCst);}
/// Consumes the flag set by [`mark_manual_run`].
pub fn take_manual_run()->bool{MANUAL_RUN.swap(false,std::sync::atomic::Ordering::SeqCst)}
#[cfg(test)]mod tests {
 use super::*;
 fn state()->State{let cs=super::super::parser::parse("vless://a@server.invalid:443#a\nvless://b@server.invalid:443#b",super::super::ConfigSource::Link,None,1).unwrap();State::default().add(cs)}
 #[test]fn hysteresis_and_freshness(){let s=state();let now=Instant::now();let a=s.configs[0].id.clone();let b=s.configs[1].id.clone();let mut r=BTreeMap::from([(a.clone(),Report{ms:200,at:now,ok:true}),(b.clone(),Report{ms:170,at:now,ok:true})]);assert_eq!(choose(&s,&r,now),Some(a));r.get_mut(&b).unwrap().ms=100;assert_eq!(choose(&s,&r,now),Some(b));assert_eq!(choose(&s,&r,now+Duration::from_secs(121)),None);}
 #[test]fn eager_threshold_and_manual_flag(){let s=state();let now=Instant::now();let a=s.configs[0].id.clone();let b=s.configs[1].id.clone();let s=s.clone();let mut st=s;st.active_id=Some(a.clone());let r=BTreeMap::from([(a.clone(),Report{ms:150,at:now,ok:true}),(b.clone(),Report{ms:115,at:now,ok:true})]);assert_eq!(choose(&st,&r,now),Some(a.clone()));assert_eq!(choose_with(&st,&r,now,20,10),Some(b));let _=take_manual_run();mark_manual_run();assert!(take_manual_run());assert!(!take_manual_run());}
 #[test]fn group_scope(){let mut s=state();s.membership.insert(s.configs[1].id.clone(),"user:other".into());assert_eq!(group_configs(&s).len(),1);}
}
