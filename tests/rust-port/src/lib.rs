//! Executes the REAL shared production modules on a Linux host without linking Tauri/WebView2.
//! The sole engine shim supplies the conventional local SOCKS port; no live tunnel is simulated.
#![allow(dead_code, unused_imports)]
#[path="../../../src-tauri/src/log.rs"] pub mod log;
#[path="../../../src-tauri/src/procguard.rs"] pub mod procguard;
#[path="../../../src-tauri/src/secret_store.rs"] pub mod secret_store;
#[path="../../../src-tauri/src/geoip.rs"] pub mod geoip;
#[path="../../../src-tauri/src/probe.rs"] pub mod probe;
#[path="../../../src-tauri/src/mini_https.rs"] pub mod mini_https;
#[path="../../../src-tauri/src/custom/mod.rs"] pub mod custom;
pub mod engine {pub const LOCAL_SOCKS_PORT:u16=1819;pub const CHAIN_SOCKS_PORT:u16=1825;pub const TOR_SOCKS_PORT:u16=1820;pub fn exit_socks_port()->u16 {1819}}

pub mod smart_plus;

#[path="../../../src-tauri/src/uplink_policy.rs"] pub mod uplink_policy;

#[path="../../../src-tauri/src/ping.rs"] pub mod ping;
#[path="../../../src-tauri/src/uplink.rs"] pub mod uplink;

#[path="../../../src-tauri/src/ai_http.rs"] pub mod ai_http;
#[path="../../../src-tauri/src/ai_client.rs"] pub mod ai_client;
#[path="../../../src-tauri/src/ai_model_policy.rs"] pub mod ai_model_policy;
#[path="../../../src-tauri/src/ai_redaction.rs"] pub mod ai_redaction;
#[path="../../../src-tauri/src/zt_web.rs"] pub mod zt_web;
#[path="../../../src-tauri/src/zt_signin.rs"] pub mod zt_signin;

#[path="../../../src-tauri/src/presets.rs"] pub mod presets;

#[path="../../../src-tauri/src/profile.rs"] pub mod profile;
#[path="../../../src-tauri/src/exit_regions.rs"] pub mod exit_regions;
#[path="../../../src-tauri/src/leakguard.rs"] pub mod leakguard;
