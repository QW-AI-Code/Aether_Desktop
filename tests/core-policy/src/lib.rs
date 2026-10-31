//! Executes real portable native modules, without QUIC/BoringSSL/Tauri.
//! Only error::Other is shimmed to avoid linking the unused QUIC error variants.
#![allow(dead_code)]
pub mod error {
 #[derive(Debug)]pub enum AetherError {Other(String)}
 impl std::fmt::Display for AetherError {fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {match self {Self::Other(s)=>f.write_str(s)}}}
 impl std::error::Error for AetherError {}
 pub type Result<T>=std::result::Result<T,AetherError>;
}
#[path="../../../native/aether/aether/src/sysprofile.rs"]pub mod sysprofile;
#[path="../../../native/aether/aether/src/netstack.rs"]pub mod netstack;
#[path="../../../native/aether/aether/src/routing.rs"]pub mod routing;
#[path="../../../native/aether/aether/src/socket_tuning.rs"]pub mod socket_tuning;
