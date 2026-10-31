//! Stable, privacy-preserving identity of the default uplink (not the VPN adapter).
use sha2::{Digest, Sha256};
#[derive(Debug, Clone)]
pub struct Identity {
    pub key: String,
    pub mobile: bool,
}
pub fn hash_link(kind: u32, gateway: &[Vec<u8>], dns: &[Vec<u8>], suffix: &str) -> String {
    let mut g = gateway.to_vec();
    g.sort();
    let mut d = dns.to_vec();
    d.sort();
    let raw = format!("{kind}|{g:?}|{d:?}|{suffix}");
    let sha = Sha256::digest(raw.as_bytes());
    sha[..6].iter().map(|b| format!("{b:02x}")).collect()
}
#[cfg(not(windows))]
pub fn current() -> Identity {
    Identity {
        key: "none".into(),
        mobile: false,
    }
}
#[cfg(windows)]
pub fn current() -> Identity {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GetBestInterface, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    let unknown = || Identity {
        key: "none".into(),
        mobile: false,
    };
    let mut index = 0;
    unsafe {
        if GetBestInterface(u32::from_ne_bytes([1, 1, 1, 1]), &mut index) != 0 {
            return unknown();
        }
    }
    let mut size = 16384;
    let mut buf = Vec::<u64>::new();
    let mut ok = false;
    for _ in 0..3 {
        buf = vec![0; (size as usize).div_ceil(8)];
        let rc = unsafe {
            GetAdaptersAddresses(
                0,
                GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST,
                None,
                Some(buf.as_mut_ptr().cast()),
                &mut size,
            )
        };
        if rc == 0 {
            ok = true;
            break;
        }
        if rc != 111 {
            return unknown();
        }
    }
    if !ok {
        return unknown();
    }
    let mut cur = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut guard = 0;
    while !cur.is_null() && guard < 1024 {
        guard += 1;
        let a = unsafe { &*cur };
        cur = a.Next;
        let idx = unsafe { a.Anonymous1.Anonymous.IfIndex };
        if idx != index || a.OperStatus.0 != 1 {
            continue;
        }
        // Match the physical default route, never a loopback/TUN pseudo-network.
        if !matches!(a.IfType, 6 | 71 | 243 | 244) {
            return unknown();
        }
        let addr = |p: *const windows::Win32::Networking::WinSock::SOCKADDR,
                    len: i32|
         -> Option<Vec<u8>> {
            if p.is_null() || len < 8 {
                return None;
            }
            let b = unsafe { std::slice::from_raw_parts(p.cast::<u8>(), len.min(128) as usize) };
            match u16::from_ne_bytes([b[0], b[1]]) {
                2 => Some(b[4..8].to_vec()),
                23 if b.len() >= 24 => Some(b[8..24].to_vec()),
                _ => None,
            }
        };
        let mut dns = vec![];
        let mut n = a.FirstDnsServerAddress;
        let mut count = 0;
        while !n.is_null() && count < 128 {
            count += 1;
            let e = unsafe { &*n };
            if let Some(ip) = addr(e.Address.lpSockaddr, e.Address.iSockaddrLength) {
                dns.push(ip);
            }
            n = e.Next;
        }
        let mut gateways = vec![];
        let mut n = a.FirstGatewayAddress;
        let mut count = 0;
        while !n.is_null() && count < 128 {
            count += 1;
            let e = unsafe { &*n };
            if let Some(ip) = addr(e.Address.lpSockaddr, e.Address.iSockaddrLength) {
                gateways.push(ip);
            }
            n = e.Next;
        }
        let suffix = unsafe { a.DnsSuffix.to_string() }.unwrap_or_default();
        if dns.is_empty() && gateways.is_empty() && suffix.is_empty() {
            return unknown();
        }
        return Identity {
            key: hash_link(
                a.IfType,
                &gateways,
                &dns,
                &format!("{}|{:?}", suffix, a.NetworkGuid),
            ),
            mobile: matches!(a.IfType, 243 | 244),
        };
    }
    unknown()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stable_and_network_specific() {
        let a = vec![vec![1, 1, 1, 1], vec![8, 8, 8, 8]];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(hash_link(6, &[], &a, ""), hash_link(6, &[], &b, ""));
        assert_ne!(hash_link(6, &[], &a, ""), hash_link(71, &[], &a, ""));
        assert_ne!(
            hash_link(6, &[], &a, ""),
            hash_link(6, &[vec![192, 168, 1, 1]], &a, "")
        );
        assert_eq!(hash_link(6, &[], &a, "").len(), 12);
    }
}
