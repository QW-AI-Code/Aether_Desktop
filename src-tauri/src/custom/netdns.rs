//! The network's own DNS resolvers, for the Xray that runs a custom config.
//!
//! # Why this exists (1.5.0, same version — "pings on Android, dead on Windows")
//!
//! Android hands Xray the resolvers of the active network first
//! (`XrayConfigBuilder.directDns(networkDns)`: network → 1.1.1.1 → 8.8.8.8 →
//! system). The Windows port always passed an EMPTY list, so a config whose
//! server is a NAME (CDN-fronted NapsternetV configs nearly always are) was
//! resolved by plain UDP DNS to 1.1.1.1 and then 8.8.8.8 only. On Iranian
//! networks both are routinely dropped or answered late; Xray waits for each
//! before it falls back to `localhost`, and the real-delay round and the
//! connection's own handshake ran out first. Result: the same file that pinged
//! and connected on Android showed "-1" and never connected on Windows.
//!
//! This module reads the IPv4 DNS servers of every adapter that is UP with
//! `GetAdaptersAddresses` (iphlpapi), skipping loopback and Aether's own Wintun
//! adapter (whose resolver lives inside the tunnel). Nothing is cached: the
//! call takes well under a millisecond and the network can change between two
//! connects. Outside Windows (unit tests on CI) the list is empty, which keeps
//! the old public-resolver behaviour.

/// IPv4 resolvers of the active network adapters, in adapter order, de-duplicated.
pub fn network_dns() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for ip in platform::adapter_dns() {
        if usable(&ip) && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// 1.5.0 (same version): one string that changes when the PC moves to another
/// network (Wi-Fi <-> Ethernet, another Wi-Fi, a phone hotspot): adapter names,
/// their IPv4 addresses and resolvers. Used to re-test and re-select custom
/// configs after a network change.
pub fn signature() -> String {
    let mut parts: Vec<String> = platform::adapters()
        .into_iter()
        .map(|(name, v4, dns)| format!("{name}={}/{}", v4.join(","), dns.join(",")))
        .collect();
    parts.sort();
    parts.join("|")
}

/// A resolver Xray can be pointed at directly: a unicast IPv4 that is not
/// loopback, unspecified, link-local, multicast or broadcast.
pub fn usable(ip: &str) -> bool {
    match ip.parse::<std::net::Ipv4Addr>() {
        Ok(v) => {
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_link_local()
                || v.is_multicast()
                || v.is_broadcast())
        }
        Err(_) => false,
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;

    const AF_INET: u32 = 2;
    const GAA_FLAG_SKIP_ANYCAST: u32 = 0x0002;
    const GAA_FLAG_SKIP_MULTICAST: u32 = 0x0004;
    const ERROR_SUCCESS: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_OPER_STATUS_UP: i32 = 1;
    /// Aether's own Wintun adapter (`tun.rs`, `ADAPTER_NAME`).
    const OWN_ADAPTER: &str = "Aether";

    /// Leading fields of `IP_ADAPTER_ADDRESSES_LH` (iptypes.h), in declaration
    /// order. Only this prefix is read; the buffer itself is sized by the OS.
    #[allow(dead_code)]
    #[repr(C)]
    struct AdapterAddresses {
        length: u32,
        if_index: u32,
        next: *const AdapterAddresses,
        adapter_name: *const u8,
        first_unicast: *const c_void,
        first_anycast: *const c_void,
        first_multicast: *const c_void,
        first_dns: *const DnsServer,
        dns_suffix: *const u16,
        description: *const u16,
        friendly_name: *const u16,
        physical_address: [u8; 8],
        physical_address_length: u32,
        flags: u32,
        mtu: u32,
        if_type: u32,
        oper_status: i32,
    }

    /// `IP_ADAPTER_DNS_SERVER_ADDRESS_XP`: a union (Alignment / Length+Reserved),
    /// `Next`, then a `SOCKET_ADDRESS` (pointer + length).
    #[allow(dead_code)]
    #[repr(C)]
    struct DnsServer {
        length: u32,
        reserved: u32,
        next: *const DnsServer,
        sockaddr: *const u8,
        sockaddr_len: i32,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetAdaptersAddresses(
            family: u32,
            flags: u32,
            reserved: *mut c_void,
            addresses: *mut AdapterAddresses,
            size: *mut u32,
        ) -> u32;
    }

    /// A NUL-terminated UTF-16 string (bounded).
    unsafe fn wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0usize;
        while n < 512 && *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }

    /// IPv4 resolvers of every usable adapter, in adapter order.
    /// IPv4 addresses of a `{Alignment, Next, SOCKET_ADDRESS}` linked list.
    ///
    /// # Safety
    /// `first` must be null or point into a buffer filled by GetAdaptersAddresses.
    unsafe fn walk(first: *const DnsServer) -> Vec<String> {
        let mut out = Vec::new();
        let mut d = first;
        let mut inner = 0;
        while !d.is_null() && inner < 32 {
            inner += 1;
            let ds = &*d;
            // SOCKADDR_IN: family (u16), port (u16), address (4 bytes).
            if !ds.sockaddr.is_null() && ds.sockaddr_len >= 8 {
                let b = std::slice::from_raw_parts(ds.sockaddr, 8);
                if u16::from_ne_bytes([b[0], b[1]]) == AF_INET as u16 {
                    out.push(format!("{}.{}.{}.{}", b[4], b[5], b[6], b[7]));
                }
            }
            d = ds.next;
        }
        out
    }

    pub fn adapter_dns() -> Vec<String> {
        adapters().into_iter().flat_map(|(_, _, dns)| dns).collect()
    }

    /// (friendly name, IPv4 addresses, IPv4 resolvers) of every adapter that is up,
    /// except loopback and Aether's own Wintun adapter.
    pub fn adapters() -> Vec<(String, Vec<String>, Vec<String>)> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        let mut size: u32 = 16 * 1024;
        for _ in 0..4 {
            // u64 storage: the OS writes 8-byte aligned structures into it.
            let words = (size as usize) / 8 + 2;
            let mut buf: Vec<u64> = vec![0u64; words];
            size = (words * 8) as u32;
            let head = buf.as_mut_ptr() as *mut AdapterAddresses;
            let rc = unsafe {
                GetAdaptersAddresses(AF_INET, flags, std::ptr::null_mut(), head, &mut size)
            };
            if rc == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if rc != ERROR_SUCCESS {
                return Vec::new();
            }
            let mut out: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
            let mut a = head as *const AdapterAddresses;
            let mut guard = 0;
            while !a.is_null() && guard < 256 {
                guard += 1;
                let ad = unsafe { &*a };
                let name = unsafe { wide(ad.friendly_name) };
                if ad.oper_status == IF_OPER_STATUS_UP
                    && ad.if_type != IF_TYPE_SOFTWARE_LOOPBACK
                    && name != OWN_ADAPTER
                {
                    // IP_ADAPTER_UNICAST_ADDRESS_LH starts with the same
                    // {Alignment, Next, SOCKET_ADDRESS} prefix as the DNS entry.
                    let v4 = unsafe { walk(ad.first_unicast as *const DnsServer) };
                    let dns = unsafe { walk(ad.first_dns) };
                    out.push((name, v4, dns));
                }
                a = ad.next;
            }
            // `buf` owns the memory every pointer above walked; it lives until here.
            let _ = &buf;
            return out;
        }
        Vec::new()
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn adapter_dns() -> Vec<String> {
        Vec::new()
    }
    pub fn adapters() -> Vec<(String, Vec<String>, Vec<String>)> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_unicast_ipv4_resolvers_are_used() {
        for ok in ["192.168.1.1", "10.0.0.1", "217.218.127.127", "1.1.1.1"] {
            assert!(usable(ok), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "224.0.0.251",
            "255.255.255.255",
            "fec0:0:0:ffff::1",
            "",
            "dns.example",
        ] {
            assert!(!usable(bad), "{bad}");
        }
    }

    #[test]
    fn signature_is_stable_between_two_reads() {
        assert_eq!(signature(), signature());
    }

    #[test]
    fn network_dns_never_panics_and_is_deduplicated() {
        let v = network_dns();
        let mut seen = std::collections::HashSet::new();
        assert!(v.iter().all(|d| seen.insert(d.clone())));
        assert!(v.iter().all(|d| usable(d)));
    }
}
