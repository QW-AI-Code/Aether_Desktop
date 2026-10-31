//! خوانندهٔ فایل‌های NapsternetV / Npv Tunnel (`.npvt`، سرآیندِ `NPVT1`) —
//! پورتِ **بایت‌به‌بایتِ** `NpvtCodec.kt` نسخهٔ اندروید ۱.۵.۰.
//!
//! ```text
//!   NPVT1
//!   <b64 part 1>,<b64 part 2>,<b64 part 3>
//! ```
//!
//! هر بخش `nonce(16) || ciphertext` است، AES در حالتِ CTR، با کلیدی که به شکلِ
//! جعبه‌سفید (جدول‌های جست‌وجو) نگه داشته شده و نه به‌صورتِ کلیدِ ساده. بخشِ ۱
//! نسخهٔ قالب (`1`)، بخشِ ۲ فهرستِ JSONِ سرورها و بخشِ ۳ تنظیماتِ قفلِ نویسنده
//! است. جدول‌ها همان `assets/npvt/wb.bin` اندروید‌اند که اینجا با
//! `include_bytes!` داخلِ باینری می‌نشینند.

use std::sync::OnceLock;

pub const HEADER: &str = "NPVT1";
pub fn is_binary(bytes: &[u8]) -> bool { bytes.starts_with(b"NPVS") }
pub fn decode_bytes(bytes: &[u8], password: Option<&str>) -> Result<Decoded, super::parser::ImportError> {
    static T: OnceLock<Tables> = OnceLock::new();
    let tables=T.get_or_init(||Tables::parse(include_bytes!("gen2-wb.bin")).expect("valid bundled gen2 tables"));
    super::npvs::decode(bytes, tables, password)
}
pub const SUB_HEADER: &str = "NPVTSUB1";
const BLOCK: usize = 16;

/// جدول‌های جعبه‌سفید — کپیِ دقیقِ `app/src/main/assets/npvt/wb.bin` (61445 بایت).
static WB_BIN: &[u8] = include_bytes!("wb.bin");

/// جدول‌ها، یک بار خوانده می‌شوند.
pub fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| Tables::parse(WB_BIN).expect("bundled npvt tables are valid"))
}

/// آیا `text` شبیهِ یک payloadِ `.npvt` است؟
pub fn looks_like(text: &str) -> bool {
    let t = text.trim_start_matches(['\u{feff}', ' ', '\n', '\r', '\t']);
    t.starts_with(HEADER) || t.starts_with(SUB_HEADER)
}

const SHIFT: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

fn shift_rows(b: &[u32; 16]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = b[SHIFT[i]];
    }
    out
}

/// جدول‌های AESِ جعبه‌سفید.
pub struct Tables {
    rounds: usize,
    xor: Vec<u8>,
    tybox: Vec<u32>,
    mbl: Vec<u32>,
    last: Vec<u8>,
}

impl Tables {
    fn x(&self, r: usize, i: usize, a: u32, b: u32) -> u32 {
        self.xor[((r * 96 + i) * 16 + (a & 15) as usize) * 16 + (b & 15) as usize] as u32
    }

    fn ty(&self, r: usize, i: usize, v: u32) -> u32 {
        self.tybox[(r * 16 + i) * 256 + (v & 0xFF) as usize]
    }

    fn mb(&self, r: usize, i: usize, v: u32) -> u32 {
        self.mbl[(r * 16 + i) * 256 + (v & 0xFF) as usize]
    }

    /// یک بلوکِ ۱۶ بایتی را رمز می‌کند (مولدِ keystreamِ CTR).
    pub fn encrypt_block(&self, input: &[u32; 16]) -> [u32; 16] {
        let mut b = *input;
        for r in 0..self.rounds {
            b = shift_rows(&b);
            for c in 0..4 {
                let o = c * 4;
                let mut v0 = self.ty(r, o, b[o]);
                let mut v1 = self.ty(r, o + 1, b[o + 1]);
                let mut v2 = self.ty(r, o + 2, b[o + 2]);
                let mut v3 = self.ty(r, o + 3, b[o + 3]);
                for j in 0..4 {
                    let k = c * 24 + j * 6;
                    let s1 = 28 - j * 8;
                    let s2 = 24 - j * 8;
                    let b10 = self.x(r, k, v0 >> s1, v1 >> s1);
                    let b11 = self.x(r, k + 1, v2 >> s1, v3 >> s1);
                    let i2 = self.x(r, k + 2, v0 >> s2, v1 >> s2);
                    let i3 = self.x(r, k + 3, v2 >> s2, v3 >> s2);
                    b[o + j] = (self.x(r, k + 5, i2, i3) | (self.x(r, k + 4, b10, b11) << 4)) & 0xFF;
                }
                v0 = self.mb(r, o, b[o]);
                v1 = self.mb(r, o + 1, b[o + 1]);
                v2 = self.mb(r, o + 2, b[o + 2]);
                v3 = self.mb(r, o + 3, b[o + 3]);
                for j in 0..4 {
                    let k = c * 24 + j * 6;
                    let s1 = 28 - j * 8;
                    let s2 = 24 - j * 8;
                    let e0 = self.x(r, k, v0 >> s1, v1 >> s1);
                    let e1 = self.x(r, k + 1, v2 >> s1, v3 >> s1);
                    let e2 = self.x(r, k + 2, v0 >> s2, v1 >> s2);
                    let e3 = self.x(r, k + 3, v2 >> s2, v3 >> s2);
                    b[o + j] = ((self.x(r, k + 4, e0, e1) << 4) | self.x(r, k + 5, e2, e3)) & 0xFF;
                }
            }
        }
        b = shift_rows(&b);
        let mut out = [0u32; 16];
        for (i, o) in out.iter_mut().enumerate() {
            *o = self.last[i * 256 + b[i] as usize] as u32;
        }
        out
    }

    /// CTR روی `nonce(16) || data`. رمزکردن و بازکردن یک عمل‌اند.
    pub fn ctr(&self, nonce_and_data: &[u8]) -> Result<Vec<u8>, String> {
        if nonce_and_data.len() < BLOCK {
            return Err("truncated npvt part".into());
        }
        let mut counter = [0u32; 16];
        for (i, c) in counter.iter_mut().enumerate() {
            *c = nonce_and_data[i] as u32;
        }
        let n = nonce_and_data.len() - BLOCK;
        let mut out = vec![0u8; n];
        let mut stream = [0u32; 16];
        for i in 0..n {
            let pos = i & 15;
            if pos == 0 {
                stream = self.encrypt_block(&counter);
                let mut k = 15i32;
                while k >= 0 {
                    let ku = k as usize;
                    counter[ku] = (counter[ku] + 1) & 0xFF;
                    if counter[ku] != 0 {
                        break;
                    }
                    k -= 1;
                }
            }
            out[i] = ((stream[pos] ^ nonce_and_data[BLOCK + i] as u32) & 0xFF) as u8;
        }
        Ok(out)
    }

    /// قالبِ `wb.bin`: `"AWB1"`، nr (یک بایت)، سپس برای nr-1 دور جدول‌های xor
    /// (96×16×16 نیم‌بایت)، جعبه‌های T-y (16×256 عددِ u32 بیگ‌اندین)، bijectionهای
    /// آمیزش (16×256 u32)، و در پایان جعبه‌های دورِ آخر (16×256 بایت).
    pub fn parse(blob: &[u8]) -> Result<Tables, String> {
        if blob.len() <= 5 || &blob[0..4] != b"AWB1" {
            return Err("not an npvt table file".into());
        }
        let nr = blob[4] as usize;
        if nr < 2 {
            return Err("bad round count".into());
        }
        let rounds = nr - 1;
        let xor_len = rounds * 96 * 256;
        let box_len = rounds * 16 * 256;
        if blob.len() != 5 + xor_len + box_len * 8 + 16 * 256 {
            return Err("npvt table file has the wrong size".into());
        }
        let mut p = 5;
        let xor = blob[p..p + xor_len].to_vec();
        p += xor_len;
        let u32s = |start: usize| -> Vec<u32> {
            (0..box_len)
                .map(|i| {
                    let q = start + i * 4;
                    u32::from_be_bytes([blob[q], blob[q + 1], blob[q + 2], blob[q + 3]])
                })
                .collect()
        };
        let tybox = u32s(p);
        p += box_len * 4;
        let mbl = u32s(p);
        p += box_len * 4;
        let last = blob[p..p + 16 * 256].to_vec();
        Ok(Tables {
            rounds,
            xor,
            tybox,
            mbl,
            last,
        })
    }
}

/// سه بخشِ بازشدهٔ یک فایل.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub version: i64,
    pub servers: String,
    pub lock: String,
}

/// یک متنِ `.npvt` را باز می‌کند؛ اگر فایلِ معتبری نباشد، علتِ خوانا برمی‌گرداند.
pub fn decode(text: &str, tables: &Tables) -> Result<Decoded, String> {
    let body = text.trim().trim_start_matches('\u{feff}');
    let body = if let Some(rest) = body.strip_prefix(SUB_HEADER) {
        rest
    } else if let Some(rest) = body.strip_prefix(HEADER) {
        rest
    } else {
        return Err("not an NPVT1 file".into());
    }
    .trim();
    let parts: Vec<&str> = body
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() != 3 {
        return Err(format!("unexpected npvt layout ({} parts)", parts.len()));
    }
    let mut plain = Vec::with_capacity(3);
    for part in parts {
        let bin = decode_base64(part).ok_or_else(|| "npvt part is not base64".to_string())?;
        let clear = tables.ctr(&bin)?;
        plain.push(String::from_utf8_lossy(&clear).trim().to_string());
    }
    let version: i64 = plain[0]
        .parse()
        .map_err(|_| "npvt file could not be decrypted".to_string())?;
    if version > 1 {
        return Err(format!(
            "this npvt file needs a newer NapsternetV format (version {version})"
        ));
    }
    Ok(Decoded {
        version,
        servers: plain[1].clone(),
        lock: plain[2].clone(),
    })
}

/// نسخهٔ رمزکنندهٔ همان قالب (فقط برای ساختِ فایل‌های آزمون؛ CTR متقارن است).
#[cfg_attr(not(test), allow(dead_code))]
pub fn encode(servers: &str, lock: &str, version: i64, tables: &Tables) -> String {
    let part = |plain: &str, seed: u8| -> String {
        let mut buf: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(7).wrapping_add(seed)).collect();
        buf.extend_from_slice(plain.as_bytes());
        let cipher = tables.ctr(&buf).expect("nonce present");
        let mut all = buf[..16].to_vec();
        all.extend_from_slice(&cipher);
        b64_encode(&all, STD_ALPHABET, true)
    };
    format!(
        "NPVT1\n{},{},{}",
        part(&version.to_string(), 1),
        part(servers, 2),
        part(lock, 3)
    )
}

// ------------------------------------------------------------------ base64

pub(crate) const STD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub(crate) const URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn b64_encode(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(alphabet[(n >> 18) as usize & 63] as char);
        out.push(alphabet[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(n >> 6) as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[n as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

/// base64 سخت‌گیر با یک الفبا. `None` برای هر نویسهٔ بیرون از الفبا یا طولِ نادرست.
pub(crate) fn b64_decode_strict(text: &str, alphabet: &[u8; 64]) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut lookup = [255u8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (ci, chunk) in bytes.chunks(4).enumerate() {
        let last = ci == bytes.len() / 4 - 1;
        let mut vals = [0u8; 4];
        let mut pads = 0;
        for (i, &c) in chunk.iter().enumerate() {
            if c == b'=' {
                if !last || i < 2 {
                    return None;
                }
                pads += 1;
                vals[i] = 0;
            } else {
                if pads > 0 {
                    return None;
                }
                let v = lookup[c as usize];
                if v == 255 {
                    return None;
                }
                vals[i] = v;
            }
        }
        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | vals[3] as u32;
        out.push((n >> 16) as u8);
        if pads < 2 {
            out.push((n >> 8) as u8);
        }
        if pads < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// `NpvtCodec.decodeBase64`: فاصله‌ها حذف، پَدینگ افزوده؛ اول الفبای استاندارد، بعد URL-safe.
pub(crate) fn decode_base64(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let padded = format!("{clean}{}", "=".repeat((4 - clean.len() % 4) % 4));
    b64_decode_strict(&padded, STD_ALPHABET).or_else(|| b64_decode_strict(&padded, URL_ALPHABET))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC: &str = include_str!("testdata/synthetic.npvt");

    #[test]
    fn bundled_tables_are_the_mobile_ones() {
        assert_eq!(WB_BIN.len(), 61_445);
        assert!(Tables::parse(WB_BIN).is_ok());
    }

    #[test]
    fn known_answer_file_decrypts_to_its_three_parts() {
        assert!(looks_like(SYNTHETIC));
        let d = decode(SYNTHETIC, tables()).unwrap();
        assert_eq!(d.version, 1);
        assert!(d.servers.contains("\"name\": \"Synthetic test\""), "{}", d.servers);
        assert!(d.servers.contains("11111111-2222-3333-4444-555555555555"));
        assert!(d.lock.contains("\"message\": \"hello\""), "{}", d.lock);
    }

    #[test]
    fn encrypting_with_the_same_tables_round_trips() {
        let text = encode("[]", "{\"isLocked\":false}", 1, tables());
        let d = decode(&text, tables()).unwrap();
        assert_eq!(d.servers, "[]");
        assert_eq!(d.lock, "{\"isLocked\":false}");
    }

    #[test]
    fn garbage_is_rejected_with_a_reason() {
        for bad in ["NPVT1\nnot,base64,!!!", "NPVT1\nAAAA", "hello"] {
            let e = decode(bad, tables()).unwrap_err();
            assert!(!e.trim().is_empty());
        }
    }

    #[test]
    fn base64_round_trip() {
        for data in [&b""[..], b"a", b"ab", b"abc", b"abcd", b"\x00\xff\x10"] {
            let e = b64_encode(data, STD_ALPHABET, true);
            assert_eq!(b64_decode_strict(&e, STD_ALPHABET).unwrap(), data);
        }
        assert_eq!(b64_encode(b"hi?", URL_ALPHABET, false), "aGk_");
    }
}
