//! TOTP (RFC 6238) inkl. otpauth://-URIs und Steam Guard.

use crate::crypto::R;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};

fn base32(s: &str) -> R<Vec<u8>> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.chars() {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            ' ' | '-' | '=' => continue,
            _ => return Err("TOTP-Schlüssel ist kein gültiges Base32".into()),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        return Err("TOTP-Schlüssel ist leer".into());
    }
    Ok(out)
}

macro_rules! mac {
    ($h:ty, $key:expr, $msg:expr) => {{
        let mut m = Hmac::<$h>::new_from_slice($key).map_err(|_| "HMAC".to_string())?;
        m.update($msg);
        m.finalize().into_bytes().to_vec()
    }};
}

pub fn totp(input: &str, now: u64) -> R<Value> {
    let s = input.trim();
    let lower = s.to_ascii_lowercase();
    let (mut secret, mut digits, mut period, mut algo, mut steam) =
        (s.to_string(), 6u32, 30u64, String::from("SHA1"), false);

    if lower.starts_with("otpauth://") {
        secret.clear();
        for kv in s.split_once('?').map_or("", |x| x.1).split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = v.replace("%3D", "").replace("%3d", "").replace("%20", ""),
                "digits" => digits = v.parse().unwrap_or(6),
                "period" => period = v.parse().unwrap_or(30),
                "algorithm" => algo = v.to_ascii_uppercase(),
                _ => {}
            }
        }
        if lower.starts_with("otpauth://steam/") {
            steam = true;
        }
    } else if lower.starts_with("steam://") {
        secret = s[8..].to_string();
        steam = true;
    }
    let digits = digits.clamp(1, 10);
    let period = period.max(1);

    let key = base32(&secret)?;
    let msg = (now / period).to_be_bytes();
    let h = match algo.as_str() {
        "SHA256" => mac!(sha2::Sha256, &key, &msg),
        "SHA512" => mac!(sha2::Sha512, &key, &msg),
        _ => mac!(sha1::Sha1, &key, &msg),
    };
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let mut bin = u32::from_be_bytes([h[off], h[off + 1], h[off + 2], h[off + 3]]) & 0x7fff_ffff;

    let code = if steam {
        const A: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";
        (0..5)
            .map(|_| {
                let c = A[(bin % 26) as usize] as char;
                bin /= 26;
                c
            })
            .collect()
    } else {
        let m = 10u64.pow(digits);
        format!("{:0width$}", bin as u64 % m, width = digits as usize)
    };
    Ok(json!({ "code": code, "period": period, "remaining": period - now % period }))
}
