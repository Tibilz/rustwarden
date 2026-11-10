//! Passwort- und Passphrasen-Generator (kryptografisch sicherer Zufall, ohne Modulo-Bias).

use crate::crypto::{random, R};
use serde_json::Value;

static WORDS: &str = include_str!("eff.txt");

fn below(n: u32) -> R<u32> {
    let limit = u32::MAX - u32::MAX % n;
    loop {
        let mut b = [0u8; 4];
        random(&mut b)?;
        let v = u32::from_le_bytes(b);
        if v < limit {
            return Ok(v % n);
        }
    }
}

fn pick(set: &[u8]) -> R<char> {
    Ok(set[below(set.len() as u32)? as usize] as char)
}

fn flag(o: &Value, k: &str, default: bool) -> bool {
    o[k].as_bool().unwrap_or(default)
}

pub fn password(o: &Value) -> R<String> {
    let len = o["length"].as_u64().unwrap_or(20).clamp(5, 128) as usize;
    let amb = flag(o, "avoidAmbiguous", false);
    let strip = |s: &str| -> Vec<u8> {
        s.bytes().filter(|c| !amb || !b"Il1O0".contains(c)).collect()
    };
    let mut sets: Vec<(Vec<u8>, usize)> = Vec::new();
    if flag(o, "upper", true) {
        sets.push((strip("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 1));
    }
    if flag(o, "lower", true) {
        sets.push((strip("abcdefghijklmnopqrstuvwxyz"), 1));
    }
    if flag(o, "numbers", true) {
        sets.push((strip("0123456789"), o["minNumbers"].as_u64().unwrap_or(1).max(1) as usize));
    }
    if flag(o, "special", true) {
        sets.push((b"!@#$%^&*".to_vec(), o["minSpecial"].as_u64().unwrap_or(1).max(1) as usize));
    }
    if sets.is_empty() {
        sets.push((strip("abcdefghijklmnopqrstuvwxyz"), 1));
    }
    let all: Vec<u8> = sets.iter().flat_map(|s| s.0.iter().copied()).collect();
    let mut out: Vec<char> = Vec::with_capacity(len);
    for (set, min) in &sets {
        for _ in 0..*min {
            if out.len() < len {
                out.push(pick(set)?);
            }
        }
    }
    while out.len() < len {
        out.push(pick(&all)?);
    }
    for i in (1..out.len()).rev() {
        out.swap(i, below(i as u32 + 1)? as usize);
    }
    Ok(out.into_iter().collect())
}

pub fn passphrase(o: &Value) -> R<String> {
    let words: Vec<&str> = WORDS.lines().filter(|l| !l.is_empty()).collect();
    let n = o["words"].as_u64().unwrap_or(4).clamp(3, 20) as usize;
    let sep = o["separator"].as_str().unwrap_or("-");
    let cap = flag(o, "capitalize", false);
    let num_at = if flag(o, "includeNumber", false) { Some(below(n as u32)? as usize) } else { None };
    let mut parts = Vec::with_capacity(n);
    for i in 0..n {
        let w = words[below(words.len() as u32)? as usize];
        let mut w = if cap {
            let mut c = w.chars();
            c.next().map(|f| f.to_uppercase().collect::<String>() + c.as_str()).unwrap_or_default()
        } else {
            w.to_string()
        };
        if num_at == Some(i) {
            w.push(char::from(b'0' + below(10)? as u8));
        }
        parts.push(w);
    }
    Ok(parts.join(sep))
}

fn word(cap: bool, number: bool) -> R<String> {
    passphrase(&serde_json::json!({ "words": 3, "separator": "", "capitalize": cap, "includeNumber": number }))
        .map(|w| w.chars().take(24).collect())
}

/// Benutzername: zufälliges Wort, Plus-Adresse (name+xyz@domain) oder Catch-all (xyz@domain).
pub fn username(o: &Value) -> R<String> {
    let mut rnd = String::new();
    for _ in 0..8 {
        rnd.push(pick(b"abcdefghijklmnopqrstuvwxyz0123456789")?);
    }
    let email = o["email"].as_str().unwrap_or("").trim();
    match o["mode"].as_str().unwrap_or("word") {
        "subaddress" => {
            let (local, domain) = email.split_once('@').ok_or("Bitte eine E-Mail-Adresse angeben")?;
            Ok(format!("{local}+{rnd}@{domain}"))
        }
        "catchall" => {
            let domain = email.rsplit('@').next().filter(|d| d.contains('.')).ok_or("Bitte eine Domain angeben")?;
            Ok(format!("{rnd}@{domain}"))
        }
        _ => word(flag(o, "capitalize", false), flag(o, "includeNumber", false)),
    }
}
