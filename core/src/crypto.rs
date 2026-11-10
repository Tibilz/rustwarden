//! Bitwarden-kompatible Kryptografie: KDF, EncStrings (AES-256-CBC + HMAC-SHA256), RSA-OAEP.

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rsa::{pkcs8::DecodePrivateKey, Oaep, RsaPrivateKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub type R<T> = Result<T, String>;

pub fn b64(d: &[u8]) -> String {
    B64.encode(d)
}

pub fn unb64(s: &str) -> R<Vec<u8>> {
    B64.decode(s.trim()).map_err(|_| "Ungültiges Base64".to_string())
}

pub fn random(buf: &mut [u8]) -> R<()> {
    getrandom::getrandom(buf).map_err(|e| format!("Zufallsquelle nicht verfügbar: {e}"))
}

/// Symmetrischer Schlüssel: 32 Byte AES + optional 32 Byte HMAC.
pub struct Key {
    pub enc: [u8; 32],
    pub mac: Option<[u8; 32]>,
}

impl Key {
    pub fn from_bytes(b: &[u8]) -> R<Key> {
        match b.len() {
            64 => Ok(Key {
                enc: b[..32].try_into().unwrap(),
                mac: Some(b[32..].try_into().unwrap()),
            }),
            32 => Ok(Key { enc: b.try_into().unwrap(), mac: None }),
            n => Err(format!("Unerwartete Schlüssellänge ({n} Byte)")),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.enc.to_vec();
        if let Some(m) = &self.mac {
            v.extend_from_slice(m);
        }
        v
    }
}

/// Leitet Master-Key und Login-Hash aus E-Mail + Master-Passwort ab.
/// `kdf`: { kdf: 0 (PBKDF2) | 1 (Argon2id), kdfIterations, kdfMemory, kdfParallelism }
pub fn derive(email: &str, password: &str, kdf: &Value) -> R<([u8; 32], String)> {
    let email = email.trim().to_lowercase();
    let iters = kdf["kdfIterations"].as_u64().unwrap_or(600_000) as u32;
    let mut mk = [0u8; 32];
    match kdf["kdf"].as_u64().unwrap_or(0) {
        0 => pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), email.as_bytes(), iters, &mut mk),
        1 => {
            let mem = kdf["kdfMemory"].as_u64().unwrap_or(64) as u32;
            let par = kdf["kdfParallelism"].as_u64().unwrap_or(4) as u32;
            let salt = Sha256::digest(email.as_bytes());
            let params = argon2::Params::new(mem * 1024, iters, par, Some(32))
                .map_err(|e| format!("Ungültige Argon2-Parameter: {e}"))?;
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(password.as_bytes(), &salt, &mut mk)
                .map_err(|e| format!("Argon2 fehlgeschlagen: {e}"))?;
        }
        n => return Err(format!("Unbekannter KDF-Typ {n}")),
    }
    let mut hash = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(&mk, password.as_bytes(), 1, &mut hash);
    Ok((mk, b64(&hash)))
}

/// HKDF-Expand des Master-Keys zu enc+mac (zum Entschlüsseln des User-Keys).
pub fn stretch(mk: &[u8]) -> R<Key> {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(mk).map_err(|_| "Ungültiger Master-Key".to_string())?;
    let (mut enc, mut mac) = ([0u8; 32], [0u8; 32]);
    hk.expand(b"enc", &mut enc).map_err(|_| "HKDF".to_string())?;
    hk.expand(b"mac", &mut mac).map_err(|_| "HKDF".to_string())?;
    Ok(Key { enc, mac: Some(mac) })
}

fn split(s: &str) -> R<(u8, Vec<&str>)> {
    let (t, rest) = s.split_once('.').ok_or("Kein EncString")?;
    let t: u8 = t.parse().map_err(|_| "Kein EncString".to_string())?;
    Ok((t, rest.split('|').collect()))
}

pub fn enc_type(s: &str) -> Option<u8> {
    split(s).ok().map(|x| x.0)
}

pub fn decrypt(s: &str, key: &Key) -> R<Vec<u8>> {
    let (t, p) = split(s)?;
    let (iv, ct) = match (t, p.len()) {
        (0, 2) => (unb64(p[0])?, unb64(p[1])?),
        (2, 3) => {
            let (iv, ct, tag) = (unb64(p[0])?, unb64(p[1])?, unb64(p[2])?);
            let mk = key.mac.as_ref().ok_or("Schlüssel ohne MAC-Anteil")?;
            let mut m = Hmac::<Sha256>::new_from_slice(mk).unwrap();
            m.update(&iv);
            m.update(&ct);
            m.verify_slice(&tag).map_err(|_| "MAC-Prüfung fehlgeschlagen".to_string())?;
            (iv, ct)
        }
        (7, _) => return Err("Neues Schlüsselformat (Typ 7) wird noch nicht unterstützt".into()),
        _ => return Err(format!("Nicht unterstützter Verschlüsselungstyp {t}")),
    };
    cbc::Decryptor::<Aes256>::new_from_slices(&key.enc, &iv)
        .map_err(|_| "Ungültiger IV".to_string())?
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| "Entschlüsselung fehlgeschlagen".to_string())
}

pub fn encrypt(data: &[u8], key: &Key) -> R<String> {
    let mk = key.mac.as_ref().ok_or("Schlüssel ohne MAC-Anteil")?;
    let mut iv = [0u8; 16];
    random(&mut iv)?;
    let ct = cbc::Encryptor::<Aes256>::new_from_slices(&key.enc, &iv)
        .map_err(|_| "Ungültiger IV".to_string())?
        .encrypt_padded_vec_mut::<Pkcs7>(data);
    let mut m = Hmac::<Sha256>::new_from_slice(mk).unwrap();
    m.update(&iv);
    m.update(&ct);
    Ok(format!("2.{}|{}|{}", b64(&iv), b64(&ct), b64(&m.finalize().into_bytes())))
}

pub fn rsa_key(der: &[u8]) -> R<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_der(der).map_err(|e| format!("Privater Schlüssel ungültig: {e}"))
}

pub fn rsa_decrypt(s: &str, pk: &RsaPrivateKey) -> R<Vec<u8>> {
    let (t, p) = split(s)?;
    let data = unb64(p[0])?;
    let pad = match t {
        3 | 5 => Oaep::new::<Sha256>(),
        4 | 6 => Oaep::new::<sha1::Sha1>(),
        _ => return Err(format!("Nicht unterstützter RSA-Typ {t}")),
    };
    pk.decrypt(pad, &data).map_err(|_| "RSA-Entschlüsselung fehlgeschlagen".to_string())
}

/// Binärformat für Anhänge/Send-Dateien: [Typ 2][IV 16][MAC 32][Ciphertext]
pub fn buf_encrypt(data: &[u8], key: &Key) -> R<Vec<u8>> {
    let mk = key.mac.as_ref().ok_or("Schlüssel ohne MAC-Anteil")?;
    let mut iv = [0u8; 16];
    random(&mut iv)?;
    let ct = cbc::Encryptor::<Aes256>::new_from_slices(&key.enc, &iv)
        .map_err(|_| "Ungültiger IV".to_string())?
        .encrypt_padded_vec_mut::<Pkcs7>(data);
    let mut m = Hmac::<Sha256>::new_from_slice(mk).unwrap();
    m.update(&iv);
    m.update(&ct);
    let mut out = Vec::with_capacity(49 + ct.len());
    out.push(2);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&m.finalize().into_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn buf_decrypt(data: &[u8], key: &Key) -> R<Vec<u8>> {
    if data.len() < 49 || data[0] != 2 {
        return Err("Unbekanntes Dateiformat".into());
    }
    let (iv, tag, ct) = (&data[1..17], &data[17..49], &data[49..]);
    let mk = key.mac.as_ref().ok_or("Schlüssel ohne MAC-Anteil")?;
    let mut m = Hmac::<Sha256>::new_from_slice(mk).unwrap();
    m.update(iv);
    m.update(ct);
    m.verify_slice(tag).map_err(|_| "MAC-Prüfung fehlgeschlagen".to_string())?;
    cbc::Decryptor::<Aes256>::new_from_slices(&key.enc, iv)
        .map_err(|_| "Ungültiger IV".to_string())?
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| "Entschlüsselung fehlgeschlagen".to_string())
}

/// Send: aus dem 16-Byte-Seed wird per HKDF der eigentliche 64-Byte-Schlüssel.
pub fn send_key(seed: &[u8]) -> R<Key> {
    let mut out = [0u8; 64];
    hkdf::Hkdf::<Sha256>::new(Some(b"bitwarden-send"), seed)
        .expand(b"send", &mut out)
        .map_err(|_| "HKDF".to_string())?;
    Key::from_bytes(&out)
}
