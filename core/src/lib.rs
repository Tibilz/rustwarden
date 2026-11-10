//! RustWarden-Kern: wird nach WebAssembly kompiliert und von der Safari-Erweiterung geladen.
//! Alle Funktionen sind zustandslos und tauschen JSON-Strings aus – die Background-Page darf
//! dadurch jederzeit entladen werden, ohne dass Zustand verloren geht.

pub mod crypto;
pub mod gen;
pub mod totp;
pub mod vault;

use crypto::R;
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

fn parse(s: &str) -> R<Value> {
    serde_json::from_str(s).map_err(|e| format!("Ungültiges JSON: {e}"))
}

fn js(r: R<String>) -> Result<String, JsError> {
    r.map_err(|e| JsError::new(&e))
}

/// -> { masterKey, hash }
#[wasm_bindgen]
pub fn derive_keys(email: &str, password: &str, kdf: &str) -> Result<String, JsError> {
    js((|| {
        let (mk, hash) = crypto::derive(email, password, &parse(kdf)?)?;
        Ok(json!({ "masterKey": crypto::b64(&mk), "hash": hash }).to_string())
    })())
}

/// -> Sitzungs-JSON { user, orgs }
#[wasm_bindgen]
pub fn open_session(master_key: &str, profile: &str) -> Result<String, JsError> {
    js((|| {
        let s = vault::open_session(&crypto::unb64(master_key)?, &parse(profile)?)?;
        Ok(s.to_json().to_string())
    })())
}

/// -> { ciphers, folders, collections } (entschlüsselt)
#[wasm_bindgen]
pub fn decrypt_vault(session: &str, vault_json: &str) -> Result<String, JsError> {
    js((|| {
        let s = vault::Session::parse(&parse(session)?)?;
        Ok(vault::decrypt_vault(&s, &parse(vault_json)?).to_string())
    })())
}

/// -> Request-Body für POST/PUT /ciphers
#[wasm_bindgen]
pub fn encrypt_cipher(session: &str, view: &str, orig: &str) -> Result<String, JsError> {
    js((|| {
        let s = vault::Session::parse(&parse(session)?)?;
        Ok(vault::encrypt_cipher(&s, &parse(view)?, &parse(orig)?)?.to_string())
    })())
}

#[wasm_bindgen]
pub fn encrypt_text(session: &str, text: &str) -> Result<String, JsError> {
    js((|| vault::encrypt_text(&vault::Session::parse(&parse(session)?)?, text))())
}

/// -> { code, period, remaining }
#[wasm_bindgen]
pub fn totp(secret: &str, now_secs: f64) -> Result<String, JsError> {
    js(totp::totp(secret, now_secs as u64).map(|v| v.to_string()))
}

#[wasm_bindgen]
pub fn generate(opts: &str) -> Result<String, JsError> {
    js((|| {
        let o = parse(opts)?;
        match o["type"].as_str() {
            Some("passphrase") => gen::passphrase(&o),
            Some("username") => gen::username(&o),
            _ => gen::password(&o),
        }
    })())
}

// ---- Bausteine für Anhänge, Send, PIN und Biometrie (Schlüssel jeweils als Base64) ----

fn key(b: &str) -> R<crypto::Key> {
    crypto::Key::from_bytes(&crypto::unb64(b)?)
}

fn jsv(r: R<Vec<u8>>) -> Result<Vec<u8>, JsError> {
    r.map_err(|e| JsError::new(&e))
}

#[wasm_bindgen]
pub fn stretch_key(master_key: &str) -> Result<String, JsError> {
    js((|| Ok(crypto::b64(&crypto::stretch(&crypto::unb64(master_key)?)?.to_bytes())))())
}

#[wasm_bindgen]
pub fn cipher_key(session: &str, cipher: &str) -> Result<String, JsError> {
    js((|| {
        let s = vault::Session::parse(&parse(session)?)?;
        Ok(crypto::b64(&vault::cipher_key(&s, &parse(cipher)?)?.to_bytes()))
    })())
}

#[wasm_bindgen]
pub fn key_encrypt(k: &str, data_b64: &str) -> Result<String, JsError> {
    js((|| crypto::encrypt(&crypto::unb64(data_b64)?, &key(k)?))())
}

#[wasm_bindgen]
pub fn key_decrypt(k: &str, enc: &str) -> Result<String, JsError> {
    js((|| Ok(crypto::b64(&crypto::decrypt(enc, &key(k)?)?)))())
}

#[wasm_bindgen]
pub fn text_encrypt(k: &str, text: &str) -> Result<String, JsError> {
    js((|| crypto::encrypt(text.as_bytes(), &key(k)?))())
}

#[wasm_bindgen]
pub fn text_decrypt(k: &str, enc: &str) -> Result<String, JsError> {
    js((|| String::from_utf8(crypto::decrypt(enc, &key(k)?)?).map_err(|_| "Kein Text".to_string()))())
}

#[wasm_bindgen]
pub fn buf_encrypt(k: &str, data: &[u8]) -> Result<Vec<u8>, JsError> {
    jsv((|| crypto::buf_encrypt(data, &key(k)?))())
}

#[wasm_bindgen]
pub fn buf_decrypt(k: &str, data: &[u8]) -> Result<Vec<u8>, JsError> {
    jsv((|| crypto::buf_decrypt(data, &key(k)?))())
}

#[wasm_bindgen]
pub fn random_b64(len: usize) -> Result<String, JsError> {
    js((|| {
        let mut b = vec![0u8; len.min(1024)];
        crypto::random(&mut b)?;
        Ok(crypto::b64(&b))
    })())
}

#[wasm_bindgen]
pub fn send_key(seed_b64: &str) -> Result<String, JsError> {
    js((|| Ok(crypto::b64(&crypto::send_key(&crypto::unb64(seed_b64)?)?.to_bytes())))())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Key;
    use rsa::pkcs8::EncodePrivateKey;

    fn account(password: &str, kdf: &Value) -> ([u8; 32], Key, String) {
        let (mk, _) = crypto::derive("User@Example.com ", password, kdf).unwrap();
        let mut raw = [0u8; 64];
        crypto::random(&mut raw).unwrap();
        let user = Key::from_bytes(&raw).unwrap();
        let protected = crypto::encrypt(&raw, &crypto::stretch(&mk).unwrap()).unwrap();
        (mk, user, protected)
    }

    #[test]
    fn totp_rfc6238() {
        let s = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp::totp(s, 59).unwrap()["code"], "287082");
        assert_eq!(totp::totp(s, 1111111109).unwrap()["code"], "081804");
        let uri = format!("otpauth://totp/x?secret={s}&digits=8&period=30&algorithm=SHA1");
        assert_eq!(totp::totp(&uri, 59).unwrap()["code"], "94287082");
        let s256 = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&digits=8&algorithm=SHA256";
        assert_eq!(totp::totp(s256, 59).unwrap()["code"], "46119246");
    }

    #[test]
    fn kdf_normalizes_email_as_salt() {
        // E-Mail wird getrimmt und kleingeschrieben als Salt verwendet.
        let kdf = json!({ "kdf": 0, "kdfIterations": 5000 });
        let (mk, _) = crypto::derive(" User@Example.com", "password", &kdf).unwrap();
        let mut expect = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(b"password", b"user@example.com", 5000, &mut expect);
        assert_eq!(mk, expect);
    }

    #[test]
    fn full_roundtrip_personal_and_org() {
        for kdf in [
            json!({ "kdf": 0, "kdfIterations": 1000 }),
            json!({ "kdf": 1, "kdfIterations": 2, "kdfMemory": 16, "kdfParallelism": 2 }),
        ] {
            let (mk, user, protected) = account("hunter2", &kdf);

            // RSA-Schlüsselpaar + Organisationsschlüssel
            let rsa_priv = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
            let der = rsa_priv.to_pkcs8_der().unwrap();
            let enc_priv = crypto::encrypt(der.as_bytes(), &user).unwrap();
            let mut org_raw = [0u8; 64];
            crypto::random(&mut org_raw).unwrap();
            let org_ct = rsa::RsaPublicKey::from(&rsa_priv)
                .encrypt(&mut rand::thread_rng(), rsa::Oaep::new::<sha1::Sha1>(), &org_raw)
                .unwrap();
            let profile = json!({
                "key": protected, "privateKey": enc_priv,
                "organizations": [{ "id": "org1", "key": format!("4.{}", crypto::b64(&org_ct)) }]
            });

            assert!(vault::open_session(&[7u8; 32], &profile).is_err());
            let s = vault::open_session(&mk, &profile).unwrap();
            let s = vault::Session::parse(&s.to_json()).unwrap();
            assert_eq!(s.orgs["org1"].to_bytes(), org_raw.to_vec());

            let view = json!({
                "type": 1, "name": "Beispiel", "notes": "geheim ✓", "favorite": true,
                "login": { "username": "bob", "password": "p@ss|2.x", "totp": null,
                           "uris": [{ "uri": "https://example.com", "match": null }] },
                "fields": [{ "type": 0, "name": "pin", "value": "1234" }]
            });
            let mut personal = vault::encrypt_cipher(&s, &view, &Value::Null).unwrap();
            personal["id"] = json!("c1");
            assert!(personal["name"].as_str().unwrap().starts_with("2."));
            assert!(personal["login"]["uris"][0]["uriChecksum"].is_string());

            // Organisationseintrag mit eigenem Cipher-Key
            let mut ck = [0u8; 64];
            crypto::random(&mut ck).unwrap();
            let orig = json!({ "organizationId": "org1", "revisionDate": "2026-01-01T00:00:00Z",
                               "key": crypto::encrypt(&ck, &s.orgs["org1"]).unwrap() });
            let mut shared = vault::encrypt_cipher(&s, &view, &orig).unwrap();
            shared["id"] = json!("c2");
            assert_eq!(shared["key"], orig["key"]);

            let folder = vault::encrypt_text(&s, "Privat").unwrap();
            let out = vault::decrypt_vault(&s, &json!({
                "ciphers": [personal, shared, { "id": "c3", "organizationId": "fremd", "name": "2.aaaa|bbbb|cccc" }],
                "folders": [{ "id": "f1", "name": folder }]
            }));
            for i in 0..2 {
                let c = &out["ciphers"][i];
                assert_eq!(c["name"], "Beispiel");
                assert_eq!(c["notes"], "geheim ✓");
                assert_eq!(c["login"]["password"], "p@ss|2.x");
                assert_eq!(c["login"]["uris"][0]["uri"], "https://example.com");
                assert_eq!(c["fields"][0]["value"], "1234");
                assert!(c.get("decryptError").is_none());
            }
            assert_eq!(out["ciphers"][2]["decryptError"], true);
            assert_eq!(out["folders"][0]["name"], "Privat");
        }
    }

    #[test]
    fn tampering_is_detected() {
        let k = Key::from_bytes(&[3u8; 64]).unwrap();
        let e = crypto::encrypt(b"hallo", &k).unwrap();
        assert_eq!(crypto::decrypt(&e, &k).unwrap(), b"hallo");
        let mut parts: Vec<String> = e[2..].split('|').map(String::from).collect();
        let mut ct = crypto::unb64(&parts[1]).unwrap();
        ct[0] ^= 1;
        parts[1] = crypto::b64(&ct);
        assert!(crypto::decrypt(&format!("2.{}", parts.join("|")), &k).is_err());
    }

    #[test]
    fn buffers_and_send_key() {
        let k = Key::from_bytes(&[9u8; 64]).unwrap();
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let mut e = crypto::buf_encrypt(&data, &k).unwrap();
        assert_eq!(crypto::buf_decrypt(&e, &k).unwrap(), data);
        let n = e.len() - 1;
        e[n] ^= 1;
        assert!(crypto::buf_decrypt(&e, &k).is_err());
        assert_eq!(crypto::send_key(&[1u8; 16]).unwrap().to_bytes().len(), 64);
        assert!(gen::username(&json!({ "mode": "subaddress", "email": "a@b.de" })).unwrap().starts_with("a+"));
        assert!(gen::username(&json!({ "mode": "catchall", "email": "b.de" })).unwrap().ends_with("@b.de"));
        assert!(!gen::username(&json!({})).unwrap().is_empty());
    }

    #[test]
    fn passkeys_are_encrypted_and_never_leak() {
        let s = vault::Session { user: Key::from_bytes(&[5u8; 64]).unwrap(), orgs: Default::default() };
        let cred = json!({ "credentialId": "11111111-2222-3333-4444-555555555555", "keyValue": "GEHEIMER-SCHLUESSEL",
                           "rpId": "example.com", "counter": "0", "creationDate": "2026-01-01T00:00:00Z" });
        let view = json!({ "type": 1, "name": "x", "login": { "username": "u", "newFido2Credentials": [cred] } });
        let mut first = vault::encrypt_cipher(&s, &view, &Value::Null).unwrap();
        let raw = first.to_string();
        assert!(!raw.contains("GEHEIMER") && !raw.contains("newFido2Credentials") && !raw.contains("example.com"));
        assert_eq!(first["login"]["fido2Credentials"][0]["creationDate"], "2026-01-01T00:00:00Z");
        first["id"] = json!("c1");
        let dec = vault::decrypt_vault(&s, &json!({ "ciphers": [first.clone()] }));
        assert_eq!(dec["ciphers"][0]["login"]["fido2Credentials"][0]["keyValue"], "GEHEIMER-SCHLUESSEL");

        // Bearbeiten: Klartext-Ansicht des Passkeys wird ignoriert, das verschlüsselte Original bleibt.
        let edited = vault::encrypt_cipher(&s, &dec["ciphers"][0], &first).unwrap();
        assert!(!edited.to_string().contains("GEHEIMER"));
        assert_eq!(edited["login"]["fido2Credentials"], first["login"]["fido2Credentials"]);
        // Entfernen
        let mut v = dec["ciphers"][0].clone();
        v["login"]["removeFido2"] = json!(true);
        let removed = vault::encrypt_cipher(&s, &v, &first).unwrap();
        assert!(removed["login"]["fido2Credentials"].is_null() && !removed.to_string().contains("removeFido2"));
    }

    #[test]
    fn generator() {
        let p = gen::password(&json!({ "length": 32, "avoidAmbiguous": true, "minNumbers": 3, "minSpecial": 3 })).unwrap();
        assert_eq!(p.chars().count(), 32);
        assert!(p.chars().filter(|c| c.is_ascii_digit()).count() >= 3);
        assert!(p.chars().filter(|c| "!@#$%^&*".contains(*c)).count() >= 3);
        assert!(!p.chars().any(|c| "Il1O0".contains(c)));
        let only = gen::password(&json!({ "length": 12, "upper": false, "numbers": false, "special": false })).unwrap();
        assert!(only.chars().all(|c| c.is_ascii_lowercase()));
        let pp = gen::passphrase(&json!({ "words": 5, "separator": ".", "capitalize": true, "includeNumber": true })).unwrap();
        assert_eq!(pp.split('.').count(), 5);
        assert!(pp.chars().any(|c| c.is_ascii_digit()));
    }
}
