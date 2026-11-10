//! Sitzung (entschlüsselte Schlüssel) sowie Ent-/Verschlüsselung der Tresor-Einträge.

use crate::crypto::{self, b64, unb64, Key, R};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub struct Session {
    pub user: Key,
    pub orgs: HashMap<String, Key>,
}

impl Session {
    pub fn parse(v: &Value) -> R<Session> {
        let user = Key::from_bytes(&unb64(v["user"].as_str().ok_or("Sitzung ungültig")?)?)?;
        let mut orgs = HashMap::new();
        if let Some(m) = v["orgs"].as_object() {
            for (id, k) in m {
                if let Some(k) = k.as_str() {
                    orgs.insert(id.clone(), Key::from_bytes(&unb64(k)?)?);
                }
            }
        }
        Ok(Session { user, orgs })
    }

    pub fn to_json(&self) -> Value {
        let orgs: Map<String, Value> =
            self.orgs.iter().map(|(id, k)| (id.clone(), Value::String(b64(&k.to_bytes())))).collect();
        json!({ "user": b64(&self.user.to_bytes()), "orgs": orgs })
    }
}

/// Öffnet den Tresor: Master-Key -> User-Key -> privater Schlüssel -> Organisationsschlüssel.
/// `profile`: { key, privateKey, organizations: [{ id, key }] }
pub fn open_session(master_key: &[u8], profile: &Value) -> R<Session> {
    let pk = profile["key"].as_str().ok_or("Kein Benutzerschlüssel im Profil")?;
    let raw = match crypto::enc_type(pk) {
        Some(0) => crypto::decrypt(pk, &Key::from_bytes(master_key)?),
        Some(2) => crypto::decrypt(pk, &crypto::stretch(master_key)?),
        Some(7) => return Err("Dieses Konto nutzt das neue Schlüsselformat (Typ 7), das noch nicht unterstützt wird".into()),
        _ => return Err("Unbekanntes Format des Benutzerschlüssels".into()),
    }
    .map_err(|_| "Falsches Master-Passwort".to_string())?;
    let user = Key::from_bytes(&raw)?;

    let mut orgs = HashMap::new();
    let list = profile["organizations"].as_array().cloned().unwrap_or_default();
    if !list.is_empty() {
        if let Some(enc_priv) = profile["privateKey"].as_str() {
            let rsa = crypto::rsa_key(&crypto::decrypt(enc_priv, &user)?)?;
            for o in &list {
                if let (Some(id), Some(k)) = (o["id"].as_str(), o["key"].as_str()) {
                    if let Ok(k) = crypto::rsa_decrypt(k, &rsa).and_then(|b| Key::from_bytes(&b)) {
                        orgs.insert(id.to_string(), k);
                    }
                }
            }
        }
    }
    Ok(Session { user, orgs })
}

fn looks_enc(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() > 20
        && b[0].is_ascii_digit()
        && b[1] == b'.'
        && s.contains('|')
        && b[2..].iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'|'))
}

/// Entschlüsselt rekursiv alle EncStrings in einem JSON-Wert.
/// Binäre Inhalte (z. B. Anhang-Schlüssel) bleiben verschlüsselt stehen.
fn walk(v: &mut Value, key: &Key, bad: &mut bool) {
    match v {
        Value::String(s) => {
            if looks_enc(s) {
                match crypto::decrypt(s, key) {
                    Ok(b) => {
                        if let Ok(t) = String::from_utf8(b) {
                            *s = t;
                        }
                    }
                    Err(_) => {
                        *bad = true;
                        *v = Value::Null;
                    }
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| walk(x, key, bad)),
        Value::Object(o) => o.values_mut().for_each(|x| walk(x, key, bad)),
        _ => {}
    }
}

fn base_key<'a>(s: &'a Session, org: Option<&str>) -> Option<&'a Key> {
    match org {
        Some(id) => s.orgs.get(id),
        None => Some(&s.user),
    }
}

/// Schlüssel, mit dem die Felder eines Eintrags verschlüsselt sind (eigener Cipher-Key oder Basis).
pub fn cipher_key(s: &Session, c: &Value) -> R<Key> {
    let base = base_key(s, c["organizationId"].as_str()).ok_or("Organisationsschlüssel fehlt")?;
    match c["key"].as_str() {
        Some(k) => Key::from_bytes(&crypto::decrypt(k, base)?),
        None => Key::from_bytes(&base.to_bytes()),
    }
}

fn decrypt_item(s: &Session, src: &Value) -> Value {
    let mut c = src.clone();
    let mut bad = false;
    let own;
    let key = match base_key(s, src["organizationId"].as_str()) {
        None => None,
        Some(base) => match src["key"].as_str() {
            None => Some(base),
            Some(k) => match crypto::decrypt(k, base).and_then(|b| Key::from_bytes(&b)) {
                Ok(k) => {
                    own = k;
                    Some(&own)
                }
                Err(_) => None,
            },
        },
    };
    if let Some(o) = c.as_object_mut() {
        o.remove("key");
    }
    match key {
        Some(k) => walk(&mut c, k, &mut bad),
        None => bad = true,
    }
    if bad {
        c["decryptError"] = Value::Bool(true);
        if !c["name"].is_string() || key.is_none() {
            c["name"] = Value::String("[Nicht entschlüsselbar]".into());
        }
    }
    c
}

/// `vault`: { ciphers, folders, collections } (verschlüsselt, wie vom Sync geliefert)
pub fn decrypt_vault(s: &Session, vault: &Value) -> Value {
    let list = |k: &str| vault[k].as_array().cloned().unwrap_or_default();
    let ciphers: Vec<Value> = list("ciphers").iter().map(|c| decrypt_item(s, c)).collect();
    let folders: Vec<Value> = list("folders")
        .iter()
        .map(|f| {
            let c = decrypt_item(s, &json!({ "id": f["id"], "name": f["name"] }));
            json!({ "id": c["id"], "name": c["name"] })
        })
        .collect();
    let collections: Vec<Value> = list("collections")
        .iter()
        .map(|f| {
            let c = decrypt_item(
                s,
                &json!({ "id": f["id"], "name": f["name"], "organizationId": f["organizationId"] }),
            );
            json!({ "id": c["id"], "name": c["name"], "organizationId": c["organizationId"] })
        })
        .collect();
    json!({ "ciphers": ciphers, "folders": folders, "collections": collections })
}

fn enc_s(v: &Value, key: &Key) -> R<Value> {
    match v.as_str() {
        Some(s) if !s.is_empty() => Ok(Value::String(crypto::encrypt(s.as_bytes(), key)?)),
        _ => Ok(Value::Null),
    }
}

/// Verschlüsselt alle String-Felder eines Objekts (außer `skip`), Rest wird übernommen.
fn enc_all(o: &Value, key: &Key, skip: &[&str]) -> R<Map<String, Value>> {
    let mut out = Map::new();
    if let Some(m) = o.as_object() {
        for (k, v) in m {
            let val = if v.is_string() && !skip.contains(&k.as_str()) { enc_s(v, key)? } else { v.clone() };
            out.insert(k.clone(), val);
        }
    }
    Ok(out)
}

pub fn encrypt_text(s: &Session, text: &str) -> R<String> {
    crypto::encrypt(text.as_bytes(), &s.user)
}

/// Baut aus einer entschlüsselten Ansicht (`view`) den Request-Body für POST/PUT /ciphers.
/// `orig` ist der verschlüsselte Originaleintrag (oder null bei Neuanlage).
pub fn encrypt_cipher(s: &Session, view: &Value, orig: &Value) -> R<Value> {
    let org = orig["organizationId"].as_str().or(view["organizationId"].as_str());
    let base = base_key(s, org).ok_or("Organisationsschlüssel fehlt")?;
    let own;
    let key = match orig["key"].as_str() {
        Some(k) => {
            own = Key::from_bytes(&crypto::decrypt(k, base)?)?;
            &own
        }
        None => base,
    };
    if view["name"].as_str().map_or(true, |n| n.is_empty()) {
        return Err("Name darf nicht leer sein".into());
    }
    let ty = view["type"].as_u64().unwrap_or(1);
    let mut r = Map::new();
    r.insert("type".into(), json!(ty));
    r.insert("folderId".into(), view["folderId"].clone());
    r.insert("organizationId".into(), org.map_or(Value::Null, |o| json!(o)));
    r.insert("favorite".into(), json!(view["favorite"].as_bool().unwrap_or(false)));
    r.insert("reprompt".into(), json!(view["reprompt"].as_u64().unwrap_or(0)));
    r.insert("name".into(), enc_s(&view["name"], key)?);
    r.insert("notes".into(), enc_s(&view["notes"], key)?);
    r.insert("key".into(), orig["key"].clone());
    if orig["revisionDate"].is_string() {
        r.insert("lastKnownRevisionDate".into(), orig["revisionDate"].clone());
    }

    let mut fields = Vec::new();
    for f in view["fields"].as_array().into_iter().flatten() {
        fields.push(Value::Object(enc_all(f, key, &[])?));
    }
    r.insert("fields".into(), if fields.is_empty() { Value::Null } else { Value::Array(fields) });

    let mut hist = Vec::new();
    for h in view["passwordHistory"].as_array().into_iter().flatten() {
        hist.push(Value::Object(enc_all(h, key, &["lastUsedDate"])?));
    }
    r.insert("passwordHistory".into(), if hist.is_empty() { Value::Null } else { Value::Array(hist) });

    match ty {
        1 => {
            let mut l = enc_all(&view["login"], key, &["passwordRevisionDate"])?;
            // Steuerfelder der Oberfläche – dürfen nie (im Klartext) im Request landen.
            l.remove("newFido2Credentials");
            l.remove("removeFido2");
            let mut uris = Vec::new();
            for u in view["login"]["uris"].as_array().into_iter().flatten() {
                let Some(uri) = u["uri"].as_str().filter(|x| !x.is_empty()) else { continue };
                let sum = b64(&Sha256::digest(uri.as_bytes()));
                uris.push(json!({
                    "uri": crypto::encrypt(uri.as_bytes(), key)?,
                    "uriChecksum": crypto::encrypt(sum.as_bytes(), key)?,
                    "match": u["match"],
                }));
            }
            l.insert("uris".into(), if uris.is_empty() { Value::Null } else { Value::Array(uris) });
            // Bestehende Passkeys werden unverändert (verschlüsselt) aus dem Original übernommen,
            // neue (`newFido2Credentials`, Klartext) verschlüsselt angehängt.
            let mut fido: Vec<Value> = if view["login"]["removeFido2"].as_bool() == Some(true) {
                Vec::new()
            } else {
                orig["login"]["fido2Credentials"].as_array().cloned().unwrap_or_default()
            };
            for c in view["login"]["newFido2Credentials"].as_array().into_iter().flatten() {
                fido.push(Value::Object(enc_all(c, key, &["creationDate"])?));
            }
            l.insert("fido2Credentials".into(), if fido.is_empty() { Value::Null } else { Value::Array(fido) });
            r.insert("login".into(), Value::Object(l));
        }
        2 => {
            r.insert("secureNote".into(), json!({ "type": 0 }));
        }
        3 => {
            r.insert("card".into(), Value::Object(enc_all(&view["card"], key, &[])?));
        }
        4 => {
            r.insert("identity".into(), Value::Object(enc_all(&view["identity"], key, &[])?));
        }
        5 => {
            r.insert("sshKey".into(), Value::Object(enc_all(&view["sshKey"], key, &[])?));
        }
        n => return Err(format!("Unbekannter Eintragstyp {n}")),
    }
    Ok(Value::Object(r))
}
