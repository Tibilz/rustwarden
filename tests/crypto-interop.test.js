// Gegenprobe des WASM-Kerns mit einer unabhängigen Implementierung (Node.js crypto).
// Prüft, dass RustWarden genau das Bitwarden-Format erzeugt/liest und manipulierte Daten ablehnt.
// Aufruf: node tests/crypto-interop.test.js   (braucht extension/wasm/ aus ./build.sh)
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const c = require('crypto');

const dir = path.join(__dirname, '../extension/wasm');
vm.runInThisContext(fs.readFileSync(path.join(dir, 'rw_core.js'), 'utf8') + '\nglobalThis.wasm_bindgen = wasm_bindgen;');
const W = globalThis.wasm_bindgen;

let failed = 0;
let passed = 0;
function check(name, cond, info = '') {
  if (cond) passed++;
  else {
    failed++;
    console.error(`FEHLGESCHLAGEN: ${name}${info ? ' – ' + info : ''}`);
  }
}
function throws(fn) {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}
const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => Buffer.from(s, 'base64');

// --- Referenzimplementierung des Bitwarden-Formats ---
function hkdfExpand(prk, info, len) {
  let t = Buffer.alloc(0);
  const out = [];
  for (let i = 1; Buffer.concat(out).length < len; i++) {
    t = c.createHmac('sha256', prk).update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])])).digest();
    out.push(t);
  }
  return Buffer.concat(out).subarray(0, len);
}
function refEncrypt(data, key) {
  const iv = c.randomBytes(16);
  const ci = c.createCipheriv('aes-256-cbc', key.subarray(0, 32), iv);
  const ct = Buffer.concat([ci.update(data), ci.final()]);
  const mac = c.createHmac('sha256', key.subarray(32)).update(Buffer.concat([iv, ct])).digest();
  return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}
function refDecrypt(enc, key) {
  const [t, rest] = enc.split(/\.(.*)/s);
  const [iv, ct, mac] = rest.split('|').map(unb64);
  if (t !== '2') throw new Error('Typ');
  const exp = c.createHmac('sha256', key.subarray(32)).update(Buffer.concat([iv, ct])).digest();
  if (!c.timingSafeEqual(exp, mac)) throw new Error('MAC');
  const d = c.createDecipheriv('aes-256-cbc', key.subarray(0, 32), iv);
  return Buffer.concat([d.update(ct), d.final()]);
}

(async () => {
  await W({ module_or_path: fs.readFileSync(path.join(dir, 'rw_core_bg.wasm')) });

  // 1. KDF: PBKDF2 (Master-Key und Login-Hash) – E-Mail wird kleingeschrieben und getrimmt
  {
    const r = JSON.parse(W.derive_keys('  User@Example.com ', 'pässwört', JSON.stringify({ kdf: 0, kdfIterations: 100000 })));
    const mk = c.pbkdf2Sync('pässwört', 'user@example.com', 100000, 32, 'sha256');
    const hash = c.pbkdf2Sync(mk, 'pässwört', 1, 32, 'sha256');
    check('PBKDF2 Master-Key', r.masterKey === b64(mk));
    check('PBKDF2 Login-Hash', r.hash === b64(hash));
  }
  // 2. KDF: Argon2id (Salt = SHA-256 der E-Mail, Speicher in MiB)
  if (c.argon2Sync) {
    const r = JSON.parse(
      W.derive_keys('user@example.com', 'pw', JSON.stringify({ kdf: 1, kdfIterations: 2, kdfMemory: 16, kdfParallelism: 2 }))
    );
    const mk = c.argon2Sync('argon2id', {
      message: 'pw',
      nonce: c.createHash('sha256').update('user@example.com').digest(),
      parallelism: 2,
      tagLength: 32,
      memory: 16 * 1024,
      passes: 2,
    });
    check('Argon2id Master-Key', r.masterKey === b64(mk));
  } else console.log('(Argon2id-Gegenprobe übersprungen: Node ohne crypto.argon2Sync)');

  // 3. Schlüsselstreckung (HKDF-Expand "enc"/"mac") und Send-Schlüssel (HKDF mit Salt)
  {
    const mk = c.randomBytes(32);
    const st = unb64(W.stretch_key(b64(mk)));
    check('HKDF-Stretch', st.equals(Buffer.concat([hkdfExpand(mk, 'enc', 32), hkdfExpand(mk, 'mac', 32)])));
    const seed = c.randomBytes(16);
    const sk = unb64(W.send_key(b64(seed)));
    check('Send-Schlüssel', sk.equals(Buffer.from(c.hkdfSync('sha256', seed, 'bitwarden-send', 'send', 64))));
  }

  // 4. EncString Typ 2 in beide Richtungen
  const key = c.randomBytes(64);
  const K = b64(key);
  {
    const text = 'Grüße 🔐 ' + 'x'.repeat(100);
    check('WASM → Referenz', refDecrypt(W.text_encrypt(K, text), key).toString() === text);
    check('Referenz → WASM', W.text_decrypt(K, refEncrypt(Buffer.from(text), key)) === text);
    const e1 = W.text_encrypt(K, 'gleich');
    const e2 = W.text_encrypt(K, 'gleich');
    check('Zufälliger IV pro Verschlüsselung', e1 !== e2);
    check('Leerer Text', W.text_decrypt(K, W.text_encrypt(K, '')) === '');
  }

  // 5. Manipulation wird erkannt (jedes Byte von IV, Ciphertext und MAC)
  {
    const enc = W.text_encrypt(K, 'geheim geheim geheim');
    const [, rest] = enc.split('.');
    const parts = rest.split('|').map(unb64);
    let undetected = 0;
    for (let p = 0; p < 3; p++)
      for (let i = 0; i < parts[p].length; i++) {
        const q = parts.map((x) => Buffer.from(x));
        q[p][i] ^= 0x01;
        if (!throws(() => W.text_decrypt(K, '2.' + q.map(b64).join('|')))) undetected++;
      }
    check('Jede Bit-Manipulation abgelehnt', undetected === 0, `${undetected} unentdeckt`);
    check('Falscher Schlüssel abgelehnt', throws(() => W.text_decrypt(b64(c.randomBytes(64)), enc)));
    check('Gekürzter MAC abgelehnt', throws(() => W.text_decrypt(K, '2.' + [parts[0], parts[1], parts[2].subarray(0, 16)].map(b64).join('|'))));
    check('Fehlender MAC abgelehnt', throws(() => W.text_decrypt(K, '2.' + [parts[0], parts[1]].map(b64).join('|'))));
  }

  // 6. Herabstufung: Typ 0 (AES-CBC ohne MAC) darf mit einem Schlüssel, der einen MAC-Anteil hat,
  //    nicht akzeptiert werden – sonst kann ein Server Daten unbemerkt austauschen.
  {
    const iv = c.randomBytes(16);
    const ci = c.createCipheriv('aes-256-cbc', key.subarray(0, 32), iv);
    const ct = Buffer.concat([ci.update('untergeschoben'), ci.final()]);
    check('Typ 0 mit MAC-Schlüssel abgelehnt', throws(() => W.text_decrypt(K, `0.${b64(iv)}|${b64(ct)}`)));
  }

  // 7. Binärformat (Anhänge, Send-Dateien): [2][IV][MAC][CT]
  {
    const data = c.randomBytes(1000);
    const out = Buffer.from(W.buf_encrypt(K, data));
    const iv = out.subarray(1, 17);
    const mac = out.subarray(17, 49);
    const ct = out.subarray(49);
    const exp = c.createHmac('sha256', key.subarray(32)).update(Buffer.concat([iv, ct])).digest();
    const d = c.createDecipheriv('aes-256-cbc', key.subarray(0, 32), iv);
    check('Binärformat Kopf', out[0] === 2 && exp.equals(mac));
    check('Binärformat Inhalt', Buffer.concat([d.update(ct), d.final()]).equals(data));
    const bad = Buffer.from(out);
    bad[bad.length - 1] ^= 1;
    check('Binärformat Manipulation abgelehnt', throws(() => W.buf_decrypt(K, bad)));
    check('Binärformat zu kurz abgelehnt', throws(() => W.buf_decrypt(K, out.subarray(0, 40))));
  }

  // 8. RFC 6238 Testvektoren (SHA1/SHA256/SHA512, 8 Stellen)
  {
    const sec = { SHA1: '12345678901234567890', SHA256: '12345678901234567890123456789012',
      SHA512: '1234567890123456789012345678901234567890123456789012345678901234' };
    const b32 = (s) => {
      const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let bits = '';
      for (const ch of Buffer.from(s)) bits += ch.toString(2).padStart(8, '0');
      return bits.match(/.{1,5}/g).map((x) => A[parseInt(x.padEnd(5, '0'), 2)]).join('');
    };
    const vec = [
      [59, '94287082', '46119246', '90693936'],
      [1111111109, '07081804', '68084774', '25091201'],
      [1234567890, '89005924', '91819424', '93441116'],
      [20000000000, '65353130', '77737706', '47863826'],
    ];
    for (const [t, ...codes] of vec)
      ['SHA1', 'SHA256', 'SHA512'].forEach((alg, i) => {
        const uri = `otpauth://totp/x?secret=${b32(sec[alg])}&digits=8&algorithm=${alg}`;
        const got = JSON.parse(W.totp(uri, t)).code;
        check(`TOTP ${alg} t=${t}`, got === codes[i], `${got} statt ${codes[i]}`);
      });
    check('TOTP Standard 6 Stellen', JSON.parse(W.totp(b32(sec.SHA1), 59)).code === '287082');
  }

  // 9. Robustheit: kaputte Eingaben liefern Fehler statt Absturz/Panik (eine Panik bricht WASM ab)
  {
    const junk = ['', '.', '2.', '2.||', '2.a|b|c', '9.x', '0.', '0.|', '2.' + '|'.repeat(50), 'x'.repeat(10000),
      '2.' + b64(Buffer.alloc(15)) + '|' + b64(Buffer.alloc(16)) + '|' + b64(Buffer.alloc(32)),
      '2.' + b64(Buffer.alloc(16)) + '|' + b64(Buffer.alloc(17)) + '|' + b64(Buffer.alloc(32)),
      '3.', '4.x|y', '7.x', '2.\u0000|\u0000|\u0000', '-1.a|b|c', '256.a|b|c'];
    let ok = 0;
    for (const j of junk) {
      try {
        W.text_decrypt(K, j);
      } catch (e) {
        if (!/unreachable|RuntimeError/.test(String(e))) ok++;
      }
    }
    check('Kaputte EncStrings → saubere Fehler', ok === junk.length, `${junk.length - ok} problematisch`);
    for (const k of ['', 'abc', b64(Buffer.alloc(31)), b64(Buffer.alloc(65))])
      check(`Ungültiger Schlüssel (${k.length})`, throws(() => W.text_encrypt(k, 'x')));
    for (const t of ['', 'otpauth://totp/x', 'otpauth://totp/x?secret=!!!', 'steam://', '1', 'otpauth://totp/x?secret=AAAA&period=0&digits=99'])
      try {
        W.totp(t, 1000);
      } catch (e) {
        check(`TOTP-Eingabe ${JSON.stringify(t)} ohne Panik`, !/unreachable|RuntimeError/.test(String(e)), String(e));
      }
    for (const j of ['', '{', '[]', 'null', '{"kdf":5}', '{"kdf":1,"kdfMemory":0}', '{"kdf":1,"kdfParallelism":0}', '{"kdf":0,"kdfIterations":0}'])
      try {
        W.derive_keys('a@b.c', 'pw', j);
      } catch (e) {
        check(`KDF-Parameter ${j} ohne Panik`, !/unreachable|RuntimeError/.test(String(e)), String(e));
      }
    // WASM muss danach noch funktionieren
    check('WASM nach Fehleingaben intakt', W.text_decrypt(K, W.text_encrypt(K, 'ok')) === 'ok');
  }

  // 10. Generator: Länge, Zeichenklassen, keine Modulo-Verzerrung (grob statistisch)
  {
    const pw = W.generate(JSON.stringify({ type: 'password', length: 40, upper: true, lower: true, digits: true, special: true }));
    const p = typeof pw === 'string' ? pw : pw.value ?? pw.password ?? pw;
    check('Passwortlänge', typeof p === 'string' && p.length === 40, JSON.stringify(pw).slice(0, 80));
    if (typeof p === 'string') check('Zeichenklassen', /[A-Z]/.test(p) && /[a-z]/.test(p) && /\d/.test(p) && /[^A-Za-z0-9]/.test(p));
    const counts = {};
    let n = 0;
    for (let i = 0; i < 400; i++) {
      const r = W.generate(JSON.stringify({ type: 'password', length: 50, upper: false, lower: false, digits: true, special: false }));
      const s = typeof r === 'string' ? r : r.value ?? r.password;
      for (const ch of s) (counts[ch] = (counts[ch] || 0) + 1), n++;
    }
    const exp = n / 10;
    const chi = Object.values(counts).reduce((a, v) => a + (v - exp) ** 2 / exp, 0);
    // Abgeleitet vom alten Passwort „Sommer#2024xY“: 13 Zeichen, A–Z, a–z, 0–9, nur „#“
    let okRules = true;
    for (let i = 0; i < 100; i++) {
      const d = W.generate(JSON.stringify({ type: 'password', length: 13, upper: true, lower: true, numbers: true, special: true, specialChars: '#', avoidAmbiguous: false }));
      if (!(d.length === 13 && /^[A-Za-z0-9#]+$/.test(d) && /[A-Z]/.test(d) && /[a-z]/.test(d) && /\d/.test(d) && d.includes('#'))) okRules = false;
    }
    check('Abgeleitete Regeln werden eingehalten', okRules);
    check('Ziffern gleichverteilt (Chi² < 27.9, p=0.001)', Object.keys(counts).length === 10 && chi < 27.9, `chi²=${chi.toFixed(1)}`);
  }

  console.log(`crypto-interop: ${passed} OK, ${failed} fehlgeschlagen`);
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
