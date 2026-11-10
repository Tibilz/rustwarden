// End-to-End-Test: lädt extension/background.js unverändert in eine Node-VM mit nachgebildeter
// browser.*-API und fährt ihn gegen ein echtes Vaultwarden.
const fs = require('fs');
const vm = require('vm');
const nc = require('crypto');
const EXT_DIR = process.argv[2];
const BASE = process.argv[3] || 'http://127.0.0.1:18080';
const EXT = 'ext://rwid/';

const store = () => {
  const d = {};
  return {
    d,
    get: async (k) => (k == null ? { ...d } : typeof k === 'string' ? { [k]: d[k] } : Object.fromEntries(k.map((x) => [x, d[x]]))),
    set: async (o) => void Object.assign(d, JSON.parse(JSON.stringify(o))),
    remove: async (k) => void [].concat(k).forEach((x) => delete d[x]),
    clear: async () => void Object.keys(d).forEach((x) => delete d[x]),
  };
};
const ev = () => ({ fns: [], addListener(f) { this.fns.push(f); } });
const injected = [];
const alarms = {};
const browser = {
  storage: { local: store(), session: store() },
  runtime: {
    id: 'rwid', getURL: (p) => EXT + p, onMessage: ev(), onInstalled: ev(), onStartup: ev(),
    sendMessage: async () => ({}),
    sendNativeMessage: async () => { throw new Error('im Test nicht vorhanden'); },
  },
  alarms: { create: (n, o) => (alarms[n] = o), clear: async (n) => delete alarms[n], onAlarm: ev() },
  action: { setBadgeText: () => {}, openPopup: async () => {} },
  commands: { onCommand: ev() },
  contextMenus: { removeAll: async () => {}, create: () => {}, onClicked: ev() },
  scripting: { executeScript: async (o) => (injected.push(o), [{ result: true }]) },
  tabs: { query: async () => [] },
};
const realFetch = fetch;
const ctx = vm.createContext({
  browser, console, URL, URLSearchParams, FormData, Blob, TextEncoder, TextDecoder, WebAssembly, structuredClone,
  crypto: nc.webcrypto, atob, btoa, setTimeout,
  fetch: async (u, init) =>
    String(u).startsWith(EXT)
      ? { arrayBuffer: async () => new Uint8Array(fs.readFileSync(EXT_DIR + '/' + String(u).slice(EXT.length))) }
      : realFetch(u, init),
});
for (const f of ['wasm/rw_core.js', 'background.js']) vm.runInContext(fs.readFileSync(`${EXT_DIR}/${f}`, 'utf8'), ctx, { filename: f });
vm.runInContext('globalThis.__core = core;', ctx);

const POPUP = { id: 'rwid', url: EXT + 'popup.html' };
function raw(cmd, extra, sender = POPUP) {
  return new Promise((resolve) => {
    const r = browser.runtime.onMessage.fns[0]({ cmd, ...(extra || {}) }, sender, resolve);
    if (r !== true) resolve(undefined);
  });
}
async function call(cmd, extra) {
  const r = await raw(cmd, extra);
  if (!r || !r.ok) throw new Error(`${cmd}: ${r && r.error}`);
  return r;
}
let n = 0;
const ok = (cond, what) => { if (!cond) throw new Error('FEHLGESCHLAGEN: ' + what); n++; console.log('  ✓', what); };
const fails = async (p, re, what) => { try { await p; } catch (e) { return ok(re.test(e.message), `${what} → „${e.message}“`); } throw new Error('FEHLGESCHLAGEN (kein Fehler): ' + what); };

async function register(w, email, password, kdf) {
  const k = JSON.parse(w.derive_keys(email, password, JSON.stringify(kdf)));
  const userKey = w.random_b64(64);
  const { publicKey, privateKey } = nc.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const body = {
    email, name: 'Test', masterPasswordHash: k.hash, masterPasswordHint: null,
    key: w.key_encrypt(w.stretch_key(k.masterKey), userKey),
    keys: {
      publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      encryptedPrivateKey: w.key_encrypt(userKey, privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')),
    },
    ...kdf,
  };
  const post = (path, b) => realFetch(BASE + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) });
  const v = await post('/identity/accounts/register/send-verification-email', { email, name: 'Test', receiveMarketingEmails: false });
  const token = v.ok ? (await v.text()).trim().replace(/^"|"$/g, '') : null;
  const r = await post('/identity/accounts/register/finish', {
    ...body, key: undefined, keys: undefined, emailVerificationToken: token, userSymmetricKey: body.key, userAsymmetricKeys: body.keys,
  });
  if (r.ok) return;
  console.log(`  (Registrierung: HTTP ${v.status}/${r.status} ${(await r.text()).slice(0, 300)})`);
  throw new Error('Registrierung fehlgeschlagen');
}

(async () => {
  const w = await ctx.__core();
  const server = { region: 'self', base: BASE + '/' };
  const stamp = Date.now();
  const A = { email: `a${stamp}@example.com`, password: 'Master-Passwort A!', kdf: { kdf: 0, kdfIterations: 600000 } };
  const B = { email: `b${stamp}@example.com`, password: 'Master-Passwort B!', kdf: { kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 } };
  await register(w, A.email, A.password, A.kdf);
  await register(w, B.email, B.password, B.kdf);
  console.log('Konten registriert (PBKDF2 + Argon2id)');

  console.log('Anmeldung');
  ok((await call('status')).state === 'loggedOut', 'Start: abgemeldet');
  await fails(call('login', { server, email: A.email, password: 'falsch' }), /falsch|invalid/i, 'falsches Passwort wird abgelehnt');
  ok((await call('login', { server, email: A.email.toUpperCase(), password: A.password })).step === 'done', 'Login Konto A (PBKDF2)');
  ok((await call('status')).state === 'unlocked', 'Status: entsperrt');
  ok(alarms.lock && alarms.lock.delayInMinutes === 15, 'Sperr-Timer gesetzt');

  console.log('Einträge');
  const { id } = await call('save', { view: {
    type: 1, name: 'Beispiel ✓', notes: 'Notiz\nZeile 2', favorite: true, reprompt: 0, folderId: null,
    login: { username: 'bob', password: 'erstes', totp: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', uris: [{ uri: 'https://login.example.com/x', match: null }] },
    fields: [{ type: 1, name: 'PIN', value: '1234', linkedId: null }],
  } });
  ok(!!id, 'Login angelegt');
  await call('sync');
  let it = (await call('get', { id })).item;
  ok(it.name === 'Beispiel ✓' && it.login.password === 'erstes' && it.notes === 'Notiz\nZeile 2' && it.fields[0].value === '1234', 'nach Sync vom Server korrekt entschlüsselt');
  let list = await call('list', { url: 'https://www.example.com/anmelden' });
  ok(list.matchIds.includes(id), 'URL-Abgleich über Basis-Domain');
  ok(!(await call('list', { url: 'https://example.org/' })).matchIds.length, 'fremde Domain: kein Treffer');
  ok(/^\d{6}$/.test((await call('totp', { id })).totp.code), 'TOTP-Code');
  const f = await call('fill', { id, tabId: 7 });
  ok(f.filled && injected[0].args[0].password === 'erstes' && injected[0].target.tabId === 7, 'Ausfüllen injiziert die richtigen Daten');

  const { id: folderId } = await call('folder', { name: 'Arbeit' });
  it.login.password = 'zweites'; it.folderId = folderId;
  await call('save', { view: it });
  await call('sync');
  it = (await call('get', { id })).item;
  ok(it.login.password === 'zweites' && it.passwordHistory[0].password === 'erstes' && it.folderId === folderId, 'Bearbeiten: Passwortverlauf + Ordner');
  ok((await call('list', {})).folders.some((x) => x.name === 'Arbeit'), 'Ordnername entschlüsselt');

  for (const [type, key, obj] of [[3, 'card', { cardholderName: 'Bob', number: '4111111111111111', expMonth: '4', expYear: '2030', code: '123' }], [4, 'identity', { firstName: 'Bob', lastName: 'Bau', email: 'b@x.de', postalCode: '10115' }], [2, 'secureNote', { type: 0 }]]) {
    const r = await call('save', { view: { type, name: 'Typ ' + type, notes: type === 2 ? 'geheim' : null, [key]: obj, fields: [] } });
    const g = (await call('get', { id: r.id })).item;
    ok(g.name === 'Typ ' + type && (type === 2 ? g.notes === 'geheim' : Object.entries(obj).every(([k, v]) => g[key][k] === v)), `Typ ${type} (${key}) gespeichert`);
  }

  console.log('Erkannte Logins');
  const WEB = { id: 'rwid', url: 'https://neu.example.net/login', tab: { id: 3, url: 'https://neu.example.net/login' } };
  ok((await raw('get', { id }, WEB)) === undefined, 'Webseiten-Kontext darf keine Tresor-Befehle senden');
  await raw('submitted', { url: WEB.url, username: 'carol', password: 'pw-neu' }, WEB);
  await new Promise((r) => setTimeout(r, 300));
  list = await call('list', {});
  ok(list.pending && list.pending.kind === 'new' && list.pending.host === 'neu.example.net', 'neuer Login wird zum Speichern angeboten');
  await call('pendingAccept');
  list = await call('list', { url: WEB.url });
  ok(list.matchIds.length === 1 && !list.pending, 'angebotener Login gespeichert');
  const FRAME = { id: 'rwid', url: EXT + 'inline.html', frameId: 5, tab: { id: 3, url: WEB.url } };
  ok((await raw('inlineList', {}, FRAME)).items.length === 1, 'Inline-Menü listet passende Logins');
  ok((await raw('get', { id }, FRAME)).ok === false, 'Inline-iframe darf keine Details abrufen');
  ok((await raw('inlineFill', { id }, FRAME)).ok === false, 'Inline-iframe darf keine fremden Einträge ausfüllen');

  console.log('Anhänge');
  const bytes = nc.randomBytes(70000);
  await call('attAdd', { id, name: 'geheim ä.bin', b64: bytes.toString('base64') });
  it = (await call('get', { id })).item;
  ok(it.attachments.length === 1 && it.attachments[0].fileName === 'geheim ä.bin', 'Anhang hochgeladen, Name entschlüsselt');
  const att = await call('attGet', { id, attId: it.attachments[0].id });
  ok(att.name === 'geheim ä.bin' && Buffer.from(att.b64, 'base64').equals(bytes), 'Anhang heruntergeladen und identisch entschlüsselt');
  await call('attDel', { id, attId: it.attachments[0].id });
  await call('sync');
  ok(!((await call('get', { id })).item.attachments || []).length, 'Anhang gelöscht');

  console.log('Send');
  const s1 = await call('sendSave', { name: 'Textsend', text: 'Hallo Welt', days: 2 });
  ok(/^http:\/\/127\.0\.0\.1:18080\/#\/send\/[^/]+\/[A-Za-z0-9_-]+$/.test(s1.url), 'Text-Send erstellt: ' + s1.url.slice(0, 48) + '…');
  await call('sendSave', { name: 'Dateisend', days: 1, file: { name: 'a.txt', b64: Buffer.from('Dateiinhalt').toString('base64') } });
  await call('sync');
  let sends = (await call('sends')).sends;
  ok(sends.length === 2 && sends.some((s) => s.text === 'Hallo Welt') && sends.some((s) => s.fileName === 'a.txt'), 'Sends nach Sync entschlüsselt');
  // Empfängersicht: nur mit dem Schlüssel aus dem Link entschlüsseln
  const [, accessId, urlKey] = s1.url.match(/send\/([^/]+)\/(.+)$/);
  const tok = await (await realFetch(`${BASE}/identity/connect/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `grant_type=send_access&client_id=send&scope=api.send.access&send_id=${accessId}` })).json();
  const pub = await (await realFetch(`${BASE}/api/sends/access`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + tok.access_token }, body: '{}' })).json();
  const seed = Buffer.from(urlKey, 'base64url').toString('base64');
  ok(w.text_decrypt(w.send_key(seed), (pub.text || pub.Text).text) === 'Hallo Welt', 'Send ist über den Link-Schlüssel lesbar (Empfängersicht)');
  await call('sendDelete', { id: sends[0].id });
  ok((await call('sends')).sends.length === 1, 'Send gelöscht');

  console.log('Passkeys');
  {
  const sha = (b) => nc.createHash('sha256').update(b).digest();
  const chal = nc.randomBytes(32).toString('base64url');
  const userId = Buffer.from('user-123').toString('base64url');
  const createOpts = { rp: { id: 'example.net', name: 'Example' }, user: { id: userId, name: 'carol', displayName: 'Carol' }, challenge: chal, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], excludeCredentials: [], credProps: true };
  ok((await raw('pkBegin', { kind: 'create', options: { ...createOpts, rp: { id: 'evil.com' } } }, WEB)).error === 'SecurityError', 'fremde rpId wird abgelehnt');
  ok((await raw('pkBegin', { kind: 'create', options: { ...createOpts, rp: { id: 'net' } } }, WEB)).error === 'SecurityError', 'rpId oberhalb der registrierbaren Domain wird abgelehnt');
  ok((await raw('pkBegin', { kind: 'get', options: { challenge: chal } }, WEB)).fallback === true, 'kein Passkey vorhanden → Safari übernimmt');
  const b1 = await raw('pkBegin', { kind: 'create', options: createOpts }, WEB);
  const i1 = await raw('pkInfo', { reqId: b1.reqId }, FRAME);
  ok(i1.ok && i1.kind === 'create' && i1.choices.length === 1 && !i1.choices[0].has, 'Dialog bietet den passenden Login an');
  ok((await raw('pkInfo', { reqId: b1.reqId }, { ...FRAME, tab: { id: 99, url: WEB.url } })).ok === false, 'anderer Tab kann die Anfrage nicht übernehmen');
  ok((await raw('pkFinish', { reqId: b1.reqId, action: 'confirm', choice: i1.choices[0].id }, FRAME)).ok, 'Passkey erzeugt und am Eintrag gespeichert');
  const c1 = (await raw('pkResult', { reqId: b1.reqId }, WEB)).credential;
  const auth = Buffer.from(c1.authenticatorData, 'base64url');
  const attObj = Buffer.from(c1.attestationObject, 'base64url');
  ok(attObj[0] === 0xa3 && attObj.includes(Buffer.from('none')) && attObj.subarray(attObj.length - auth.length).equals(auth), 'attestationObject (fmt none) enthält authData');
  ok(auth.subarray(0, 32).equals(sha('example.net')) && auth[32] === 0x5d && auth.readUInt16BE(53) === 16 && auth.subarray(55, 71).toString('base64url') === c1.id, 'authData: rpId-Hash, Flags, Credential-ID');
  const pub = nc.createPublicKey({ key: Buffer.from(c1.publicKey, 'base64url'), format: 'der', type: 'spki' });
  const jwk = pub.export({ format: 'jwk' });
  const cose = auth.subarray(71);
  ok(cose.length === 77 && cose.subarray(10, 42).toString('base64url') === jwk.x && cose.subarray(45, 77).toString('base64url') === jwk.y, 'COSE-Schlüssel stimmt mit dem öffentlichen Schlüssel überein');
  const cd1 = JSON.parse(Buffer.from(c1.clientDataJSON, 'base64url'));
  ok(cd1.type === 'webauthn.create' && cd1.challenge === chal && cd1.origin === 'https://neu.example.net', 'clientDataJSON (create)');
  await call('sync');
  const pkItem = (await call('get', { id: i1.choices[0].id })).item;
  const stored = pkItem.login.fido2Credentials;
  ok(stored.length === 1 && stored[0].rpId === 'example.net' && stored[0].userName === 'carol' && pkItem.login.password === 'pw-neu', 'nach Sync: Passkey am Eintrag, Passwort unverändert');
  ok(!Object.values(browser.storage.local.d).some((v) => typeof v === 'string' && v.includes(stored[0].keyValue)), 'privater Schlüssel liegt nur verschlüsselt vor');
  ok((await raw('pkBegin', { kind: 'create', options: { ...createOpts, excludeCredentials: [c1.id] } }, WEB)).error === 'InvalidStateError', 'excludeCredentials: bereits registriert');

  const chal2 = nc.randomBytes(32).toString('base64url');
  const b2 = await raw('pkBegin', { kind: 'get', options: { rpId: 'example.net', challenge: chal2, allowCredentials: [c1.id] } }, WEB);
  const i2 = await raw('pkInfo', { reqId: b2.reqId }, FRAME);
  ok(i2.ok && i2.choices.length === 1 && i2.choices[0].sub === 'carol', 'Anmeldedialog zeigt den Passkey');
  await raw('pkFinish', { reqId: b2.reqId, action: 'confirm', choice: i2.choices[0].id }, FRAME);
  const a1 = (await raw('pkResult', { reqId: b2.reqId }, WEB)).credential;
  const ad = Buffer.from(a1.authenticatorData, 'base64url');
  const cdj = Buffer.from(a1.clientDataJSON, 'base64url');
  ok(nc.verify('sha256', Buffer.concat([ad, sha(cdj)]), { key: pub, dsaEncoding: 'der' }, Buffer.from(a1.signature, 'base64url')), 'Signatur der Anmeldung ist gegen den registrierten Schlüssel gültig');
  ok(a1.id === c1.id && a1.userHandle === userId && ad.length === 37 && ad[32] === 0x1d && JSON.parse(cdj).challenge === chal2, 'Assertion: ID, userHandle, Flags, Challenge');
  ok((await raw('pkResult', { reqId: b2.reqId }, WEB)).error === 'NotAllowedError', 'Ergebnis ist nur einmal abrufbar');
  const OTHER = { id: 'rwid', url: 'https://other.org/', tab: { id: 4, url: 'https://other.org/' } };
  ok((await raw('pkBegin', { kind: 'get', options: { rpId: 'example.net', challenge: chal2 } }, OTHER)).error === 'SecurityError', 'fremde Seite kann den Passkey nicht anfordern');
  const b3 = await raw('pkBegin', { kind: 'get', options: { rpId: 'example.net', challenge: chal2 } }, WEB);
  await raw('pkFinish', { reqId: b3.reqId, action: 'cancel' }, FRAME);
  ok((await raw('pkResult', { reqId: b3.reqId }, WEB)).error === 'NotAllowedError', 'Abbrechen → NotAllowedError');
  await call('setSettings', { settings: { passkeys: false } });
  ok((await raw('pkBegin', { kind: 'get', options: { rpId: 'example.net', challenge: chal2 } }, WEB)).fallback === true, 'Passkeys abgeschaltet → Safari übernimmt');
  await call('setSettings', { settings: { passkeys: true } });

  }

  console.log('Sperren / PIN');
  await call('setPin', { pin: '4711' });
  await call('lock');
  ok((await call('status')).state === 'locked' && (await call('status')).hasPin, 'gesperrt, PIN vorhanden');
  await fails(call('list', {}), /gesperrt/, 'gesperrt: kein Zugriff');
  await fails(call('unlockPin', { pin: '0000' }), /Falsche PIN/, 'falsche PIN');
  await call('unlockPin', { pin: '4711' });
  ok((await call('get', { id })).item.login.password === 'zweites', 'mit PIN entsperrt');
  await call('lock');
  await fails(call('unlock', { password: 'falsch' }), /Falsches Master-Passwort/, 'falsches Master-Passwort');
  await call('unlock', { password: A.password });
  ok((await call('status')).state === 'unlocked', 'mit Master-Passwort entsperrt');
  await fails(call('bioEnable'), /Native Komponente/, 'Touch ID ohne native Seite: saubere Fehlermeldung');

  console.log('Papierkorb / Export / Import');
  await call('remove', { id });
  ok((await call('list', {})).items.find((x) => x.id === id).deleted, 'in den Papierkorb verschoben');
  await call('restore', { id });
  await call('sync');
  ok(!(await call('list', {})).items.find((x) => x.id === id).deleted, 'wiederhergestellt');
  const exp = await call('export');
  const before = (await call('list', {})).items.length;
  ok(exp.count === before && JSON.parse(exp.json).items.some((x) => x.login && x.login.password === 'zweites'), `Export: ${exp.count} Einträge`);

  console.log('Zweites Konto (Argon2id)');
  ok((await call('login', { server, email: B.email, password: B.password })).step === 'done', 'Login Konto B (Argon2id)');
  ok((await call('list', {})).items.length === 0, 'Konto B: leerer Tresor');
  ok((await call('import', { json: exp.json })).count === before, 'Import des Exports in Konto B');
  const imp = (await call('list', {})).items;
  const moved = (await call('get', { id: imp.find((x) => x.name === 'Beispiel ✓').id })).item;
  ok(imp.length === before && moved.login.password === 'zweites' && moved.login.uris[0].uri === 'https://login.example.com/x', 'importierte Einträge lesbar');
  ok((await call('list', {})).folders.some((x) => x.name === 'Arbeit'), 'Ordner mit importiert');
  ok((await call('get', { id: imp.find((x) => x.name === 'neu.example.net').id })).item.login.fido2Credentials[0].rpId === 'example.net', 'Passkey mit importiert');
  const st = await call('status');
  ok(st.accounts.length === 2 && st.email === B.email, 'zwei Konten, B aktiv');
  await call('switchAccount', { id: st.accounts.find((a) => a.email === A.email).id });
  ok((await call('get', { id })).item.name === 'Beispiel ✓', 'zurück zu Konto A – noch entsperrt, eigene Daten');
  await browser.alarms.onAlarm.fns[0]({ name: 'lock' });
  ok((await call('status')).state === 'locked', 'Timer sperrt');
  await call('logout');
  ok((await call('status')).email === B.email, 'Abmelden von A → B wird aktiv');
  ok(!Object.keys(browser.storage.local.d).some((k) => k.includes(A.email)), 'lokale Daten von A entfernt');
  await call('logout');
  ok((await call('status')).state === 'loggedOut', 'vollständig abgemeldet');

  console.log(`\nE2E OK – ${n} Prüfungen gegen ${BASE}`);
})().catch((e) => { console.error('\n' + (e.stack || e)); process.exit(1); });
