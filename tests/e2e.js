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
const tabsById = {};
let activeTab = null;
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
  tabs: {
    query: async () => (activeTab ? [activeTab] : []),
    get: async (id) => tabsById[id] || { id, url: 'about:blank' },
  },
};
const realFetch = fetch;
let fakePrelogin = null; // simuliert einen bösartigen Server, der eine schwache KDF vorgibt
const ctx = vm.createContext({
  browser, console, URL, URLSearchParams, FormData, Blob, TextEncoder, TextDecoder, WebAssembly, structuredClone,
  crypto: nc.webcrypto, atob, btoa, setTimeout,
  fetch: async (u, init) =>
    String(u).startsWith(EXT)
      ? {
          arrayBuffer: async () => new Uint8Array(fs.readFileSync(EXT_DIR + '/' + String(u).slice(EXT.length))),
          text: async () => fs.readFileSync(EXT_DIR + '/' + String(u).slice(EXT.length), 'utf8'),
        }
      : fakePrelogin && String(u).endsWith('/accounts/prelogin')
        ? new Response(JSON.stringify(fakePrelogin), { status: 200, headers: { 'Content-Type': 'application/json' } })
        : realFetch(u, init),
});
for (const f of ['wasm/rw_core.js', 'background.js']) vm.runInContext(fs.readFileSync(`${EXT_DIR}/${f}`, 'utf8'), ctx, { filename: f });
vm.runInContext('globalThis.__core = core; globalThis.__fillPage = fillPage;', ctx);

// fillPage in einer nachgebildeten Seite ausführen (Origin + ein Passwortfeld).
function runFillPage(origin, d) {
  const field = { tagName: 'INPUT', type: 'password', value: '', form: null, getAttribute: (k) => (k === 'type' ? 'password' : null),
    getBoundingClientRect: () => ({ width: 100, height: 20 }), focus() {}, dispatchEvent() {}, disabled: false, readOnly: false };
  const win = {};
  win.top = win;
  const page = vm.createContext({
    window: win, location: { origin }, Event: class { constructor(t) { this.type = t; } },
    getComputedStyle: () => ({ visibility: 'visible' }),
    HTMLInputElement: { prototype: Object.defineProperty({}, 'value', { set(v) { this.value_ = v; } }) },
    HTMLTextAreaElement: { prototype: {} },
    document: { querySelectorAll: () => [field] },
  });
  page.__d = d;
  const r = vm.runInContext(`(${ctx.__fillPage.toString()})(__d)`, page);
  return { r, value: field.value_ };
}

const POPUP = { id: 'rwid', url: EXT + 'popup.html' };
// Inline-Menü-Token, wie es das Content-Script im Top-Frame des Tabs vergibt
async function inlineToken(tab) {
  const token = nc.randomBytes(16).toString('hex');
  await raw('inlineToken', { token }, { id: 'rwid', url: tab.url, tab });
  return token;
}
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
  await fails(call('login', { server: { region: 'self', base: 'http://vault.example.com' }, email: A.email, password: A.password }), /https/, 'unverschlüsselte Server-URL (außer localhost) wird abgelehnt');
  fakePrelogin = { kdf: 0, kdfIterations: 1 };
  await fails(call('login', { server, email: A.email, password: A.password }), /unsichere KDF/, 'Server mit schwacher KDF (1 Iteration) wird abgelehnt');
  fakePrelogin = { kdf: 1, kdfIterations: 3, kdfMemory: 8192, kdfParallelism: 4 };
  await fails(call('login', { server, email: A.email, password: A.password }), /unsichere KDF/, 'Server mit absurdem Argon2-Speicher wird abgelehnt');
  fakePrelogin = null;
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
  tabsById[7] = { id: 7, url: 'https://login.example.com/x' };
  const f = await call('fill', { id, tabId: 7 });
  ok(f.filled && injected[0].args[0].password === 'erstes' && injected[0].target.tabId === 7, 'Ausfüllen injiziert die richtigen Daten');
  ok(injected[0].args[0].origin === 'https://login.example.com', 'Ausfüllen ist an die Origin der Seite gebunden');

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
  await fails(call('pendingAccept', { ts: 1 }), /geändert/, 'Speichern einer inzwischen ersetzten Abfrage wird abgelehnt');
  await call('pendingAccept', { ts: list.pending.ts });
  list = await call('list', { url: WEB.url });
  ok(list.matchIds.length === 1 && !list.pending, 'angebotener Login gespeichert');
  const FRAME = { id: 'rwid', url: EXT + 'inline.html', frameId: 5, tab: { id: 3, url: WEB.url } };
  ok((await raw('inlineList', {}, FRAME)).ok === false, 'Inline-Menü ohne Token (fremdes iframe bettet inline.html ein) wird abgelehnt');
  ok((await raw('inlineList', { token: 'geraten' }, FRAME)).ok === false, 'Inline-Menü mit falschem Token wird abgelehnt');
  const tok3 = await inlineToken(FRAME.tab);
  ok((await raw('inlineList', { token: tok3 }, { ...FRAME, tab: { id: 9, url: WEB.url } })).ok === false, 'Token gilt nur für den eigenen Tab');
  ok((await raw('inlineList', { token: tok3 }, FRAME)).items.length === 1, 'Inline-Menü listet passende Logins');
  ok((await raw('get', { id }, FRAME)).ok === false, 'Inline-iframe darf keine Details abrufen');
  ok((await raw('inlineFill', { id, token: tok3 }, FRAME)).ok === false, 'Inline-iframe darf keine fremden Einträge ausfüllen');

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

  console.log('Einstellungen');
  await browser.storage.local.set({ settings: { savePrompt: false } });
  let mig = (await call('getSettings')).settings;
  ok(mig.addPrompt === false && mig.updatePrompt === false && !('savePrompt' in mig), 'alte Einstellung „Speichern anbieten: aus“ wird übernommen');
  await call('setSettings', { settings: { addPrompt: true, updatePrompt: true } });
  mig = (await call('getSettings')).settings;
  ok(mig.addPrompt && mig.updatePrompt, 'danach gelten die neuen Schalter');
  ok((await call('list', { url: 'https://www.example.com/' })).matchIds.includes(id), 'Standard-Übereinstimmung: Basis-Domain');
  await call('setSettings', { settings: { defaultMatch: 1 } });
  ok(!(await call('list', { url: 'https://www.example.com/' })).matchIds.includes(id), 'Standard-Übereinstimmung „Host“: andere Subdomain passt nicht');
  ok((await call('list', { url: 'https://login.example.com/abc' })).matchIds.includes(id), 'Standard-Übereinstimmung „Host“: gleicher Host passt');
  await call('setSettings', { settings: { defaultMatch: 5 } });
  ok(!(await call('list', { url: 'https://login.example.com/abc' })).matchIds.includes(id), 'Standard-Übereinstimmung „Nie“');
  await call('setSettings', { settings: { defaultMatch: 0 } });
  ok((await call('list', {})).settings.defaultMatch === 0, 'Liste liefert die Einstellungen mit');

  const wait = () => new Promise((r) => setTimeout(r, 300));
  const NEW = { id: 'rwid', url: 'https://shop.example.org/login', tab: { id: 8, url: 'https://shop.example.org/login' } };
  await call('setSettings', { settings: { addPrompt: false } });
  await raw('submitted', { url: NEW.url, username: 'dave', password: 'pw1' }, NEW);
  await wait();
  ok(!(await call('list', {})).pending, '„Hinzufügen anbieten“ aus: kein Angebot für neuen Login');
  await call('setSettings', { settings: { addPrompt: true, updatePrompt: false } });
  await raw('submitted', { url: WEB.url, username: 'carol', password: 'anderes' }, WEB);
  await wait();
  ok(!(await call('list', {})).pending, '„Aktualisieren anbieten“ aus: kein Angebot für geändertes Passwort');
  await call('setSettings', { settings: { updatePrompt: true } });
  await raw('submitted', { url: WEB.url, username: 'carol', password: 'anderes' }, WEB);
  await wait();
  ok((await call('list', {})).pending.kind === 'update', '„Aktualisieren anbieten“ an: Angebot erscheint');
  await call('neverDomain');
  ok(!(await call('list', {})).pending, '„Nie für diese Seite“ verwirft das Angebot');
  ok((await call('getSettings')).settings.neverDomains.includes('neu.example.net'), 'Domain landet in den ausgeschlossenen Domains');
  await raw('submitted', { url: WEB.url, username: 'carol', password: 'nochmal' }, WEB);
  await wait();
  ok(!(await call('list', {})).pending, 'ausgeschlossene Domain: kein Angebot mehr');
  await call('setSettings', { settings: { neverDomains: [] } });
  ok((await call('get', { id: (await call('list', { url: WEB.url })).matchIds[0] })).item.login.password === 'pw-neu', 'Passwort blieb unverändert');

  console.log('Gemerkter Login pro Host');
  {
    const mk = async (name, user) =>
      (await call('save', { view: { type: 1, name, login: { username: user, password: 'pw-' + user, uris: [{ uri: 'https://example.com', match: null }] }, fields: [] } })).id;
    const one = await mk('Konto Eins', 'eins');
    const two = await mk('Konto Zwei', 'zwei');
    const APP = 'https://app.example.com/start';
    tabsById[11] = { id: 11, url: APP };
    let l = await call('list', { url: APP });
    ok(l.matchIds.length === 3 && !l.otherMatchIds.length, 'ohne Zuordnung: alle passenden Logins');
    await call('fill', { id: two, tabId: 11 });
    l = await call('list', { url: APP });
    ok(l.matchIds.length === 1 && l.matchIds[0] === two && l.otherMatchIds.length === 2 && l.rememberedId === two, 'nach dem Ausfüllen: nur noch der verwendete Login, die anderen als „weitere“');
    ok((await call('list', { url: 'https://app.example.com/anderer/pfad?x=1' })).matchIds.length === 1, 'gilt für den ganzen Host, unabhängig vom Pfad');
    ok((await call('list', { url: 'https://other.example.com/' })).matchIds.length === 3, 'andere Subdomain: weiterhin alle');
    const APPFRAME = { id: 'rwid', url: EXT + 'inline.html', frameId: 6, tab: { id: 11, url: APP } };
    const tok11 = await inlineToken(APPFRAME.tab);
    const il = await raw('inlineList', { token: tok11 }, APPFRAME);
    ok(il.items.length === 1 && il.items[0].id === two, 'Auswahlmenü zeigt nur den gemerkten Login');
    activeTab = tabsById[11];
    injected.length = 0;
    browser.commands.onCommand.fns[0]('autofill');
    await new Promise((r) => setTimeout(r, 300));
    ok(injected.length && injected[injected.length - 1].args[0].username === 'zwei', 'Tastenkürzel füllt den gemerkten Login');
    activeTab = null;
    await raw('inlineFill', { id: one, token: tok11 }, APPFRAME);
    ok((await call('list', { url: APP })).rememberedId === one, 'Auswahl eines anderen Logins merkt den neuen');
    ok(!Object.entries(browser.storage.local.d).some(([k, v]) => (k + JSON.stringify(v)).includes('app.example.com')), 'Hostnamen liegen nicht im Klartext im Speicher');
    await call('forgetHost', { url: APP });
    ok((await call('list', { url: APP })).matchIds.length === 3, '„Zuordnung vergessen“ zeigt wieder alle');
    await call('fill', { id: one, tabId: 11 });
    await call('remove', { id: one });
    l = await call('list', { url: APP });
    ok(l.matchIds.length === 2 && !l.rememberedId, 'gemerkter Login gelöscht: Zuordnung wird ignoriert');
    await call('setSettings', { settings: { rememberHost: false } });
    await call('fill', { id: two, tabId: 11 });
    ok((await call('list', { url: APP })).matchIds.length === 2, 'Einstellung aus: nichts wird gemerkt oder gefiltert');
    await call('forgetAllHosts');
    await call('setSettings', { settings: { rememberHost: true } });
    await call('fill', { id: two, tabId: 11 });
    ok((await call('getSettings')).rememberedHosts === 1, 'Einstellungen zeigen die Anzahl gemerkter Zuordnungen');
    await call('forgetAllHosts');
    ok((await call('getSettings')).rememberedHosts === 0 && (await call('list', { url: APP })).matchIds.length === 2, 'alle Zuordnungen zurücksetzen');
    await call('remove', { id: one });
    await call('remove', { id: two });
    await call('remove', { id: two });
  }

  console.log('Sicherheit: Abgleich, Ausfüllen, Timer');
  {
    const mk = async (name, uri) =>
      (await call('save', { view: { type: 1, name, login: { username: 'u', password: 'p-' + name, uris: [{ uri, match: null }] }, fields: [] } })).id;
    const vn = await mk('Bank VN', 'https://vietbank.com.vn/login');
    const shop = await mk('Shop', 'https://meinshop.myshopify.com');
    ok((await call('list', { url: 'https://www.vietbank.com.vn/' })).matchIds.includes(vn), 'PSL: Subdomain derselben Domain passt (com.vn)');
    ok(!(await call('list', { url: 'https://evil.com.vn/' })).matchIds.includes(vn), 'PSL: fremde Domain unter com.vn passt nicht');
    ok(!(await call('list', { url: 'https://evil.myshopify.com/' })).matchIds.includes(shop), 'PSL: fremder Shop unter myshopify.com passt nicht');
    ok(!(await call('list', { url: 'https://vietbank.com.vn.evil.io/' })).matchIds.includes(vn), 'angehängte Fremddomain passt nicht');
    ok(!(await call('list', { url: 'https://vietbank.com.vn@evil.io/' })).matchIds.includes(vn), 'Benutzerinfo in der URL täuscht den Abgleich nicht');
    const VNEVIL = { id: 'rwid', url: 'https://evil.com.vn/', tab: { id: 21, url: 'https://evil.com.vn/' } };
    const opts = { rp: { id: 'com.vn' }, user: { id: 'dQ', name: 'x' }, challenge: 'AAAA', pubKeyCredParams: [{ type: 'public-key', alg: -7 }] };
    ok((await raw('pkBegin', { kind: 'create', options: opts }, VNEVIL)).error === 'SecurityError', 'Passkey: öffentliches Suffix als rpId wird abgelehnt');
    const DOT = { id: 'rwid', url: 'https://example.net./', tab: { id: 22, url: 'https://example.net./' } };
    ok((await raw('pkBegin', { kind: 'create', options: { ...opts, rp: { id: 'net.' } } }, DOT)).error === 'SecurityError', 'Passkey: rpId mit Schlusspunkt wird abgelehnt');

    // https-Login nicht in http-Seite
    tabsById[12] = { id: 12, url: 'http://login.example.com/x' };
    const ins = await raw('fill', { id, tabId: 12 });
    ok(ins.ok === false && ins.code === 'insecure', 'https-Login wird nicht ungefragt in eine http-Seite gefüllt');
    ok((await call('fill', { id, tabId: 12, allowHttp: true })).filled, 'nach ausdrücklicher Bestätigung schon');
    const HTTPFRAME = { id: 'rwid', url: EXT + 'inline.html', frameId: 5, tab: tabsById[12] };
    const tok12 = await inlineToken(tabsById[12]);
    ok((await raw('inlineFill', { id, token: tok12 }, HTTPFRAME)).ok === false, 'Inline-Menü füllt https-Login nicht in http-Seite');
    // Seite hat zwischen Anzeige und Klick gewechselt
    tabsById[13] = { id: 13, url: 'https://evil.example.org/' };
    await fails(call('fill', { id, tabId: 13, url: 'https://login.example.com/x' }), /geändert/, 'Popup: Seitenwechsel vor dem Ausfüllen wird erkannt');
    const fp = runFillPage('https://evil.example.org', { kind: 'login', username: 'u', password: 'geheim', origin: 'https://login.example.com' });
    ok(fp.r === false && fp.value === undefined, 'fillPage füllt nichts, wenn die Origin nicht mehr stimmt');
    const fp2 = runFillPage('https://login.example.com', { kind: 'login', username: 'u', password: 'geheim', origin: 'https://login.example.com' });
    ok(fp2.r === true && fp2.value === 'geheim', 'fillPage füllt bei passender Origin');

    // Speichern-Abfrage: URL kommt vom Browser, nicht aus der Nachricht
    await raw('submitted', { url: 'https://login.example.com/', username: 'bob', password: 'untergeschoben' }, { id: 'rwid', url: 'https://evil.example.org/', tab: tabsById[13] });
    await new Promise((r) => setTimeout(r, 300));
    const pend = (await call('list', {})).pending;
    ok(!pend || pend.host === 'evil.example.org', 'Speichern-Abfrage nutzt die echte Seiten-URL');
    if (pend) await call('pendingDismiss');

    // Passive Befehle verlängern den Sperr-Timer nicht
    await new Promise((r) => setTimeout(r, 100)); // Timer-Neustart des vorigen Befehls läuft nebenher
    delete alarms.lock;
    await call('totp', { id });
    await call('totp', { id });
    await call('status');
    ok(!alarms.lock, 'TOTP-Countdown/Status halten den Tresor nicht offen');
    await call('list', {});
    await new Promise((r) => setTimeout(r, 100));
    ok(!!alarms.lock, 'echte Nutzung verlängert den Timer');

    // Passkey-Optionen werden bereinigt, nur eine offene Anfrage pro Tab
    const big = { ...opts, rp: { id: 'example.net', name: 'X' }, user: { id: 'dQ', name: 'A'.repeat(100000) }, junk: 'B'.repeat(100000) };
    const p1 = await raw('pkBegin', { kind: 'create', options: big }, WEB);
    const p2 = await raw('pkBegin', { kind: 'create', options: big }, WEB);
    const pkKeys = Object.keys(browser.storage.session.d).filter((k) => k.startsWith('pk:'));
    ok(p1.reqId && p2.reqId && pkKeys.length === 1 && pkKeys[0] === 'pk:' + p2.reqId, 'nur eine offene Passkey-Anfrage pro Tab');
    ok(JSON.stringify(browser.storage.session.d).length < 20000, 'Passkey-Optionen der Seite werden gekürzt/bereinigt');
    await raw('pkFinish', { reqId: p2.reqId, action: 'cancel' }, FRAME);
    await raw('pkResult', { reqId: p2.reqId }, WEB);
    ok((await raw('pkBegin', { kind: 'create', options: { ...opts, rp: { id: 'example.net' }, challenge: 'kein base64!' } }, WEB)).fallback, 'ungültige Challenge → Safari übernimmt');
    await call('remove', { id: vn });
    await call('remove', { id: vn });
    await call('remove', { id: shop });
    await call('remove', { id: shop });
  }

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
  const b5 = await raw('pkBegin', { kind: 'create', options: { ...createOpts, rp: { id: 'neu.example.net', name: 'Sub' } } }, WEB);
  const i5 = await raw('pkInfo', { reqId: b5.reqId }, FRAME);
  ok(i5.ok && !i5.choices.some((c) => c.id === i1.choices[0].id), 'Passkey einer anderen rpId wird nicht zum Ersetzen angeboten');
  ok((await raw('pkFinish', { reqId: b5.reqId, action: 'confirm', choice: i1.choices[0].id }, FRAME)).ok === false, '… und kann auch nicht erzwungen ersetzt werden');
  await raw('pkResult', { reqId: b5.reqId }, WEB);

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
  await fails(call('setPin', { pin: '4711', persist: true }), /8 Zeichen/, 'dauerhafte PIN braucht mindestens 8 Zeichen');
  await call('setPin', { pin: '4711' });
  ok(!Object.keys(browser.storage.local.d).some((k) => k.endsWith(':pin')), 'PIN-Schlüssel standardmäßig nicht auf der Festplatte');
  await call('lock');
  ok((await call('status')).state === 'locked' && (await call('status')).hasPin, 'gesperrt, PIN vorhanden');
  await fails(call('list', {}), /gesperrt/, 'gesperrt: kein Zugriff');
  await fails(call('unlockPin', { pin: '0000' }), /Falsche PIN/, 'falsche PIN');
  ok(Object.keys(browser.storage.local.d).some((k) => k.endsWith(':pinFail')), 'Fehlversuche werden dauerhaft gezählt (Neustart setzt nicht zurück)');
  await call('unlockPin', { pin: '4711' });
  ok((await call('get', { id })).item.login.password === 'zweites', 'mit PIN entsperrt');
  await call('lock');
  await fails(call('unlock', { password: 'falsch' }), /Falsches Master-Passwort/, 'falsches Master-Passwort');
  await call('unlock', { password: A.password });
  ok((await call('status')).state === 'unlocked', 'mit Master-Passwort entsperrt');
  await fails(call('bioEnable'), /Native Komponente/, 'Touch ID ohne native Seite: saubere Fehlermeldung');
  await call('setPin', { pin: 'lange-pin-123', persist: true });
  ok(Object.keys(browser.storage.local.d).some((k) => k.endsWith(':pin')) && (await call('status')).hasPin, 'dauerhafte PIN auf ausdrücklichen Wunsch');
  await call('clearPin');
  ok(!(await call('getSettings')).hasPin, 'PIN entfernt');

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
  await call('lock');
  await call('switchAccount', { id: st.accounts.find((a) => a.email === B.email).id });
  ok((await call('status')).state === 'locked', 'manuelles Sperren sperrt auch das andere Konto');
  await call('switchAccount', { id: st.accounts.find((a) => a.email === A.email).id });
  await call('unlock', { password: A.password });
  await browser.alarms.onAlarm.fns[0]({ name: 'lock' });
  ok((await call('status')).state === 'locked', 'Timer sperrt');
  await call('logout');
  ok((await call('status')).email === B.email, 'Abmelden von A → B wird aktiv');
  ok(!Object.keys(browser.storage.local.d).some((k) => k.includes(A.email)), 'lokale Daten von A entfernt');
  await call('unlock', { password: B.password });
  await call('setSettings', { settings: { timeoutAction: 'logout' } });
  await browser.alarms.onAlarm.fns[0]({ name: 'lock' });
  ok((await call('status')).state === 'loggedOut', 'Timeout-Aktion „Abmelden“ meldet ab');
  ok(!Object.keys(browser.storage.local.d).some((k) => k.startsWith('a:')), 'keine Kontodaten mehr gespeichert');
  ok((await call('getSettings')).settings.timeoutAction === 'logout', 'Einstellungen bleiben nach dem Abmelden erhalten');

  console.log(`\nE2E OK – ${n} Prüfungen gegen ${BASE}`);
})().catch((e) => { console.error('\n' + (e.stack || e)); process.exit(1); });
