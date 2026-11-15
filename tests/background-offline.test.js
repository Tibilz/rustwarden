// Offline-Test des Hintergrundskripts (ohne Server): lokal verschlüsselter Tresor mit Identität und
// Karte. Prüft Kontextmenüs „Identität/Karte ausfüllen“, das Ausfüllen daraus und die Umstellung der
// Einstellung „Identitäten anzeigen“.
// Aufruf: node tests/background-offline.test.js   (braucht extension/wasm aus ./build.sh)
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const nc = require('crypto');

const DIR = path.join(__dirname, '../extension');
const EXT = 'ext://rwid/';
const store = () => {
  const d = {};
  return {
    d,
    get: async (k) => (k == null ? { ...d } : typeof k === 'string' ? { [k]: d[k] } : Object.fromEntries(k.map((x) => [x, d[x]]))),
    set: async (o) => void Object.assign(d, JSON.parse(JSON.stringify(o))),
    remove: async (k) => void [].concat(k).forEach((x) => delete d[x]),
  };
};
const ev = () => ({ fns: [], addListener(f) { this.fns.push(f); } });
let menus = [];
const injected = [];
let popupOpened = 0;
const browser = {
  storage: { local: store(), session: store() },
  runtime: { id: 'rwid', getURL: (p) => EXT + p, onMessage: ev(), onInstalled: ev(), onStartup: ev(), sendMessage: async () => ({}) },
  alarms: { create() {}, clear: async () => {}, onAlarm: ev() },
  action: { setBadgeText() {}, openPopup: async () => void popupOpened++ },
  commands: { onCommand: ev() },
  contextMenus: {
    removeAll: async () => void (menus = []),
    create: (o, cb) => {
      if (menus.some((m) => m.id === o.id)) throw new Error('doppelte ID ' + o.id);
      menus.push(o);
      cb && cb();
    },
    onClicked: ev(),
  },
  scripting: { executeScript: async (o) => (injected.push(o), [{ result: true }]) },
  tabs: { query: async () => [], get: async (id) => ({ id, url: 'about:blank' }) },
};
const ctx = vm.createContext({
  browser, console, URL, TextEncoder, TextDecoder, WebAssembly, structuredClone, crypto: nc.webcrypto, atob, btoa,
  setTimeout, clearTimeout,
  fetch: async (u) => {
    const f = path.join(DIR, String(u).slice(EXT.length));
    return { arrayBuffer: async () => new Uint8Array(fs.readFileSync(f)), text: async () => fs.readFileSync(f, 'utf8') };
  },
});
for (const f of ['wasm/rw_core.js', 'background.js']) vm.runInContext(fs.readFileSync(path.join(DIR, f), 'utf8'), ctx, { filename: f });
vm.runInContext('globalThis.__core = core; globalThis.__settings = settings; globalThis.__lock = lock;', ctx);

let n = 0;
const ok = (c, what) => {
  if (!c) {
    console.error('FEHLGESCHLAGEN: ' + what);
    process.exit(1);
  }
  n++;
};
const wait = (ms = 300) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const w = await ctx.__core();
  // Einstellung: alter gespeicherter Standard „aus“ (ohne Version) → wird einmalig eingeschaltet
  await browser.storage.local.set({ settings: { showIdentities: false, timeout: 15 } });
  ok((await ctx.__settings()).showIdentities === true, 'alter Standard „Identitäten aus“ wird einmalig eingeschaltet');
  await browser.storage.local.set({ settings: { showIdentities: false, v: 2 } });
  ok((await ctx.__settings()).showIdentities === false, 'bewusst ausgeschaltet (v2) bleibt aus');
  await browser.storage.local.set({ settings: {} });

  // Tresor mit Login, Identität, Karte und einer Identität mit Master-Passwort-Abfrage
  const session = JSON.stringify({ user: w.random_b64(64), orgs: {} });
  const enc = (id, view) => ({ id, ...JSON.parse(w.encrypt_cipher(session, JSON.stringify(view), 'null')) });
  const ciphers = [
    enc('l1', { type: 1, name: 'Login', login: { username: 'u', password: 'p', uris: [{ uri: 'https://shop.example.com' }] } }),
    enc('i1', { type: 4, name: 'Privat', identity: { firstName: 'Erika', lastName: 'Mustermann', email: 'erika@example.com', city: 'Berlin', postalCode: '10115' } }),
    enc('i2', { type: 4, name: 'Geheim', reprompt: 1, identity: { firstName: 'X' } }),
    enc('c1', { type: 3, name: 'Visa', card: { cardholderName: 'Erika M', number: '4111111111111111', expMonth: '4', expYear: '2030', code: '123' } }),
  ];
  const id = 'erika@example.com|test';
  await browser.storage.local.set({
    active: id,
    accounts: [{ id, email: 'erika@example.com', server: { region: 'us' } }],
    [`a:${id}:vault`]: JSON.stringify({ ciphers, folders: [], collections: [], sends: [] }),
  });

  // Gesperrt: nur „Login ausfüllen“, keine Namen von Einträgen im Menü
  vm.runInContext('scheduleMenus()', ctx);
  await wait();
  ok(menus.length === 1 && menus[0].id === 'fill', 'gesperrt: nur „Login ausfüllen“ im Kontextmenü');

  // Entsperrt: Untermenüs mit Identitäten und Karten
  await browser.storage.session.set({ ['s:' + id]: session });
  vm.runInContext('scheduleMenus()', ctx);
  await wait();
  const ids = menus.map((m) => m.id);
  ok(ids.includes('identity') && ids.includes('identity:i1') && ids.includes('identity:i2'), 'entsperrt: Untermenü „Identität ausfüllen“');
  ok(ids.includes('card') && ids.includes('card:c1'), 'entsperrt: Untermenü „Karte ausfüllen“');
  ok(!ids.includes('identity:l1') && !ids.includes('card:i1'), 'Untermenüs enthalten nur den passenden Typ');
  ok(menus.find((m) => m.id === 'identity:i1').parentId === 'identity' && /Privat – Erika Mustermann/.test(menus.find((m) => m.id === 'identity:i1').title), 'Menüeintrag zeigt Name und Person');
  ok(!menus.some((m) => /4111/.test(m.title)), 'Kartennummer erscheint nicht im Menü');

  // Klick auf eine Identität füllt die Seite mit den Identitätsdaten (an die Origin gebunden)
  const tab = { id: 5, url: 'https://shop.example.com/kasse' };
  browser.contextMenus.onClicked.fns[0]({ menuItemId: 'identity:i1' }, tab);
  await wait();
  const d = injected.at(-1) && injected.at(-1).args[0];
  ok(d && d.kind === 'rules' && d.origin === 'https://shop.example.com', 'Identität wird in die Seite gefüllt, gebunden an deren Origin');
  const val = (ac) => (d.rules.find((r) => r[0] === ac) || [])[2];
  ok(val('given-name') === 'Erika' && val('family-name') === 'Mustermann' && val('email') === 'erika@example.com' && val('postal-code') === '10115' && val('address-level2') === 'Berlin', 'richtige Identitätsfelder');
  browser.contextMenus.onClicked.fns[0]({ menuItemId: 'card:c1' }, tab);
  await wait();
  ok(injected.at(-1).args[0].rules.find((r) => r[0] === 'cc-number')[2] === '4111111111111111', 'Karte wird ausgefüllt');

  // Eintrag mit Master-Passwort-Abfrage → Popup statt direktem Ausfüllen
  const before = injected.length;
  popupOpened = 0;
  browser.contextMenus.onClicked.fns[0]({ menuItemId: 'identity:i2' }, tab);
  await wait();
  ok(injected.length === before && popupOpened === 1, 'Eintrag mit Master-Passwort-Abfrage öffnet das Popup statt auszufüllen');

  // Sperren entfernt die Untermenüs wieder
  await ctx.__lock();
  await wait();
  ok(menus.length === 1 && menus[0].id === 'fill', 'nach dem Sperren: Untermenüs entfernt');

  // Skripte ohne eigene HTML-Seite (Hintergrund, Content-Script, Seiten-Brücke) brauchen ein UTF-8-BOM,
  // sonst liest Safari sie nicht als UTF-8 und Umlaute in Menüs/Meldungen werden zu „Ã¼“.
  for (const f of ['background.js', 'content.js', 'passkey-page.js']) {
    const b = fs.readFileSync(path.join(DIR, f));
    const ascii = b.every((x) => x < 0x80);
    ok(ascii || (b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf), `${f}: UTF-8-BOM vorhanden (enthält Umlaute)`);
  }

  console.log(`background-offline: ${n} OK`);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
