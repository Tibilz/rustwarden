// Regressionstest: render() darf null/false/undefined nicht als Text ("null") in die Seite schreiben.
// Minimales DOM mit der Semantik von ParentNode.replaceChildren/append: Nicht-Knoten werden zu String(x).
const fs = require('fs');
const vm = require('vm');
const path = require('path');

class Node {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.attrs = {};
    this.style = {};
    this.classList = { add() {}, remove() {} };
  }
  static conv(x) {
    return x instanceof Node ? x : { text: String(x) };
  }
  append(...xs) {
    this.children.push(...xs.map(Node.conv));
  }
  replaceChildren(...xs) {
    this.children = xs.map(Node.conv);
  }
  setAttribute(k, v) {
    this.attrs[k] = v;
  }
  addEventListener() {}
  focus() {}
  get textContent() {
    return this.children.map((c) => (c instanceof Node ? c.textContent : c.text)).join('');
  }
  set textContent(v) {
    this.children = [{ text: String(v) }];
  }
}
const app = new Node('div');
const toastNode = new Node('div');
const document = {
  getElementById: (id) => (id === 'app' ? app : id === 'toast' ? toastNode : new Node('div')),
  createElement: (t) => new Node(t),
  body: new Node('body'),
};
const clipboard = [];
let fillReply = null;
let fills = 0;
const sent = [];
let bioReply = new Promise(() => {});
const ctx = vm.createContext({
  document,
  location: { hash: '' },
  window: { close() {} },
  navigator: { clipboard: { writeText: async (t) => void clipboard.push(t) } },
  crypto: require('crypto').webcrypto,
  TextEncoder,
  console,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  browser: {
    runtime: {
      sendMessage: async (m) => {
        sent.push(m.cmd);
        if (m.cmd === 'unlockBio') return bioReply;
        if (m.cmd === 'fill') return fills++, fillReply;
        return m.cmd === 'copied' ? { ok: true } : new Promise(() => {});
      },
      onMessage: { addListener() {} },
    },
    tabs: { query: async () => [] },
  },
});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../extension/popup.js'), 'utf8'), ctx);

const header = vm.runInContext("el('header', {}, 'Kopf')", ctx);
ctx.__args = [header, null, false, undefined, [null, false]];
vm.runInContext('render(...__args)', ctx);
const text = app.textContent;
if (text !== 'Kopf') {
  console.error(`FEHLGESCHLAGEN: render() erzeugt sichtbaren Text "${text}" statt "Kopf"`);
  process.exit(1);
}
console.log('popup-render OK');

// „TOTP automatisch kopieren“: Nach dem Ausfüllen wird der Code nur kopiert, wenn die Einstellung an ist.
(async () => {
  fillReply = { ok: true, filled: true, totp: '123456' };
  await new Promise((r) => setTimeout(r, 20)); // start() des Popups läuft beim Laden asynchron und setzt tab zurück
  for (const [setting, expected] of [[false, 0], [true, 1], [undefined, 1]]) {
    clipboard.length = 0;
    fills = 0;
    vm.runInContext("tab = { id: 1, url: 'https://example.com/' }", ctx);
    ctx.__s = setting === undefined ? {} : { autoCopyTotp: setting };
    vm.runInContext('data = { settings: __s }', ctx);
    await vm.runInContext("doFill({ id: 'x', reprompt: false })", ctx);
    await new Promise((r) => setTimeout(r, 20));
    if (fills !== 1) {
      console.error(`FEHLGESCHLAGEN: autoCopyTotp=${setting} → doFill hat nicht ausgefüllt`);
      process.exit(1);
    }
    if (clipboard.length !== expected || (expected && clipboard[0] !== '123456')) {
      console.error(`FEHLGESCHLAGEN: autoCopyTotp=${setting} → ${clipboard.length}x kopiert, erwartet ${expected}x`);
      process.exit(1);
    }
  }
  console.log('auto-copy-totp OK');

  // Touch ID wird beim Öffnen des gesperrten Popups automatisch angefragt – genau einmal.
  const bioCalls = () => sent.filter((c) => c === 'unlockBio').length;
  const locked = (extra) => ({ state: 'locked', email: 'a@b.c', accounts: [], hasPin: false, hasBio: true, bioAuto: true, ...extra });
  const fail = (m) => (console.error('FEHLGESCHLAGEN: ' + m), process.exit(1));
  ctx.__st = locked({ bioAuto: false });
  vm.runInContext('viewLocked(__st)', ctx);
  if (bioCalls() !== 0) fail('Touch ID trotz ausgeschalteter Einstellung angefragt');
  ctx.__st = locked({ hasBio: false });
  vm.runInContext('viewLocked(__st)', ctx);
  if (bioCalls() !== 0) fail('Touch ID angefragt, obwohl nicht eingerichtet');
  bioReply = Promise.resolve({ ok: false, error: 'Abgebrochen', code: 'cancelled' });
  ctx.__st = locked();
  vm.runInContext('viewLocked(__st)', ctx);
  await new Promise((r) => setTimeout(r, 20));
  if (bioCalls() !== 1) fail(`Touch ID ${bioCalls()}x statt 1x angefragt`);
  if (/Abgebrochen/.test(toastNode.textContent)) fail('Abbruch wird als Fehler angezeigt');
  vm.runInContext('viewLocked(__st)', ctx); // erneutes Zeichnen (z. B. nach Abbruch) fragt nicht nochmal
  await new Promise((r) => setTimeout(r, 20));
  if (bioCalls() !== 1) fail('Touch ID nach Abbruch erneut automatisch angefragt');
  console.log('touch-id-auto OK');

  // „Vom alten Passwort ableiten“: nur Regeln, kein Inhalt
  const rules = (pw) => JSON.parse(vm.runInContext(`JSON.stringify(rulesOf(${JSON.stringify(pw)}))`, ctx));
  const r1 = rules('Sommer#2024xY');
  if (!(r1.length === 13 && r1.upper && r1.lower && r1.numbers && r1.special && r1.specialChars === '#')) fail('Regeln falsch: ' + JSON.stringify(r1));
  const r2 = rules('nur-kleine_buchstaben-');
  if (!(r2.length === 22 && !r2.upper && r2.lower && !r2.numbers && r2.specialChars === '-_')) fail('Regeln falsch: ' + JSON.stringify(r2));
  const r3 = rules('1234');
  if (!(r3.length === 5 && r3.numbers && !r3.upper && !r3.lower && !r3.special)) fail('Mindestlänge/Ziffern falsch: ' + JSON.stringify(r3));
  if (vm.runInContext("describeRules(rulesOf('Ab1#'))", ctx) !== '5 Zeichen · A–Z · a–z · 0–9 · Sonderzeichen #') fail('Beschreibung falsch');
  console.log('derive-rules OK');
})();
