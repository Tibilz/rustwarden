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
const document = {
  getElementById: (id) => (id === 'app' ? app : new Node('div')),
  createElement: (t) => new Node(t),
  body: new Node('body'),
};
const clipboard = [];
let fillReply = null;
let fills = 0;
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
})();
