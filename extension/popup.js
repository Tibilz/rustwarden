// RustWarden – Popup. Reines DOM, kein Framework. Alle Nutzdaten werden per textContent gesetzt.
'use strict';

const app = document.getElementById('app');
const toastEl = document.getElementById('toast');

const TYPE = { 1: 'Login', 2: 'Notiz', 3: 'Karte', 4: 'Identität', 5: 'SSH-Schlüssel' };
const BADGE = { 1: 'LG', 2: 'NO', 3: 'KA', 4: 'ID', 5: 'SSH' };
const CARD = [
  ['cardholderName', 'Karteninhaber'],
  ['brand', 'Marke'],
  ['number', 'Nummer', true],
  ['expMonth', 'Ablaufmonat'],
  ['expYear', 'Ablaufjahr'],
  ['code', 'Prüfnummer', true],
];
const IDENT = [
  ['title', 'Anrede'],
  ['firstName', 'Vorname'],
  ['middleName', 'Zweiter Vorname'],
  ['lastName', 'Nachname'],
  ['username', 'Benutzername'],
  ['company', 'Firma'],
  ['email', 'E-Mail'],
  ['phone', 'Telefon'],
  ['ssn', 'Sozialversicherungsnummer', true],
  ['passportNumber', 'Reisepassnummer', true],
  ['licenseNumber', 'Führerscheinnummer', true],
  ['address1', 'Adresse 1'],
  ['address2', 'Adresse 2'],
  ['address3', 'Adresse 3'],
  ['city', 'Stadt'],
  ['state', 'Bundesland'],
  ['postalCode', 'PLZ'],
  ['country', 'Land'],
];
const SSH = [
  ['publicKey', 'Öffentlicher Schlüssel'],
  ['keyFingerprint', 'Fingerabdruck'],
  ['privateKey', 'Privater Schlüssel', true],
];
const MATCH = { '': 'Standard', 0: 'Basis-Domain', 1: 'Host', 2: 'Beginnt mit', 3: 'Exakt', 4: 'Regex', 5: 'Nie' };

let tab = null;
let data = null; // Antwort von "list"
let query = '';
let filter = 'all';
let folderFilter = '';
let timer = null;
const verified = new Set();
let showOthers = false; // weitere passende Logins trotz gemerktem Login aufgeklappt

// Safari schließt das Popup, sobald ein Dateidialog aufgeht – Dateiaktionen laufen deshalb in einem Tab.
const inTab = location.hash.startsWith('#tab');
if (inTab) document.body.classList.add('tab');

function openTab(route) {
  browser.tabs.create({ url: browser.runtime.getURL('popup.html#tab/' + (route || '')) });
  window.close();
}

function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type: type || 'application/octet-stream' }));
  const a = el('a', { href: url, download: name });
  document.body.append(a);
  a.click();
  setTimeout(() => (URL.revokeObjectURL(url), a.remove()), 30000);
}

function pickFile(accept) {
  return new Promise((resolve) => {
    const i = el('input', { type: 'file', accept });
    i.onchange = () => resolve(i.files[0] || null);
    i.click();
  });
}

async function fileB64(file) {
  const u = new Uint8Array(await file.arrayBuffer());
  let str = '';
  for (let i = 0; i < u.length; i += 0x8000) str += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(str);
}

function b64Bytes(b) {
  const str = atob(b);
  const u = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) u[i] = str.charCodeAt(i);
  return u;
}

async function sha256Hex(text) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------- Basis ----------

// Einheitliche Strich-Icons (24er Raster) statt Unicode-Zeichen, die je nach Schrift winzig ausfallen.
const ICONS = {
  back: 'M15 18l-6-6 6-6',
  sync: 'M21 12a9 9 0 1 1-2.64-6.36L21 8M21 3v5h-5',
  plus: 'M12 5v14M5 12h14',
  dice: 'M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zM8.5 8.5h.01M15.5 8.5h.01M12 12h.01M8.5 15.5h.01M15.5 15.5h.01',
  send: 'M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z',
  gear: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
  external: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z',
  key: 'M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.78 7.78 5.5 5.5 0 0 1 7.78-7.78zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 6v6l4 2',
  chevron: 'M9 18l6-6-6-6',
  eye: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  copy: 'M9 9h11a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-9a2 2 0 0 1-2-2V9zM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1',
  download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3',
  x: 'M18 6L6 18M6 6l12 12',
};
function icon(name) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  for (const [k, v] of Object.entries({ viewBox: '0 0 24 24', width: 20, height: 20, fill: 'none', stroke: 'currentColor',
    'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) svg.setAttribute(k, v);
  const path = document.createElementNS(NS, 'path');
  path.setAttribute('d', ICONS[name]);
  svg.append(path);
  return svg;
}
const iconBtn = (name, title, onclick) => el('button', { class: 'icon', title, 'aria-label': title, onclick }, icon(name));

function applyTheme(theme) {
  if (theme === 'light' || theme === 'dark') document.documentElement.setAttribute('data-theme', theme);
  else document.documentElement.removeAttribute('data-theme');
}

function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  let value;
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') e.className = v;
    else if (k === 'value') value = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, '');
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) e.append(c);
  if (value != null) e.value = value;
  return e;
}

async function send(cmd, extra) {
  const r = await browser.runtime.sendMessage({ cmd, ...(extra || {}) });
  if (!r || !r.ok) throw new Error((r && r.error) || 'Keine Antwort vom Hintergrundprozess');
  return r;
}

function toast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.add('show');
  clearTimeout(toast.t);
  toast.t = setTimeout(() => toastEl.classList.remove('show'), 1800);
}

function render(...nodes) {
  clearInterval(timer);
  timer = null;
  // Wie in el(): bedingte Teile (`x && el(...)`) liefern null/false und dürfen nicht als Text erscheinen.
  app.replaceChildren(...nodes.flat(Infinity).filter((n) => n != null && n !== false));
}

// Safari verlangt Clipboard-Zugriff im Klick-Kontext – daher ClipboardItem mit Promise.
async function copy(value, label) {
  const p = Promise.resolve(value).then((v) => String(v ?? ''));
  // Für das optionale automatische Leeren der Zwischenablage (nur der Hash verlässt das Popup).
  p.then(sha256Hex)
    .then((hash) => send('copied', { hash }))
    .catch(() => {});
  try {
    if (window.ClipboardItem) {
      await navigator.clipboard.write([
        new ClipboardItem({ 'text/plain': p.then((t) => new Blob([t], { type: 'text/plain' })) }),
      ]);
    } else {
      await navigator.clipboard.writeText(await p);
    }
    toast(`${label} kopiert`);
  } catch {
    try {
      await navigator.clipboard.writeText(await p);
      toast(`${label} kopiert`);
    } catch {
      toast('Kopieren fehlgeschlagen');
    }
  }
}

function header(title, { back, actions } = {}) {
  return el(
    'header',
    {},
    back && iconBtn('back', 'Zurück', back),
    el('h1', {}, title),
    actions,
  );
}

function busy(btn, fn) {
  return async (e) => {
    if (e) e.preventDefault();
    const b = typeof btn === 'function' ? btn() : btn;
    if (b) b.disabled = true;
    try {
      await fn(e);
    } catch (err) {
      toast(err.message);
    } finally {
      if (b) b.disabled = false;
    }
  };
}

function askPassword() {
  return new Promise((resolve) => {
    const inp = el('input', { type: 'password', placeholder: 'Master-Passwort', autocomplete: 'off' });
    const done = (ok) => {
      dlg.remove();
      resolve(ok);
    };
    const dlg = el(
      'div',
      { class: 'modal' },
      el(
        'form',
        {
          onsubmit: async (e) => {
            e.preventDefault();
            try {
              await send('verify', { password: inp.value });
              done(true);
            } catch (err) {
              toast(err.message);
            }
          },
        },
        el('p', {}, 'Master-Passwort erneut eingeben'),
        inp,
        el(
          'div',
          { class: 'btns' },
          el('button', { type: 'button', onclick: () => done(false) }, 'Abbrechen'),
          el('button', { class: 'primary' }, 'Bestätigen'),
        ),
      ),
    );
    document.body.append(dlg);
    inp.focus();
  });
}

async function guard(it) {
  if (!it.reprompt || verified.has(it.id)) return true;
  if (!(await askPassword())) return false;
  verified.add(it.id);
  return true;
}

// ---------- Anmeldung ----------

function viewLogin(adding) {
  const region = el(
    'select',
    { onchange: () => (base.style.display = region.value === 'self' ? '' : 'none') },
    el('option', { value: 'us' }, 'bitwarden.com'),
    el('option', { value: 'eu' }, 'bitwarden.eu'),
    el('option', { value: 'self' }, 'Selbst gehostet (z. B. Vaultwarden)'),
  );
  const base = el('input', { type: 'url', placeholder: 'https://vault.example.com', style: 'display:none;margin-top:6px' });
  const email = el('input', { type: 'email', autocomplete: 'username', placeholder: 'name@example.com' });
  const pw = el('input', { type: 'password', autocomplete: 'current-password' });
  const btn = el('button', { class: 'primary' }, 'Anmelden');
  try {
    const last = JSON.parse(localStorage.getItem('lastLogin') || '{}');
    if (last.region) region.value = last.region;
    if (last.base) base.value = last.base;
    if (last.email) email.value = last.email;
    base.style.display = region.value === 'self' ? '' : 'none';
  } catch {}
  render(
    el(
      'main',
      {},
      el('div', { class: 'brand' }, 'Rust', el('span', {}, 'Warden')),
      el(
        'form',
        {
          onsubmit: busy(btn, async () => {
            const server = { region: region.value, base: base.value.trim() };
            try {
              localStorage.setItem('lastLogin', JSON.stringify({ ...server, email: email.value.trim() }));
            } catch {}
            const r = await send('login', { server, email: email.value, password: pw.value });
            await afterLogin(r);
          }),
        },
        el('label', {}, 'Server'),
        region,
        base,
        el('label', {}, 'E-Mail'),
        email,
        el('label', {}, 'Master-Passwort'),
        pw,
        el('div', { class: 'btns' }, btn),
      ),
      adding && el('p', { class: 'center' }, el('button', { class: 'link', onclick: () => start() }, 'Abbrechen')),
    ),
  );
  (email.value && !adding ? pw : email).focus();
}

async function afterLogin(r) {
  if (r.step === 'twoFactor') viewTwoFactor(r);
  else if (r.step === 'newDevice') viewNewDevice();
  else await viewMain();
}

function viewTwoFactor(st) {
  const names = { 0: 'Authenticator-App', 1: 'E-Mail', 3: 'YubiKey' };
  const usable = (st.providers || []).map(String).filter((p) => names[p]);
  const cancel = el('button', { type: 'button', class: 'link', onclick: async () => (await send('cancelLogin'), start()) }, 'Abbrechen');
  if (!usable.length) {
    render(
      header('Zwei-Faktor-Anmeldung'),
      el('main', {}, el('p', {}, 'Für dieses Konto sind nur Verfahren aktiv, die RustWarden noch nicht unterstützt (Duo, WebAuthn/Passkey).'), cancel),
    );
    return;
  }
  const sent = new Set();
  const mailCode = async () => {
    try {
      await send('emailCode');
      toast('Code per E-Mail gesendet');
    } catch (e) {
      toast(e.message);
    }
  };
  const resend = el('button', { type: 'button', class: 'link', onclick: mailCode }, 'Code erneut senden');
  const onProvider = () => {
    const isMail = provider.value === '1';
    resend.style.display = isMail ? '' : 'none';
    hint.textContent = isMail && st.emailHint ? `Code wird an ${st.emailHint} gesendet.` : '';
    if (isMail && !sent.has('1')) {
      sent.add('1');
      mailCode();
    }
  };
  const provider = el('select', { onchange: onProvider }, usable.map((p) => el('option', { value: p }, names[p])));
  const hint = el('div', { class: 'muted small' });
  const code = el('input', { autocomplete: 'one-time-code', placeholder: 'Code' });
  const remember = el('input', { type: 'checkbox' });
  const btn = el('button', { class: 'primary' }, 'Weiter');
  render(
    header('Zwei-Faktor-Anmeldung'),
    el(
      'main',
      {},
      el(
        'form',
        {
          onsubmit: busy(btn, async () => {
            const r = await send('login', {
              twoFactor: { provider: Number(provider.value), token: code.value, remember: remember.checked },
            });
            await afterLogin(r);
          }),
        },
        el('label', {}, 'Verfahren'),
        provider,
        hint,
        el('label', {}, 'Bestätigungscode'),
        code,
        el('label', { class: 'check' }, remember, 'Dieses Gerät merken'),
        el('div', { class: 'btns' }, btn),
        el('p', { class: 'inline', style: 'justify-content:space-between' }, cancel, resend),
      ),
    ),
  );
  onProvider();
  code.focus();
}

function viewNewDevice() {
  const code = el('input', { autocomplete: 'one-time-code', placeholder: 'Code aus der E-Mail' });
  const btn = el('button', { class: 'primary' }, 'Weiter');
  render(
    header('Neues Gerät bestätigen'),
    el(
      'main',
      {},
      el('p', {}, 'Der Server hat einen Bestätigungscode an deine E-Mail-Adresse gesendet.'),
      el(
        'form',
        { onsubmit: busy(btn, async () => afterLogin(await send('login', { newDeviceOtp: code.value }))) },
        code,
        el('div', { class: 'btns' }, btn),
      ),
      el('p', {}, el('button', { class: 'link', onclick: async () => (await send('cancelLogin'), start()) }, 'Abbrechen')),
    ),
  );
  code.focus();
}

function accountSwitcher(st) {
  const others = (st.accounts || []).filter((a) => a.id !== st.active);
  return el(
    'p',
    { class: 'center small' },
    others.map((a) =>
      el(
        'button',
        { class: 'link', style: 'display:block;margin:5px auto', onclick: async () => (await send('switchAccount', { id: a.id }), start()) },
        `Wechseln zu ${a.email}`,
      ),
    ),
    el('button', { class: 'link', onclick: () => viewLogin(true) }, 'Konto hinzufügen'),
  );
}

function viewLocked(st) {
  const pw = el('input', { type: 'password', autocomplete: 'current-password', placeholder: 'Master-Passwort' });
  const btn = el('button', { class: st.hasPin ? '' : 'primary' }, 'Entsperren');
  const pin = st.hasPin ? el('input', { type: 'password', autocomplete: 'off', placeholder: 'PIN' }) : null;
  const pinBtn = el('button', { class: 'primary' }, 'Mit PIN entsperren');
  render(
    el(
      'main',
      {},
      el('div', { class: 'brand' }, 'Rust', el('span', {}, 'Warden')),
      el('p', { class: 'center muted' }, st.email),
      st.hasBio &&
        el(
          'div',
          { class: 'btns' },
          el('button', { class: 'primary', onclick: busy(null, async () => (await send('unlockBio'), start())) }, 'Mit Touch ID entsperren'),
        ),
      pin &&
        el(
          'form',
          { onsubmit: busy(pinBtn, async () => (await send('unlockPin', { pin: pin.value }), start())) },
          el('label', {}, 'PIN'),
          pin,
          el('div', { class: 'btns' }, pinBtn),
        ),
      el(
        'form',
        { onsubmit: busy(btn, async () => (await send('unlock', { password: pw.value }), start())) },
        el('label', {}, 'Master-Passwort'),
        pw,
        el('div', { class: 'btns' }, btn),
      ),
      el('p', { class: 'center' }, el('button', { class: 'link', onclick: async () => (await send('logout'), start()) }, 'Abmelden')),
      accountSwitcher(st),
    ),
  );
  (pin || pw).focus();
}

// ---------- Tresorliste ----------

async function loadList() {
  data = await send('list', { url: tab && tab.url });
  showOthers = false;
}

async function viewMain(reload = true) {
  if (reload || !data) await loadList();
  const search = el('input', {
    type: 'search',
    placeholder: 'Tresor durchsuchen',
    value: query,
    oninput: () => {
      query = search.value;
      drawList(list);
    },
  });
  const chip = (id, label) =>
    el(
      'button',
      {
        class: 'chip' + (filter === id ? ' on' : ''),
        onclick: () => {
          filter = id;
          viewMain(false);
        },
      },
      label,
    );
  const folderSel = el(
    'select',
    {
      value: folderFilter,
      onchange: () => {
        folderFilter = folderSel.value;
        drawList(list);
      },
    },
    el('option', { value: '' }, 'Alle Ordner'),
    el('option', { value: 'none' }, 'Kein Ordner'),
    data.folders.map((f) => el('option', { value: f.id }, f.name || '?')),
  );
  const list = el('main', { class: 'flush' });
  const p = data.pending;
  render(
    el(
      'header',
      {},
      search,
      iconBtn(
        'sync',
        'Mit Server abgleichen',
        busy(null, async () => {
          toast('Synchronisiere …');
          await send('sync');
          await viewMain();
          toast('Tresor ist aktuell');
        }),
      ),
      iconBtn('plus', 'Neuer Eintrag', () => viewNew()),
      iconBtn('dice', 'Generator', () => viewGenerator()),
      iconBtn('send', 'Send', () => viewSends()),
      iconBtn('gear', 'Einstellungen', () => viewSettings()),
    ),
    p &&
      el(
        'div',
        { class: 'banner' },
        el(
          'div',
          { class: 'txt' },
          p.kind === 'update' ? `Passwort für „${p.name}“ aktualisieren?` : `Login für ${p.host} speichern?`,
          p.username && el('div', { class: 'muted small' }, p.username),
        ),
        el('button', { class: 'primary', onclick: busy(null, async () => (await send('pendingAccept'), toast('Gespeichert'), viewMain())) }, 'Speichern'),
        el('button', { title: 'Für diese Seite nie anbieten', onclick: busy(null, async () => (await send('neverDomain'), toast(`${p.host} ausgeschlossen`), viewMain())) }, 'Nie'),
        el('button', { title: 'Jetzt nicht', onclick: busy(null, async () => (await send('pendingDismiss'), viewMain())) }, '✕'),
      ),
    el(
      'div',
      { class: 'chips' },
      chip('all', 'Alle'),
      chip('fav', 'Favoriten'),
      chip('1', 'Logins'),
      chip('3', 'Karten'),
      chip('4', 'Identitäten'),
      chip('2', 'Notizen'),
      chip('trash', 'Papierkorb'),
      folderSel,
    ),
    list,
  );
  drawList(list);
  search.focus();
}

function drawList(root) {
  const q = query.trim().toLowerCase();
  const pass = (it) => {
    if (filter === 'trash') {
      if (!it.deleted) return false;
    } else {
      if (it.deleted) return false;
      if (filter === 'fav' && !it.fav) return false;
      if (/^\d$/.test(filter) && it.type !== Number(filter)) return false;
    }
    if (folderFilter === 'none' && it.folderId) return false;
    if (folderFilter && folderFilter !== 'none' && it.folderId !== folderFilter) return false;
    return !q || it.name.toLowerCase().includes(q) || (it.sub || '').toLowerCase().includes(q);
  };
  const items = data.items.filter(pass);
  const nodes = [];
  const plain = filter === 'all' && !q && !folderFilter;
  if (plain && tab && /^https?:/.test(tab.url || '')) {
    const byId = new Map(data.items.map((i) => [i.id, i]));
    const m = data.matchIds.map((id) => byId.get(id)).filter(Boolean);
    const others = (data.otherMatchIds || []).map((id) => byId.get(id)).filter(Boolean);
    nodes.push(el('div', { class: 'section' }, `Diese Seite (${m.length})`));
    if (m.length) m.forEach((it) => nodes.push(row(it, true)));
    else nodes.push(el('div', { class: 'empty' }, 'Keine passenden Logins für diese Seite.'));
    if (others.length) {
      if (showOthers) others.forEach((it) => nodes.push(row(it, true)));
      nodes.push(
        el(
          'div',
          { class: 'more' },
          el(
            'button',
            { class: 'link', onclick: () => ((showOthers = !showOthers), drawList(root)) },
            showOthers ? 'Weitere ausblenden' : `${others.length} weitere ${others.length === 1 ? 'passt' : 'passen'} ebenfalls`,
          ),
          el(
            'button',
            {
              class: 'link muted',
              title: 'Für diese Adresse wieder alle passenden Logins vorschlagen',
              onclick: busy(null, async () => {
                await send('forgetHost', { url: tab.url });
                toast('Zuordnung vergessen');
                await viewMain();
              }),
            },
            'Zuordnung vergessen',
          ),
        ),
      );
    }
    const st = data.settings || {};
    for (const [on, type, label] of [[st.showCards, 3, 'Karten'], [st.showIdentities, 4, 'Identitäten']]) {
      const list = on ? data.items.filter((i) => i.type === type && !i.deleted) : [];
      if (!list.length) continue;
      nodes.push(el('div', { class: 'section' }, `${label} (${list.length})`));
      list.forEach((it) => nodes.push(row(it, true)));
    }
    nodes.push(el('div', { class: 'section' }, `Alle Einträge (${items.length})`));
  }
  const MAX = 300;
  items.slice(0, MAX).forEach((it) => nodes.push(row(it, false)));
  if (!items.length) nodes.push(el('div', { class: 'empty' }, q ? 'Keine Treffer.' : 'Keine Einträge.'));
  if (items.length > MAX) nodes.push(el('div', { class: 'empty small' }, `${items.length - MAX} weitere – Suche eingrenzen.`));
  root.replaceChildren(...nodes);
}

function row(it, isMatch) {
  const act = (label, title, fn) =>
    el(
      'button',
      {
        class: 'icon',
        title,
        onclick: (e) => {
          e.stopPropagation();
          fn();
        },
      },
      label,
    );
  const getField = (pick) => send('get', { id: it.id }).then((r) => pick(r.item));
  const quick = (data && data.settings ? data.settings.quickCopy !== false : true) && !it.reprompt && !it.deleted && it.type === 1;
  return el(
    'div',
    {
      class: 'row',
      title: isMatch ? 'Klicken zum Ausfüllen' : '',
      onclick: () => (isMatch ? doFill(it) : viewItem(it.id)),
    },
    el('div', { class: 'badge' }, BADGE[it.type] || '?'),
    el(
      'div',
      { class: 'txt' },
      el('div', { class: 'name' }, it.name, it.fav && el('span', { class: 'star' }, ' ★')),
      el('div', { class: 'sub' }, it.sub || TYPE[it.type] || ''),
    ),
    el(
      'div',
      { class: 'acts' },
      quick && it.user && act(icon('user'), 'Benutzername kopieren', () => copy(getField((v) => v.login.username), 'Benutzername')),
      quick && it.pass && act(icon('key'), 'Passwort kopieren', () => copy(getField((v) => v.login.password), 'Passwort')),
      quick && it.totp && act(icon('clock'), 'TOTP-Code kopieren', () => copy(send('totp', { id: it.id }).then((r) => r.totp.code), 'Code')),
      isMatch && act(icon('chevron'), 'Details', () => viewItem(it.id)),
    ),
  );
}

async function doFill(it) {
  try {
    if (!(await guard(it))) return;
    if (!tab) throw new Error('Kein aktiver Tab');
    const r = await send('fill', { id: it.id, tabId: tab.id });
    if (!r.filled) return toast('Keine passenden Felder gefunden');
    const autoCopy = !data || !data.settings || data.settings.autoCopyTotp !== false;
    if (r.totp && autoCopy) await copy(r.totp, 'Ausgefüllt – TOTP-Code');
    window.close();
  } catch (e) {
    toast(e.message);
  }
}

// ---------- Detail ----------

function fieldRow(label, value, { secret, mono, copyLabel, link } = {}) {
  if (value == null || value === '') return null;
  let shown = !secret;
  const v = el('div', { class: 'v' + (mono || secret ? ' mono' : '') });
  const draw = () => (v.textContent = shown ? value : '••••••••••');
  draw();
  return el(
    'div',
    { class: 'field' },
    el('div', { class: 'body' }, el('div', { class: 'k' }, label), v),
    secret && el('button', { class: 'icon', title: 'Anzeigen/Verbergen', onclick: () => ((shown = !shown), draw()) }, icon('eye')),
    link && el('button', { class: 'icon', title: 'Öffnen', onclick: () => browser.tabs.create({ url: link }) }, icon('external')),
    el('button', { class: 'icon', title: 'Kopieren', onclick: () => copy(value, copyLabel || label) }, icon('copy')),
  );
}

async function viewItem(id) {
  let it;
  try {
    const s = data && data.items.find((x) => x.id === id);
    if (s && !(await guard(s))) return;
    it = (await send('get', { id })).item;
  } catch (e) {
    return toast(e.message);
  }
  const rows = [];
  const canEdit = it.edit !== false && !it.decryptError;
  const addAttachment = busy(null, async () => {
    if (!inTab) return openTab('item/' + id);
    const file = await pickFile();
    if (!file) return;
    toast('Wird verschlüsselt und hochgeladen …');
    await send('attAdd', { id, name: file.name, b64: await fileB64(file) });
    toast('Anhang gespeichert');
    await loadList();
    await viewItem(id);
  });
  const table = (obj, defs) => defs.forEach(([k, label, secret]) => rows.push(fieldRow(label, obj && obj[k], { secret })));

  if (it.type === 1) {
    const l = it.login || {};
    rows.push(fieldRow('Benutzername', l.username));
    rows.push(fieldRow('Passwort', l.password, { secret: true }));
    if (l.totp) {
      const code = el('div', { class: 'v mono' }, '…');
      const left = el('span', { class: 'muted small' });
      let cur = null;
      const tick = async () => {
        if (!cur || Date.now() / 1000 >= cur.until) {
          try {
            const t = (await send('totp', { id })).totp;
            cur = { code: t.code, until: Math.floor(Date.now() / 1000) + t.remaining };
          } catch (e) {
            code.textContent = e.message;
            return;
          }
        }
        code.textContent = cur.code.replace(/^(\d{3})(\d{3})$/, '$1 $2');
        left.textContent = `${Math.max(0, Math.ceil(cur.until - Date.now() / 1000))} s`;
      };
      rows.push(
        el(
          'div',
          { class: 'field' },
          el('div', { class: 'body' }, el('div', { class: 'k' }, 'Einmalcode (TOTP)'), code),
          left,
          el('button', { class: 'icon', title: 'Kopieren', onclick: () => cur && copy(cur.code, 'Code') }, icon('copy')),
        ),
      );
      tick();
      setTimeout(() => (timer = setInterval(tick, 1000)));
    }
    (l.uris || []).forEach((u) => {
      const href = /^https?:\/\//i.test(u.uri || '') ? u.uri : null;
      rows.push(fieldRow('Website', u.uri, { link: href }));
    });
    (l.fido2Credentials || []).forEach((c) =>
      rows.push(
        fieldRow('Passkey', [c.rpId, c.userName, c.creationDate && `erstellt ${new Date(c.creationDate).toLocaleDateString('de-DE')}`].filter(Boolean).join(' · ')),
      ),
    );
  } else if (it.type === 3) table(it.card, CARD);
  else if (it.type === 4) table(it.identity, IDENT);
  else if (it.type === 5) table(it.sshKey, SSH);

  rows.push(fieldRow('Notizen', it.notes));
  (it.fields || []).forEach((f) => {
    if (f.type === 3) return;
    const val = f.type === 2 ? (f.value === 'true' ? 'Ja' : 'Nein') : f.value;
    rows.push(fieldRow(f.name || 'Feld', val, { secret: f.type === 1 }));
  });
  (it.attachments || []).forEach((a) =>
    rows.push(
      el(
        'div',
        { class: 'field' },
        el('div', { class: 'body' }, el('div', { class: 'k' }, 'Anhang'), el('div', { class: 'v' }, `${a.fileName || '?'} (${a.sizeName || ''})`)),
        el(
          'button',
          {
            class: 'icon',
            title: 'Herunterladen',
            onclick: busy(null, async () => {
              if (!inTab) return openTab('item/' + id);
              const r = await send('attGet', { id, attId: a.id });
              download(r.name, b64Bytes(r.b64));
            }),
          },
          icon('download'),
        ),
        canEdit &&
          el(
            'button',
            {
              class: 'icon',
              title: 'Anhang löschen',
              onclick: busy(null, async () => {
                if (!confirm('Anhang löschen?')) return;
                await send('attDel', { id, attId: a.id });
                await loadList();
                await viewItem(id);
              }),
            },
            icon('x'),
          ),
      ),
    ),
  );
  if ((it.passwordHistory || []).length) {
    rows.push(el('label', {}, 'Passwortverlauf'));
    it.passwordHistory.forEach((h) =>
      rows.push(fieldRow(new Date(h.lastUsedDate).toLocaleString('de-DE'), h.password, { secret: true, copyLabel: 'Altes Passwort' })),
    );
  }
  const folder = data && data.folders.find((f) => f.id === it.folderId);
  const meta = [
    TYPE[it.type],
    folder && `Ordner: ${folder.name}`,
    it.organizationId && 'Organisation',
    it.revisionDate && `Geändert: ${new Date(it.revisionDate).toLocaleString('de-DE')}`,
  ].filter(Boolean);

  const canFill = !inTab && !it.deletedDate && [1, 3, 4].includes(it.type);
  const editable = canEdit;
  render(
    header(it.name || '(ohne Namen)', { back: () => viewMain(false) }),
    el(
      'main',
      {},
      it.decryptError && el('p', { class: 'error' }, 'Dieser Eintrag konnte nicht vollständig entschlüsselt werden.'),
      rows,
      el('p', { class: 'muted small' }, meta.join(' · ')),
      el(
        'div',
        { class: 'btns' },
        canFill && el('button', { class: 'primary', onclick: () => doFill({ id, reprompt: false }) }, 'Ausfüllen'),
        !it.deletedDate && editable && el('button', { onclick: () => viewEdit(it) }, 'Bearbeiten'),
        !it.deletedDate && editable && el('button', { onclick: addAttachment }, 'Anhang +'),
        it.deletedDate &&
          el('button', { onclick: busy(null, async () => (await send('restore', { id }), toast('Wiederhergestellt'), viewMain())) }, 'Wiederherstellen'),
        editable &&
          el(
            'button',
            {
              class: 'danger',
              onclick: busy(null, async () => {
                if (!confirm(it.deletedDate ? 'Endgültig löschen?' : 'In den Papierkorb verschieben?')) return;
                await send('remove', { id });
                toast('Gelöscht');
                await viewMain();
              }),
            },
            it.deletedDate ? 'Endgültig löschen' : 'Löschen',
          ),
      ),
    ),
  );
}

// ---------- Bearbeiten ----------

function viewNew() {
  const host = tab && /^https?:/.test(tab.url || '') ? new URL(tab.url) : null;
  const pick = (type) => {
    const v = { type, name: '', notes: null, favorite: false, reprompt: 0, folderId: null, fields: [] };
    if (type === 1) {
      v.name = host ? host.hostname.replace(/^www\./, '') : '';
      v.login = { username: null, password: null, totp: null, uris: host ? [{ uri: host.origin, match: null }] : [] };
    } else if (type === 2) v.secureNote = { type: 0 };
    else if (type === 3) v.card = {};
    else if (type === 4) v.identity = {};
    viewEdit(v);
  };
  render(
    header('Neuer Eintrag', { back: () => viewMain(false) }),
    el(
      'main',
      { class: 'flush' },
      [1, 3, 4, 2].map((t) =>
        el(
          'div',
          { class: 'row', onclick: () => pick(t) },
          el('div', { class: 'badge' }, BADGE[t]),
          el('div', { class: 'txt' }, el('div', { class: 'name' }, TYPE[t])),
        ),
      ),
    ),
  );
}

function viewEdit(orig) {
  const v = structuredClone(orig);
  const inputs = [];
  const bind = (obj, key, label, opts = {}) => {
    const tag = opts.area ? 'textarea' : 'input';
    const inp = el(tag, {
      type: opts.secret ? 'password' : 'text',
      class: opts.secret || opts.mono ? 'mono' : '',
      autocomplete: 'off',
      spellcheck: 'false',
      value: obj[key] ?? '',
    });
    inputs.push(() => (obj[key] = inp.value === '' ? null : inp.value));
    const extra = [];
    if (opts.secret) {
      extra.push(el('button', { type: 'button', class: 'icon', title: 'Anzeigen', onclick: () => (inp.type = inp.type === 'password' ? 'text' : 'password') }, icon('eye')));
    }
    if (opts.generate) {
      extra.push(
        el(
          'button',
          {
            type: 'button',
            class: 'icon',
            title: 'Generieren',
            onclick: () =>
              viewGenerator((val) => {
                inp.value = val;
                inp.type = 'text';
              }),
          },
          icon('dice'),
        ),
      );
    }
    return [el('label', {}, label), extra.length ? el('div', { class: 'inline' }, inp, extra) : inp];
  };

  const body = [bind(v, 'name', 'Name')];
  if (v.type === 1) {
    v.login = v.login || {};
    body.push(bind(v.login, 'username', 'Benutzername'));
    body.push(bind(v.login, 'password', 'Passwort', { secret: true, generate: true }));
    body.push(bind(v.login, 'totp', 'TOTP-Schlüssel oder otpauth://-URI', { mono: true }));

    const uriBox = el('div');
    const uriRows = [];
    const addUri = (u) => {
      const inp = el('input', { type: 'text', placeholder: 'https://…', value: u.uri || '', autocomplete: 'off' });
      const sel = el(
        'select',
        { class: 'narrow', value: u.match == null ? '' : String(u.match) },
        Object.entries(MATCH).map(([k, n]) => el('option', { value: k }, n)),
      );
      const entry = { get: () => ({ uri: inp.value.trim(), match: sel.value === '' ? null : Number(sel.value) }) };
      const line = el(
        'div',
        { class: 'inline', style: 'margin-bottom:5px' },
        inp,
        sel,
        el('button', { type: 'button', class: 'icon', onclick: () => (line.remove(), uriRows.splice(uriRows.indexOf(entry), 1)) }, icon('x')),
      );
      uriRows.push(entry);
      uriBox.append(line);
    };
    (v.login.uris || []).forEach(addUri);
    inputs.push(() => (v.login.uris = uriRows.map((r) => r.get()).filter((u) => u.uri)));
    body.push(el('label', {}, 'Websites'), uriBox, el('button', { type: 'button', class: 'link', onclick: () => addUri({}) }, '+ Website hinzufügen'));
  } else if (v.type === 3) {
    v.card = v.card || {};
    CARD.forEach(([k, label, secret]) => body.push(bind(v.card, k, label, { secret })));
  } else if (v.type === 4) {
    v.identity = v.identity || {};
    IDENT.forEach(([k, label, secret]) => body.push(bind(v.identity, k, label, { secret })));
  }
  body.push(bind(v, 'notes', 'Notizen', { area: true }));

  // Benutzerdefinierte Felder (verknüpfte Felder bleiben unverändert erhalten)
  const linked = (v.fields || []).filter((f) => f.type === 3);
  const fieldBox = el('div');
  const fieldRows = [];
  const addField = (f) => {
    const name = el('input', { type: 'text', placeholder: 'Name', value: f.name || '', autocomplete: 'off' });
    const val = el('input', { type: 'text', placeholder: 'Wert', value: f.value || '', autocomplete: 'off' });
    const type = el(
      'select',
      { class: 'narrow', value: String(f.type || 0) },
      el('option', { value: '0' }, 'Text'),
      el('option', { value: '1' }, 'Versteckt'),
      el('option', { value: '2' }, 'Ja/Nein'),
    );
    const entry = {
      get: () => ({ type: Number(type.value), name: name.value || null, value: val.value || null, linkedId: null }),
    };
    const line = el(
      'div',
      { class: 'inline', style: 'margin-bottom:5px' },
      name,
      val,
      type,
      el('button', { type: 'button', class: 'icon', onclick: () => (line.remove(), fieldRows.splice(fieldRows.indexOf(entry), 1)) }, icon('x')),
    );
    fieldRows.push(entry);
    fieldBox.append(line);
  };
  (v.fields || []).filter((f) => f.type !== 3).forEach(addField);
  inputs.push(() => (v.fields = [...fieldRows.map((r) => r.get()).filter((f) => f.name || f.value), ...linked]));
  body.push(el('label', {}, 'Eigene Felder'), fieldBox, el('button', { type: 'button', class: 'link', onclick: () => addField({}) }, '+ Feld hinzufügen'));

  const folder = el(
    'select',
    { value: v.folderId || '' },
    el('option', { value: '' }, 'Kein Ordner'),
    ((data && data.folders) || []).map((f) => el('option', { value: f.id }, f.name || '?')),
  );
  const dropKey = el('input', { type: 'checkbox' });
  const hasKey = v.type === 1 && ((v.login || {}).fido2Credentials || []).length > 0;
  if (hasKey) inputs.push(() => (v.login.removeFido2 = dropKey.checked));
  const fav = el('input', { type: 'checkbox' });
  fav.checked = !!v.favorite;
  const rep = el('input', { type: 'checkbox' });
  rep.checked = v.reprompt === 1;
  inputs.push(() => {
    v.folderId = folder.value || null;
    v.favorite = fav.checked;
    v.reprompt = rep.checked ? 1 : 0;
  });
  body.push(
    el('label', {}, 'Ordner'),
    folder,
    el('label', { class: 'check' }, fav, 'Favorit'),
    el('label', { class: 'check' }, rep, 'Master-Passwort erneut abfragen'),
    hasKey && el('label', { class: 'check' }, dropKey, 'Gespeicherten Passkey entfernen'),
  );

  if (!orig.id && data && (data.orgs || []).length) {
    const colBox = el('div');
    let checks = [];
    const drawCols = () => {
      checks = (data.collections || [])
        .filter((c) => c.organizationId === owner.value)
        .map((c) => {
          const cb = el('input', { type: 'checkbox' });
          return { id: c.id, cb, node: el('label', { class: 'check' }, cb, c.name || '?') };
        });
      colBox.replaceChildren(...checks.map((c) => c.node));
    };
    const owner = el(
      'select',
      { onchange: drawCols },
      el('option', { value: '' }, 'Ich (persönlich)'),
      data.orgs.map((o) => el('option', { value: o.id }, o.name || '?')),
    );
    inputs.push(() => {
      v.organizationId = owner.value || null;
      v.collectionIds = owner.value ? checks.filter((c) => c.cb.checked).map((c) => c.id) : null;
    });
    body.push(el('label', {}, 'Besitzer'), owner, colBox);
  }

  const btn = el('button', { class: 'primary' }, 'Speichern');
  const back = () => (orig.id ? viewItem(orig.id) : viewMain(false));
  render(
    header(orig.id ? 'Bearbeiten' : `${TYPE[v.type]} anlegen`, { back }),
    el(
      'main',
      {},
      el(
        'form',
        {
          onsubmit: busy(btn, async () => {
            inputs.forEach((f) => f());
            const r = await send('save', { view: v });
            toast('Gespeichert');
            await loadList();
            await viewItem(r.id);
          }),
        },
        body,
        el('div', { class: 'btns' }, el('button', { type: 'button', onclick: back }, 'Abbrechen'), btn),
      ),
    ),
  );
}

// ---------- Generator ----------

function viewGenerator(onUse) {
  const prev = [...app.childNodes];
  const prevTimer = timer;
  timer = null;
  const back = () => {
    app.replaceChildren(...prev);
    timer = prevTimer;
  };
  let o = { type: 'password', length: 20, upper: true, lower: true, numbers: true, special: true, avoidAmbiguous: false, words: 4, separator: '-', capitalize: false, includeNumber: false };
  try {
    o = { ...o, ...JSON.parse(localStorage.getItem('gen') || '{}') };
  } catch {}
  const out = el('div', { class: 'out mono' }, '…');
  const opts = el('div');
  const gen = async () => {
    try {
      localStorage.setItem('gen', JSON.stringify(o));
    } catch {}
    try {
      out.textContent = (await send('generate', { opts: o })).value;
    } catch (e) {
      toast(e.message);
    }
  };
  const check = (key, label) => {
    const c = el('input', { type: 'checkbox', onchange: () => ((o[key] = c.checked), gen()) });
    c.checked = !!o[key];
    return el('label', { class: 'check' }, c, label);
  };
  const range = (key, label, min, max) => {
    const val = el('span', {}, String(o[key]));
    const r = el('input', {
      type: 'range',
      min,
      max,
      value: o[key],
      oninput: () => ((o[key] = Number(r.value)), (val.textContent = r.value), gen()),
    });
    return [el('label', {}, label, ': ', val), r];
  };
  const drawOpts = () => {
    if (o.type === 'username') {
      const mode = el(
        'select',
        { value: o.mode || 'word', onchange: () => ((o.mode = mode.value), drawOpts(), gen()) },
        el('option', { value: 'word' }, 'Zufälliges Wort'),
        el('option', { value: 'subaddress' }, 'Plus-Adresse (name+xyz@…)'),
        el('option', { value: 'catchall' }, 'Catch-all-Domain (xyz@domain)'),
      );
      const mail = el('input', {
        type: 'text',
        placeholder: o.mode === 'catchall' ? 'example.com' : 'name@example.com',
        value: o.email || '',
        onchange: () => ((o.email = mail.value), gen()),
      });
      const rest = o.mode && o.mode !== 'word' ? [el('label', {}, 'Adresse'), mail] : [check('capitalize', 'Großschreiben'), check('includeNumber', 'Zahl einfügen')];
      opts.replaceChildren(el('label', {}, 'Variante'), mode, ...rest);
    } else if (o.type === 'passphrase') {
      const sep = el('input', { type: 'text', maxlength: 3, value: o.separator, oninput: () => ((o.separator = sep.value), gen()) });
      opts.replaceChildren(
        ...[range('words', 'Wörter', 3, 12), el('label', {}, 'Trennzeichen'), sep, check('capitalize', 'Großschreiben'), check('includeNumber', 'Zahl einfügen')].flat(),
      );
    } else {
      opts.replaceChildren(
        ...[
          range('length', 'Länge', 8, 64),
          check('upper', 'Großbuchstaben (A–Z)'),
          check('lower', 'Kleinbuchstaben (a–z)'),
          check('numbers', 'Ziffern (0–9)'),
          check('special', 'Sonderzeichen (!@#$%^&*)'),
          check('avoidAmbiguous', 'Mehrdeutige Zeichen vermeiden'),
        ].flat(),
      );
    }
  };
  const type = el(
    'select',
    { value: o.type, onchange: () => ((o.type = type.value), drawOpts(), gen()) },
    el('option', { value: 'password' }, 'Passwort'),
    el('option', { value: 'passphrase' }, 'Passphrase'),
    el('option', { value: 'username' }, 'Benutzername'),
  );
  app.replaceChildren(
    header('Generator', { back }),
    el(
      'main',
      {},
      out,
      el(
        'div',
        { class: 'btns' },
        el('button', { onclick: gen }, 'Neu erzeugen'),
        el('button', { onclick: () => copy(out.textContent, o.type === 'username' ? 'Benutzername' : 'Passwort') }, 'Kopieren'),
        onUse && el('button', { class: 'primary', onclick: () => (onUse(out.textContent), back()) }, 'Übernehmen'),
      ),
      el('label', {}, 'Art'),
      type,
      opts,
    ),
  );
  drawOpts();
  gen();
}

// ---------- Send ----------

async function viewSends() {
  let list;
  try {
    list = (await send('sends')).sends;
  } catch (e) {
    return toast(e.message);
  }
  const rows = list.map((sd) =>
    el(
      'div',
      { class: 'row', title: 'Klicken kopiert den Link', onclick: () => sd.url && copy(sd.url, 'Link') },
      el('div', { class: 'badge' }, sd.type === 1 ? 'DA' : 'TX'),
      el(
        'div',
        { class: 'txt' },
        el('div', { class: 'name' }, sd.name),
        el(
          'div',
          { class: 'sub' },
          [
            sd.type === 1 ? sd.fileName || 'Datei' : 'Text',
            sd.deletionDate && `bis ${new Date(sd.deletionDate).toLocaleDateString('de-DE')}`,
            `${sd.accessCount || 0}${sd.maxAccessCount ? '/' + sd.maxAccessCount : ''} Abrufe`,
          ]
            .filter(Boolean)
            .join(' · '),
        ),
      ),
      el(
        'div',
        { class: 'acts' },
        el(
          'button',
          {
            class: 'icon',
            title: 'Löschen',
            onclick: async (e) => {
              e.stopPropagation();
              if (!confirm(`Send „${sd.name}“ löschen?`)) return;
              try {
                await send('sendDelete', { id: sd.id });
                await viewSends();
              } catch (err) {
                toast(err.message);
              }
            },
          },
          icon('x'),
        ),
      ),
    ),
  );
  render(
    header('Send', {
      back: () => viewMain(false),
      actions: iconBtn('plus', 'Neues Send', () => viewSendNew()),
    }),
    el('main', { class: 'flush' }, rows.length ? rows : el('div', { class: 'empty' }, 'Noch keine Sends.')),
  );
}

function viewSendNew() {
  let file = null;
  const name = el('input', { type: 'text', autocomplete: 'off' });
  const text = el('textarea', {});
  const hidden = el('input', { type: 'checkbox' });
  const fileInfo = el('span', { class: 'muted small' }, 'Keine Datei gewählt');
  const textPart = el('div', {}, el('label', {}, 'Text'), text, el('label', { class: 'check' }, hidden, 'Text beim Abruf zunächst verbergen'));
  const filePart = el(
    'div',
    { style: 'display:none' },
    el('label', {}, 'Datei'),
    el(
      'div',
      { class: 'inline' },
      el(
        'button',
        {
          type: 'button',
          onclick: async () => {
            file = await pickFile();
            fileInfo.textContent = file ? `${file.name} (${Math.ceil(file.size / 1024)} kB)` : 'Keine Datei gewählt';
            if (file && !name.value) name.value = file.name;
          },
        },
        'Datei wählen',
      ),
      fileInfo,
    ),
  );
  const type = el(
    'select',
    {
      onchange: () => {
        if (type.value === 'file' && !inTab) return openTab('sends');
        textPart.style.display = type.value === 'file' ? 'none' : '';
        filePart.style.display = type.value === 'file' ? '' : 'none';
      },
    },
    el('option', { value: 'text' }, 'Text'),
    el('option', { value: 'file' }, 'Datei'),
  );
  const days = el('select', { value: '7' }, [1, 2, 3, 7, 14, 30].map((d) => el('option', { value: d }, d === 1 ? '1 Tag' : `${d} Tage`)));
  const max = el('input', { type: 'number', min: 1, placeholder: 'unbegrenzt' });
  const btn = el('button', { class: 'primary' }, 'Erstellen & Link kopieren');
  render(
    header('Neues Send', { back: () => viewSends() }),
    el(
      'main',
      {},
      el(
        'form',
        {
          onsubmit: busy(btn, async () => {
            const isFile = type.value === 'file';
            if (isFile && !file) throw new Error('Bitte eine Datei wählen');
            const job = (async () =>
              send('sendSave', {
                name: name.value.trim(),
                text: isFile ? null : text.value,
                hidden: hidden.checked,
                days: Number(days.value),
                maxAccess: Number(max.value) || null,
                file: isFile ? { name: file.name, b64: await fileB64(file) } : null,
              }))();
            copy(job.then((r) => r.url), 'Send erstellt – Link');
            await job;
            await viewSends();
          }),
        },
        el('label', {}, 'Art'),
        type,
        el('label', {}, 'Name'),
        name,
        textPart,
        filePart,
        el('label', {}, 'Wird gelöscht nach'),
        days,
        el('label', {}, 'Maximale Abrufe'),
        max,
        el('div', { class: 'btns' }, btn),
      ),
    ),
  );
  name.focus();
}

// ---------- Einstellungen ----------

async function viewSettings() {
  let r;
  try {
    r = await send('getSettings');
  } catch (e) {
    return toast(e.message);
  }
  const s = r.settings;
  const save = (patch) => send('setSettings', { settings: patch }).catch((e) => toast(e.message));
  const select = (key, options, onSaved) => {
    const sel = el(
      'select',
      {
        value: String(s[key]),
        onchange: () => {
          const v = options.find((o) => String(o[0]) === sel.value)[0];
          save({ [key]: v });
          if (onSaved) onSaved(v);
        },
      },
      options.map(([v, n]) => el('option', { value: v }, n)),
    );
    return sel;
  };
  const toggle = (key, label, hint) => {
    const c = el('input', { type: 'checkbox', onchange: () => save({ [key]: c.checked }) });
    c.checked = !!s[key];
    return [el('label', { class: 'check' }, c, label), hint && el('p', { class: 'muted small hint' }, hint)];
  };
  const section = (title) => el('h2', { class: 'group' }, title);
  const neverBox = el('div');
  const drawNever = () =>
    neverBox.replaceChildren(
      ...(s.neverDomains.length
        ? s.neverDomains.map((d) =>
            el(
              'div',
              { class: 'field' },
              el('div', { class: 'body' }, el('div', { class: 'v' }, d)),
              el(
                'button',
                {
                  class: 'icon small-icon',
                  title: 'Entfernen',
                  onclick: async () => {
                    s.neverDomains = s.neverDomains.filter((x) => x !== d);
                    await save({ neverDomains: s.neverDomains });
                    drawNever();
                  },
                },
                icon('x'),
              ),
            ),
          )
        : [el('p', { class: 'muted small' }, 'Keine – Speichern wird überall angeboten.')]),
    );
  drawNever();
  const neverInput = el('input', { type: 'text', placeholder: 'example.com' });
  const act = (label, fn, cls) => el('button', { class: cls || '', onclick: busy(null, fn) }, label);
  const again = async (msg) => (toast(msg), viewSettings());

  const pinInput = el('input', { type: 'password', placeholder: 'Neue PIN (mind. 4 Zeichen)', autocomplete: 'off' });
  const folderName = el('input', { type: 'text', placeholder: 'Neuer Ordner' });
  const srvName = (srv) => (!srv ? '' : srv.region === 'self' ? srv.base : srv.region === 'eu' ? 'bitwarden.eu' : 'bitwarden.com');
  const syncInfo = el('span', { class: 'muted small' }, r.lastSync ? `Zuletzt: ${new Date(r.lastSync).toLocaleString('de-DE')}` : 'Noch nie');

  render(
    header('Einstellungen', {
      back: () => viewMain(),
      actions: !inTab && iconBtn('external', 'In Tab öffnen', () => openTab('settings')),
    }),
    el(
      'main',
      {},
      el('label', {}, 'Konten'),
      (r.accounts || []).map((a) =>
        el(
          'div',
          { class: 'field' },
          el('div', { class: 'body' }, el('div', { class: 'v' }, a.email), el('div', { class: 'k' }, srvName(a.server))),
          a.id === r.active
            ? el('span', { class: 'muted small' }, 'aktiv')
            : el('button', { onclick: async () => (await send('switchAccount', { id: a.id }), start()) }, 'Wechseln'),
        ),
      ),
      el('button', { class: 'link', onclick: () => viewLogin(true) }, '+ Konto hinzufügen'),

      section('Kontosicherheit'),
      el('label', {}, 'Tresor-Timeout'),
      select('timeout', [
        [1, '1 Minute'],
        [5, '5 Minuten'],
        [15, '15 Minuten'],
        [30, '30 Minuten'],
        [60, '1 Stunde'],
        [240, '4 Stunden'],
        [0, 'Beim Neustart des Browsers'],
      ]),
      el('label', {}, 'Timeout-Aktion'),
      select('timeoutAction', [
        ['lock', 'Sperren'],
        ['logout', 'Abmelden'],
      ]),
      el('p', { class: 'muted small hint' }, 'Abmelden entfernt die lokalen Tresordaten aller Konten; danach ist eine neue Anmeldung (mit Zwei-Faktor) nötig.'),
      el('label', {}, 'Entsperren mit PIN'),
      r.hasPin
        ? act('PIN entfernen', async () => (await send('clearPin'), again('PIN entfernt')))
        : el('div', { class: 'inline' }, pinInput, act('Festlegen', async () => (await send('setPin', { pin: pinInput.value }), again('PIN festgelegt')))),
      el('label', {}, 'Entsperren mit Touch ID'),
      r.hasBio
        ? act('Touch ID deaktivieren', async () => (await send('bioDisable'), again('Touch ID deaktiviert')))
        : act('Touch ID aktivieren', async () => (await send('bioEnable'), again('Touch ID aktiviert'))),

      section('Automatisches Ausfüllen'),
      el('label', {}, 'Standard-URI-Übereinstimmungserkennung'),
      select('defaultMatch', [
        [0, 'Basis-Domain'],
        [1, 'Host'],
        [2, 'Beginnt mit'],
        [3, 'Exakt'],
        [4, 'Regulärer Ausdruck'],
        [5, 'Nie'],
      ]),
      el('p', { class: 'muted small hint' }, 'Gilt für alle Websites eines Eintrags, bei denen „Standard“ eingestellt ist.'),
      toggle('autoCopyTotp', 'TOTP automatisch kopieren', 'Nach dem Ausfüllen eines Logins mit Einmalcode wird der Code in die Zwischenablage kopiert.'),
      toggle('autoFill', 'Beim Laden der Seite automatisch ausfüllen', 'Nur auf https-Seiten. Kostet etwas Leistung auf Seiten mit Login-Formular.'),
      toggle('inline', 'Auswahlmenü in Login-Feldern anzeigen'),
      toggle('badge', 'Anzahl passender Logins am Symbol anzeigen'),
      toggle(
        'rememberHost',
        'Verwendeten Login pro Subdomain merken',
        'Nach dem Ausfüllen wird auf derselben Adresse nur noch dieser Login vorgeschlagen; die übrigen bleiben über „weitere“ erreichbar.',
      ),
      r.rememberedHosts > 0 &&
        el(
          'div',
          { class: 'inline hint-row' },
          el('span', { class: 'muted small' }, `${r.rememberedHosts} ${r.rememberedHosts === 1 ? 'Zuordnung' : 'Zuordnungen'} gespeichert`),
          act('Alle vergessen', async () => (await send('forgetAllHosts'), again('Zuordnungen gelöscht'))),
        ),
      toggle('showCards', 'Karten unter „Diese Seite“ anzeigen'),
      toggle('showIdentities', 'Identitäten unter „Diese Seite“ anzeigen'),

      section('Benachrichtigungen'),
      toggle('addPrompt', 'Fragen, ob neue Logins hinzugefügt werden sollen'),
      toggle('updatePrompt', 'Fragen, ob geänderte Passwörter aktualisiert werden sollen'),
      toggle('passkeys', 'Passkeys in RustWarden speichern und verwenden'),
      el('label', {}, 'Ausgeschlossene Domains'),
      neverBox,
      el(
        'div',
        { class: 'inline' },
        neverInput,
        act('Hinzufügen', async () => {
          const d = neverInput.value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/:].*$/, '');
          if (!d) return;
          if (!s.neverDomains.includes(d)) s.neverDomains = [...s.neverDomains, d];
          await save({ neverDomains: s.neverDomains });
          neverInput.value = '';
          drawNever();
        }),
      ),

      section('Darstellung'),
      el('label', {}, 'Design'),
      select(
        'theme',
        [
          ['system', 'Systemstandard'],
          ['light', 'Hell'],
          ['dark', 'Dunkel'],
        ],
        applyTheme,
      ),
      toggle('quickCopy', 'Schnellkopier-Aktionen in der Liste anzeigen'),

      section('Sonstiges'),
      el('label', {}, 'Zwischenablage leeren nach'),
      select('clipClear', [
        [0, 'Nie'],
        [30, '30 Sekunden'],
        [60, '1 Minute'],
        [120, '2 Minuten'],
        [300, '5 Minuten'],
      ]),

      el('label', {}, 'Synchronisierung'),
      el(
        'div',
        { class: 'inline' },
        act('Jetzt synchronisieren', async () => {
          await send('sync');
          syncInfo.textContent = `Zuletzt: ${new Date().toLocaleString('de-DE')}`;
          toast('Synchronisiert');
        }),
        syncInfo,
      ),

      el('label', {}, 'Ordner anlegen'),
      el(
        'div',
        { class: 'inline' },
        folderName,
        act('Anlegen', async () => {
          if (!folderName.value.trim()) return;
          await send('folder', { name: folderName.value.trim() });
          folderName.value = '';
          toast('Ordner angelegt');
        }),
      ),

      el('label', {}, 'Tresor exportieren / importieren'),
      el(
        'div',
        { class: 'btns', style: 'margin-top:0' },
        act('Exportieren (JSON)', async () => {
          if (!inTab) return openTab('settings');
          if (!(await askPassword())) return;
          const x = await send('export');
          download(`rustwarden-export-${new Date().toISOString().slice(0, 10)}.json`, x.json, 'application/json');
          toast(`${x.count} Einträge exportiert (unverschlüsselt!)`);
        }),
        act('Importieren (JSON)', async () => {
          if (!inTab) return openTab('settings');
          const file = await pickFile('.json,application/json');
          if (!file) return;
          const x = await send('import', { json: await file.text() });
          toast(`${x.count} Einträge importiert`);
        }),
      ),

      el('label', {}, 'Tastenkürzel'),
      el('p', { class: 'muted small' }, '⌘⇧Y öffnet RustWarden · ⌘⇧L füllt den ersten passenden Login aus'),
      el(
        'div',
        { class: 'btns' },
        el('button', { onclick: async () => (await send('lock'), start()) }, 'Sperren'),
        el(
          'button',
          {
            class: 'danger',
            onclick: async () => {
              if (!confirm('Wirklich abmelden? Lokale Tresordaten dieses Kontos werden entfernt.')) return;
              await send('logout');
              start();
            },
          },
          'Abmelden',
        ),
      ),
    ),
  );
}

// ---------- Start ----------

async function start() {
  try {
    try {
      applyTheme(((await browser.storage.local.get('settings')).settings || {}).theme);
    } catch {}
    data = null;
    tab = null;
    if (!inTab) {
      try {
        [tab] = await browser.tabs.query({ active: true, currentWindow: true });
      } catch {}
    }
    const st = await send('status');
    if (st.state === 'unlocked') {
      await viewMain();
      const route = inTab ? location.hash.slice(5).split('/') : [];
      if (route[0]) history.replaceState(null, '', '#tab');
      if (route[0] === 'item' && route[1]) await viewItem(route[1]);
      else if (route[0] === 'sends') await viewSends();
      else if (route[0] === 'settings') await viewSettings();
    } else if (st.state === 'locked') viewLocked(st);
    else if (st.state === 'twoFactor') viewTwoFactor(st);
    else if (st.state === 'newDevice') viewNewDevice();
    else viewLogin();
  } catch (e) {
    render(el('main', {}, el('p', { class: 'error' }, e.message), el('button', { onclick: start }, 'Erneut versuchen')));
  }
}

browser.runtime.onMessage.addListener((m) => {
  // Nach Hintergrund-Sync die Liste aktualisieren, falls sie gerade sichtbar ist.
  if (m && m.evt === 'synced' && app.querySelector('.chips')) viewMain().catch(() => {});
});

start();
