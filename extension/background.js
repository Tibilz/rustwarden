// RustWarden – Background (nicht persistent). Hält keinen dauerhaften Zustand im Speicher:
// Schlüssel liegen in storage.session (nur RAM), der verschlüsselte Tresor in storage.local.
// Der WASM-Kern wird erst geladen, wenn tatsächlich Kryptografie gebraucht wird.
'use strict';

const CLIENT_VERSION = '2026.10.0';
const HEAD = {
  Accept: 'application/json',
  'Bitwarden-Client-Name': 'browser',
  'Bitwarden-Client-Version': CLIENT_VERSION,
  'Device-Type': '20',
};
const DEFAULTS = {
  timeout: 15,
  timeoutAction: 'lock', // 'lock' | 'logout'
  clipClear: 0,
  addPrompt: true,
  updatePrompt: true,
  neverDomains: [],
  defaultMatch: 0, // 0 Basis-Domain, 1 Host, 2 Beginnt mit, 3 Exakt, 4 Regex, 5 Nie
  autoCopyTotp: true,
  badge: false,
  autoFill: false,
  inline: false,
  passkeys: true,
  bioAutoPrompt: true, // beim Öffnen des gesperrten Popups sofort nach Touch ID fragen
  rememberHost: true, // zuletzt verwendeten Login pro Host merken
  quickCopy: true,
  showCards: false,
  showIdentities: true,
  theme: 'system', // 'system' | 'light' | 'dark'
  v: 2, // Version der Einstellungen (für einmalige Umstellungen)
};
const EXT = browser.runtime.getURL('');

const L = browser.storage.local;
// Sitzungsschlüssel nicht für Content-Scripts lesbar machen (Standard in Chrome; in Safari explizit setzen).
try {
  browser.storage.session?.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' })?.catch?.(() => {});
} catch {}
const mem = {};
const S = browser.storage.session || {
  get: async (k) => ({ [k]: mem[k] }),
  set: async (o) => void Object.assign(mem, o),
  remove: async (k) => void delete mem[k],
  clear: async () => void Object.keys(mem).forEach((k) => delete mem[k]),
};
const lget = async (k) => (await L.get(k))[k];
const sget = async (k) => (await S.get(k))[k];

// Kontobezogene Daten liegen unter "a:<kontoId>:<name>", die Sitzung unter "s:<kontoId>".
let activeId;
async function aid() {
  if (activeId === undefined) activeId = (await lget('active')) || '';
  return activeId;
}
const aget = async (k) => lget(`a:${await aid()}:${k}`);
async function aset(o) {
  const id = await aid();
  const r = {};
  for (const k in o) r[`a:${id}:${k}`] = o[k];
  await L.set(r);
}
const adel = async (k) => L.remove(`a:${await aid()}:${k}`);
const getSession = async () => ((await aid()) ? sget('s:' + (await aid())) : undefined);
const setSession = async (v) => S.set({ ['s:' + (await aid())]: v });
async function needSession() {
  const s = await getSession();
  if (!s) throw new Error('Tresor ist gesperrt');
  return s;
}
const accountList = async () => (await lget('accounts')) || [];

let wasmReady = null;
let views = null; // Cache der entschlüsselten Einträge, solange die Page lebt

function core() {
  return (wasmReady ??= fetch(browser.runtime.getURL('wasm/rw_core_bg.wasm'))
    .then((r) => r.arrayBuffer())
    .then((buf) => wasm_bindgen({ module_or_path: buf }))
    .then(() => guardCore(wasm_bindgen)));
}

// Nach einem WebAssembly-Trap (z. B. Speicherüberlauf) ist der Zustand des Moduls unbestimmt:
// beim nächsten Aufruf frisch instanziieren statt die kaputte Instanz weiterzuverwenden.
function guardCore(w) {
  return new Proxy(w, {
    get(t, k) {
      const f = t[k];
      if (typeof f !== 'function') return f;
      return (...a) => {
        try {
          return f(...a);
        } catch (e) {
          if (e instanceof WebAssembly.RuntimeError) wasmReady = null;
          throw e;
        }
      };
    },
  });
}

// ---------- Helfer ----------

function camel(o) {
  if (Array.isArray(o)) return o.map(camel);
  if (o && typeof o === 'object') {
    const r = {};
    for (const k in o) r[k ? k[0].toLowerCase() + k.slice(1) : k] = camel(o[k]);
    return r;
  }
  return o;
}

function toB64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s);
}
function fromB64(b) {
  const s = atob(b);
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
}
const b64url = (b) => b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function serverBase(server) {
  const b = String(server.base || '').trim().replace(/\/+$/, '');
  let u;
  try {
    u = new URL(b);
  } catch {
    throw new Error('Ungültige Server-URL');
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) throw new Error('Server-URL muss mit https:// beginnen');
  if (u.username || u.password) throw new Error('Server-URL darf keine Zugangsdaten enthalten');
  return b;
}

function urls(server) {
  if (server.region === 'eu') return { id: 'https://identity.bitwarden.eu', api: 'https://api.bitwarden.eu' };
  if (server.region === 'self') return { id: serverBase(server) + '/identity', api: serverBase(server) + '/api' };
  return { id: 'https://identity.bitwarden.com', api: 'https://api.bitwarden.com' };
}

function errText(body, status) {
  if (body && typeof body === 'object') {
    const v = body.validationErrors && Object.values(body.validationErrors)[0];
    return (
      (body.errorModel && body.errorModel.message) ||
      (v && v[0]) ||
      body.message ||
      body.error_description ||
      (body.error && typeof body.error === 'object' ? body.error.description || body.error.reason : body.error) ||
      `HTTP ${status}`
    );
  }
  return `HTTP ${status}`;
}

const UNREACHABLE =
  'Server nicht erreichbar. Prüfe VPN, Website-Zugriff der Erweiterung für die Server-Adresse und ob das ' +
  '(selbst signierte) Zertifikat im Schlüsselbund als vertrauenswürdig markiert ist.';

async function http(url, init) {
  let res;
  try {
    res = await fetch(url, init);
  } catch {
    throw new Error(UNREACHABLE);
  }
  let body = null;
  const text = await res.text();
  if (text) {
    try {
      body = camel(JSON.parse(text));
    } catch {}
  }
  return { ok: res.ok, status: res.status, body };
}

async function deviceId() {
  let id = await lget('deviceId');
  if (!id) {
    id = crypto.randomUUID();
    await L.set({ deviceId: id });
  }
  return id;
}

async function settings() {
  const saved = (await lget('settings')) || {};
  const st = { ...DEFAULTS, ...saved, _set: saved };
  // Frühere Version hatte nur einen Schalter für beide Speicher-Angebote.
  if (st.savePrompt === false && !('addPrompt' in st._set)) st.addPrompt = st.updatePrompt = false;
  // v2: Identitäten werden (wie bei Bitwarden) standardmäßig im Popup angeboten – auch für alle,
  // die den alten Standard „aus“ gespeichert haben. Danach gilt die eigene Wahl.
  if (!(saved.v >= 2)) {
    st.showIdentities = true;
    st.v = 2;
  }
  delete st._set;
  delete st.savePrompt;
  return st;
}

async function native(msg) {
  let r;
  try {
    r = await browser.runtime.sendNativeMessage('application.id', msg);
  } catch (e) {
    throw new Error('Native Komponente nicht erreichbar: ' + ((e && e.message) || e));
  }
  if (!r || r.error) {
    const e = new Error((r && r.error) || 'Keine Antwort der nativen Komponente');
    e.code = r && r.cancelled ? 'cancelled' : undefined;
    throw e;
  }
  return r;
}

// ---------- Auth ----------

function tokenRequest(server, form) {
  return http(urls(server).id + '/connect/token', {
    method: 'POST',
    headers: { ...HEAD, 'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8' },
    body: new URLSearchParams(form).toString(),
  });
}

async function login(m) {
  let p;
  if (m.password) {
    const email = String(m.email || '').trim().toLowerCase();
    if (!email) throw new Error('E-Mail fehlt');
    const pre = await http(urls(m.server).id + '/accounts/prelogin', {
      method: 'POST',
      headers: { ...HEAD, 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    if (!pre.ok) throw new Error(errText(pre.body, pre.status));
    const kdf = {
      kdf: pre.body.kdf ?? 0,
      kdfIterations: pre.body.kdfIterations,
      kdfMemory: pre.body.kdfMemory,
      kdfParallelism: pre.body.kdfParallelism,
    };
    const c = await core();
    const k = JSON.parse(c.derive_keys(email, m.password, JSON.stringify(kdf)));
    p = { server: m.server, email, kdf, masterKey: k.masterKey, hash: k.hash, ts: Date.now() };
  } else {
    p = await sget('pendingLogin');
    if (!p || Date.now() - p.ts > 600000) {
      await S.remove('pendingLogin');
      throw new Error('Anmeldung abgelaufen, bitte erneut beginnen');
    }
  }

  const form = {
    grant_type: 'password',
    username: p.email,
    password: p.hash,
    scope: 'api offline_access',
    client_id: 'browser',
    deviceType: '20',
    deviceIdentifier: await deviceId(),
    deviceName: 'safari',
  };
  const remembered = ((await lget('remember')) || {})[accountId(p)];
  if (m.twoFactor) {
    form.twoFactorProvider = String(m.twoFactor.provider);
    form.twoFactorToken = String(m.twoFactor.token).replace(/\s+/g, '');
    form.twoFactorRemember = m.twoFactor.remember ? '1' : '0';
  } else if (remembered) {
    form.twoFactorProvider = '5';
    form.twoFactorToken = remembered;
    form.twoFactorRemember = '0';
  }
  if (m.newDeviceOtp) form.newDeviceOtp = String(m.newDeviceOtp).trim();

  const res = await tokenRequest(p.server, form);
  const b = res.body || {};
  if (!res.ok) {
    const providers = b.twoFactorProviders2 || b.twoFactorProviders;
    if (providers) {
      p.providers = Array.isArray(providers) ? providers.map(String) : Object.keys(providers);
      p.emailHint = (b.twoFactorProviders2 && b.twoFactorProviders2['1'] && b.twoFactorProviders2['1'].email) || '';
      p.step = 'twoFactor';
      await S.set({ pendingLogin: p });
      if (m.twoFactor) throw new Error('Code ungültig');
      return { step: 'twoFactor', providers: p.providers, emailHint: p.emailHint };
    }
    const msg = errText(b, res.status);
    if (/new device verification/i.test(msg)) {
      p.step = 'newDevice';
      await S.set({ pendingLogin: p });
      if (m.newDeviceOtp) throw new Error('Code ungültig');
      return { step: 'newDevice' };
    }
    throw new Error(/invalid_grant|username or password/i.test(msg) ? 'E-Mail oder Master-Passwort falsch' : msg);
  }

  if (b.twoFactorToken) {
    const r = (await lget('remember')) || {};
    r[accountId(p)] = b.twoFactorToken;
    await L.set({ remember: r });
  }
  const prev = await aid();
  const id = accountId(p);
  const list = (await accountList()).filter((a) => a.id !== id);
  list.push({ id, email: p.email, server: p.server });
  activeId = id;
  views = null;
  await L.set({ active: id, accounts: list });
  await aset({
    account: {
      email: p.email,
      server: p.server,
      kdf: p.kdf,
      tokens: { access: b.access_token, refresh: b.refresh_token, exp: Date.now() + (b.expires_in || 3600) * 1000 },
    },
  });
  try {
    await sync();
    const c = await core();
    await setSession(c.open_session(p.masterKey, JSON.stringify(await aget('profile'))));
  } catch (e) {
    await logout();
    if (prev && prev !== id) await switchTo(prev).catch(() => {});
    throw e;
  }
  await S.remove('pendingLogin');
  await touch();
  return { step: 'done' };
}

const accountId = (p) => p.email + '|' + (p.server.region === 'self' ? serverBase(p.server) : p.server.region || 'us');

async function sendEmailCode() {
  const p = await sget('pendingLogin');
  if (!p) throw new Error('Anmeldung abgelaufen');
  const r = await http(urls(p.server).api + '/two-factor/send-email-login', {
    method: 'POST',
    headers: { ...HEAD, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: p.email, masterPasswordHash: p.hash, deviceIdentifier: await deviceId() }),
  });
  if (!r.ok) throw new Error(errText(r.body, r.status));
  return {};
}

async function needAccount() {
  const acc = (await aid()) && (await aget('account'));
  if (!acc) throw new Error('Nicht angemeldet');
  return acc;
}

let refreshing = null;
async function accessToken(force) {
  const acc = await needAccount();
  if (!force && Date.now() < acc.tokens.exp - 60000) return acc.tokens.access;
  // Parallele Aufrufe teilen sich einen Refresh (sonst kann ein rotiertes Refresh-Token zum Logout führen).
  return (refreshing ??= refreshToken(acc).finally(() => (refreshing = null)));
}

async function refreshToken(acc) {
  const res = await tokenRequest(acc.server, {
    grant_type: 'refresh_token',
    client_id: 'browser',
    refresh_token: acc.tokens.refresh,
  });
  if (!res.ok) {
    if (res.status === 400 || res.status === 401) {
      await logout();
      throw new Error('Sitzung abgelaufen, bitte neu anmelden');
    }
    throw new Error(errText(res.body, res.status));
  }
  acc.tokens = {
    access: res.body.access_token,
    refresh: res.body.refresh_token || acc.tokens.refresh,
    exp: Date.now() + (res.body.expires_in || 3600) * 1000,
  };
  await aset({ account: acc });
  return acc.tokens.access;
}

async function api(path, method = 'GET', body) {
  const acc = await needAccount();
  const form = typeof FormData !== 'undefined' && body instanceof FormData;
  const call = async (force) =>
    http(urls(acc.server).api + path, {
      method,
      headers: {
        ...HEAD,
        Authorization: 'Bearer ' + (await accessToken(force)),
        ...(body && !form ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body ? (form ? body : JSON.stringify(body)) : undefined,
    });
  let res = await call(false);
  if (res.status === 401) res = await call(true);
  if (!res.ok) throw new Error(errText(res.body, res.status));
  return res.body;
}

async function unlockWith(password) {
  const acc = await needAccount();
  const c = await core();
  const k = JSON.parse(c.derive_keys(acc.email, password, JSON.stringify(acc.kdf)));
  return c.open_session(k.masterKey, JSON.stringify(await aget('profile')));
}

// Sperrt immer alle Konten – sonst bliebe ein anderes entsperrtes Konto ohne Sperr-Timer zurück.
async function lock() {
  views = null;
  for (const a of await accountList()) await S.remove('s:' + a.id);
  await S.remove(['pendingSave', 'pendingLogin']);
  await browser.alarms.clear('lock');
  setBadge('');
  notifyLocked();
  scheduleMenus();
}

function notifyLocked() {
  try {
    browser.runtime.sendMessage({ evt: 'locked' }).catch(() => {});
  } catch {}
}

async function logout() {
  const id = await aid();
  views = null;
  if (id) {
    const all = await L.get(null);
    await L.remove(Object.keys(all).filter((k) => k.startsWith(`a:${id}:`)));
    await S.remove(['s:' + id, 'pin:' + id]);
    native({ cmd: 'bioDelete', account: id }).catch(() => {});
    const r = (await lget('remember')) || {};
    if (id in r) {
      delete r[id];
      await L.set({ remember: r });
    }
  }
  const list = (await accountList()).filter((a) => a.id !== id);
  activeId = list.length ? list[0].id : '';
  await L.set({ accounts: list, active: activeId });
  await S.remove('pendingSave');
  setBadge('');
  notifyLocked();
  scheduleMenus();
}

async function switchTo(id) {
  if (!(await accountList()).some((a) => a.id === id)) throw new Error('Konto unbekannt');
  activeId = id;
  views = null;
  await L.set({ active: id });
  await S.remove('pendingSave');
  setBadge('');
  scheduleMenus();
}

async function touch() {
  const { timeout } = await settings();
  if (timeout > 0) browser.alarms.create('lock', { delayInMinutes: timeout });
  else await browser.alarms.clear('lock');
}

function setBadge(text, tabId) {
  try {
    browser.action.setBadgeText(tabId ? { text, tabId } : { text });
  } catch {}
}

// ---------- PIN / Touch ID ----------

async function pinKey(pin) {
  const acc = await needAccount();
  const c = await core();
  return c.stretch_key(JSON.parse(c.derive_keys(acc.email, 'pin:' + pin, JSON.stringify(acc.kdf))).masterKey);
}

// Standard wie bei Bitwarden: der PIN-geschützte Schlüssel liegt nur im Arbeitsspeicher
// (storage.session) – nach einem Browser-Neustart ist das Master-Passwort nötig. Auf der Festplatte
// (storage.local) nur auf ausdrücklichen Wunsch, dann mit längerer PIN, weil sie offline angreifbar ist.
async function pinBlob() {
  return (await aget('pin')) || (await sget('pin:' + (await aid())));
}

async function clearPin() {
  await adel('pin');
  await S.remove('pin:' + (await aid()));
}

async function setPin(m) {
  const session = await needSession();
  const persist = m.persist === true;
  const min = persist ? 8 : 4;
  if (typeof m.pin !== 'string' || m.pin.length < min) throw new Error(`Die PIN braucht mindestens ${min} Zeichen`);
  const c = await core();
  const blob = c.text_encrypt(await pinKey(m.pin), session);
  await clearPin();
  if (persist) await aset({ pin: blob });
  else await S.set({ ['pin:' + (await aid())]: blob });
  await adel('pinFail');
  return {};
}

async function unlockPin(m) {
  const blob = await pinBlob();
  if (!blob) throw new Error('Keine PIN eingerichtet');
  const c = await core();
  let session;
  try {
    session = c.text_decrypt(await pinKey(String(m.pin || '')), blob);
  } catch {
    // Zähler auf der Festplatte: ein Browser-Neustart setzt ihn nicht zurück.
    const n = ((await aget('pinFail')) || 0) + 1;
    await aset({ pinFail: n });
    if (n >= 5) {
      await clearPin();
      await adel('pinFail');
      throw new Error('Zu viele Fehlversuche – PIN entfernt, bitte Master-Passwort verwenden');
    }
    throw new Error(`Falsche PIN (${5 - n} Versuche übrig)`);
  }
  await adel('pinFail');
  await afterUnlock(session);
  return {};
}

async function bioEnable() {
  const session = await needSession();
  const avail = await native({ cmd: 'bioAvailable' });
  if (!avail.ok) throw new Error('Touch ID ist auf diesem Mac nicht verfügbar');
  const c = await core();
  const secret = c.random_b64(64);
  await native({ cmd: 'bioStore', account: await aid(), secret });
  await aset({ bio: c.text_encrypt(secret, session) });
  return {};
}

async function unlockBio() {
  const blob = await aget('bio');
  if (!blob) throw new Error('Touch ID ist nicht eingerichtet');
  const r = await native({ cmd: 'bioGet', account: await aid() });
  const c = await core();
  let session;
  try {
    session = c.text_decrypt(r.secret, blob);
  } catch {
    await adel('bio');
    throw new Error('Touch-ID-Schlüssel passt nicht mehr – bitte neu einrichten');
  }
  await afterUnlock(session);
  return {};
}

async function afterUnlock(session) {
  await setSession(session);
  views = null;
  scheduleMenus();
  await touch();
  syncInBackground();
}

// ---------- Tresor ----------

async function sync() {
  const d = await api('/sync');
  const p = d.profile || {};
  const profile = {
    id: p.id,
    email: p.email,
    key: p.key,
    privateKey: p.privateKey,
    organizations: (p.organizations || []).map((o) => ({ id: o.id, name: o.name, key: o.key })),
  };
  const eq = [];
  const dom = d.domains || {};
  for (const g of dom.equivalentDomains || []) eq.push(g);
  for (const g of dom.globalEquivalentDomains || []) if (!g.excluded) eq.push(g.domains);
  await aset({
    profile,
    eq,
    vault: JSON.stringify({
      ciphers: d.ciphers || [],
      folders: d.folders || [],
      collections: d.collections || [],
      sends: d.sends || [],
    }),
    lastSync: Date.now(),
  });
  views = null;
  scheduleMenus();
}

function syncInBackground() {
  sync()
    .then(() => browser.runtime.sendMessage({ evt: 'synced' }))
    .catch(() => {});
}

async function getViews() {
  if (views) return views;
  const session = await needSession();
  const c = await core();
  views = JSON.parse(c.decrypt_vault(session, (await aget('vault')) || '{}'));
  return views;
}

async function getView(id) {
  const v = (await getViews()).ciphers.find((x) => x.id === id);
  if (!v) throw new Error('Eintrag nicht gefunden');
  return v;
}

async function rawVault() {
  return JSON.parse((await aget('vault')) || '{"ciphers":[],"folders":[],"collections":[],"sends":[]}');
}

async function rawCipher(id) {
  const c = (await rawVault()).ciphers.find((x) => x.id === id);
  if (!c) throw new Error('Eintrag nicht gefunden');
  return c;
}

async function patchVault(fn) {
  const vault = await rawVault();
  fn(vault);
  await aset({ vault: JSON.stringify(vault) });
  views = null;
  scheduleMenus();
}

function upsert(vault, cipher) {
  const i = vault.ciphers.findIndex((x) => x.id === cipher.id);
  if (i >= 0) vault.ciphers[i] = cipher;
  else vault.ciphers.push(cipher);
}

async function saveCipher(view) {
  const session = await needSession();
  const c = await core();
  let orig = null;
  if (view.id) {
    orig = await rawCipher(view.id);
    const old = await getView(view.id);
    if (view.type === 1 && old.login && old.login.password && old.login.password !== (view.login || {}).password) {
      const now = new Date().toISOString();
      view.passwordHistory = [
        { password: old.login.password, lastUsedDate: now },
        ...(old.passwordHistory || []),
      ].slice(0, 5);
      view.login.passwordRevisionDate = now;
    }
  }
  const req = JSON.parse(c.encrypt_cipher(session, JSON.stringify(view), JSON.stringify(orig)));
  req.encryptedFor = ((await aget('profile')) || {}).id; // von aktuellen Servern verlangt
  let saved;
  if (view.id) saved = await api('/ciphers/' + view.id, 'PUT', req);
  else if (view.organizationId) {
    if (!(view.collectionIds || []).length) throw new Error('Bitte mindestens eine Sammlung wählen');
    saved = await api('/ciphers/create', 'POST', { cipher: req, collectionIds: view.collectionIds });
  } else saved = await api('/ciphers', 'POST', req);
  await patchVault((v) => upsert(v, saved));
  return { id: saved.id };
}

async function deleteCipher(id) {
  const v = await getView(id);
  if (v.deletedDate) {
    await api('/ciphers/' + id, 'DELETE');
    await patchVault((vault) => {
      vault.ciphers = vault.ciphers.filter((x) => x.id !== id);
    });
  } else {
    await api('/ciphers/' + id + '/delete', 'PUT');
    await patchVault((vault) => {
      const c = vault.ciphers.find((x) => x.id === id);
      if (c) c.deletedDate = new Date().toISOString();
    });
  }
  return {};
}

async function restoreCipher(id) {
  const saved = await api('/ciphers/' + id + '/restore', 'PUT');
  await patchVault((v) => upsert(v, saved));
  return {};
}

async function createFolder(name) {
  const c = await core();
  const f = await api('/folders', 'POST', { name: c.encrypt_text(await needSession(), name) });
  await patchVault((v) => v.folders.push(f));
  return { id: f.id };
}

// ---------- Anhänge ----------

async function fetchBytes(url) {
  const acc = await needAccount();
  const base = acc.server.region === 'self' ? serverBase(acc.server) : urls(acc.server).api;
  const u = new URL(url, base + '/');
  const get = async (target) => {
    const r = await fetch(target);
    if (!r.ok) throw new Error(`Download fehlgeschlagen (HTTP ${r.status})`);
    return new Uint8Array(await r.arrayBuffer());
  };
  try {
    return await get(u.href);
  } catch (e) {
    // Vaultwarden liefert Links mit seiner konfigurierten DOMAIN – die muss nicht zur genutzten Adresse passen.
    const b = new URL(base);
    if (acc.server.region !== 'self' || u.origin === b.origin) throw e;
    u.protocol = b.protocol;
    u.host = b.host;
    return get(u.href);
  }
}

async function uploadBlob(r, path, data, name) {
  if (r.fileUploadType === 1 && r.url) {
    const res = await fetch(r.url, { method: 'PUT', headers: { 'x-ms-blob-type': 'BlockBlob' }, body: data });
    if (!res.ok) throw new Error(`Upload fehlgeschlagen (HTTP ${res.status})`);
    return;
  }
  const fd = new FormData();
  fd.append('data', new Blob([data], { type: 'application/octet-stream' }), name);
  await api(path, 'POST', fd);
}

async function attGet(m) {
  const c = await core();
  const session = await needSession();
  const enc = await rawCipher(m.id);
  const att = (enc.attachments || []).find((a) => a.id === m.attId);
  if (!att) throw new Error('Anhang nicht gefunden');
  const ck = c.cipher_key(session, JSON.stringify(enc));
  const key = att.key ? c.key_decrypt(ck, att.key) : ck;
  const info = await api(`/ciphers/${m.id}/attachment/${m.attId}`).catch(() => null);
  const data = await fetchBytes((info && info.url) || att.url);
  return { name: c.text_decrypt(ck, att.fileName), b64: toB64(c.buf_decrypt(key, data)) };
}

async function attAdd(m) {
  const c = await core();
  const session = await needSession();
  const ck = c.cipher_key(session, JSON.stringify(await rawCipher(m.id)));
  const raw = c.random_b64(64);
  const data = c.buf_encrypt(raw, fromB64(m.b64));
  const fileName = c.text_encrypt(ck, m.name);
  const r = await api(`/ciphers/${m.id}/attachment/v2`, 'POST', {
    key: c.key_encrypt(ck, raw),
    fileName,
    fileSize: data.length,
    adminRequest: false,
  });
  await uploadBlob(r, `/ciphers/${m.id}/attachment/${r.attachmentId}`, data, fileName);
  const fresh = await api('/ciphers/' + m.id);
  await patchVault((v) => upsert(v, fresh));
  return {};
}

async function attDel(m) {
  await api(`/ciphers/${m.id}/attachment/${m.attId}`, 'DELETE');
  await patchVault((v) => {
    const c = v.ciphers.find((x) => x.id === m.id);
    if (c) c.attachments = (c.attachments || []).filter((a) => a.id !== m.attId);
  });
  return {};
}

// ---------- Send ----------

function sendUrl(server, accessId, key) {
  if (server.region === 'self') return `${serverBase(server)}/#/send/${accessId}/${key}`;
  if (server.region === 'eu') return `https://vault.bitwarden.eu/#/send/${accessId}/${key}`;
  return `https://send.bitwarden.com/#${accessId}/${key}`;
}

async function sendsList() {
  const c = await core();
  const uk = JSON.parse(await needSession()).user;
  const acc = await needAccount();
  const sends = ((await rawVault()).sends || []).map((s) => {
    try {
      const seed = c.key_decrypt(uk, s.key);
      const k = c.send_key(seed);
      return {
        id: s.id,
        type: s.type,
        name: c.text_decrypt(k, s.name),
        text: s.text && s.text.text ? c.text_decrypt(k, s.text.text) : null,
        fileName: s.file && s.file.fileName ? c.text_decrypt(k, s.file.fileName) : null,
        deletionDate: s.deletionDate,
        accessCount: s.accessCount || 0,
        maxAccessCount: s.maxAccessCount || null,
        url: sendUrl(acc.server, s.accessId, b64url(seed)),
      };
    } catch {
      return { id: s.id, type: s.type, name: '[Nicht entschlüsselbar]', deletionDate: s.deletionDate };
    }
  });
  return { sends };
}

async function sendSave(m) {
  const c = await core();
  const uk = JSON.parse(await needSession()).user;
  if (!m.name) throw new Error('Name fehlt');
  const seed = c.random_b64(16);
  const k = c.send_key(seed);
  const body = {
    type: m.file ? 1 : 0,
    key: c.key_encrypt(uk, seed),
    name: c.text_encrypt(k, m.name),
    notes: null,
    password: null,
    disabled: false,
    hideEmail: false,
    maxAccessCount: m.maxAccess || null,
    expirationDate: null,
    deletionDate: new Date(Date.now() + (m.days || 7) * 86400000).toISOString(),
  };
  let saved;
  if (m.file) {
    const data = c.buf_encrypt(k, fromB64(m.file.b64));
    const fileName = c.text_encrypt(k, m.file.name);
    body.file = { fileName };
    body.fileLength = data.length;
    const r = await api('/sends/file/v2', 'POST', body);
    saved = r.sendResponse;
    await uploadBlob(r, `/sends/${saved.id}/file/${saved.file.id}`, data, fileName);
  } else {
    if (!m.text) throw new Error('Text fehlt');
    body.text = { text: c.text_encrypt(k, m.text), hidden: !!m.hidden };
    saved = await api('/sends', 'POST', body);
  }
  await patchVault((v) => (v.sends = [...(v.sends || []), saved]));
  const acc = await needAccount();
  return { url: sendUrl(acc.server, saved.accessId, b64url(seed)) };
}

async function sendDelete(m) {
  await api('/sends/' + m.id, 'DELETE');
  await patchVault((v) => (v.sends = (v.sends || []).filter((s) => s.id !== m.id)));
  return {};
}

// ---------- Export / Import (unverschlüsseltes Bitwarden-JSON) ----------

async function exportVault() {
  const v = await getViews();
  const items = v.ciphers
    .filter((c) => !c.organizationId && !c.deletedDate && !c.decryptError)
    .map((c) => ({
      id: c.id,
      organizationId: null,
      folderId: c.folderId || null,
      type: c.type,
      reprompt: c.reprompt || 0,
      name: c.name,
      notes: c.notes || null,
      favorite: !!c.favorite,
      fields: c.fields || [],
      login: c.login
        ? { ...c.login, uris: (c.login.uris || []).map((u) => ({ match: u.match ?? null, uri: u.uri })) }
        : undefined,
      card: c.card || undefined,
      identity: c.identity || undefined,
      secureNote: c.secureNote || undefined,
      sshKey: c.sshKey || undefined,
      passwordHistory: c.passwordHistory || null,
      revisionDate: c.revisionDate,
      creationDate: c.creationDate,
      deletedDate: null,
      collectionIds: null,
    }));
  return { json: JSON.stringify({ encrypted: false, folders: v.folders, items }, null, 2), count: items.length };
}

async function importVault(m) {
  let d;
  try {
    d = JSON.parse(m.json);
  } catch {
    throw new Error('Datei ist kein gültiges JSON');
  }
  if (d.encrypted) throw new Error('Verschlüsselte Exporte werden nicht unterstützt');
  if (!Array.isArray(d.items)) throw new Error('Kein Bitwarden-JSON-Export (items fehlt)');
  const c = await core();
  const session = await needSession();
  const folders = Array.isArray(d.folders) ? d.folders.filter((f) => f && f.name) : [];
  const folderIndex = new Map(folders.map((f, i) => [f.id, i]));
  const ciphers = [];
  const folderRelationships = [];
  const userId = ((await aget('profile')) || {}).id;
  for (const it of d.items) {
    if (!it || ![1, 2, 3, 4, 5].includes(it.type)) continue;
    const view = { ...it, id: undefined, organizationId: null, folderId: null, collectionIds: null, name: it.name || '(ohne Namen)' };
    if (view.login && Array.isArray(view.login.fido2Credentials)) {
      view.login = { ...view.login, newFido2Credentials: view.login.fido2Credentials }; // Passkeys mit importieren
    }
    ciphers.push({ ...JSON.parse(c.encrypt_cipher(session, JSON.stringify(view), 'null')), encryptedFor: userId });
    if (folderIndex.has(it.folderId)) folderRelationships.push({ key: ciphers.length - 1, value: folderIndex.get(it.folderId) });
  }
  if (!ciphers.length) throw new Error('Keine importierbaren Einträge gefunden');
  await api('/ciphers/import', 'POST', {
    ciphers,
    folders: folders.map((f) => ({ name: c.encrypt_text(session, f.name) })),
    folderRelationships,
  });
  await sync();
  return { count: ciphers.length };
}

// ---------- URL-Abgleich ----------

// Public Suffix List (extension/psl.txt, aus tools/gen-psl.js). Wird erst beim ersten Abgleich geladen
// und bleibt bis zum Entladen der Background-Page im Speicher.
let PSL = null;
let pslReady = null;
function loadPsl() {
  return (pslReady ??= fetch(browser.runtime.getURL('psl.txt'))
    .then((r) => r.text())
    .then((t) => {
      const rules = new Set();
      const wild = new Set();
      const except = new Set();
      for (const l of t.split('\n')) {
        if (!l || l.startsWith('//')) continue;
        if (l[0] === '!') except.add(l.slice(1));
        else if (l.startsWith('*.')) wild.add(l.slice(2));
        else rules.add(l);
      }
      PSL = { rules, wild, except };
    })
    .catch((e) => {
      pslReady = null;
      throw e;
    }));
}

// Öffentliches Suffix eines Hosts nach den PSL-Regeln (längste Regel gewinnt, Ausnahmen zuerst).
function publicSuffix(host) {
  if (!PSL) throw new Error('Suffixliste nicht geladen');
  const p = host.split('.');
  for (let i = 0; i < p.length; i++) {
    const cand = p.slice(i).join('.');
    if (PSL.except.has(cand)) return p.slice(i + 1).join('.');
    if (PSL.rules.has(cand) || (i + 1 < p.length && PSL.wild.has(p.slice(i + 1).join('.')))) return cand;
  }
  return p[p.length - 1]; // Standardregel "*"
}

const isIp = (host) => /^[\d.]+$/.test(host) || host.includes(':') || host.startsWith('[');

// Registrierbare Domain (eTLD+1). Hosts, die selbst ein öffentliches Suffix sind, bleiben unverändert.
function baseDomain(host) {
  host = host.replace(/\.$/, '');
  if (isIp(host) || !host.includes('.')) return host;
  const suf = publicSuffix(host);
  if (suf === host) return host;
  const p = host.split('.');
  return p.slice(-(suf.split('.').length + 1)).join('.');
}

function parseUrl(u) {
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(u) ? u : 'http://' + u);
  } catch {
    return null;
  }
}

function matcher(tabUrl, eq, defaultMatch = 0) {
  const tab = parseUrl(tabUrl || '');
  if (!tab || !/^https?:$/.test(tab.protocol)) return () => false;
  const tb = baseDomain(tab.hostname);
  const domains = new Set([tb]);
  for (const g of eq || []) if (g.includes(tb)) g.forEach((d) => domains.add(d));
  return (v) => {
    if (v.type !== 1 || v.deletedDate || !v.login || !v.login.uris) return false;
    return v.login.uris.some((u) => {
      if (!u || !u.uri) return false;
      switch (u.match ?? defaultMatch) {
        case 5:
          return false;
        case 4:
          // Begrenzung gegen katastrophales Backtracking (ReDoS) bei langen URLs/Mustern.
          if (u.uri.length > 500 || tabUrl.length > 2048) return false;
          try {
            return new RegExp(u.uri, 'i').test(tabUrl);
          } catch {
            return false;
          }
        case 3:
          return u.uri === tabUrl;
        case 2:
          return tabUrl.startsWith(u.uri);
        case 1: {
          const p = parseUrl(u.uri);
          return !!p && p.host === tab.host;
        }
        default: {
          const p = parseUrl(u.uri);
          return !!p && /^https?:$/.test(p.protocol) && domains.has(baseDomain(p.hostname));
        }
      }
    });
  };
}

const byName = (a, b) => (b.favorite ? 1 : 0) - (a.favorite ? 1 : 0) || String(a.name).localeCompare(String(b.name));

async function matchesFor(url) {
  await loadPsl();
  const m = matcher(url, await aget('eq'), (await settings()).defaultMatch);
  return (await getViews()).ciphers.filter(m).sort(byName);
}

// ---------- Gemerkter Login pro Host ----------
// Zuordnung Host → Eintrag, lokal und mit dem Benutzerschlüssel verschlüsselt (Hostnamen verraten den Verlauf).

function hostOf(url) {
  try {
    const u = new URL(url);
    return /^https?:$/.test(u.protocol) ? u.host.toLowerCase() : null;
  } catch {
    return null;
  }
}

async function hostMap() {
  const blob = await aget('hosts');
  const session = await getSession();
  if (!blob || !session) return {};
  try {
    return JSON.parse((await core()).text_decrypt(JSON.parse(session).user, blob));
  } catch {
    return {};
  }
}

async function saveHostMap(map) {
  if (!Object.keys(map).length) return adel('hosts');
  const c = await core();
  await aset({ hosts: c.text_encrypt(JSON.parse(await needSession()).user, JSON.stringify(map)) });
}

async function rememberHost(url, id) {
  const host = hostOf(url);
  if (!host || !(await settings()).rememberHost) return;
  if (!(await matchesFor(url)).some((v) => v.id === id)) return;
  const map = await hostMap();
  if (map[host] === id) return;
  map[host] = id;
  await saveHostMap(map);
}

// Vorschläge für eine Seite: der gemerkte Login allein, die übrigen Treffer als „weitere“.
async function suggestionsFor(url) {
  const all = await matchesFor(url);
  const host = hostOf(url);
  if (host && all.length > 1 && (await settings()).rememberHost) {
    const id = (await hostMap())[host];
    const hit = all.find((v) => v.id === id);
    if (hit) return { list: [hit], others: all.filter((v) => v !== hit), remembered: id };
  }
  return { list: all, others: [], remembered: null };
}

function subtitle(v) {
  if (v.type === 1) return (v.login && v.login.username) || '';
  if (v.type === 3) {
    const n = (v.card && v.card.number) || '';
    return [v.card && v.card.brand, n && '•••• ' + n.slice(-4)].filter(Boolean).join(' ');
  }
  if (v.type === 4) return [v.identity && v.identity.firstName, v.identity && v.identity.lastName].filter(Boolean).join(' ');
  if (v.type === 5) return (v.sshKey && v.sshKey.keyFingerprint) || '';
  return '';
}

function slim(v) {
  return {
    id: v.id,
    type: v.type,
    name: v.name || '(ohne Namen)',
    sub: subtitle(v),
    fav: !!v.favorite,
    folderId: v.folderId || null,
    orgId: v.organizationId || null,
    deleted: !!v.deletedDate,
    reprompt: v.reprompt === 1,
    totp: !!(v.login && v.login.totp),
    user: !!(v.login && v.login.username),
    pass: !!(v.login && v.login.password),
    err: !!v.decryptError,
  };
}

// ---------- Erkannte Logins (Speichern/Aktualisieren) ----------

async function evalPending() {
  const p = await sget('pendingSave');
  if (!p) return null;
  const drop = async () => {
    await S.remove('pendingSave');
    setBadge('');
    return null;
  };
  if (Date.now() - p.ts > 600000) return drop();
  const logins = await matchesFor(p.url);
  const u = (p.username || '').toLowerCase();
  const userOf = (v) => (v.login.username || '').toLowerCase();
  if (logins.some((v) => v.login.password === p.password && (!u || userOf(v) === u))) return drop();
  const host = new URL(p.url).hostname;
  const hit = u ? logins.find((v) => userOf(v) === u) : logins.length === 1 ? logins[0] : null;
  const st = await settings();
  if (hit ? !st.updatePrompt : !st.addPrompt) return drop();
  setBadge('+');
  return hit
    ? { kind: 'update', id: hit.id, name: hit.name, host, username: p.username, ts: p.ts }
    : { kind: 'new', host, username: p.username, ts: p.ts };
}

// `ts` identifiziert die Abfrage, die das Popup angezeigt hat: wurde sie inzwischen (z. B. von einem
// anderen Tab) ersetzt, wird nichts gespeichert.
async function acceptPending(ts) {
  const p = await sget('pendingSave');
  const info = await evalPending();
  if (!p || !info) return {};
  if (p.ts !== ts) throw new Error('Die Speichern-Abfrage hat sich geändert – bitte erneut prüfen');
  if (info.kind === 'update') {
    const v = structuredClone(await getView(info.id));
    v.login.password = p.password;
    await saveCipher(v);
  } else {
    const url = new URL(p.url);
    await saveCipher({
      type: 1,
      name: url.hostname.replace(/^www\./, ''),
      login: { username: p.username || null, password: p.password, uris: [{ uri: url.origin, match: null }] },
    });
  }
  await S.remove('pendingSave');
  setBadge('');
  return {};
}

// ---------- Ausfüllen ----------

async function totpFor(v) {
  if (!v.login || !v.login.totp) return null;
  const c = await core();
  return JSON.parse(c.totp(v.login.totp, Math.floor(Date.now() / 1000)));
}

async function fillData(v) {
  if (v.type === 1) {
    let totp = null;
    try {
      totp = (await totpFor(v))?.code || null;
    } catch {}
    return { kind: 'login', username: v.login?.username || '', password: v.login?.password || '', totp };
  }
  if (v.type === 3) {
    const c = v.card || {};
    const mm = c.expMonth ? String(c.expMonth).padStart(2, '0') : '';
    const yy = c.expYear ? String(c.expYear).slice(-2) : '';
    return {
      kind: 'rules',
      rules: [
        ['cc-name', 'card.?holder|name.?on.?card|cc.?name|karteninhaber', c.cardholderName],
        ['cc-number', 'card.?(number|no|nr|num)|cc.?num|kartennummer', c.number],
        ['cc-exp-month', 'exp.*(month|mm|mon)|monat', mm],
        ['cc-exp-year', 'exp.*(year|yy|jahr)', c.expYear],
        ['cc-exp', 'expir|exp.?date|ablauf|gültig|valid', mm && yy ? `${mm}/${yy}` : ''],
        ['cc-csc', 'cvc|cvv|csc|security.?code|prüf', c.code],
      ],
    };
  }
  if (v.type === 4) {
    const i = v.identity || {};
    const full = [i.firstName, i.middleName, i.lastName].filter(Boolean).join(' ');
    return {
      kind: 'rules',
      rules: [
        ['honorific-prefix', 'salutation|anrede|^title|prefix', i.title],
        ['given-name', 'first.?name|vorname|given', i.firstName],
        ['additional-name', 'middle', i.middleName],
        ['family-name', 'last.?name|nachname|surname|family', i.lastName],
        ['name', 'full.?name|your.?name', full],
        ['email', 'e.?mail', i.email],
        ['tel', 'phone|telefon|mobil', i.phone],
        ['organization', 'company|firma|organi[sz]ation', i.company],
        ['address-line2', 'address.?(line)?.?2|adresszusatz', i.address2],
        ['address-line3', 'address.?(line)?.?3', i.address3],
        ['address-line1', 'address.?(line)?.?1|street|stra(ß|ss)e', i.address1],
        ['street-address', '^address|adresse', i.address1],
        ['address-level2', 'city|town|ort|stadt', i.city],
        ['address-level1', 'state|province|region|bundesland', i.state],
        ['postal-code', 'zip|postal|plz|postcode', i.postalCode],
        ['country-name', 'country|land', i.country],
        ['country', '', i.country],
        ['username', 'user.?name|benutzer|login', i.username],
      ],
    };
  }
  return null;
}

// Wird in die Seite injiziert – muss vollständig in sich geschlossen sein.
function fillPage(d) {
  // Nur Top-Frame und same-origin-Frames befüllen (kein Abgreifen über fremde iframes) – und nur,
  // wenn die Seite noch dieselbe ist, für die der Eintrag ausgewählt wurde (Navigation dazwischen).
  try {
    if (window.top !== window) void window.top.location.href;
  } catch {
    return false;
  }
  if (location.origin !== d.origin) return false;
  const visible = (e) => {
    const r = e.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden' && !e.disabled && !e.readOnly;
  };
  const set = (e, v) => {
    if (v == null || v === '') return false;
    v = String(v);
    if (e.tagName === 'SELECT') {
      const cands = [v, v.replace(/^0/, ''), v.padStart(2, '0'), v.slice(-2)].map((x) => x.toLowerCase());
      const o = [...e.options].find(
        (o) => cands.includes(o.value.trim().toLowerCase()) || cands.includes(o.text.trim().toLowerCase()),
      );
      if (!o) return false;
      e.value = o.value;
    } else {
      e.focus();
      const proto = e.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value').set.call(e, v);
    }
    for (const t of ['input', 'change']) e.dispatchEvent(new Event(t, { bubbles: true }));
    return true;
  };
  const typeOf = (e) => (e.getAttribute('type') || 'text').toLowerCase();
  const all = [...document.querySelectorAll('input,select,textarea')].filter(visible);
  const texts = all.filter((e) => e.tagName === 'INPUT' && /^(text|email|tel|number)$/.test(typeOf(e)));
  const hint = (e) => `${e.name} ${e.id} ${e.getAttribute('placeholder') || ''} ${e.getAttribute('aria-label') || ''}`;
  let n = 0;

  if (d.kind === 'login') {
    const isOtp = (e) =>
      e.autocomplete === 'one-time-code' ||
      /otp|totp|2fa|mfa|one.?time|verification.?code|authenticator/i.test(hint(e)) ||
      (e.maxLength === 6 && e.inputMode === 'numeric');
    const pws = all.filter((e) => e.tagName === 'INPUT' && typeOf(e) === 'password');
    const pw = pws.find((e) => e.autocomplete !== 'new-password') || pws[0];
    let user = null;
    if (pw) {
      const before = texts.filter((e) => !isOtp(e) && all.indexOf(e) < all.indexOf(pw));
      user = before.filter((e) => pw.form && e.form === pw.form).pop() || before.pop() || null;
    } else {
      user =
        texts.find(
          (e) =>
            !isOtp(e) &&
            (/username|email/.test(e.autocomplete || '') ||
              typeOf(e) === 'email' ||
              /user|e.?mail|login|ident|account|kennung|benutzer/i.test(hint(e))),
        ) || null;
    }
    if (user && set(user, d.username)) n++;
    if (pw && set(pw, d.password)) n++;
    if (d.totp) {
      const otp = texts.find(isOtp);
      if (otp && set(otp, d.totp)) n++;
    }
    return n > 0;
  }

  const fields = all.filter((e) => e.tagName !== 'INPUT' || /^(text|email|tel|number)$/.test(typeOf(e)));
  for (const e of fields) {
    const ac = (e.getAttribute('autocomplete') || '').toLowerCase().trim().split(/\s+/).pop();
    const h = hint(e);
    const rule = d.rules.find((r) => r[2] && ((ac && ac === r[0]) || (r[1] && new RegExp(r[1], 'i').test(h))));
    if (rule && set(e, rule[2])) n++;
  }
  return n > 0;
}

// Zugangsdaten, die für https gespeichert sind, nicht in eine unverschlüsselte (http) Seite schreiben.
function insecureFor(view, url) {
  if (view.type !== 1 || !/^http:/i.test(url)) return false;
  const uris = ((view.login && view.login.uris) || []).map((u) => u && u.uri).filter(Boolean);
  return uris.some((u) => /^https:/i.test(u)) && !uris.some((u) => /^http:/i.test(u));
}

// `url`: Seite, für die der Eintrag ausgewählt wurde. Ausgefüllt wird nur in Frames mit genau dieser Origin.
async function fill(id, tabId, url, { allowHttp = false } = {}) {
  const view = await getView(id);
  let origin;
  try {
    origin = new URL(url).origin;
  } catch {
    throw new Error('Unbekannte Seite');
  }
  if (!/^https?:/.test(origin)) throw new Error('Auf dieser Seite kann nicht ausgefüllt werden');
  if (!allowHttp && insecureFor(view, url)) {
    const e = new Error('Unverschlüsselte Verbindung (http) – Ausfüllen abgebrochen');
    e.code = 'insecure';
    throw e;
  }
  const data = await fillData(view);
  if (!data) throw new Error('Dieser Eintragstyp kann nicht ausgefüllt werden');
  data.origin = origin;
  let res;
  try {
    res = await browser.scripting.executeScript({ target: { tabId, allFrames: true }, func: fillPage, args: [data] });
  } catch {
    res = await browser.scripting.executeScript({ target: { tabId }, func: fillPage, args: [data] });
  }
  return { filled: (res || []).some((r) => r && r.result), totp: data.totp || null };
}

async function autofillTab(tab) {
  if (!tab) return;
  if (!(await getSession())) {
    await browser.action.openPopup();
    return;
  }
  const m = (await suggestionsFor(tab.url)).list.filter((v) => v.reprompt !== 1);
  if (m.length) {
    await fill(m[0].id, tab.id, tab.url).catch(() => browser.action.openPopup());
    await touch();
  } else {
    await browser.action.openPopup();
  }
}

// ---------- Passkeys (WebAuthn) ----------
// Format der gespeicherten Passkeys entspricht dem der offiziellen Clients (ECDSA P-256, PKCS#8 als base64url).

const utf8 = (s) => new TextEncoder().encode(s);
const b64uEnc = (u8) => b64url(toB64(u8));
const b64uDec = (s) => fromB64(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
const sha256 = async (u8) => new Uint8Array(await crypto.subtle.digest('SHA-256', u8));
function concat(...parts) {
  const arrs = parts.map((p) => (p instanceof Uint8Array ? p : new Uint8Array(p)));
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}
function guidBytes(g) {
  const hex = String(g).replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/i.test(hex)) return null;
  return new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16)));
}
function credIdBytes(cred) {
  const id = String(cred.credentialId || '');
  try {
    return guidBytes(id) || b64uDec(id.replace(/^b64\./, ''));
  } catch {
    return null;
  }
}
// WebCrypto liefert r||s, WebAuthn verlangt DER.
function derSig(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.subarray(i);
    return b[0] & 0x80 ? [2, b.length + 1, 0, ...b] : [2, b.length, ...b];
  };
  const r = int(raw.subarray(0, 32));
  const s = int(raw.subarray(32));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}
// rpId muss zum Host gehören und darf kein bloßes Suffix oberhalb der registrierbaren Domain sein.
// Zusätzlich: keine Hosts mit Schlusspunkt, keine IP-Adressen (außer 127.0.0.1) und kein öffentliches Suffix.
function rpIdOk(rpId, host) {
  if (typeof rpId !== 'string' || !rpId || rpId.endsWith('.') || host.endsWith('.')) return false;
  if (isIp(host) && host !== '127.0.0.1') return false;
  if (host === 'localhost' || host === '127.0.0.1') return rpId === host;
  const base = baseDomain(host);
  if (base === publicSuffix(host)) return false;
  return (host === rpId || host.endsWith('.' + rpId)) && (rpId === base || rpId.endsWith('.' + base));
}

async function passkeysFor(rpId, allow) {
  const out = [];
  for (const v of (await getViews()).ciphers) {
    if (v.type !== 1 || v.deletedDate || v.reprompt === 1 || !v.login) continue;
    for (const cred of v.login.fido2Credentials || []) {
      if (!cred || cred.rpId !== rpId) continue;
      const id = credIdBytes(cred);
      if (!id || (allow && allow.length && !allow.includes(b64uEnc(id)))) continue;
      out.push({ cipher: v, cred, id });
    }
  }
  return out;
}

// Nur bekannte, typgeprüfte und größenbegrenzte Felder der WebAuthn-Optionen übernehmen –
// die Seite kontrolliert sie vollständig.
const B64U = /^[A-Za-z0-9_-]*={0,2}$/;
function cleanOpts(kind, o) {
  const str = (v, max) => (typeof v === 'string' && v.length <= max ? v : undefined);
  const id = (v, max = 1024) => (typeof v === 'string' && v.length <= max && B64U.test(v) ? v : undefined);
  // passkey-page.js liefert Credential-IDs als base64url-Strings
  const creds = (l) => (Array.isArray(l) ? l.slice(0, 64).map((c) => id(c)).filter(Boolean) : undefined);
  const challenge = id(o.challenge, 2048);
  if (!challenge) return null;
  if (kind === 'get')
    return { challenge, rpId: str(o.rpId, 253), allowCredentials: creds(o.allowCredentials), userVerification: str(o.userVerification, 20) };
  const user = o.user || {};
  const rp = o.rp || {};
  return {
    challenge,
    rp: { id: str(rp.id, 253), name: str(rp.name, 256) },
    user: { id: id(user.id, 128), name: str(user.name, 256), displayName: str(user.displayName, 256) },
    pubKeyCredParams: Array.isArray(o.pubKeyCredParams)
      ? o.pubKeyCredParams.slice(0, 32).map((p) => ({ type: p && p.type, alg: p && p.alg })).filter((p) => typeof p.alg === 'number')
      : [],
    excludeCredentials: creds(o.excludeCredentials),
    credProps: o.credProps === true,
  };
}

async function pkBegin(m, sender) {
  if ((await settings()).passkeys === false || !(await aid())) return { fallback: true };
  let url;
  try {
    url = new URL(sender.url || sender.tab.url);
  } catch {
    return { fallback: true };
  }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !local) return { fallback: true };
  const kind = m.kind === 'create' ? 'create' : 'get';
  const o = cleanOpts(kind, m.options && typeof m.options === 'object' ? m.options : {});
  if (!o) return { fallback: true };
  const rpId = String((kind === 'create' ? o.rp.id : o.rpId) || url.hostname).toLowerCase();
  await loadPsl();
  if (!rpIdOk(rpId, url.hostname)) return { error: 'SecurityError' };
  if (await getSession()) {
    if (kind === 'create') {
      if (!(o.pubKeyCredParams || []).some((p) => p.type === 'public-key' && p.alg === -7)) return { fallback: true };
      const ex = o.excludeCredentials || [];
      if (ex.length && (await passkeysFor(rpId, ex)).length) return { error: 'InvalidStateError' };
    } else if (!(await passkeysFor(rpId, o.allowCredentials)).length) return { fallback: true };
  }
  const reqId = crypto.randomUUID();
  // Höchstens eine offene Anfrage pro Tab: ältere verwerfen (verhindert Volllaufen des Speichers).
  const old = Object.entries(await S.get(null)).filter(([k, v]) => k.startsWith('pk:') && v && v.tabId === sender.tab.id);
  if (old.length) await S.remove(old.map(([k]) => k));
  await S.set({ ['pk:' + reqId]: { kind, rpId, origin: url.origin, tabId: sender.tab.id, tabUrl: url.href, options: o, ts: Date.now() } });
  return { reqId };
}

async function pkReq(m, sender) {
  const req = await sget('pk:' + m.reqId);
  if (!req || req.tabId !== sender.tab.id || Date.now() - req.ts > 180000) throw new Error('Anfrage abgelaufen');
  return req;
}

async function pkInfo(m, sender) {
  const req = await pkReq(m, sender);
  const base = { kind: req.kind, rpId: req.rpId };
  if (!(await getSession())) return { ...base, locked: true };
  if (req.kind === 'create') {
    const choices = (await matchesFor(req.tabUrl))
      .filter((v) => v.reprompt !== 1 && v.edit !== false && sameRpOnly(v, req.rpId))
      .map((v) => ({ id: v.id, name: v.name || '', sub: subtitle(v), has: !!(v.login.fido2Credentials || []).length }));
    return { ...base, userName: req.options.user.name || req.options.user.displayName || '', choices };
  }
  const choices = (await passkeysFor(req.rpId, req.options.allowCredentials)).map((e) => ({
    id: e.cipher.id + '|' + b64uEnc(e.id),
    name: e.cipher.name || '',
    sub: e.cred.userName || subtitle(e.cipher),
  }));
  return { ...base, choices };
}

// Ein vorhandener Passkey darf nur durch einen für dieselbe rpId ersetzt werden.
const sameRpOnly = (v, rpId) => (v.login.fido2Credentials || []).every((c) => c && c.rpId === rpId);

async function pkCreate(req, choice) {
  const o = req.options;
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const guid = crypto.randomUUID();
  const id = guidBytes(guid);
  // COSE_Key: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
  const cose = concat([0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20], b64uDec(jwk.x), [0x22, 0x58, 0x20], b64uDec(jwk.y));
  // Flags: UP | UV | BE | BS | AT ; Zähler 0 ; AAGUID 0 ; Länge + ID ; öffentlicher Schlüssel
  const authData = concat(await sha256(utf8(req.rpId)), [0x5d], [0, 0, 0, 0], new Uint8Array(16), [0, id.length], id, cose);
  // CBOR: {"fmt": "none", "attStmt": {}, "authData": bytes}
  const attestationObject = concat(
    [0xa3, 0x63], utf8('fmt'), [0x64], utf8('none'), [0x67], utf8('attStmt'), [0xa0],
    [0x68], utf8('authData'), [0x58, authData.length], authData,
  );
  const clientData = utf8(JSON.stringify({ type: 'webauthn.create', challenge: o.challenge, origin: req.origin, crossOrigin: false }));
  const cred = {
    credentialId: guid,
    keyType: 'public-key',
    keyAlgorithm: 'ECDSA',
    keyCurve: 'P-256',
    keyValue: b64uEnc(pkcs8),
    rpId: req.rpId,
    userHandle: o.user.id || null,
    userName: o.user.name || null,
    counter: '0',
    rpName: (o.rp && o.rp.name) || null,
    userDisplayName: o.user.displayName || null,
    discoverable: 'true',
    creationDate: new Date().toISOString(),
  };
  if (choice && choice !== 'new') {
    const allowed = (await matchesFor(req.tabUrl)).some(
      (v) => v.id === choice && v.reprompt !== 1 && v.edit !== false && sameRpOnly(v, req.rpId),
    );
    if (!allowed) throw new Error('Eintrag passt nicht zu dieser Seite');
    const view = structuredClone(await getView(choice));
    view.login.removeFido2 = true; // ein Passkey pro Eintrag – der neue ersetzt einen vorhandenen
    view.login.newFido2Credentials = [cred];
    await saveCipher(view);
  } else {
    await saveCipher({
      type: 1,
      name: (o.rp && o.rp.name) || req.rpId,
      login: { username: o.user.name || null, uris: [{ uri: req.origin, match: null }], newFido2Credentials: [cred] },
    });
  }
  return {
    type: 'create',
    id: b64uEnc(id),
    clientDataJSON: b64uEnc(clientData),
    attestationObject: b64uEnc(attestationObject),
    authenticatorData: b64uEnc(authData),
    publicKey: b64uEnc(spki),
    credProps: !!o.credProps,
  };
}

async function pkGet(req, choice) {
  const list = await passkeysFor(req.rpId, req.options.allowCredentials);
  const e = list.find((x) => x.cipher.id + '|' + b64uEnc(x.id) === choice) || (choice ? null : list[0]);
  if (!e) throw new Error('Passkey nicht gefunden');
  const key = await crypto.subtle.importKey('pkcs8', b64uDec(e.cred.keyValue), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const authData = concat(await sha256(utf8(req.rpId)), [0x1d], [0, 0, 0, 0]); // UP | UV | BE | BS, Zähler 0
  const clientData = utf8(JSON.stringify({ type: 'webauthn.get', challenge: req.options.challenge, origin: req.origin, crossOrigin: false }));
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, concat(authData, await sha256(clientData))));
  return {
    type: 'get',
    id: b64uEnc(e.id),
    clientDataJSON: b64uEnc(clientData),
    authenticatorData: b64uEnc(authData),
    signature: b64uEnc(derSig(raw)),
    userHandle: e.cred.userHandle || null,
  };
}

async function pkFinish(m, sender) {
  const req = await pkReq(m, sender);
  let result;
  if (m.action === 'fallback') result = { fallback: true };
  else if (m.action !== 'confirm') result = { error: 'NotAllowedError' };
  else {
    await needSession();
    result = { credential: req.kind === 'create' ? await pkCreate(req, m.choice) : await pkGet(req, m.choice) };
  }
  await S.set({ ['pkres:' + m.reqId]: { tabId: req.tabId, result } });
  await S.remove('pk:' + m.reqId);
  return {};
}

async function pkResult(m, sender) {
  const r = await sget('pkres:' + m.reqId);
  await S.remove('pkres:' + m.reqId);
  await S.remove('pk:' + m.reqId);
  if (!r || r.tabId !== sender.tab.id) return { error: 'NotAllowedError' };
  return r.result;
}

// ---------- Nachrichten ----------

const handlers = {
  async status() {
    const accounts = (await accountList()).map((a) => ({ id: a.id, email: a.email, server: a.server }));
    // Eine angefangene Anmeldung (2FA/Gerätebestätigung) hat Vorrang – auch beim Hinzufügen eines weiteren Kontos.
    const p = await sget('pendingLogin');
    if (p && p.step && Date.now() - p.ts < 600000) {
      return { state: p.step, providers: p.providers || [], emailHint: p.emailHint || '', email: p.email, accounts };
    }
    const acc = (await aid()) && (await aget('account'));
    if (!acc) return { state: 'loggedOut', accounts };
    return {
      state: (await getSession()) ? 'unlocked' : 'locked',
      email: acc.email,
      active: await aid(),
      accounts,
      hasPin: !!(await pinBlob()),
      pinPersist: !!(await aget('pin')),
      hasBio: !!(await aget('bio')),
      bioAuto: (await settings()).bioAutoPrompt !== false,
    };
  },
  login,
  emailCode: sendEmailCode,
  async cancelLogin() {
    await S.remove('pendingLogin');
    return {};
  },
  async unlock(m) {
    await afterUnlock(await unlockWith(m.password));
    return {};
  },
  unlockPin,
  unlockBio,
  setPin,
  async clearPin() {
    await clearPin();
    return {};
  },
  bioEnable,
  async bioDisable() {
    await adel('bio');
    native({ cmd: 'bioDelete', account: await aid() }).catch(() => {});
    return {};
  },
  async verify(m) {
    await unlockWith(m.password);
    return {};
  },
  async lock() {
    await lock();
    return {};
  },
  async logout() {
    await logout();
    return {};
  },
  async switchAccount(m) {
    await switchTo(m.id);
    return {};
  },
  async sync() {
    await sync();
    return {};
  },
  async list(m) {
    const v = await getViews();
    const last = (await aget('lastSync')) || 0;
    if (Date.now() - last > 30 * 60000) syncInBackground();
    let sug = { list: [], others: [], remembered: null };
    if (m.url) sug = await suggestionsFor(m.url);
    const profile = (await aget('profile')) || {};
    return {
      items: v.ciphers.map(slim).sort((a, b) => a.name.localeCompare(b.name)),
      matchIds: sug.list.map((x) => x.id),
      otherMatchIds: sug.others.map((x) => x.id),
      rememberedId: sug.remembered,
      folders: v.folders,
      collections: v.collections,
      orgs: (profile.organizations || []).map((o) => ({ id: o.id, name: o.name })),
      pending: await evalPending().catch(() => null),
      lastSync: last,
      settings: await settings(),
    };
  },
  async get(m) {
    return { item: await getView(m.id) };
  },
  async totp(m) {
    return { totp: await totpFor(await getView(m.id)) };
  },
  async fill(m) {
    // Die Seite muss noch die sein, die das Popup angezeigt hat.
    const t = await browser.tabs.get(m.tabId).catch(() => null);
    const url = (t && t.url) || m.url;
    if (!url || (m.url && new URL(m.url).origin !== new URL(url).origin)) throw new Error('Die Seite hat sich geändert');
    const r = await fill(m.id, m.tabId, url, { allowHttp: m.allowHttp === true });
    if (r.filled) await rememberHost(url, m.id).catch(() => {});
    return r;
  },
  async forgetHost(m) {
    const host = hostOf(m.url);
    const map = await hostMap();
    if (host && host in map) {
      delete map[host];
      await saveHostMap(map);
    }
    return {};
  },
  async forgetAllHosts() {
    await adel('hosts');
    return {};
  },
  async save(m) {
    return saveCipher(m.view);
  },
  async remove(m) {
    return deleteCipher(m.id);
  },
  async restore(m) {
    return restoreCipher(m.id);
  },
  async folder(m) {
    return createFolder(m.name);
  },
  attGet,
  attAdd,
  attDel,
  sends: sendsList,
  sendSave,
  sendDelete,
  export: exportVault,
  import: importVault,
  async generate(m) {
    const c = await core();
    return { value: c.generate(JSON.stringify(m.opts || {})) };
  },
  async pendingAccept(m) {
    return acceptPending(m.ts);
  },
  async neverDomain() {
    const p = await sget('pendingSave');
    if (p) {
      const host = new URL(p.url).hostname;
      const st = await settings();
      if (!st.neverDomains.includes(host)) await L.set({ settings: { ...st, neverDomains: [...st.neverDomains, host] } });
    }
    await S.remove('pendingSave');
    setBadge('');
    return {};
  },
  async pendingDismiss() {
    await S.remove('pendingSave');
    setBadge('');
    return {};
  },
  async copied(m) {
    const { clipClear } = await settings();
    if (clipClear > 0 && m.hash) {
      await S.set({ clip: m.hash });
      browser.alarms.create('clip', { delayInMinutes: Math.max(0.5, clipClear / 60) });
    }
    return {};
  },
  async getSettings() {
    const acc = (await aid()) && (await aget('account'));
    return {
      settings: await settings(),
      lastSync: (await aget('lastSync')) || 0,
      account: acc && { email: acc.email, server: acc.server },
      active: await aid(),
      accounts: (await accountList()).map((a) => ({ id: a.id, email: a.email, server: a.server })),
      hasPin: !!(await pinBlob()),
      pinPersist: !!(await aget('pin')),
      hasBio: !!(await aget('bio')),
      rememberedHosts: Object.keys(await hostMap()).length,
    };
  },
  async setSettings(m) {
    const patch = { ...(m.settings || {}) };
    if ('neverDomains' in patch) {
      patch.neverDomains = [...new Set((patch.neverDomains || []).map((d) => String(d).trim().toLowerCase().replace(/^\*?\./, '')).filter(Boolean))];
    }
    if ('defaultMatch' in patch && ![0, 1, 2, 3, 4, 5].includes(patch.defaultMatch)) throw new Error('Ungültige Übereinstimmungserkennung');
    await L.set({ settings: { ...(await settings()), ...patch } });
    if (await getSession()) await touch();
    return {};
  },
  // --- aus dem Inline-Menü (iframe in der Webseite) ---
  async inlineList(m, sender) {
    await inlineAuth(m, sender);
    if (!(await getSession())) return { locked: true, items: [] };
    const items = (await suggestionsFor(sender.tab.url)).list
      .filter((v) => v.reprompt !== 1)
      .map((v) => ({ id: v.id, name: v.name || '', sub: subtitle(v) }));
    return { items };
  },
  async inlineFill(m, sender) {
    await inlineAuth(m, sender);
    // Nur Einträge, die zur Seite des Tabs passen – das iframe kann nichts anderes anfordern.
    const ok = (await matchesFor(sender.tab.url)).some((v) => v.id === m.id && v.reprompt !== 1);
    if (!ok) throw new Error('Eintrag passt nicht zu dieser Seite');
    const r = await fill(m.id, sender.tab.id, sender.tab.url);
    if (r.filled) await rememberHost(sender.tab.url, m.id).catch(() => {});
    return r;
  },
  async openPopup() {
    await browser.action.openPopup();
    return {};
  },
  pkInfo,
  pkFinish,
};
// Inline-Menü: Token, das unser Content-Script im Top-Frame des Tabs vergeben hat (5 Minuten gültig).
async function inlineAuth(m, sender) {
  const t = await sget('inl:' + sender.tab.id);
  if (!t || typeof m.token !== 'string' || t.token !== m.token || Date.now() - t.ts > 300000) throw new Error('Nicht erlaubt');
}

// Befehle, die unsere iframes innerhalb von Webseiten senden dürfen – und nur diese.
const FRAME_ONLY = new Set(['inlineList', 'inlineFill', 'pkInfo', 'pkFinish']);
const FRAME_CMDS = new Set([...FRAME_ONLY, 'openPopup']);
// Befehle, die keine Nutzeraktivität bedeuten und daher den Sperr-Timer nicht verlängern
// (z. B. der TOTP-Countdown eines offenen Eintrags oder ein in die Seite eingebettetes Menü).
const PASSIVE = new Set(['lock', 'logout', 'status', 'totp', 'inlineList', 'pkInfo', 'openPopup', 'getSettings']);

function excluded(url, list) {
  let host;
  try {
    host = new URL(url).hostname;
  } catch {
    return true;
  }
  return (list || []).some((d) => host === d || host.endsWith('.' + d));
}

async function onSubmitted(m, sender) {
  const st = await settings();
  if ((!st.addPrompt && !st.updatePrompt) || !(await aid())) return;
  // URL vom Browser, nicht aus der Nachricht.
  const url = sender.url || (sender.tab && sender.tab.url) || '';
  if (typeof m.password !== 'string' || !m.password || m.password.length > 1000 || !/^https?:/.test(url)) return;
  if (excluded(url, st.neverDomains)) return;
  await S.set({
    pendingSave: { url, username: String(m.username || '').slice(0, 500), password: m.password, ts: Date.now() },
  });
  if (await getSession()) await evalPending().catch(() => {});
}

// Optional (Einstellungen): Treffer-Zähler und Auto-Ausfüllen auf Seiten mit Passwortfeld.
async function onLoginPage(sender) {
  const s = await settings();
  if ((!s.badge && !s.autoFill) || !sender.tab || !(await getSession())) return;
  const m = (await suggestionsFor(sender.tab.url)).list;
  if (s.badge) setBadge(m.length ? String(m.length) : '', sender.tab.id);
  const usable = m.filter((v) => v.reprompt !== 1);
  if (s.autoFill && usable.length && /^https:/.test(sender.tab.url || '')) await fill(usable[0].id, sender.tab.id, sender.tab.url);
}

browser.runtime.onMessage.addListener((m, sender, respond) => {
  if (!m || !m.cmd) return;
  // Volle Rechte nur für eigene Erweiterungsseiten (Popup bzw. Popup-im-Tab).
  const fromExt =
    sender.id === browser.runtime.id && (sender.url ? String(sender.url).startsWith(EXT) : !sender.tab);
  if (!fromExt) {
    if (!sender.tab) return;
    if ((m.cmd === 'pkBegin' || m.cmd === 'pkResult') && !sender.frameId) {
      (m.cmd === 'pkBegin' ? pkBegin : pkResult)(m, sender).then(respond, () => respond({ fallback: true }));
      return true;
    }
    if (m.cmd === 'inlineToken' && !sender.frameId && typeof m.token === 'string' && m.token.length <= 64) {
      S.set({ ['inl:' + sender.tab.id]: { token: m.token, ts: Date.now() } }).then(() => respond({}), () => respond({}));
      return true;
    }
    if (m.cmd === 'submitted') onSubmitted(m, sender).catch(() => {});
    else if (m.cmd === 'loginPage') onLoginPage(sender).catch(() => {});
    return;
  }
  const embedded = !!sender.tab && !!sender.frameId; // unser iframe innerhalb einer Webseite
  const fn = handlers[m.cmd];
  if (!fn || (embedded && !FRAME_CMDS.has(m.cmd)) || (!embedded && FRAME_ONLY.has(m.cmd))) {
    respond({ ok: false, error: 'Unbekannter Befehl' });
    return;
  }
  (async () => {
    try {
      const r = (await fn(m, sender)) || {};
      if (!PASSIVE.has(m.cmd) && (await getSession())) touch().catch(() => {});
      respond({ ok: true, ...r });
    } catch (e) {
      respond({ ok: false, error: String((e && e.message) || e), code: (e && e.code) || undefined });
    }
  })();
  return true;
});

async function logoutAll() {
  for (const a of await accountList()) {
    await switchTo(a.id);
    await logout();
  }
}

browser.alarms.onAlarm.addListener(async (a) => {
  if (a.name === 'lock') {
    if ((await settings()).timeoutAction === 'logout') await logoutAll();
    else await lock();
  }
  else if (a.name === 'clip') {
    const hash = await sget('clip');
    await S.remove('clip');
    if (hash) native({ cmd: 'clipClear', hash }).catch(() => {});
  }
});

browser.commands.onCommand.addListener((cmd) => {
  if (cmd !== 'autofill') return;
  browser.tabs
    .query({ active: true, currentWindow: true })
    .then(([tab]) => autofillTab(tab))
    .catch(() => {});
});

// Kontextmenü: Login ausfüllen, dazu – nur solange entsperrt – Untermenüs mit Identitäten und Karten
// (wie bei Bitwarden). Namen der Einträge erscheinen also nie im Menü, solange der Tresor gesperrt ist.
let menuTimer = null;
function scheduleMenus() {
  clearTimeout(menuTimer);
  menuTimer = setTimeout(() => setupMenus().catch(() => {}), 150);
}

async function setupMenus() {
  if (!browser.contextMenus) return;
  const make = (o) =>
    new Promise((res) => {
      try {
        browser.contextMenus.create(o, () => res());
      } catch {
        res();
      }
    });
  let groups = [];
  if (await getSession().catch(() => null)) {
    const all = (await getViews().catch(() => ({ ciphers: [] }))).ciphers.filter((v) => !v.deletedDate).sort(byName);
    groups = [
      ['identity', 'RustWarden: Identität ausfüllen', all.filter((v) => v.type === 4)],
      ['card', 'RustWarden: Karte ausfüllen', all.filter((v) => v.type === 3)],
    ].filter((g) => g[2].length);
  }
  await browser.contextMenus.removeAll();
  await make({ id: 'fill', title: 'RustWarden: Login ausfüllen', contexts: ['editable', 'page'] });
  for (const [kind, title, items] of groups) {
    await make({ id: kind, title, contexts: ['editable', 'page'] });
    for (const v of items.slice(0, 25)) {
      const sub = subtitle(v);
      const label = (v.name || '(ohne Namen)') + (sub && sub !== v.name ? ' – ' + sub : '');
      await make({ id: `${kind}:${v.id}`, parentId: kind, title: label.slice(0, 60), contexts: ['editable', 'page'] });
    }
  }
}

// Identität/Karte aus dem Kontextmenü ausfüllen. Einträge mit Master-Passwort-Abfrage → Popup.
async function fillFromMenu(id, tab) {
  if (!tab) return;
  if (!(await getSession())) return browser.action.openPopup();
  const v = await getView(id);
  if (v.reprompt === 1 || (v.type !== 3 && v.type !== 4)) return browser.action.openPopup();
  await fill(id, tab.id, tab.url);
  await touch();
}
browser.runtime.onInstalled.addListener(scheduleMenus);
browser.runtime.onStartup.addListener(scheduleMenus);
// Nach einem Browser-Neustart sind die Sitzungen weg – bei Timeout-Aktion „Abmelden“ heißt das: abmelden.
browser.runtime.onStartup.addListener(async () => {
  if ((await settings()).timeoutAction === 'logout') await logoutAll().catch(() => {});
});
if (browser.contextMenus) {
  browser.contextMenus.onClicked.addListener((info, tab) => {
    const mid = String(info.menuItemId);
    if (mid === 'fill') autofillTab(tab).catch(() => {});
    else if (/^(identity|card):/.test(mid)) fillFromMenu(mid.slice(mid.indexOf(':') + 1), tab).catch(() => {});
  });
}
