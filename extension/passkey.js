// Passkey-Dialog: läuft als iframe der Erweiterung in der Webseite (für die Seite nicht lesbar).
'use strict';
(async () => {
  const reqId = location.hash.slice(1);
  const box = document.getElementById('box');
  const tell = (m) => parent.postMessage(m, '*');
  const send = (cmd, extra) => browser.runtime.sendMessage({ cmd, reqId, ...(extra || {}) });
  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  const size = () => tell({ rw: 'pkSize', h: document.documentElement.scrollHeight });
  const error = el('p', 'error');
  let busy = false;

  async function finish(action, choice) {
    if (busy) return;
    busy = true;
    error.textContent = '';
    try {
      const r = await send('pkFinish', { action, choice });
      if (!r || !r.ok) throw new Error((r && r.error) || 'Keine Antwort');
      tell({ rw: 'pkDone' });
    } catch (e) {
      busy = false;
      error.textContent = e.message;
      size();
    }
  }
  const button = (label, fn, primary) => {
    const b = el('button', primary ? 'primary' : '', label);
    b.onclick = fn;
    return b;
  };

  let info;
  try {
    info = await send('pkInfo');
  } catch {
    info = null;
  }
  const title = el('h1');
  title.append('Rust', el('span', '', 'Warden'), ' · Passkey');
  box.append(title);

  if (!info || !info.ok) {
    box.append(el('p', 'error', (info && info.error) || 'RustWarden nicht erreichbar'));
    box.append(button('Schließen', () => tell({ rw: 'pkDone' })));
    return size();
  }

  const fallback = button('Safari verwenden', () => finish('fallback'));
  const cancel = button('Abbrechen', () => finish('cancel'));
  const btns = el('div', 'btns');

  if (info.locked) {
    box.append(
      el('p', '', `${info.rpId} möchte einen Passkey ${info.kind === 'create' ? 'anlegen' : 'verwenden'}.`),
      el('p', 'muted', 'RustWarden ist gesperrt. Entsperre den Tresor über das Symbol in der Symbolleiste und versuche es danach auf der Seite erneut.'),
    );
    btns.append(fallback, cancel);
  } else {
    const radios = [];
    const option = (value, name, sub, checked) => {
      const l = el('label');
      const r = el('input');
      r.type = 'radio';
      r.name = 'c';
      r.value = value;
      r.checked = !!checked;
      const t = el('span', '', name);
      if (sub) t.append(' ', el('span', 'muted', sub));
      l.append(r, t);
      radios.push(r);
      return l;
    };
    const picked = () => (radios.find((r) => r.checked) || {}).value;
    if (info.kind === 'create') {
      box.append(el('p', '', `Passkey für ${info.rpId} speichern?`), el('p', 'muted', info.userName || ''));
      box.append(option('new', 'Neuer Eintrag', '', true));
      for (const c of info.choices) box.append(option(c.id, c.name, c.sub + (c.has ? ' · ersetzt vorhandenen Passkey' : '')));
      btns.append(button('Speichern', () => finish('confirm', picked()), true), fallback, cancel);
    } else {
      box.append(el('p', '', `Mit Passkey bei ${info.rpId} anmelden?`));
      info.choices.forEach((c, i) => box.append(option(c.id, c.name, c.sub, i === 0)));
      btns.append(button('Anmelden', () => finish('confirm', picked()), true), fallback, cancel);
    }
  }
  box.append(error, btns);
  size();
})();
