// Minimaler Content-Script (nur Top-Frame). Beim Laden passiert fast nichts:
// ein querySelector, dazu passive Listener. Alles Weitere erst bei Nutzerinteraktion.
(() => {
  'use strict';
  const say = (m) => {
    try {
      browser.runtime.sendMessage(m).catch(() => {});
    } catch {}
  };
  const opts = () =>
    browser.storage.local
      .get('settings')
      .then((r) => r.settings || {})
      .catch(() => ({}));

  // ---- 1. Abgeschickte Logins erkennen ("Speichern?" im Popup) ----
  let last = 0;
  const grab = (root) => {
    const scope = root && root.querySelectorAll ? root : document;
    const pw = [...scope.querySelectorAll('input[type=password]')].find((e) => e.value);
    if (!pw) return;
    const now = Date.now();
    if (now - last < 1500) return;
    last = now;
    const all = [...(pw.form || document).querySelectorAll('input')];
    let username = '';
    for (let i = all.indexOf(pw) - 1; i >= 0; i--) {
      const t = (all[i].getAttribute('type') || 'text').toLowerCase();
      if (/^(text|email|tel)$/.test(t) && all[i].value) {
        username = all[i].value;
        break;
      }
    }
    say({ cmd: 'submitted', url: location.href, username, password: pw.value });
  };
  addEventListener('submit', (e) => grab(e.target), true);
  addEventListener(
    'keydown',
    (e) => {
      if (e.key === 'Escape') close();
      else if (e.key === 'Enter' && e.target && e.target.type === 'password') grab(e.target.form);
    },
    true,
  );
  addEventListener(
    'click',
    (e) => {
      const b = e.target && e.target.closest && e.target.closest('button,input[type=submit],[role=button]');
      if (b) grab(b.form);
    },
    true,
  );

  // ---- 2. Einstellungen einmal lesen: Passkey-Brücke laden, optional Zähler / Auto-Ausfüllen ----
  opts().then((s) => {
    if (s.passkeys !== false && window.PublicKeyCredential) {
      const sc = document.createElement('script');
      sc.src = browser.runtime.getURL('passkey-page.js');
      sc.onload = sc.onerror = () => sc.remove();
      (document.head || document.documentElement).append(sc);
    }
    if ((s.badge || s.autoFill) && document.querySelector('input[type=password]')) say({ cmd: 'loginPage' });
  });

  // ---- 2b. Passkeys: Anfragen des Seiten-Skripts an RustWarden weiterreichen, Dialog als iframe zeigen ----
  let pkFrame = null;
  let pkDone = null;
  function pkDialog(reqId) {
    return new Promise((resolve) => {
      if (pkFrame) pkFrame.remove();
      const f = (pkFrame = document.createElement('iframe'));
      f.src = browser.runtime.getURL('passkey.html') + '#' + reqId;
      f.style.cssText =
        'position:fixed;z-index:2147483647;top:14px;right:14px;width:340px;height:150px;max-height:80vh;' +
        'border:1px solid rgba(128,128,128,.5);border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,.3);' +
        'background:#fff;color-scheme:light dark;';
      const timer = setTimeout(() => pkDone && pkDone(), 120000);
      pkDone = async () => {
        clearTimeout(timer);
        pkDone = null;
        f.remove();
        if (pkFrame === f) pkFrame = null;
        try {
          resolve((await browser.runtime.sendMessage({ cmd: 'pkResult', reqId })) || { error: 'NotAllowedError' });
        } catch {
          resolve({ error: 'NotAllowedError' });
        }
      };
      document.documentElement.append(f);
    });
  }
  addEventListener('message', async (e) => {
    if (pkFrame && e.source === pkFrame.contentWindow && e.data) {
      if (e.data.rw === 'pkDone' && pkDone) pkDone();
      else if (e.data.rw === 'pkSize') pkFrame.style.height = Math.max(110, Math.min(460, Number(e.data.h) || 150)) + 'px';
      return;
    }
    if (e.source !== window || !e.data || e.data.rwpk !== 'req') return;
    const reply = (r) => postMessage({ rwpk: 'res', n: e.data.n, r }, location.origin);
    let b;
    try {
      b = await browser.runtime.sendMessage({ cmd: 'pkBegin', kind: e.data.kind, options: e.data.options });
    } catch {
      b = null;
    }
    if (!b || !b.reqId) return reply(b || { fallback: true });
    reply(await pkDialog(b.reqId));
  });

  // ---- 3. Optional: Inline-Menü unter Login-Feldern (iframe der Erweiterung, für die Seite nicht lesbar) ----
  let inline; // wird erst beim ersten Fokus auf ein Login-Feld aus den Einstellungen gelesen
  let frame = null;
  let mute = 0;
  function close() {
    if (frame) frame.remove();
    frame = null;
  }
  function open(t) {
    close();
    const r = t.getBoundingClientRect();
    frame = document.createElement('iframe');
    frame.src = browser.runtime.getURL('inline.html');
    const w = Math.max(240, Math.min(r.width, 380));
    frame.style.cssText =
      'position:fixed;z-index:2147483647;border:1px solid rgba(128,128,128,.5);border-radius:8px;' +
      'box-shadow:0 6px 24px rgba(0,0,0,.25);background:#fff;color-scheme:light dark;height:44px;' +
      `width:${w}px;left:${Math.max(4, Math.min(r.left, innerWidth - w - 4))}px;top:${r.bottom + 3}px;`;
    document.documentElement.append(frame);
  }
  addEventListener(
    'focusin',
    async (e) => {
      const t = e.target;
      if (!t || t.tagName !== 'INPUT' || Date.now() < mute) return;
      const ty = (t.getAttribute('type') || 'text').toLowerCase();
      if (!/^(text|email|password)$/.test(ty)) return;
      if (
        ty !== 'password' &&
        !document.querySelector('input[type=password]') &&
        !/user|e.?mail|login/i.test(`${t.name} ${t.id} ${t.autocomplete || ''}`)
      )
        return;
      if (inline === undefined) inline = !!(await opts()).inline;
      if (inline && document.activeElement === t) open(t);
    },
    true,
  );
  addEventListener('mousedown', (e) => frame && e.target !== frame && close(), true);
  addEventListener('scroll', () => frame && close(), true);
  addEventListener('resize', () => frame && close());
  addEventListener('message', (e) => {
    if (!frame || e.source !== frame.contentWindow || !e.data) return;
    if (e.data.rw === 'close') {
      mute = Date.now() + 2500; // Fokus-Ereignisse des Ausfüllens nicht als neuen Anlass werten
      close();
    } else if (e.data.rw === 'size') {
      frame.style.height = Math.max(36, Math.min(230, Number(e.data.h) || 44)) + 'px';
    }
  });
})();
