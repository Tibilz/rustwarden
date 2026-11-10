// Inline-Menü: läuft als iframe der Erweiterung in der Webseite. Die Seite kann den Inhalt nicht lesen.
'use strict';
(async () => {
  const list = document.getElementById('list');
  const tell = (m) => parent.postMessage(m, '*');
  const div = (cls, text) => {
    const d = document.createElement('div');
    d.className = cls;
    d.textContent = text;
    return d;
  };
  let r;
  try {
    r = await browser.runtime.sendMessage({ cmd: 'inlineList' });
  } catch {
    r = null;
  }
  if (!r || !r.ok) list.append(div('info', 'RustWarden nicht erreichbar'));
  else if (r.locked) {
    const row = div('row', 'Tresor gesperrt – RustWarden öffnen');
    row.onclick = () => {
      tell({ rw: 'close' });
      browser.runtime.sendMessage({ cmd: 'openPopup' }).catch(() => {});
    };
    list.append(row);
  } else if (!r.items.length) list.append(div('info', 'Keine passenden Logins'));
  else {
    for (const it of r.items) {
      const row = div('row', it.name);
      row.append(div('sub', it.sub || ''));
      row.onclick = () => {
        tell({ rw: 'close' });
        browser.runtime.sendMessage({ cmd: 'inlineFill', id: it.id }).catch(() => {});
      };
      list.append(row);
    }
  }
  tell({ rw: 'size', h: document.documentElement.scrollHeight });
})();
