// Erzeugt extension/psl.txt aus der Public Suffix List (https://publicsuffix.org, MPL-2.0).
// Aufruf: node tools/gen-psl.js   (lädt die aktuelle Liste herunter)
// Format: eine Regel pro Zeile, Punycode; "*.x" = Wildcard, "!x" = Ausnahme.
// Einstufige Regeln (reine TLDs) fehlen absichtlich: die Standardregel "*" deckt sie ab.
const fs = require('fs');
const path = require('path');
const { domainToASCII } = require('url');

(async () => {
  const res = await fetch('https://publicsuffix.org/list/public_suffix_list.dat');
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const text = await res.text();
  const rules = new Set();
  for (let line of text.split('\n')) {
    line = line.trim().split(/\s/)[0];
    if (!line || line.startsWith('//')) continue;
    const pre = line.startsWith('!') ? '!' : line.startsWith('*.') ? '*.' : '';
    const ascii = domainToASCII(line.slice(pre.length));
    if (!ascii) throw new Error('Ungültige Regel: ' + line);
    if (!pre && !ascii.includes('.')) continue;
    rules.add(pre + ascii);
  }
  const out =
    '// Public Suffix List, https://publicsuffix.org – Mozilla Public License 2.0, https://mozilla.org/MPL/2.0/\n' +
    `// Erzeugt von tools/gen-psl.js am ${new Date().toISOString().slice(0, 10)}\n` +
    [...rules].sort().join('\n') + '\n';
  fs.writeFileSync(path.join(__dirname, '../extension/psl.txt'), out);
  console.log(`${rules.size} Regeln, ${(out.length / 1024).toFixed(0)} kB`);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
