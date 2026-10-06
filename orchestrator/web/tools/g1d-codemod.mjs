// One-time G1d codemod (deleted in Task 9): converts inline handlers in
// index.html that are a single call with literal arguments into data-on-*
// actions via on(). Everything else is reported for hand conversion.
// Run: node tools/g1d-codemod.mjs [--write]
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { EVENT_TYPES, on } from '../src/core/actions.js';

const ENTITIES = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&apos;': "'" };
const decode = (s) => s.replace(/&(?:amp|lt|gt|quot|apos|#39);|&#(\d+);|&#x([0-9a-f]+);/gi, (m, d, h) => (d ? String.fromCodePoint(+d) : h ? String.fromCodePoint(parseInt(h, 16)) : ENTITIES[m.toLowerCase()]));

// Parses a comma-separated list of JS literals; returns null on anything else.
function parseArgs(s) {
  const out = []; let i = 0;
  const ws = () => { while (i < s.length && /\s/.test(s[i])) i++; };
  ws();
  if (i === s.length) return out;
  for (;;) {
    ws();
    const q = s[i];
    if (q === "'" || q === '"') {
      let v = ''; i++;
      while (i < s.length && s[i] !== q) {
        if (s[i] === '\\') { i++; const c = s[i]; v += c === 'n' ? '\n' : c === 't' ? '\t' : c; i++; } else { v += s[i++]; }
      }
      if (s[i] !== q) return null;
      i++; out.push(v);
    } else {
      const m = /^(-?\d+(?:\.\d+)?|true|false|null)(?![\w$])/.exec(s.slice(i));
      if (!m) return null;
      out.push(JSON.parse(m[1])); i += m[1].length;
    }
    ws();
    if (i === s.length) return out;
    if (s[i] !== ',') return null;
    i++;
  }
}

export function convertHandler(event, body) {
  if (!EVENT_TYPES.includes(event)) return null;
  const m = /^\s*([A-Za-z_$][\w$]*)\s*\(([\s\S]*)\)\s*;?\s*$/.exec(body);
  if (!m) return null;
  const args = parseArgs(m[2]);
  if (args === null) return null;
  return on(event, m[1], ...args);
}

export function convertHtml(html) {
  let converted = 0; const skipped = [];
  const lines = html.split('\n').map((line, n) => line.replace(/\son([a-z]+)="([^"]*)"/g, (whole, ev, raw) => {
    const attr = convertHandler(ev, decode(raw));
    if (attr === null) { skipped.push({ line: n + 1, attr: whole.trim() }); return whole; }
    converted++; return attr;
  }));
  return { html: lines.join('\n'), converted, skipped };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const file = fileURLToPath(new URL('../index.html', import.meta.url));
  const { html, converted, skipped } = convertHtml(readFileSync(file, 'utf8'));
  for (const s of skipped) console.log(`skip L${s.line}: ${s.attr}`);
  console.log(`converted ${converted}, skipped ${skipped.length}`);
  if (process.argv.includes('--write')) writeFileSync(file, html);
}
