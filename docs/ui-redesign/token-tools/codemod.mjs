// Exact-match token adoption: only declarations whose px value equals a token value are rewritten.
//   node tests/_t/codemod.mjs [--write]
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
const write = process.argv.includes('--write');
const TEXT = { '11px': '--text-xs', '12px': '--text-sm', '13px': '--text-base', '14px': '--text-md', '15px': '--text-lg', '24px': '--text-display' };
const SP = { '2px': '--sp-2', '4px': '--sp-4', '6px': '--sp-6', '8px': '--sp-8', '10px': '--sp-10', '12px': '--sp-12', '14px': '--sp-14', '16px': '--sp-16', '20px': '--sp-20', '24px': '--sp-24', '32px': '--sp-32' };
const PROP = new RegExp('(^|[; {])(font-size|padding|padding-top|padding-right|padding-bottom|padding-left|margin|margin-top|margin-right|margin-bottom|margin-left|row-gap|column-gap|gap)( *: *)([^;{}]*?)( *!important)?( *)(?=[;}]|$)', 'gm');
const stats = { text: {}, sp: {}, files: {} };
for (const f of readdirSync('styles').filter((x) => x.endsWith('.css') && x !== 'inline-equivalent.css' && x !== 'tokens.css')) {
  const src = readFileSync('styles/' + f, 'utf8'); let n = 0;
  const out = src.replace(PROP, (m, pre, prop, colon, val, imp, ws) => {
    if (['calc(', 'var(', 'clamp(', 'min(', 'max(', '/*'].some((k) => val.includes(k))) return m;
    const isText = prop === 'font-size';
    const nv = val.split(' ').map((t) => { const map = isText ? TEXT : SP; const k = t.replace(/^-/, ''); if (t.startsWith('-')) return t; const tok = map[k]; if (!tok) return t; (isText ? stats.text : stats.sp)[k] = ((isText ? stats.text : stats.sp)[k] || 0) + 1; n++; return 'var(' + tok + ')'; }).join(' ');
    return nv === val ? m : pre + prop + colon + nv + (imp || '') + ws;
  });
  stats.files[f] = n; if (write && out !== src) writeFileSync('styles/' + f, out);
}
console.log('text', JSON.stringify(stats.text)); console.log('spacing', JSON.stringify(stats.sp));
console.log('total replacements', Object.values(stats.files).reduce((a, b) => a + b, 0), write ? '(written)' : '(dry run)');
