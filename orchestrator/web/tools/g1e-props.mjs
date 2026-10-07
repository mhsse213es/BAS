// One-time (G1e): every CSS property named in an inline style attribute, in
// markup or JS templates, at the baseline tree. Output: tests/visual/props.json.
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = fileURLToPath(new URL('..', import.meta.url));
const files = [join(web, 'index.html')];
(function walk(d) { for (const e of readdirSync(d)) { const p = join(d, e); if (statSync(p).isDirectory()) walk(p); else if (p.endsWith('.js')) files.push(p); } })(join(web, 'src'));
const props = new Set(['display', 'visibility', 'opacity']);
const ATTR = /(?<![\w.-])style=\\?(["'])([\s\S]*?)\\?\1/g;
for (const f of files) {
  for (const m of readFileSync(f, 'utf8').matchAll(ATTR)) {
    for (const decl of m[2].split(';')) {
      const name = decl.split(':')[0].trim().toLowerCase();
      if (/^-?[a-z][a-z-]*$/.test(name)) props.add(name);
    }
  }
}
writeFileSync(join(web, 'tests/visual/props.json'), JSON.stringify([...props].sort(), null, 1) + '\n');
console.log(`props.json: ${props.size} properties`);
