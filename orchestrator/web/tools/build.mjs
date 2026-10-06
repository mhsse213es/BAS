// Production bundle: src/main.js + styles/app.css -> dist/ with content-hashed
// names, rewritten index.html, copied images and MANIFEST.sha256 (G1c spec 7).
import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = fileURLToPath(new URL('..', import.meta.url));
const dist = join(web, 'dist');
rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, 'assets'), { recursive: true });

const result = await build({
  absWorkingDir: web,
  entryPoints: { app: 'src/main.js', 'app-css': 'styles/app.css' },
  bundle: true,
  format: 'iife',
  target: 'es2020',
  minify: false,
  legalComments: 'inline',
  charset: 'utf8',
  outdir: 'dist/assets',
  entryNames: '[name].[hash]',
  // Absolute same-origin URLs in CSS (e.g. url(/images/logo.png)) are served
  // as-is, never inlined or resolved by the bundler.
  external: ['/images/*', '/assets/*', '/fonts/*'],
  metafile: true,
  logLevel: 'warning',
});
let jsName, cssName;
for (const out of Object.keys(result.metafile.outputs)) {
  const base = out.split('/').pop();
  if (base.startsWith('app.') && base.endsWith('.js')) jsName = base;
  if (base.startsWith('app-css.') && base.endsWith('.css')) cssName = base.replace(/^app-css\./, 'app.');
  if (base.startsWith('app-css.') && base.endsWith('.css')) cpSync(join(web, out), join(dist, 'assets', cssName)), rmSync(join(web, out));
}
if (!jsName || !cssName) throw new Error('esbuild did not emit app js/css');

const html = readFileSync(join(web, 'index.html'), 'utf8').replace('%%APP_JS%%', jsName).replace('%%APP_CSS%%', cssName);
writeFileSync(join(dist, 'index.html'), html);
cpSync(join(web, 'images'), join(dist, 'images'), { recursive: true });
cpSync(join(web, 'fonts'), join(dist, 'fonts'), { recursive: true, filter: (p) => !p.endsWith('.txt') });

const files = [];
(function walk(d) { for (const e of readdirSync(d)) { const p = join(d, e); if (statSync(p).isDirectory()) walk(p); else files.push(p); } })(dist);
const manifest = files
  .map((p) => relative(dist, p).split(sep).join('/'))
  .filter((p) => p !== 'MANIFEST.sha256')
  .sort()
  .map((p) => `${createHash('sha256').update(readFileSync(join(dist, p))).digest('hex')}  ${p}\n`)
  .join('');
writeFileSync(join(dist, 'MANIFEST.sha256'), manifest);
console.log(`built dist/: ${jsName}, ${cssName}, ${files.length} files`);
