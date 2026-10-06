import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = fileURLToPath(new URL('../..', import.meta.url));
const dist = join(web, 'dist');

test('build emits hashed assets, rewritten index.html and a complete manifest', () => {
  execFileSync('node', ['tools/build.mjs'], { cwd: web, stdio: 'pipe' });
  const assets = readdirSync(join(dist, 'assets')).sort();
  const js = assets.find((f) => /^app\.[A-Z0-9]+\.js$/i.test(f));
  const css = assets.find((f) => /^app\.[A-Z0-9]+\.css$/i.test(f));
  assert.ok(js && css, `assets: ${assets}`);
  const html = readFileSync(join(dist, 'index.html'), 'utf8');
  assert.ok(html.includes(`/assets/${js}`) && html.includes(`/assets/${css}`));
  assert.ok(!html.includes('%%APP_'));
  const lines = readFileSync(join(dist, 'MANIFEST.sha256'), 'utf8').trim().split('\n');
  const paths = lines.map((l) => l.split('  ')[1]);
  assert.deepEqual(paths, [...paths].sort());
  assert.ok(paths.includes('index.html') && paths.includes(`assets/${js}`) && paths.includes('images/logo.png'));
  assert.ok(!paths.includes('MANIFEST.sha256'));
  for (const l of lines) {
    const [hash, p] = l.split('  ');
    assert.equal(createHash('sha256').update(readFileSync(join(dist, p))).digest('hex'), hash, p);
  }
});

test('build is deterministic', () => {
  execFileSync('node', ['tools/build.mjs'], { cwd: web, stdio: 'pipe' });
  const a = readFileSync(join(dist, 'MANIFEST.sha256'), 'utf8');
  execFileSync('node', ['tools/build.mjs'], { cwd: web, stdio: 'pipe' });
  assert.equal(readFileSync(join(dist, 'MANIFEST.sha256'), 'utf8'), a);
});

test('build ships self-hosted fonts and no external font origins', () => {
  const manifest = readFileSync(join(dist, 'MANIFEST.sha256'), 'utf8');
  for (const f of ['inter-latin-wght-normal.woff2', 'space-grotesk-latin-wght-normal.woff2', 'jetbrains-mono-latin-wght-normal.woff2']) {
    assert.match(manifest, new RegExp(`  fonts/${f}\n`));
  }
  assert.doesNotMatch(readFileSync(join(dist, 'index.html'), 'utf8'), /fonts\.(googleapis|gstatic)\.com/);
});

test('self-hosted @font-face weight ranges match the previous Google Fonts request', () => {
  const css = readFileSync(join(web, 'styles', 'app.css'), 'utf8');
  const expected = { 'Inter': '300 700', 'Space Grotesk': '500 700', 'JetBrains Mono': '400 500' };
  for (const [family, weights] of Object.entries(expected)) {
    const m = css.match(new RegExp(String.raw`@font-face\s*\{[^}]*font-family:\s*'${family}'[^}]*\}`));
    assert.ok(m, `@font-face for ${family}`);
    assert.match(m[0], new RegExp(String.raw`font-weight:\s*${weights}\s*;`), family);
  }
});
