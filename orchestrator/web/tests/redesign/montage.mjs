// Builds one contact sheet from a folder of screenshots (or side by side from two folders).
//
//   node tests/redesign/montage.mjs --out sheet.png --dir shots [--dir2 other] [--tabs a,b,c] [--cols 3] [--cell 640]
//
// With --dir2, each tab is shown as a before/after pair (dir on the left, dir2 on the right).
import { chromium } from 'playwright-core';
import { readdirSync, existsSync, writeFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const arg = (k, d) => { const i = process.argv.indexOf(`--${k}`); return i > 0 ? process.argv[i + 1] : d; };
const dir = resolve(arg('dir', '.'));
const dir2 = arg('dir2', '') ? resolve(arg('dir2')) : null;
const out = resolve(arg('out', 'sheet.png'));
const cols = Number(arg('cols', dir2 ? 1 : 3));
const cell = Number(arg('cell', dir2 ? 720 : 640));
const only = arg('tabs', '') ? arg('tabs').split(',') : null;

const names = readdirSync(dir).filter((f) => f.endsWith('.png') && !f.startsWith('_')).map((f) => f.replace(/\.png$/, ''))
  .filter((n) => !only || only.includes(n)).sort();
const img = (d, n) => (existsSync(join(d, `${n}.png`)) ? `<img src="${pathToFileURL(join(d, `${n}.png`))}">` : '<div class="missing">missing</div>');
const html = `<!doctype html><meta charset="utf-8"><style>
body{margin:0;background:#222;font:12px sans-serif;color:#ddd}
.g{display:grid;grid-template-columns:repeat(${cols},auto);gap:10px;padding:10px;width:max-content}
.c{background:#111;padding:6px}.c b{display:block;margin-bottom:4px}
.pair{display:flex;gap:6px}
img{width:${cell}px;display:block}
.missing{width:${cell}px;height:80px;display:grid;place-items:center;background:#400}
</style><div class="g">${names.map((n) => `<div class="c"><b>${n}</b><div class="pair">${img(dir, n)}${dir2 ? img(dir2, n) : ''}</div></div>`).join('')}</div>`;
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1000, height: 800 } });
const tmp = `${out}.html`;
writeFileSync(tmp, html);
await page.goto(pathToFileURL(tmp).href);
await page.waitForFunction(() => [...document.images].every((i) => i.complete));
await page.screenshot({ path: out, fullPage: true });
await browser.close();
rmSync(tmp, { force: true });
console.log(`${names.length} page(s) -> ${out}`);
