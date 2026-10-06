// Test helpers: a jsdom window with the real dashboard markup, and a lookup
// that finds an exported function in whichever module currently owns it, so
// tests do not change as Task 10 moves code between modules.
import { JSDOM } from 'jsdom';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const web = fileURLToPath(new URL('../..', import.meta.url));

export function setupDom() {
  const html = readFileSync(join(web, 'index.html'), 'utf8').replace(/<script src="[^"]*"><\/script>/, '');
  const dom = new JSDOM(html, { url: 'http://127.0.0.1/', pretendToBeVisual: true });
  // defineProperty, not assignment: Node 24 ships getter-only globals
  // (navigator, localStorage) that a plain assignment cannot replace.
  for (const k of ['window', 'document', 'localStorage', 'navigator', 'HTMLElement', 'Node', 'Event', 'CustomEvent']) {
    Object.defineProperty(globalThis, k, { value: dom.window[k], configurable: true, writable: true });
  }
  return dom;
}

export async function load(names) {
  const files = [];
  (function walk(d) { for (const e of readdirSync(d)) { const p = join(d, e); if (statSync(p).isDirectory()) walk(p); else if (p.endsWith('.js')) files.push(p); } })(join(web, 'src'));
  const found = {};
  for (const f of files.sort()) {
    if (f.endsWith('main.js')) continue; // main.js runs load-time code
    const mod = await import(pathToFileURL(f).href);
    for (const n of names) if (typeof mod[n] === 'function' && !found[n]) found[n] = mod[n];
  }
  for (const n of names) if (!found[n]) throw new Error(`no module exports ${n}`);
  return found;
}

export const PAYLOADS = [
  '<img src=x onerror="globalThis.__xss=1">',
  '"><svg onload="globalThis.__xss=1">',
  "'><script>globalThis.__xss=1</script>",
  '</textarea><script>globalThis.__xss=1</script>',
];
