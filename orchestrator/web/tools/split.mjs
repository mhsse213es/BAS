// G1c generator: frozen monolith -> web/index.html, styles/app.css, src/**.
// Verbatim by construction: only the edits listed in the plan's
// "Generator rules" are applied. Run: node tools/split.mjs [--check]
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join, relative, posix } from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeScript } from './analyze.mjs';

const HANDLER_ATTR = /\son[a-z]+=\\?"(.*?)\\?"/g;
const NOT_APP = new Set(['if', 'function', 'return', 'typeof', 'var', 'event', 'this', 'new', 'encodeURIComponent', 'decodeURIComponent', 'setTimeout', 'clearTimeout', 'parseInt', 'parseFloat', 'String', 'Number', 'JSON', 'Math', 'Date', 'alert', 'confirm', 'prompt', 'window', 'document', 'rgba', 'rgb', 'true', 'false', 'null', 'undefined']);

function handlerScan(text) {
  const calls = new Set(); const bare = new Set();
  for (const m of text.matchAll(HANDLER_ATTR)) {
    const v = m[1];
    for (const c of v.matchAll(/(?<![.\w$'"])([A-Za-z_$][\w$]*)\s*\(/g)) calls.add(c[1]);
    for (const b of v.matchAll(/(?<![.\w$'"])([A-Za-z_$][\w$]*)\b(?!\s*\()/g)) bare.add(b[1]);
  }
  return { calls, bare };
}

function moduleOf(chunk, headers, cfg) {
  for (const n of chunk.names) if (cfg.pin[n]) return cfg.pin[n];
  let section = null;
  for (const h of headers) if (h.line <= chunk.line) section = h.title; else break;
  const hit = section && cfg.sections.find((s) => section.startsWith(s.header));
  if (!section && cfg.preamble) return cfg.preamble;
  return hit ? hit.module : cfg.default;
}

function relImport(from, to) {
  let r = posix.relative(posix.dirname(from), to);
  if (!r.startsWith('.')) r = './' + r;
  return r;
}

export function splitMonolith(html, cfg) {
  const bom = html.startsWith('﻿') ? '﻿' : '';
  const lines = html.slice(bom.length).split('\n');
  const want = { 11: '<style>', 1321: '</style>', 5161: '<script>' };
  for (const [n, t] of Object.entries(want)) if (lines[n - 1].replace(/\r$/, '') !== t) throw new Error(`line ${n} is not ${t}`);
  const scriptEnd = lines.indexOf('</script>', 5161) + 1; // 1-based line of </script>
  if (scriptEnd <= 0) throw new Error('no closing </script>');

  const indexHtml = bom + [...lines.slice(0, 10), '<link rel="stylesheet" href="/assets/%%APP_CSS%%">', ...lines.slice(1321, 5160), '<script src="/assets/%%APP_JS%%"></script>', ...lines.slice(scriptEnd)].join('\n');
  const css = lines.slice(11, 1320).join('\n') + '\n';
  const js = lines.slice(5161, scriptEnd - 1).join('\n') + '\n';
  const LINE0 = 5161; // js line 1 == file line 5162

  const a = analyzeScript(js);
  const fileLine = (l) => l + LINE0;
  const headers = [];
  js.split('\n').forEach((l, i) => { const m = l.match(/^\/\/ ── (.+?)\s*─*\s*$/); if (m) headers.push({ line: i + 1, title: m[1] }); });

  const handlers = handlerScan(html);
  const modOfChunk = a.chunks.map((c) => moduleOf(c, headers, cfg));
  const ownerMod = (name) => modOfChunk[a.topNames.get(name).chunk];

  // ── State variables (rule 6)
  const isVar = (n) => a.topNames.has(n) && a.topNames.get(n).kind === 'var';
  const windowRead = new Set(a.windowMembers.map((w) => w.name));
  const stateGlobals = new Set();
  for (const n of handlers.bare) if (isVar(n)) stateGlobals.add(n);
  for (const n of windowRead) if (isVar(n)) stateGlobals.add(n);
  for (const n of cfg.windowVars) { if (!isVar(n)) throw new Error(`windowVars entry "${n}" is not a top-level variable`); stateGlobals.add(n); }
  const stateVars = new Set(stateGlobals);
  for (const r of a.refs) if (r.write && isVar(r.name) && modOfChunk[r.chunkIndex] !== ownerMod(r.name)) stateVars.add(r.name);
  const implicit = new Set(a.through.filter((r) => r.write).map((r) => r.name));
  for (const n of implicit) stateVars.add(n);
  for (const n of implicit) if (handlers.bare.has(n) || windowRead.has(n)) stateGlobals.add(n);

  // ── Edits per chunk: [start, end, text] in js coordinates
  const edits = a.chunks.map(() => []);
  const stateInit = new Map(); // name -> init text
  const lateInits = new Map(); // chunkIndex -> [stmt text]
  const report = { laterVarReads: [], undeclaredReads: [], thisCount: a.thisCount, stateVars: [], modules: {} };

  const declNode = (name) => a.topNames.get(name).def.node; // VariableDeclarator
  // Applies js-coordinate edits that fall inside [start, end) to that slice.
  const applyIn = (start, end, es) => {
    let t = js.slice(start, end);
    for (const [s, e, r] of es.filter(([s, e]) => s >= start && e <= end).sort((x, y) => y[0] - x[0])) t = t.slice(0, s - start) + r + t.slice(e - start);
    return t;
  };
  // Every reference to a state variable becomes state.NAME, except the
  // declarator identifiers of state variables (those declarators are removed).
  const refEdits = [];
  for (const r of a.refs.concat(a.through)) {
    if (!stateVars.has(r.name)) continue;
    if (a.topNames.has(r.name) && r.start === declNode(r.name).id.range[0]) continue;
    refEdits.push([r.start, r.end, r.inShorthand ? `${r.name}: state.${r.name}` : `state.${r.name}`, r.chunkIndex]);
  }
  const consumed = new Set();
  const take = (start, end) => refEdits.filter((e, i) => { const hit = e[0] >= start && e[1] <= end; if (hit) consumed.add(i); return hit; });

  for (const name of [...stateVars].sort()) {
    if (implicit.has(name)) { stateInit.set(name, 'undefined'); continue; }
    const d = declNode(name);
    if (!d.init) { stateInit.set(name, 'undefined'); continue; }
    const usesApp = a.refs.concat(a.through).some((r) => r.start >= d.init.range[0] && r.end <= d.init.range[1] && (a.topNames.has(r.name) || implicit.has(r.name)));
    if (usesApp && !cfg.lateInit.includes(name)) throw new Error(`state initializer of "${name}" reads app code; add it to modules.json lateInit`);
    const initText = applyIn(d.init.range[0], d.init.range[1], take(d.init.range[0], d.init.range[1]));
    if (usesApp) { stateInit.set(name, 'undefined'); const ci = a.topNames.get(name).chunk; (lateInits.get(ci) || lateInits.set(ci, []).get(ci)).push(`state.${name} = ${initText};`); }
    else stateInit.set(name, initText);
  }
  // Remove state declarators: the whole statement when none remain, otherwise
  // the declarator list is rebuilt from the kept declarators (their own
  // state rewrites applied), so no two edits ever overlap.
  for (const c of a.chunks) {
    if (c.kind !== 'var') continue;
    const decls = c.node.declarations;
    const keep = decls.filter((d) => !stateVars.has(d.id.name));
    if (keep.length === decls.length) continue;
    const ci = a.chunks.indexOf(c);
    for (const d of decls) if (stateVars.has(d.id.name)) take(d.range[0], d.range[1]); // inits already copied to state.js
    if (!keep.length) { take(c.stmtStart, c.stmtEnd); edits[ci].push([c.stmtStart, c.stmtEnd, '']); continue; }
    const listStart = decls[0].range[0], listEnd = decls[decls.length - 1].range[1];
    const text = keep.map((d) => applyIn(d.range[0], d.range[1], take(d.range[0], d.range[1]))).join(', ');
    take(listStart, listEnd);
    edits[ci].push([listStart, listEnd, text]);
  }
  refEdits.forEach((e, i) => { if (!consumed.has(i)) edits[e[3]].push([e[0], e[1], e[2]]); });

  // Cross-module module-level initializers (rule 10).
  for (const [name, info] of a.topNames) {
    if (info.kind !== 'var' || stateVars.has(name)) continue;
    const d = info.def.node; if (!d.init) continue;
    for (const r of a.refs) {
      if (r.start < d.init.range[0] || r.end > d.init.range[1]) continue;
      if (isVar(r.name) && ownerMod(r.name) !== modOfChunk[info.chunk]) throw new Error(`initializer of "${name}" reads "${r.name}" from another module`);
    }
  }
  // Report-only checks.
  for (const r of a.refs) {
    const owner = a.topNames.get(r.name);
    if (a.chunks[r.chunkIndex].kind === 'other' && owner.kind === 'var' && owner.chunk > r.chunkIndex) report.laterVarReads.push({ line: fileLine(a.chunks[r.chunkIndex].line), name: r.name });
  }
  const undeclared = new Set(a.through.filter((r) => !r.write && !implicit.has(r.name)).map((r) => r.name));
  report.undeclaredReads = [...undeclared].sort();

  // ── Exports, imports, inits
  const usedBy = new Map(); // module -> Set(names from other modules)
  const needsState = new Set();
  for (const r of a.refs) {
    const m = modOfChunk[r.chunkIndex];
    if (stateVars.has(r.name)) { needsState.add(m); continue; }
    const owner = ownerMod(r.name);
    if (owner !== m) (usedBy.get(m) || usedBy.set(m, new Set()).get(m)).add(r.name);
  }
  for (const r of a.through) if (stateVars.has(r.name)) needsState.add(modOfChunk[r.chunkIndex]);
  for (const ci of lateInits.keys()) needsState.add(modOfChunk[ci]);

  const isFn = (n) => a.topNames.has(n) && a.topNames.get(n).kind === 'function';
  const handlerFns = new Set([...handlers.calls].filter(isFn));
  // Functions reached by name rather than by a handler call: modules.json
  // windowFns (window[name] lookups) plus any top-level function accessed as
  // window.NAME. Both are listed in DYNAMIC_HANDLERS so the registry check
  // does not report them as stale.
  const dynamicFns = new Set();
  for (const n of cfg.windowFns) { if (!isFn(n)) throw new Error(`windowFns entry "${n}" is not a top-level function`); dynamicFns.add(n); }
  for (const n of windowRead) if (isFn(n)) dynamicFns.add(n);
  for (const n of dynamicFns) handlerFns.add(n);
  const exported = new Set(handlerFns);
  for (const set of usedBy.values()) for (const n of set) exported.add(n);
  for (const name of exported) {
    const ci = a.topNames.get(name).chunk; const c = a.chunks[ci];
    if (!edits[ci].some((e) => e[0] === c.stmtStart && e[2] === 'export ')) edits[ci].push([c.stmtStart, c.stmtStart, 'export ']);
  }
  const windowWrites = new Set(a.windowMembers.filter((w) => w.write && !a.topNames.has(w.name)).map((w) => w.name));

  // ── Emit modules
  const files = new Map();
  const bodies = new Map(); const inits = [];
  a.chunks.forEach((c, ci) => {
    let text = js.slice(c.start, c.end);
    const es = edits[ci].map(([s, e, t]) => [s - c.start, e - c.start, t]).sort((x, y) => y[0] - x[0] || y[1] - x[1]);
    for (const [s, e, t] of es) text = text.slice(0, s) + t + text.slice(e);
    const m = modOfChunk[ci];
    if (c.kind === 'other') {
      // Leading comments/whitespace stay outside; only the statement is wrapped.
      const cut = c.stmtStart - c.start;
      const prefix = text.slice(0, cut), stmt = text.slice(cut);
      const fn = `__init_L${fileLine(c.line)}`;
      text = `${prefix}export function ${fn}() {\n${stmt}${stmt.endsWith('\n') ? '' : '\n'}}\n`;
      inits.push({ m, fn });
    }
    if (lateInits.has(ci)) {
      const fn = `__init_L${fileLine(c.line)}_state`;
      text += `export function ${fn}() {\n  ${lateInits.get(ci).join('\n  ')}\n}\n`;
      inits.push({ m, fn });
    }
    bodies.set(m, (bodies.get(m) || '') + text);
  });
  const modules = [...new Set(modOfChunk)].sort();
  for (const m of modules) {
    const p = `src/${m}`;
    const imp = [];
    if (needsState.has(m)) imp.push(`import { state } from '${relImport(p, 'src/core/state.js')}';`);
    const byOwner = new Map();
    for (const n of [...(usedBy.get(m) || [])].sort()) { const o = ownerMod(n); (byOwner.get(o) || byOwner.set(o, []).get(o)).push(n); }
    for (const o of [...byOwner.keys()].sort()) imp.push(`import { ${byOwner.get(o).join(', ')} } from '${relImport(p, `src/${o}`)}';`);
    files.set(p, `// GENERATED by web/tools/split.mjs from tools/monolith.html -- do not edit during G1c.\n${imp.join('\n')}${imp.length ? '\n' : ''}${bodies.get(m)}`);
    report.modules[m] = { imports: imp.length, inits: inits.filter((i) => i.m === m).length };
  }
  files.set('src/core/state.js', `// GENERATED by web/tools/split.mjs -- shared mutable state (G1c spec section 5).\nexport const state = {\n${[...stateInit.keys()].sort().map((n) => `  ${n}: ${stateInit.get(n)},`).join('\n')}\n};\n`);

  const g = [];
  const gByOwner = new Map();
  for (const n of [...handlerFns].sort()) { const o = ownerMod(n); (gByOwner.get(o) || gByOwner.set(o, []).get(o)).push(n); }
  g.push('// GENERATED by web/tools/split.mjs -- the only code that defines app names on window (G1c spec section 6).');
  g.push(`import { state } from './core/state.js';`);
  for (const o of [...gByOwner.keys()].sort()) g.push(`import { ${gByOwner.get(o).join(', ')} } from '${relImport('src/globals.js', `src/${o}`)}';`);
  g.push('', '// Called from inline on*= handlers.', `export const HANDLER_FUNCTIONS = {\n${[...handlerFns].sort().map((n) => `  ${n},`).join('\n')}\n};`);
  g.push('', '// Named only via strings (window[name]) -- see web/tools/modules.json windowFns.', `export const DYNAMIC_HANDLERS = [\n${[...dynamicFns].sort().map((n) => `  '${n}',`).join('\n')}\n];`);
  g.push('', '// Variables read or written by handlers or via window.NAME; backed by state.', `export const STATE_GLOBALS = [\n${[...stateGlobals].sort().map((n) => `  '${n}',`).join('\n')}\n];`);
  g.push('', '// Assigned as window.NAME = ... in app code (left verbatim).', `export const WINDOW_WRITES = [\n${[...windowWrites].sort().map((n) => `  '${n}',`).join('\n')}\n];`);
  g.push('', 'export function installGlobals() {', '  Object.assign(window, HANDLER_FUNCTIONS);', '  for (const name of STATE_GLOBALS) {', '    Object.defineProperty(window, name, {', '      get() { return state[name]; },', '      set(v) { state[name] = v; },', '      configurable: true,', '      enumerable: true,', '    });', '  }', '}', '');
  files.set('src/globals.js', g.join('\n'));

  const mainImports = new Map();
  for (const { m, fn } of inits) (mainImports.get(m) || mainImports.set(m, []).get(m)).push(fn);
  const main = ['// GENERATED by web/tools/split.mjs -- entry point: install globals, then run load-time code in original order.', `import { installGlobals } from './globals.js';`];
  for (const m of modules) main.push(mainImports.has(m) ? `import { ${[...mainImports.get(m)].sort().join(', ')} } from './${m}';` : `import './${m}';`);
  main.push('', 'installGlobals();', ...inits.map((i) => `${i.fn}();`), '');
  files.set('src/main.js', main.join('\n'));
  files.set('index.html', indexHtml);
  files.set('styles/app.css', css);
  report.stateVars = [...stateVars].sort();
  return { files, report };
}

// ── CLI
const here = dirname(fileURLToPath(import.meta.url));
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const web = join(here, '..');
  const cfg = JSON.parse(readFileSync(join(here, 'modules.json'), 'utf8'));
  const { files, report } = splitMonolith(readFileSync(join(here, 'monolith.html'), 'utf8'), cfg);
  if (process.argv.includes('--check')) {
    const drift = [...files].filter(([p, t]) => !existsSync(join(web, p)) || readFileSync(join(web, p), 'utf8') !== t).map(([p]) => p);
    if (drift.length) { console.error('generated files differ from committed:\n  ' + drift.join('\n  ')); process.exit(1); }
    console.log(`split:check OK (${files.size} files)`);
  } else {
    for (const [p, t] of files) { mkdirSync(dirname(join(web, p)), { recursive: true }); writeFileSync(join(web, p), t); }
    writeFileSync(join(here, 'split-report.json'), JSON.stringify(report, null, 2) + '\n');
    console.log(`wrote ${files.size} files; report: tools/split-report.json`);
  }
}
