// One-time G1e rewrite (plan Task 5): routes every inline-style read/clear in
// feature modules through src/core/inline-style.js. Refuses forms it does not
// handle. Usage: node tools/g1e-js-codemod.mjs [--write] src/features/*.js
import { readFileSync, writeFileSync } from 'node:fs';
import * as espree from 'espree';

const isStyle = (n) => n && n.type === 'MemberExpression' && !n.computed && n.property.name === 'style';
const isDisplay = (n) => n && n.type === 'MemberExpression' && isStyle(n.object) && !n.computed && n.property.name === 'display';
const lineOf = (src, i) => src.slice(0, i).split('\n').length;

function walk(node, parent, fn) {
  if (!node || typeof node.type !== 'string') return;
  fn(node, parent);
  for (const k of Object.keys(node)) {
    if (k === 'parent') continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach((c) => walk(c, node, fn));
    else if (v && typeof v.type === 'string') walk(v, node, fn);
  }
}

export function rewrite(src, file) {
  const ast = espree.parse(src, { ecmaVersion: 'latest', sourceType: 'module', range: true, loc: true });
  // Each edit replaces the source range [s, e) with make(). make() renders
  // nested edits first, so a read inside a write's right-hand side is rewritten
  // with it (each rewrite is a plain expression substitution).
  const edits = [];
  let sorted = [];
  const sites = [];
  const used = new Set();
  const text = (n) => src.slice(n.range[0], n.range[1]);
  const render = (s, e) => {
    let out = '';
    let at = s;
    for (const ed of sorted) {
      if (ed.s < at || ed.e > e) continue; // inside an edit already applied, or outside the range
      out += src.slice(at, ed.s) + ed.make();
      at = ed.e;
    }
    return out + src.slice(at, e);
  };
  const textOf = (n) => render(n.range[0], n.range[1]);
  const refuse = (n, why) => { throw new Error(`refused ${file}:${lineOf(src, n.range[0])}: ${why}: ${text(n).slice(0, 80)}`); };
  const add = (n, kind, make, helper) => {
    edits.push({ s: n.range[0], e: n.range[1], make });
    sites.push({ file, line: lineOf(src, n.range[0]), kind, before: text(n), make });
    used.add(helper);
  };
  const handled = new Set();
  walk(ast, null, (n) => {
    if (n.type === 'CallExpression' && n.callee.type === 'MemberExpression') {
      const name = n.callee.property.name;
      const arg0 = n.arguments[0];
      const lit = arg0 && arg0.type === 'Literal' ? arg0.value : undefined;
      if (name === 'setAttribute' && (lit === 'style' || lit === 'class')) refuse(n, `setAttribute('${lit}')`);
      if (isStyle(n.callee.object) && (name === 'setProperty' || name === 'removeProperty') && lit === 'display') refuse(n, `style.${name}('display')`);
      if (name === 'removeAttribute' && lit === 'style') add(n, 'style-remove', () => `clearInlineStyle(${textOf(n.callee.object)})`, 'clearInlineStyle');
    }
    if (n.type === 'MemberExpression' && isStyle(n.object) && n.computed && n.property.type === 'Literal' && n.property.value === 'display') refuse(n, "style['display']");
    if (n.type === 'AssignmentExpression') {
      const l = n.left;
      const isClass = l.type === 'MemberExpression' && !l.computed && l.property.name === 'className';
      const isCss = l.type === 'MemberExpression' && isStyle(l.object) && !l.computed && l.property.name === 'cssText';
      if ((isDisplay(l) || isClass || isCss) && n.operator !== '=') refuse(n, `compound assignment ${n.operator}`);
      if (isDisplay(l)) {
        handled.add(l);
        const r = n.right;
        const kind = r.type === 'Literal' ? (r.value === '' ? 'display-reveal' : r.value === 'none' ? 'display-hide' : 'display-set') : 'display-expr';
        add(n, kind, () => `setDisplay(${textOf(l.object.object)}, ${textOf(r)})`, 'setDisplay');
      } else if (isClass) {
        add(n, 'class-write', () => `replaceClasses(${textOf(l.object)}, ${textOf(n.right)})`, 'replaceClasses');
      } else if (isCss) {
        add(n, 'csstext-write', () => `setCssText(${textOf(l.object.object)}, ${textOf(n.right)})`, 'setCssText');
      }
    }
  });
  walk(ast, null, (n) => {
    if (isDisplay(n) && !handled.has(n)) add(n, 'display-read', () => `displayOf(${textOf(n.object.object)})`, 'displayOf');
  });
  if (!edits.length) return { code: src, sites };
  sorted = [...edits].sort((a, b) => a.s - b.s || b.e - a.e); // outer edits before the ones they contain
  const names = [...used].sort();
  for (const h of names) {
    if (new RegExp(`(?:function|const|let|var|import[^;]*\\b)\\s*\\b${h}\\b`).test(src)) throw new Error(`refused ${file}: local name would shadow ${h}`);
  }
  let code = render(0, src.length);
  const imports = [...code.matchAll(/^import [^;]*;\n/gm)];
  const at = imports.length ? imports[imports.length - 1].index + imports[imports.length - 1][0].length : 0;
  code = code.slice(0, at) + `import { ${names.join(', ')} } from '../core/inline-style.js';\n` + code.slice(at);
  for (const site of sites) site.after = site.make();
  for (const site of sites) delete site.make;
  sites.sort((a, b) => a.line - b.line);
  return { code, sites };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('g1e-js-codemod.mjs')) {
  const write = process.argv.includes('--write');
  const all = [];
  for (const f of process.argv.slice(2).filter((a) => !a.startsWith('--'))) {
    const src = readFileSync(f, 'utf8');
    const { code, sites } = rewrite(src, f.replace(/^.*src\//, ''));
    all.push(...sites);
    if (write && code !== src) writeFileSync(f, code);
  }
  process.stdout.write(JSON.stringify(all, null, 1) + '\n');
}
