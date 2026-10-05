// Scope analysis of the monolith's classic script using ESLint's own parser
// and scope manager (no extra dependency). Pure: text in, data out.
import { Linter } from 'eslint';

export function analyzeScript(js) {
  const out = { chunks: [], topNames: new Map(), refs: [], through: [], windowMembers: [], thisCount: 0 };
  let program = null;
  let scopeManager = null;
  const collector = {
    create(context) {
      return {
        Program(node) { program = node; scopeManager = context.sourceCode.scopeManager; },
        ThisExpression() { out.thisCount++; },
        MemberExpression(node) {
          if (node.object.type !== 'Identifier' || node.object.name !== 'window') return;
          let name = null;
          if (!node.computed && node.property.type === 'Identifier') name = node.property.name;
          else if (node.computed && node.property.type === 'Literal' && typeof node.property.value === 'string') name = node.property.value;
          if (!name) return;
          const p = node.parent;
          const write = p && p.type === 'AssignmentExpression' && p.left === node;
          out.windowMembers.push({ name, start: node.range[0], end: node.range[1], write });
        },
      };
    },
  };
  const linter = new Linter({ configType: 'flat' });
  const messages = linter.verify(js, [{
    languageOptions: { ecmaVersion: 'latest', sourceType: 'script' },
    plugins: { g1c: { rules: { collect: collector } } },
    rules: { 'g1c/collect': 'error' },
  }], { filename: 'monolith.js' });
  const fatal = messages.find((m) => m.fatal);
  if (fatal) throw new Error(`parse error at ${fatal.line}:${fatal.column}: ${fatal.message}`);

  // Lossless partition: each chunk runs from the previous statement's end to
  // its own end; trailing text after the last statement joins the last chunk.
  let cursor = 0;
  program.body.forEach((node, i) => {
    const isLast = i === program.body.length - 1;
    const end = isLast ? js.length : node.range[1];
    let kind = 'other';
    if (node.type === 'FunctionDeclaration') kind = 'function';
    else if (node.type === 'ClassDeclaration') kind = 'class';
    else if (node.type === 'VariableDeclaration') kind = 'var';
    out.chunks.push({ start: cursor, end, stmtStart: node.range[0], stmtEnd: node.range[1], line: node.loc.start.line, kind, names: [], node });
    cursor = end;
  });
  if (out.chunks.map((c) => js.slice(c.start, c.end)).join('') !== js) throw new Error('lossless partition failed');

  const chunkAt = (pos) => {
    let lo = 0, hi = out.chunks.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (out.chunks[mid].start <= pos) lo = mid; else hi = mid - 1; }
    return lo;
  };
  const isShorthand = (id) => id.parent && id.parent.type === 'Property' && id.parent.shorthand && id.parent.value === id;

  const global = scopeManager.globalScope;
  for (const v of global.variables) {
    if (!v.defs.length) continue;
    const def = v.defs[0];
    const chunkIndex = chunkAt(def.name.range[0]);
    const kind = out.chunks[chunkIndex].kind;
    if (out.topNames.has(v.name)) throw new Error(`duplicate top-level name "${v.name}"`);
    out.topNames.set(v.name, { chunk: chunkIndex, kind, declKind: def.parent && def.parent.kind, def });
    out.chunks[chunkIndex].names.push(v.name);
    for (const r of v.references) {
      const id = r.identifier;
      if (id === def.name && !r.init) continue;
      out.refs.push({ name: v.name, start: id.range[0], end: id.range[1], write: r.isWrite() && !r.init, init: !!r.init, chunkIndex: chunkAt(id.range[0]), inShorthand: isShorthand(id) });
    }
  }
  for (const r of global.through) {
    const id = r.identifier;
    out.through.push({ name: id.name, start: id.range[0], end: id.range[1], write: r.isWrite(), chunkIndex: chunkAt(id.range[0]), inShorthand: isShorthand(id) });
  }
  return out;
}
