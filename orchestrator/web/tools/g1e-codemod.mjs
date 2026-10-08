#!/usr/bin/env node
// G1e style codemod: converts inline `style="..."` attributes (markup and JS
// template strings) into generated utility classes, per
// docs/superpowers/specs/2026-10-06-g1e-strict-style-csp-design.md §4.1.
//
// Exports: classFor, splitDecls, planStyle, parseCss, writeCss, convertMarkup,
// convertJs, splitDynamic, parseCssVarRules, writeCssVarRules. CLI: --markup <file>, --js <file>..., --split
// '<text>' --types t1,t2, --class '<text>', --check-determinism <dir>.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import * as espree from 'espree';
import { JSDOM } from 'jsdom';

// ---------------------------------------------------------------------------
// Shared primitives

function hash8(text) {
  return createHash('sha256').update(text).digest('hex').slice(0, 8);
}

export function classFor(text) {
  return `g1-s-${hash8(text)}`;
}

// Splits `text` on `;` that is not inside a quoted string or parentheses.
function splitTopLevel(text, sep) {
  const segs = [];
  let start = 0;
  let depth = 0;
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '(') { depth++; continue; }
    if (c === ')') { depth = Math.max(0, depth - 1); continue; }
    if (c === sep && depth === 0) { segs.push(text.slice(start, i)); start = i + 1; }
  }
  segs.push(text.slice(start));
  return segs;
}

export function splitDecls(text) {
  return splitTopLevel(text, ';')
    .map((seg) => {
      const raw = seg.trim();
      const ci = raw.indexOf(':');
      const prop = (ci === -1 ? raw : raw.slice(0, ci)).trim().toLowerCase();
      return { prop, raw };
    })
    .filter((d) => d.raw !== '');
}

// Rule 1 (markup side): decode &quot; &amp; &#39; &lt; &gt;; refuse any other &.
function decodeEntities(s) {
  if (/&(?!quot;|amp;|#39;|lt;|gt;)/.test(s)) throw new Error('refused: unsupported HTML entity in style text');
  return s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

// Rule 1 (JS side): unescape \' \" \\; refuse any other backslash.
function unescapeJsRaw(text) {
  let out = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '\\') {
      const n = text[i + 1];
      if (n === '\'' || n === '"' || n === '\\') { out += n; i++; }
      else throw new Error('refused: unsupported backslash escape in style text');
    } else {
      out += c;
    }
  }
  return out;
}

// Re-escapes plain text for embedding back into a JS string of the given
// quote form. Our generated class text never itself needs escaping unless
// the form is the backslash-escaped kind.
function escapeJsValue(text, escaped, quote) {
  if (!escaped) return text;
  return text.replace(/\\/g, '\\\\').replace(new RegExp(quote, 'g'), '\\' + quote);
}

// ---------------------------------------------------------------------------
// planStyle (rules 1-3)

export function planStyle(text) {
  if (/!important/.test(text) || /[{}<]/.test(text) || /\/\*/.test(text)) {
    throw new Error('refused: unsafe characters in style text');
  }

  const parsed = splitTopLevel(text, ';')
    .map((seg) => {
      const t = seg.trim();
      const ci = t.indexOf(':');
      const prop = (ci === -1 ? t : t.slice(0, ci)).trim().toLowerCase();
      const value = ci === -1 ? '' : t.slice(ci + 1).trim();
      return { seg, prop, value };
    })
    .filter((d) => d.seg.trim() !== '');

  const displays = parsed.filter((d) => d.prop === 'display');
  if (displays.length > 1) throw new Error('refused: multiple display declarations');

  const classes = [];
  const rules = new Map();

  if (displays.length === 1) {
    const v = displays[0].value;
    if (v === 'none') {
      classes.push('is-hidden');
      rules.set('is-hidden', '.is-hidden { display: none; }');
    } else if (/^[a-z-]+$/.test(v)) {
      const c = `g1-display-${v}`;
      classes.push(c);
      rules.set(c, `.${c} { display: ${v}; }`);
    } else {
      throw new Error('refused: unsupported display value');
    }
  }

  const remaining = parsed.filter((d) => d.prop !== 'display');
  if (remaining.length) {
    const remainingText = remaining.map((d) => d.seg).join(';').trim();
    const c = classFor(remainingText);
    classes.push(c);
    rules.set(c, `.${c} { ${remainingText} }`);
  }

  return { classes, rules };
}

// ---------------------------------------------------------------------------
// CSS registry read/write (rule 8)

export function parseCss(css) {
  const lines = css.split('\n');
  let charPos = 0;
  let headerEnd = css.length;
  for (const line of lines) {
    if (/^\.([\w-]+)(?:\.[\w-]+)*\s*\{/.test(line)) { headerEnd = charPos; break; }
    charPos += line.length + 1;
  }
  const header = css.slice(0, headerEnd);
  const rules = new Map();
  const body = css.slice(headerEnd).split('\n');
  const braceDelta = (s) => (s.match(/\{/g) || []).length - (s.match(/\}/g) || []).length;
  for (let i = 0; i < body.length; i++) {
    const line = body[i];
    const m = /^\.([\w-]+)(?:\.[\w-]+)*\s*\{/.exec(line);
    if (!m) continue;
    let text = line;
    let depth = braceDelta(line);
    while (depth > 0 && i + 1 < body.length) {
      i++;
      text += '\n' + body[i];
      depth += braceDelta(body[i]);
    }
    rules.set(m[1], text);
  }
  return { header, rules };
}

export function writeCss(header, rules) {
  let out = header;
  for (const k of [...rules.keys()].sort()) out += rules.get(k) + '\n';
  return out;
}

// ---------------------------------------------------------------------------
// convertMarkup (rules 1-4, static HTML)

const TAG_RE = /<([a-zA-Z][\w:-]*)((?:\s+[^\s=>\/]+(?:=(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?)>/g;
const ATTR_RE = /\s+([^\s=>\/]+)(?:=("[^"]*"|'[^']*'|[^\s>]+))?/g;

function parseAttrTokens(attrs) {
  const re = new RegExp(ATTR_RE.source, 'g');
  const tokens = [];
  let m;
  while ((m = re.exec(attrs))) tokens.push({ name: m[1], raw: m[2], fullText: m[0] });
  return tokens;
}

function rewriteTagAttrs(attrs) {
  const tokens = parseAttrTokens(attrs);
  const styleTok = tokens.find((t) => t.name.toLowerCase() === 'style');
  if (!styleTok || !styleTok.raw) return { attrs, rules: new Map() };

  const quote = styleTok.raw[0];
  const valueText = quote === '"' || quote === "'" ? styleTok.raw.slice(1, -1) : styleTok.raw;
  const decoded = decodeEntities(valueText);
  const { classes, rules } = planStyle(decoded);
  const newClasses = classes.join(' ');

  const classTok = tokens.find((t) => t.name.toLowerCase() === 'class');
  let newAttrs;
  if (classTok && classTok.raw) {
    const cq = classTok.raw[0];
    const cVal = cq === '"' || cq === "'" ? classTok.raw.slice(1, -1) : classTok.raw;
    const leadingWs = classTok.fullText.match(/^\s+/)[0];
    const newClassFullText = `${leadingWs}class=${cq}${cVal} ${newClasses}${cq}`;
    newAttrs = tokens
      .filter((t) => t !== styleTok)
      .map((t) => (t === classTok ? newClassFullText : t.fullText))
      .join('');
  } else {
    const leadingWs = styleTok.fullText.match(/^\s+/)[0];
    const newStyleFullText = `${leadingWs}class=${quote}${newClasses}${quote}`;
    newAttrs = tokens.map((t) => (t === styleTok ? newStyleFullText : t.fullText)).join('');
  }
  return { attrs: newAttrs, rules };
}

function walkCompare(a, b) {
  if (a.children.length !== b.children.length) throw new Error('refused: converted markup changes child count');
  for (let i = 0; i < a.children.length; i++) {
    const ea = a.children[i];
    const eb = b.children[i];
    if (ea.tagName !== eb.tagName) throw new Error('refused: converted markup changes a tag name');
    const attrsA = [...ea.attributes].filter((x) => x.name !== 'style' && x.name !== 'class');
    const attrsB = [...eb.attributes].filter((x) => x.name !== 'style' && x.name !== 'class');
    if (attrsA.length !== attrsB.length) throw new Error('refused: converted markup changes non-style/class attributes');
    for (const at of attrsA) {
      if (eb.getAttribute(at.name) !== at.value) throw new Error('refused: converted markup changes an attribute value');
    }
    const inClasses = (ea.getAttribute('class') || '').split(/\s+/).filter(Boolean);
    const outClasses = (eb.getAttribute('class') || '').split(/\s+/).filter(Boolean);
    for (const c of inClasses) {
      if (!outClasses.includes(c)) throw new Error('refused: converted markup loses an existing class token');
    }
    walkCompare(ea, eb);
  }
}

function verifyMarkupEquivalence(inputHtml, outputHtml) {
  const a = new JSDOM(`<!doctype html><body>${inputHtml}</body>`).window.document.body;
  const b = new JSDOM(`<!doctype html><body>${outputHtml}</body>`).window.document.body;
  walkCompare(a, b);
}

export function convertMarkup(html) {
  const re = new RegExp(TAG_RE.source, 'g');
  const edits = [];
  const allRules = new Map();
  let m;
  while ((m = re.exec(html))) {
    const [full, tagName, attrs, selfClose] = m;
    const { attrs: newAttrs, rules } = rewriteTagAttrs(attrs);
    if (newAttrs !== attrs) {
      for (const [k, v] of rules) allRules.set(k, v);
      edits.push({ start: m.index, end: m.index + full.length, text: `<${tagName}${newAttrs}${selfClose}>` });
    }
  }
  let out = html;
  for (let i = edits.length - 1; i >= 0; i--) {
    const e = edits[i];
    out = out.slice(0, e.start) + e.text + out.slice(e.end);
  }
  verifyMarkupEquivalence(html, out);
  return { html: out, rules: allRules };
}

// ---------------------------------------------------------------------------
// convertJs (rules 1, 4, 5 -- JS string/template literals)

const STYLE_ATTR_RE = /(?<![\w.-])style=(\\?)(["'])/g;
const CLASS_ATTR_RE = /(?<![\w.-])class=(\\?)(["'])/g;

function processPiece(piece) {
  const reports = [];
  const edits = [];
  const allRules = new Map();
  const styleRe = new RegExp(STYLE_ATTR_RE.source, 'g');
  let sm;
  while ((sm = styleRe.exec(piece))) {
    const escaped = sm[1] === '\\';
    const quote = sm[2];
    const valueStart = sm.index + sm[0].length;
    const closeSeq = escaped ? '\\' + quote : quote;
    const valueEnd = piece.indexOf(closeSeq, valueStart);
    if (valueEnd === -1) {
      reports.push({ at: sm.index, why: 'style value is not complete within this string piece (dynamic/concatenated)' });
      continue;
    }
    const styleSpanEnd = valueEnd + closeSeq.length;

    let tagStart = -1;
    for (let i = sm.index - 1; i >= 0; i--) {
      if (piece[i] === '>') break;
      if (piece[i] === '<') { tagStart = i; break; }
    }
    if (tagStart === -1) {
      reports.push({ at: sm.index, why: "this tag's start lies in another string piece" });
      continue;
    }

    let tagEnd = -1;
    for (let i = styleSpanEnd; i < piece.length; i++) {
      if (piece[i] === '<') break;
      if (piece[i] === '>') { tagEnd = i; break; }
    }
    if (tagEnd === -1) {
      reports.push({ at: sm.index, why: "this tag's end lies in another string piece" });
      continue;
    }

    const tagSpan = piece.slice(tagStart, tagEnd + 1);
    const classRe = new RegExp(CLASS_ATTR_RE.source, 'g');
    const classMatches = [];
    let cm;
    while ((cm = classRe.exec(tagSpan))) classMatches.push(cm);
    if (classMatches.length > 1) {
      reports.push({ at: sm.index, why: 'tag has more than one class attribute' });
      continue;
    }

    let rawValue;
    let planned;
    try {
      rawValue = unescapeJsRaw(piece.slice(valueStart, valueEnd));
      planned = planStyle(rawValue);
    } catch (e) {
      reports.push({ at: sm.index, why: e.message });
      continue;
    }
    const newClasses = planned.classes.join(' ');
    for (const [k, v] of planned.rules) allRules.set(k, v);

    if (classMatches.length === 1) {
      const cm0 = classMatches[0];
      const cEscaped = cm0[1] === '\\';
      const cQuote = cm0[2];
      const cValueStartRel = cm0.index + cm0[0].length;
      const cCloseSeq = cEscaped ? '\\' + cQuote : cQuote;
      const cValueEndRel = tagSpan.indexOf(cCloseSeq, cValueStartRel);
      if (cValueEndRel === -1) {
        reports.push({ at: sm.index, why: 'class value is not complete within this string piece' });
        continue;
      }
      let existingClassRaw;
      try {
        existingClassRaw = unescapeJsRaw(tagSpan.slice(cValueStartRel, cValueEndRel));
      } catch (e) {
        reports.push({ at: sm.index, why: e.message });
        continue;
      }
      const mergedEscaped = escapeJsValue(`${existingClassRaw} ${newClasses}`, cEscaped, cQuote);
      let removeStart = sm.index;
      while (removeStart > 0 && /\s/.test(piece[removeStart - 1])) removeStart--;
      edits.push({ start: removeStart, end: styleSpanEnd, text: '' });
      edits.push({ start: tagStart + cValueStartRel, end: tagStart + cValueEndRel, text: mergedEscaped });
    } else {
      const newClassEscaped = escapeJsValue(newClasses, escaped, quote);
      const bs = escaped ? '\\' : '';
      const replacement = `class=${bs}${quote}${newClassEscaped}${bs}${quote}`;
      edits.push({ start: sm.index, end: styleSpanEnd, text: replacement });
    }
  }

  if (!edits.length) return { text: piece, rules: allRules, reports };
  edits.sort((a, b) => b.start - a.start);
  let out = piece;
  for (const e of edits) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return { text: out, rules: allRules, reports };
}

export function convertJs(src, file) {
  const tokens = espree.tokenize(src, { ecmaVersion: 'latest', sourceType: 'module', range: true });
  const edits = [];
  const allRules = new Map();
  const reports = [];
  for (const tok of tokens) {
    if (tok.type !== 'String' && tok.type !== 'Template') continue;
    const piece = src.slice(tok.range[0], tok.range[1]);
    const { text, rules, reports: pieceReports } = processPiece(piece);
    for (const [k, v] of rules) allRules.set(k, v);
    for (const r of pieceReports) {
      const abs = tok.range[0] + r.at;
      const line = src.slice(0, abs).split('\n').length;
      const snippetStart = Math.max(0, r.at - 10);
      reports.push({ file, line, text: piece.slice(snippetStart, r.at + 30), why: r.why });
    }
    if (text !== piece) edits.push({ start: tok.range[0], end: tok.range[1], text });
  }
  edits.sort((a, b) => b.start - a.start);
  let out = src;
  for (const e of edits) out = out.slice(0, e.start) + e.text + out.slice(e.end);
  return { code: out, rules: allRules, reports };
}

// ---------------------------------------------------------------------------
// splitDynamic (rule 6)

function propsOverlap(a, b) {
  if (a === b) return true;
  if (a.startsWith(b + '-') || b.startsWith(a + '-')) return true;
  const sets = [
    ['inset', 'top', 'right', 'bottom', 'left'],
    ['gap', 'row-gap', 'column-gap'],
  ];
  for (const s of sets) if (s.includes(a) && s.includes(b)) return true;
  const isPlace = (p) => p.startsWith('place-');
  const isAlignJustify = (p) => p.startsWith('align-') || p.startsWith('justify-');
  return (isPlace(a) && isAlignJustify(b)) || (isPlace(b) && isAlignJustify(a));
}

export function splitDynamic(template, types) {
  const segs = splitTopLevel(template, ';').map((s) => s.trim()).filter((s) => s !== '');
  const decls = segs.map((raw) => {
    const ci = raw.indexOf(':');
    const prop = (ci === -1 ? raw : raw.slice(0, ci)).trim().toLowerCase();
    const value = ci === -1 ? '' : raw.slice(ci + 1).trim();
    const placeholderIdx = [...value.matchAll(/\{(\d+)\}/g)].map((m) => Number(m[1]));
    return { raw, prop, value, placeholderIdx, dynamic: placeholderIdx.length > 0 };
  });

  for (const d of decls) {
    if (d.prop === 'display' && d.dynamic) throw new Error('refused: display cannot be a dynamic declaration');
  }
  for (let i = 0; i < decls.length; i++) {
    if (!decls[i].dynamic) continue;
    for (let j = i + 1; j < decls.length; j++) {
      if (propsOverlap(decls[i].prop, decls[j].prop)) {
        throw new Error('refused: a later declaration overlaps a dynamic declaration\'s property');
      }
    }
  }

  const dynamic = [];
  const ruleLines = new Map();
  const literalRaws = [];
  for (const d of decls) {
    if (!d.dynamic) { literalRaws.push(d.raw); continue; }
    const uniqueOrdered = [...new Set(d.placeholderIdx)].sort((a, b) => a - b);
    const renumberMap = new Map(uniqueOrdered.map((orig, local) => [orig, local]));
    const renumberedValue = d.value.replace(/\{(\d+)\}/g, (_, n) => `{${renumberMap.get(Number(n))}}`);
    const rule = `g1-v-${hash8(`${d.prop}:${d.value}`)}`;
    const localTypes = uniqueOrdered.map((i) => types[i]);
    dynamic.push({ rule, prop: d.prop, value: renumberedValue, types: localTypes });
    ruleLines.set(rule, `.${rule}.${rule} { ${d.prop}: var(--${rule}); }`);
  }

  let staticClass = '';
  if (literalRaws.length) {
    const planned = planStyle(literalRaws.join(';'));
    staticClass = planned.classes.join(' ');
    for (const [k, v] of planned.rules) ruleLines.set(k, v);
  }

  return { dynamic, ruleLines, staticClass };
}

// ---------------------------------------------------------------------------
// CSS_VAR_RULES (src/core/css-var-rules.js) read/merge/write, Task 2 format

export function parseCssVarRules(src) {
  const open = /CSS_VAR_RULES\s*=\s*\{/.exec(src);
  if (!open) throw new Error('refused: CSS_VAR_RULES declaration not found');
  const start = open.index + open[0].length - 1;
  const end = src.lastIndexOf('}');
  const header = src.slice(0, start + 1);
  const footer = src.slice(end);
  const body = src.slice(start + 1, end);
  const entries = new Map();
  for (const line of body.split('\n')) {
    const m = /^\s*'([^']+)':\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2].trim();
    if (value.endsWith(',')) value = value.slice(0, -1);
    entries.set(m[1], value);
  }
  return { header, footer, entries };
}

export function writeCssVarRules(header, footer, entries) {
  const lines = [...entries.keys()].sort().map((k) => `  '${k}': ${entries.get(k)},`);
  return `${header}\n${lines.join('\n')}\n${footer}`;
}

function mergeCssVarEntries(filePath, dynamicDecls) {
  if (!dynamicDecls.length) return;
  const src = readFileSync(filePath, 'utf8');
  const { header, footer, entries } = parseCssVarRules(src);
  for (const d of dynamicDecls) {
    const value = JSON.stringify({ prop: d.prop, value: d.value, types: d.types });
    const existing = entries.get(d.rule);
    if (existing && existing !== value) throw new Error(`refused: css-var rule collision for ${d.rule}`);
    entries.set(d.rule, value);
  }
  writeFileSync(filePath, writeCssVarRules(header, footer, entries));
}

function mergeCssRules(filePath, newRules) {
  if (!newRules.size) return;
  const css = readFileSync(filePath, 'utf8');
  const { header, rules } = parseCss(css);
  for (const [k, v] of newRules) {
    const existing = rules.get(k);
    if (existing && existing !== v) throw new Error(`refused: css rule collision for ${k}`);
    rules.set(k, v);
  }
  writeFileSync(filePath, writeCss(header, rules));
}

// ---------------------------------------------------------------------------
// CLI

async function main() {
  const args = process.argv.slice(2);
  const webDir = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
  const cssPath = `${webDir}/styles/inline-equivalent.css`;
  const varsPath = `${webDir}/src/core/css-var-rules.js`;
  const dry = args.includes('--dry');

  const idx = (flag) => args.indexOf(flag);

  if (idx('--markup') !== -1) {
    const file = args[idx('--markup') + 1];
    const html = readFileSync(file, 'utf8');
    const { html: out, rules } = convertMarkup(html);
    console.log(`markup: ${rules.size} rules generated`);
    if (!dry) {
      writeFileSync(file, out);
      mergeCssRules(cssPath, rules);
    }
    return;
  }

  if (idx('--js') !== -1) {
    const files = args.slice(idx('--js') + 1).filter((a) => !a.startsWith('--'));
    let totalRules = 0;
    let totalReports = 0;
    const allRules = new Map();
    for (const file of files) {
      const src = readFileSync(file, 'utf8');
      const { code, rules, reports } = convertJs(src, file);
      for (const [k, v] of rules) allRules.set(k, v);
      totalRules += rules.size;
      totalReports += reports.length;
      for (const r of reports) console.log(`${r.file}:${r.line}: ${r.why}`);
      if (!dry) writeFileSync(file, code);
    }
    console.log(`js: ${totalRules} rules generated, ${totalReports} reports`);
    if (!dry) mergeCssRules(cssPath, allRules);
    return;
  }

  if (idx('--split') !== -1) {
    const template = args[idx('--split') + 1];
    const typesIdx = idx('--types');
    const types = typesIdx !== -1 ? args[typesIdx + 1].split(',') : [];
    const { dynamic, ruleLines, staticClass } = splitDynamic(template, types);
    console.log(JSON.stringify({ dynamic, staticClass }, null, 2));
    if (!dry) {
      mergeCssRules(cssPath, ruleLines);
      mergeCssVarEntries(varsPath, dynamic);
    }
    return;
  }

  if (idx('--class') !== -1) {
    const text = args[idx('--class') + 1];
    const { classes, rules } = planStyle(text);
    console.log(classes.join(' '));
    if (!dry) mergeCssRules(cssPath, rules);
    return;
  }

  if (idx('--check-determinism') !== -1) {
    const dir = args[idx('--check-determinism') + 1];
    const { rules } = parseCss(readFileSync(cssPath, 'utf8'));
    const produced = new Map();
    if (existsSync(`${dir}/index.html`)) {
      const { rules: r } = convertMarkup(readFileSync(`${dir}/index.html`, 'utf8'));
      for (const [k, v] of r) produced.set(k, v);
    }
    let mismatches = 0;
    for (const [k, v] of produced) {
      if (rules.get(k) !== v) { console.log(`MISMATCH: ${k}`); mismatches++; }
    }
    const handConverted = [...rules.keys()].filter((k) => !produced.has(k)).length;
    console.log(`hand-converted (not produced by this run): ${handConverted}`);
    process.exit(mismatches ? 1 : 0);
  }

  console.error('usage: g1e-codemod.mjs --markup <file> | --js <file>... | --split <text> --types <t1,t2> | --class <text> | --check-determinism <dir> [--dry]');
  process.exit(1);
}

if (import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}` || process.argv[1]?.endsWith('g1e-codemod.mjs')) {
  main();
}
