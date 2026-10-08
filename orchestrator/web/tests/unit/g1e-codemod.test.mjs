import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { JSDOM } from 'jsdom';
import { classFor, splitDecls, planStyle, parseCss, writeCss, convertMarkup, convertJs, splitDynamic, parseCssVarRules, writeCssVarRules } from '../../tools/g1e-codemod.mjs';

const h8 = (t) => createHash('sha256').update(t).digest('hex').slice(0, 8);

test('class name is the sha256 prefix of the exact text', () => {
  assert.equal(classFor('color:red;font-size:11px'), `g1-s-${h8('color:red;font-size:11px')}`);
  assert.notEqual(classFor('color:red'), classFor('color: red'));
});

test('declarations are preserved byte for byte', () => {
  const { classes, rules } = planStyle('  margin:0 auto; font-family:"Inter", sans-serif ;color:#fff ');
  const c = classes.find((x) => x.startsWith('g1-s-'));
  assert.equal(rules.get(c), `.${c} { margin:0 auto; font-family:"Inter", sans-serif ;color:#fff }`);
});

test('display:none becomes is-hidden and other display values their own class', () => {
  assert.deepEqual(planStyle('display:none').classes, ['is-hidden']);
  const p = planStyle('color:red;display: inline-flex;gap:4px');
  assert.ok(p.classes.includes('g1-display-inline-flex'));
  const s = p.classes.find((x) => x.startsWith('g1-s-'));
  assert.equal(p.rules.get(s), `.${s} { color:red;gap:4px }`);
  assert.equal(p.rules.get('g1-display-inline-flex'), '.g1-display-inline-flex { display: inline-flex; }');
});

test('unsafe or ambiguous text is refused', () => {
  for (const t of ['display:none;display:block', 'color:red !important', 'a{b}', 'x:/*y*/z', 'display:var(--d)']) assert.throws(() => planStyle(t), /refused/, t);
});

test('css round-trips byte-identically and stays sorted', () => {
  const header = '/* h */\n';
  const rules = new Map([['g1-s-ffffffff', '.g1-s-ffffffff { a:b }'], ['is-hidden', '.is-hidden { display: none; }'], ['g1-display-flex', '.g1-display-flex { display: flex; }']]);
  const css = writeCss(header, rules);
  assert.equal(writeCss(...Object.values(parseCss(css))), css);
  assert.ok(css.indexOf('.g1-display-flex') < css.indexOf('.g1-s-ffffffff') && css.indexOf('.g1-s-ffffffff') < css.indexOf('.is-hidden'));
});

test('css round-trip preserves a multi-line rule', () => {
  const header = '/* h */\n';
  const multiline = '.g1-s-53dda9d3 { background:#fff2;border:1px solid rgba(255,255,255,.4);\n    color:#fff;border-radius:6px;padding:4px 14px;\n    transition:background .2s }';
  const rules = new Map([['g1-s-53dda9d3', multiline], ['g1-s-ffffffff', '.g1-s-ffffffff { a:b }']]);
  const css = writeCss(header, rules);
  const reparsed = parseCss(css);
  assert.equal(reparsed.rules.get('g1-s-53dda9d3'), multiline);
  assert.equal(writeCss(reparsed.header, reparsed.rules), css);
});

test('css round-trip preserves a doubled-class g1-v rule', () => {
  const header = '/* h */\n';
  const doubled = '.g1-v-7d75dfc9.g1-v-7d75dfc9 { color: var(--g1-v-7d75dfc9); }';
  const rules = new Map([['g1-v-7d75dfc9', doubled], ['g1-s-ffffffff', '.g1-s-ffffffff { a:b }']]);
  const css = writeCss(header, rules);
  const reparsed = parseCss(css);
  assert.equal(reparsed.rules.get('g1-v-7d75dfc9'), doubled);
  assert.equal(writeCss(reparsed.header, reparsed.rules), css);
});

test('css-var-rules round-trip does not truncate on the header comment\'s own {0}..{n} example', () => {
  const src = "// Registry of data-driven declarations (G1e spec 4.4). Maintained by\n" +
    "// tools/g1e-codemod.mjs --split; keys sorted. Each rule is one declaration:\n" +
    "// prop, value template with {0}..{n} placeholders, and one type per placeholder.\n" +
    "export const CSS_VAR_RULES = {\n" +
    "};\n";
  const { header, footer, entries } = parseCssVarRules(src);
  assert.ok(header.includes('export const CSS_VAR_RULES = {'), 'header lost the declaration line');
  assert.equal(entries.size, 0);
  entries.set('g1-v-7d75dfc9', '{"prop":"color","value":"{0}","types":["color"]}');
  const out = writeCssVarRules(header, footer, entries);
  const reparsed = parseCssVarRules(out);
  assert.equal(reparsed.entries.get('g1-v-7d75dfc9'), '{"prop":"color","value":"{0}","types":["color"]}');
  assert.ok(out.includes('export const CSS_VAR_RULES = {'), 'round-trip lost the declaration line');
});

test('markup: class merged into an existing class attribute, attributes otherwise unchanged', () => {
  const html = '<div id="a" class="card x" style="color:red" title="t &amp; u"><p style="display:none">x</p></div>';
  const { html: out } = convertMarkup(html);
  const c = classFor('color:red');
  assert.equal(out, `<div id="a" class="card x ${c}" title="t &amp; u"><p class="is-hidden">x</p></div>`);
  const d = new JSDOM(out).window.document;
  assert.equal(d.querySelectorAll('[class]').length, 2);
});

test('markup: entities in the style value are decoded before hashing', () => {
  const { html: out } = convertMarkup('<b style="font-family:&quot;Inter&quot;">x</b>');
  assert.ok(out.includes(classFor('font-family:"Inter"')));
});

test('templates: literal styles converted, class merged, quote form kept', () => {
  const src = "const a = '<div class=\"row\" style=\"color:red\">' + v + '</div>';\nconst b = \"<span style=\\\"margin:0\\\">\";\nconst c = `<i style=\"padding:2px\">${v}</i>`;\n";
  const { code, reports } = convertJs(src, 'x.js');
  assert.ok(code.includes(`'<div class="row ${classFor('color:red')}">'`));
  assert.ok(code.includes(`"<span class=\\"${classFor('margin:0')}\\">"`));
  assert.ok(code.includes(`\`<i class="${classFor('padding:2px')}">\${v}</i>\``));
  assert.deepEqual(reports, []);
});

test('templates: dynamic styles and split tags are reported, never rewritten', () => {
  const src = "const a = '<b style=\"color:' + c + '\">';\nconst b = '<p class=\"' + k + '\" style=\"color:red\">';\nconst d = '<em ' + attrs + ' style=\"color:red\">';\n";
  const { code, reports } = convertJs(src, 'x.js');
  assert.equal(code, src);
  assert.equal(reports.length, 3);
});

test('templates: never emits a second class attribute', () => {
  const src = "const a = '<p class=\"a\" style=\"color:red\" class=\"b\">';\n";
  const { code, reports } = convertJs(src, 'x.js');
  assert.equal(code, src);
  assert.equal(reports.length, 1);
});

test('split: one doubled-class rule per dynamic declaration, literal part as g1-s', () => {
  const r = splitDynamic('font-size:11px;border:1px solid {0}44;width:{1}%', ['color', 'number']);
  const b = `g1-v-${h8('border:1px solid {0}44')}`;
  const w = `g1-v-${h8('width:{1}%')}`;
  assert.deepEqual(r.dynamic.map((d) => d.rule), [b, w]);
  assert.deepEqual(r.dynamic[0], { rule: b, prop: 'border', value: '1px solid {0}44', types: ['color'] });
  assert.deepEqual(r.dynamic[1], { rule: w, prop: 'width', value: '{0}%', types: ['number'] });
  assert.equal(r.ruleLines.get(b), `.${b}.${b} { border: var(--${b}); }`);
  assert.equal(r.staticClass, classFor('font-size:11px'));
});

test('split: order-dependent overlaps and dynamic display are refused', () => {
  assert.throws(() => splitDynamic('border-color:{0};border:1px solid #333', ['color']), /refused/);
  assert.throws(() => splitDynamic('color:{0};background:{1};background-color:{1}', ['color', 'color']), /refused/);
  assert.throws(() => splitDynamic('display:{0}', ['color']), /refused/);
  assert.doesNotThrow(() => splitDynamic('border:1px solid #333;border-color:{0}', ['color']));
});
