import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeScript } from '../../tools/analyze.mjs';
import { splitMonolith } from '../../tools/split.mjs';

// Builds a minimal monolith with the real file's fixed line layout:
// lines 1-10 head, 11 <style>, 12-1320 css, 1321 </style>, 1322-5160 markup,
// 5161 <script>, 5162.. js, then </script></body></html>.
function monolith(js, markup = '<div id="app"></div>') {
  const pad = (n, s = '') => Array.from({ length: n }, () => s);
  const head = ['<!DOCTYPE html>', '<html>', '<head>', ...pad(7, '<!-- h -->')];
  const css = pad(1309, '/* c */');
  const body = [markup, ...pad(3838, '<!-- m -->')];
  return [...head, '<style>', ...css, '</style>', ...body, '<script>', ...js.split('\n'), '</script>', '</body>', '</html>'].join('\n');
}
const cfg = (over = {}) => ({ default: 'legacy.js', sections: [], pin: {}, windowVars: [], windowFns: [], lateInit: [], ...over });
const file = (out, p) => out.files.get(p);

test('chunks partition the script losslessly', () => {
  const js = '// lead\nvar a = 1;\nfunction f() { return a; }\n\n// tail comment\nf();\n';
  const { chunks } = analyzeScript(js);
  assert.equal(chunks.map((c) => js.slice(c.start, c.end)).join(''), js);
});

test('cross-module write turns a variable into state', () => {
  const js = '// ── One ──\nvar count = 0;\nfunction show() { return count; }\n// ── Two ──\nfunction bump() { count = count + 1; }\n';
  const out = splitMonolith(monolith(js), cfg({ sections: [{ header: 'One', module: 'features/one.js' }, { header: 'Two', module: 'features/two.js' }] }));
  assert.match(file(out, 'src/core/state.js'), /count: 0/);
  assert.match(file(out, 'src/features/one.js'), /return state\.count;/);
  assert.match(file(out, 'src/features/two.js'), /state\.count = state\.count \+ 1;/);
  assert.doesNotMatch(file(out, 'src/features/one.js'), /var count/);
});

test('handler-assigned variable is exposed through a state accessor', () => {
  const js = "var scenarioView = 'landing';\nfunction render() { return scenarioView; }\n";
  const out = splitMonolith(monolith(js, '<input oninput="scenarioView = \'search\'; render()">'), cfg());
  const g = file(out, 'src/globals.js');
  assert.match(g, /STATE_GLOBALS = \[\s*'scenarioView'/);
  assert.match(g, /HANDLER_FUNCTIONS = \{[^}]*\brender\b/);
  assert.match(file(out, 'src/legacy.js'), /return state\.scenarioView;/);
});

test('windowVars entries become state globals', () => {
  const js = 'var _groupSel = {};\nfunction read(n) { return window[n]; }\n';
  const out = splitMonolith(monolith(js), cfg({ windowVars: ['_groupSel'] }));
  assert.match(file(out, 'src/globals.js'), /'_groupSel'/);
  assert.match(file(out, 'src/core/state.js'), /_groupSel: \{\}/);
});

test('shorthand property reference is expanded', () => {
  const js = 'var mode = 1;\nfunction pack() { return { mode }; }\n';
  const out = splitMonolith(monolith(js, '<a onclick="mode=2">'), cfg());
  assert.match(file(out, 'src/legacy.js'), /\{ mode: state\.mode \}/);
});

test('load-time statements become ordered init functions', () => {
  const js = 'function a() {}\nwindow.addEventListener("load", a);\nfunction b() {}\nb();\n';
  const out = splitMonolith(monolith(js), cfg());
  const main = file(out, 'src/main.js');
  assert.ok(main.indexOf('__init_L5163()') < main.indexOf('__init_L5165()'));
  assert.ok(main.indexOf('installGlobals()') < main.indexOf('__init_L5163()'));
  assert.match(file(out, 'src/legacy.js'), /export function __init_L5163\(\) \{\nwindow\.addEventListener\("load", a\);\n?\}/);
});

test('cross-module function call gets an import', () => {
  const js = '// ── One ──\nfunction helper() { return 1; }\n// ── Two ──\nfunction user() { return helper(); }\n';
  const out = splitMonolith(monolith(js), cfg({ sections: [{ header: 'One', module: 'features/one.js' }, { header: 'Two', module: 'features/two.js' }] }));
  assert.match(file(out, 'src/features/two.js'), /^import \{ helper \} from '\.\/one\.js';/m);
  assert.match(file(out, 'src/features/one.js'), /^export function helper\(\)/m);
});

test('implicit global write becomes state', () => {
  const js = 'function setIt() { leaked = 5; }\nfunction getIt() { return leaked; }\n';
  const out = splitMonolith(monolith(js), cfg());
  assert.match(file(out, 'src/core/state.js'), /leaked: undefined/);
  assert.match(file(out, 'src/legacy.js'), /state\.leaked = 5;/);
});

test('cross-module initializer is a hard error', () => {
  const js = '// ── One ──\nvar base = 2;\nfunction noop() {}\n// ── Two ──\nvar derived = base * 2;\n';
  assert.throws(() => splitMonolith(monolith(js), cfg({ sections: [{ header: 'One', module: 'features/one.js' }, { header: 'Two', module: 'features/two.js' }] })), /initializer of "derived" reads "base" from another module/);
});

test('init that reads a later-declared var is reported', () => {
  const js = 'console.log(late);\nvar late = 1;\n';
  const out = splitMonolith(monolith(js), cfg());
  assert.deepEqual(out.report.laterVarReads, [{ line: 5162, name: 'late' }]);
});

test('mixed declaration keeps the non-state declarator and rewrites its state reads', () => {
  const js = "var mode = 1, label = 'x', copy = mode;\nfunction f() { return [label, copy]; }\n";
  const out = splitMonolith(monolith(js, '<a onclick="mode=2;f()">'), cfg());
  assert.match(file(out, 'src/legacy.js'), /var label = 'x', copy = state\.mode;/);
  assert.match(file(out, 'src/core/state.js'), /mode: 1/);
});

test('function named by a string literal is exposed as a dynamic handler', () => {
  // covSegHtml(items, active, 'setAgentFilter') builds onclick="' + fnName + '(…)"
  const js = "function setAgentFilter(v) {}\nfunction seg(fn) { return '<b onclick=\"' + fn + '(1)\">'; }\nfunction bar() { return seg('setAgentFilter'); }\n";
  const out = splitMonolith(monolith(js), cfg());
  assert.match(file(out, 'src/globals.js'), /DYNAMIC_HANDLERS = \[\s*'setAgentFilter'/);
  assert.match(file(out, 'src/globals.js'), /HANDLER_FUNCTIONS = \{[^}]*\bsetAgentFilter\b/);
});

test('testExports entries are exported but not put on window', () => {
  const js = 'function helper(s) { return s; }\nfunction user() { return helper(1); }\n';
  const out = splitMonolith(monolith(js), cfg({ testExports: ['helper'] }));
  assert.match(file(out, 'src/legacy.js'), /^export function helper\(s\)/m);
  assert.doesNotMatch(file(out, 'src/globals.js'), /\bhelper\b/);
  assert.throws(() => splitMonolith(monolith(js), cfg({ testExports: ['nope'] })), /testExports entry "nope" is not a top-level function/);
});

test('window.NAME writes of undeclared names are registered verbatim', () => {
  const js = '(function(){ window.openRunPanel = function(){}; })();\n';
  const out = splitMonolith(monolith(js), cfg());
  assert.match(file(out, 'src/globals.js'), /WINDOW_WRITES = \[\s*'openRunPanel'/);
  assert.match(file(out, 'src/legacy.js'), /window\.openRunPanel = function\(\)\{\};/);
});
