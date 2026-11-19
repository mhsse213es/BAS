import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The Initiatives instructions name buttons and menu items. Each name must exist in the app, or the help misleads.
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (p) => fs.readFileSync(path.join(web, p), 'utf8');
const C = await import('../../src/features/initiative-copy.js');

test('every control the Initiatives help names exists in the app', () => {
  const html = read('index.html');
  const features = ['initiatives.js', 'page-heroes.js', 'scheduled.js'].map((f) => read('src/features/' + f)).join('\n');
  const all = html + features;
  assert.ok(all.includes('>New Initiative<') || all.includes("'New Initiative'"), 'New Initiative button');
  assert.ok(features.includes('>Attach Job<') || features.includes('Attach Job</button>'), 'Attach Job button');
  assert.ok(html.includes('Initiative (optional)'), 'Scheduled Assessment initiative field');
  assert.ok(html.includes('Scheduled Assessments'), 'Scheduled Assessments sidebar item');
});

test('the copy names the steps in the order a user takes them', () => {
  assert.match(C.EMPTY_BODY, /New Initiative/);
  assert.match(C.EMPTY_BODY, /Scheduled Assessment/);
  assert.match(C.DRAWER_EMPTY, /Attach Job/);
});

test('the copy says what an initiative is in plain words, without the engine terms', () => {
  assert.match(C.HERO_SUB, /goal|group/i);
  assert.doesNotMatch(C.HERO_SUB + C.EMPTY_BODY, /programme|job engine|validation job/i);
});
