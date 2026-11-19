import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The coverage page must carry one name everywhere: the sidebar item, the browser title and the page header.
const web = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (p) => fs.readFileSync(path.join(web, p), 'utf8');

test('the sidebar item, page title and page header for the coverage tab use the same name', () => {
  const html = read('index.html');
  const nav = html.match(/data-tab="coverage"[^>]*>[\s\S]*?<\/svg>\s*([^<]+?)\s*<\/div>/);
  assert.ok(nav, 'coverage nav item not found');
  const navLabel = nav[1].trim();

  const shell = read('src/features/shell.js');
  const tabTitle = shell.match(/\bcoverage:\s*'([^']+)'/)[1];

  const heroes = read('src/features/page-heroes.js');
  const heroTitle = heroes.match(/'hero-coverage':\s*\{[\s\S]*?title:\s*'([^']+)'/)[1];

  assert.equal(tabTitle, navLabel, 'browser/tab title differs from the sidebar label');
  assert.equal(heroTitle, navLabel, 'page header differs from the sidebar label');
});
