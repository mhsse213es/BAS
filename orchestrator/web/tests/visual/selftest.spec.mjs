import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { boot, makeDeterministic } from '../smoke/harness.mjs';
import { settle, snapshotStyles, screenshot, elementPath } from './capture.mjs';
import { SEP, compareStyles } from './compare.mjs';

const PROPS = JSON.parse(readFileSync(fileURLToPath(new URL('./props.json', import.meta.url)), 'utf8'));
const HEAD = 'http://127.0.0.1:4175';

async function pair(browser) {
  const pages = [];
  for (let i = 0; i < 2; i++) {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
    const p = await ctx.newPage();
    await makeDeterministic(p);
    await boot(p, HEAD);
    await settle(p);
    pages.push(p);
  }
  return pages;
}

test('the same build twice is identical (determinism)', async ({ browser }) => {
  const [a, b] = await pair(browser);
  const [sa, sb] = [await snapshotStyles(a, PROPS), await snapshotStyles(b, PROPS)];
  const props = sa['#props'].split(SEP);
  delete sa['#props']; delete sb['#props'];
  expect(compareStyles('self', sa, sb, props)).toEqual([]);
  expect((await screenshot(a)).equals(await screenshot(b))).toBe(true);
});

test('a planted 1px margin change fails the screenshot comparison', async ({ browser }) => {
  const [a, b] = await pair(browser);
  await b.evaluate(() => { document.getElementById('app').style.marginTop = '1px'; });
  expect((await screenshot(a)).equals(await screenshot(b))).toBe(false);
});

test('a planted font-weight change fails the computed-style comparison, naming element and property', async ({ browser }) => {
  const [a, b] = await pair(browser);
  await b.evaluate(() => { document.getElementById('app').style.fontWeight = '900'; });
  const [sa, sb] = [await snapshotStyles(a, PROPS), await snapshotStyles(b, PROPS)];
  const props = sa['#props'].split(SEP);
  delete sa['#props']; delete sb['#props'];
  const path = await elementPath(a, '#app');
  const diffs = compareStyles('self', sa, sb, props);
  expect(diffs).toContainEqual(expect.objectContaining({ path, property: 'font-weight', head: '900' }));
});
