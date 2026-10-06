import { test, expect } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { boot, makeDeterministic, tabNames, openTab, DRAWERS, openDrawer } from '../smoke/harness.mjs';
import { settle, snapshotStyles, screenshot, runSteps } from './capture.mjs';
import { SEP, compareStyles, validateAllowlist, isAllowed, masksFor, formatDiff } from './compare.mjs';
import { CHECKPOINTS, UNREACHABLE_RULES } from './checkpoints.mjs';

const here = (p) => fileURLToPath(new URL(p, import.meta.url));
const PROPS = JSON.parse(readFileSync(here('./props.json'), 'utf8'));
const ALLOW = validateAllowlist(JSON.parse(readFileSync(here('./g1e-visual-allowlist.json'), 'utf8')));
const BASE = 'http://127.0.0.1:4174';
const HEAD = 'http://127.0.0.1:4175';

async function rules() {
  try { return Object.keys((await import('../../src/core/css-var-rules.js')).CSS_VAR_RULES); } catch { return []; }
}

test('G1e: HEAD renders identically to the baseline build', async ({ browser }, testInfo) => {
  const open = async (origin) => {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
    const page = await ctx.newPage();
    await makeDeterministic(page);
    await boot(page, origin);
    return page;
  };
  const problems = [];
  const allowed = [];
  const seenRules = new Set();
  const compare = async (name, pb, ph) => {
    await Promise.all([settle(pb), settle(ph)]);
    const [sb, sh] = await Promise.all([snapshotStyles(pb, PROPS), snapshotStyles(ph, PROPS)]);
    const props = sb['#props'].split(SEP);
    delete sb['#props']; delete sh['#props'];
    for (const d of compareStyles(name, sb, sh, props)) (isAllowed(d, ALLOW) ? allowed : problems).push(formatDiff(d));
    const masks = masksFor(name, ALLOW);
    const [ib, ih] = await Promise.all([screenshot(pb, masks), screenshot(ph, masks)]);
    if (!ib.equals(ih)) {
      const slug = name.replace(/[^a-z0-9]+/gi, '_');
      writeFileSync(testInfo.outputPath(`${slug}.base.png`), ib);
      writeFileSync(testInfo.outputPath(`${slug}.head.png`), ih);
      problems.push(`${name}  screenshot differs (see ${slug}.base.png / ${slug}.head.png)`);
    }
    for (const c of await ph.evaluate(() => [...document.querySelectorAll('[class*="g1-v-"]')].flatMap((e) => [...e.classList]))) {
      if (c.startsWith('g1-v-')) seenRules.add(c);
    }
  };

  // Every checkpoint gets a fresh page per build, and the two builds run one
  // after the other: state carried across tabs, and response timing shifted by
  // two pages competing for the CPU, made identical trees render differently.
  const prepare = async (origin, steps) => {
    const page = await open(origin);
    await steps(page);
    await settle(page);
    return page;
  };
  const checkpoint = async (name, steps) => {
    const pb = await prepare(BASE, steps);
    const ph = await prepare(HEAD, steps);
    await compare(name, pb, ph);
    await Promise.all([pb.context().close(), ph.context().close()]);
  };

  const [tb, th] = [await open(BASE), await open(HEAD)];
  const tabs = await tabNames(tb);
  expect(await tabNames(th)).toEqual(tabs);
  await Promise.all([tb.context().close(), th.context().close()]);
  for (const tab of tabs) await checkpoint(`tab:${tab}`, (p) => openTab(p, tab));
  for (const drawer of DRAWERS) await checkpoint(`drawer:${drawer.name}`, (p) => openDrawer(p, drawer));
  for (const cp of CHECKPOINTS) {
    await checkpoint(`checkpoint:${cp.name}`, async (p) => { await openTab(p, cp.tab); await settle(p); await runSteps(p, cp.steps); });
  }
  for (const r of await rules()) {
    if (!seenRules.has(r) && !(r in UNREACHABLE_RULES)) problems.push(`coverage: ${r} rendered by no checkpoint (add a fixture/checkpoint or UNREACHABLE_RULES entry)`);
  }
  for (const r of Object.keys(UNREACHABLE_RULES)) {
    if (seenRules.has(r)) problems.push(`coverage: ${r} is listed unreachable but rendered`);
  }
  for (const a of allowed) console.log(`allowlisted: ${a}`);
  console.log(`checkpoints: ${tabs.length} tabs, ${DRAWERS.length} drawers, ${CHECKPOINTS.length} extra; g1-v rules seen: ${seenRules.size}`);
  expect(problems, 'rendering differs from the baseline build').toEqual([]);
});
