import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load, PAYLOADS } from './dom.mjs';

setupDom();
const { breadcrumbFor, formatClock, pageHeroHtml, renderBreadcrumb, setHeroStat, mountHero } =
  await load(['breadcrumbFor', 'formatClock', 'pageHeroHtml', 'renderBreadcrumb', 'setHeroStat', 'mountHero']);

test('breadcrumbFor puts every nav tab under its sidebar group', () => {
  assert.deepEqual(breadcrumbFor('dashboard', 'Dashboard'), [{ label: 'Operations' }, { label: 'Dashboard', current: true }]);
  assert.deepEqual(breadcrumbFor('findings', 'Findings'), [{ label: 'Visibility' }, { label: 'Findings', current: true }]);
  assert.deepEqual(breadcrumbFor('agents', 'Agents'), [{ label: 'Infrastructure' }, { label: 'Agents', current: true }]);
  assert.deepEqual(breadcrumbFor('settings', 'Settings'), [{ label: 'Administration' }, { label: 'Settings', current: true }]);
});

test('breadcrumbFor nests the report sub-pages under Reports', () => {
  assert.deepEqual(breadcrumbFor('sla-report', 'SLA Compliance'),
    [{ label: 'Visibility' }, { label: 'Reports', tab: 'reports' }, { label: 'SLA Compliance', current: true }]);
  assert.deepEqual(breadcrumbFor('compliance', 'Compliance'),
    [{ label: 'Visibility' }, { label: 'Reports', tab: 'reports' }, { label: 'Compliance', current: true }]);
});

test('breadcrumbFor falls back to just the page for an unknown tab', () => {
  assert.deepEqual(breadcrumbFor('nope', 'Nope'), [{ label: 'Nope', current: true }]);
});

test('formatClock zero-pads hours, minutes and seconds', () => {
  assert.equal(formatClock(new Date(2026, 9, 26, 7, 5, 9)), '07:05:09');
  assert.equal(formatClock(new Date(2026, 9, 26, 23, 59, 59)), '23:59:59');
});

test('pageHeroHtml renders title, subtitle, actions and stats', () => {
  const html = pageHeroHtml({
    icon: '<svg></svg>', title: 'Simulation agents', sub: 'Collectors', actions: '<button>Go</button>',
    stats: [{ id: 'hs-total', value: '12', label: 'Agents' }],
  });
  assert.match(html, /<h1[^>]*>Simulation agents<\/h1>/);
  assert.match(html, /Collectors/);
  assert.match(html, /<button>Go<\/button>/);
  assert.match(html, /id="hs-total"[^>]*>12</);
  assert.match(html, />Agents</);
});

test('pageHeroHtml escapes hostile text in title, subtitle and stats', () => {
  for (const p of PAYLOADS) {
    const html = pageHeroHtml({ title: p, sub: p, stats: [{ id: 'hs-x', value: p, label: p }] });
    assert.ok(!html.includes('<img') && !html.includes('<svg onload') && !html.includes('<script'), p);
  }
});

test('pageHeroHtml leaves out the stat strip when there are no stats', () => {
  assert.ok(!pageHeroHtml({ title: 'T', sub: 'S' }).includes('hero-stats'));
});

test('renderBreadcrumb writes the trail into the page and marks the current item', () => {
  renderBreadcrumb('sla-report', 'SLA Compliance');
  const trail = document.getElementById('crumb-trail');
  assert.ok(trail, 'index.html has #crumb-trail');
  assert.match(trail.textContent.replace(/\s+/g, ' '), /Visibility.*Reports.*SLA Compliance/);
  assert.equal(trail.querySelector('[aria-current="page"]').textContent, 'SLA Compliance');
  assert.match(document.getElementById('crumb-updated').textContent, /^Updated \d\d:\d\d:\d\d$/);
});

test('renderBreadcrumb escapes a hostile page title', () => {
  renderBreadcrumb('nope', '<img src=x onerror="globalThis.__xss=1">');
  assert.equal(document.querySelector('#crumb-trail img'), null);
});

test('setHeroStat updates only the named stat and ignores a missing one', () => {
  document.body.insertAdjacentHTML('beforeend', '<b id="hs-demo">1</b>');
  setHeroStat('hs-demo', 42);
  assert.equal(document.getElementById('hs-demo').textContent, '42');
  assert.doesNotThrow(() => setHeroStat('hs-missing', 1));
});

test('a stat can carry a tone that colours its icon, and a bad tone name is not trusted', () => {
  const html = pageHeroHtml({ title: 'T', stats: [
    { id: 'a', icon: '<i></i>', tone: 'ok', value: 1, label: 'x' },
    { id: 'b', icon: '<i></i>', tone: '"><script>', value: 1, label: 'y' },
  ] });
  assert.match(html, /hero-stat-ico tone-ok/);
  assert.ok(!html.includes('<script'));
  assert.ok(!/tone-"/.test(html));
});

test('mountHero fills its placeholder with the banner and ignores a missing placeholder', () => {
  document.body.insertAdjacentHTML('beforeend', '<div id="hero-demo"></div>');
  mountHero('hero-demo', { title: 'Demo page', sub: 'Sub' });
  assert.equal(document.querySelector('#hero-demo h1').textContent, 'Demo page');
  assert.doesNotThrow(() => mountHero('hero-nope', { title: 'x' }));
});
