import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const { mountPageHeroes } = await load(['mountPageHeroes']);

test('every hero placeholder in index.html gets a banner with a heading and no undefined parts', () => {
  const holders = [...document.querySelectorAll('[id^="hero-"]')];
  assert.ok(holders.length >= 20, `expected the redesigned pages, found ${holders.length}`);
  mountPageHeroes();
  for (const h of holders) {
    assert.ok(h.querySelector('h1'), `${h.id} has no banner`);
    assert.ok(!/undefined|\[object/.test(h.innerHTML), `${h.id} rendered an undefined value`);
    assert.ok(h.querySelector('.hero-ico svg'), `${h.id} has no icon`);
  }
});

test('hero action buttons use the action registry, never inline handlers', () => {
  mountPageHeroes();
  for (const el of document.querySelectorAll('.page-hero *')) {
    for (const a of el.attributes) assert.ok(!/^on[a-z]+$/.test(a.name), `inline handler ${a.name} in a hero`);
  }
});

test('a banner chip keeps the id its page loader writes to (counts)', () => {
  mountPageHeroes();
  for (const id of ['runs-cnt', 'campaign-cnt', 'init-cnt', 'sched-cnt', 'k8s-cnt']) {
    assert.ok(document.getElementById(id), `#${id} missing from the banner`);
  }
});
