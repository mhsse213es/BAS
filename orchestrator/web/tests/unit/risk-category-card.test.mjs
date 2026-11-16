import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

// The risk tab shows why a compliance category is or is not scored, and keeps real failed controls visible.

async function card(c) {
  setupDom();
  const { _riskCategoryCard } = await load(['_riskCategoryCard']);
  const div = document.createElement('div');
  div.innerHTML = _riskCategoryCard(c);
  return div;
}

test('an unscored compliance category says it is not scored and why, and lists the failed controls', async () => {
  const d = await card({ id: 'compliance', name: 'Compliance', collected: false,
    note: 'Not scored: too little has been tested. Not scored: RBI.', findings: [{ title: 'Boundary defence', severity: 'High' }] });
  const text = d.textContent;
  assert.match(text, /Not scored/);
  assert.match(text, /too little has been tested/);
  assert.match(text, /1 failed control finding/);
  assert.match(text, /Boundary defence/);
  assert.doesNotMatch(text, /Not yet collected/);
});

test('a category with no data and no note still says not yet collected', async () => {
  const d = await card({ id: 'identity', name: 'Identity', collected: false });
  assert.match(d.textContent, /Not yet collected/);
});

test('a scored category shows its score and the frameworks it left out', async () => {
  const d = await card({ id: 'compliance', name: 'Compliance', collected: true, score: 70,
    note: 'Left out for too little testing (under 50% control coverage): RBI.', findings: [] });
  assert.match(d.textContent, /70/);
  assert.match(d.textContent, /Left out for too little testing/);
});

test('a hostile note is escaped', async () => {
  const d = await card({ name: 'x', collected: false, note: '<img src=x onerror=alert(1)>' });
  assert.equal(d.querySelector('img'), null);
});
