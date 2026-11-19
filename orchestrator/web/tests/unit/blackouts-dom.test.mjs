import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

// Drives the real change-freeze panel markup and handlers: a preset fills the form, the right fields show, and the
// request that is sent is the one the server expects.

function stubFetch(calls) {
  globalThis.fetch = async (url, opts) => {
    calls.push({ url, opts: opts || {} });
    const created = opts && opts.method === 'POST';
    return { status: created ? 201 : 200, json: async () => (created ? { ID: 'new' } : { blackouts: [] }) };
  };
}

const $ = (id) => document.getElementById(id);

async function ready() {
  setupDom();
  const calls = [];
  stubFetch(calls);
  const fns = await load(['loadBlackouts', 'blackoutPreset', 'blackoutCreate', 'blackoutKindChange']);
  fns.loadBlackouts();
  await new Promise((r) => setTimeout(r, 0));
  return { fns, calls };
}

test('the preset picker lists every preset once', async () => {
  const { fns } = await ready();
  fns.loadBlackouts(); // a second load must not duplicate the options
  const labels = [...$('blk-preset').options].map((o) => o.textContent);
  assert.equal(labels.length, 5, 'the prompt plus four presets: ' + labels.join(' | '));
  assert.match(labels.join('|'), /Month-end/);
});

test('the month-end preset fills a daily window and leaves the timezone alone', async () => {
  const { fns } = await ready();
  $('blk-tz').value = 'Asia/Kolkata';
  const sel = $('blk-preset');
  sel.value = 'month-end';
  fns.blackoutPreset(sel);

  assert.equal($('blk-kind').value, 'daily');
  assert.equal($('blk-from').value, '00:00');
  assert.equal($('blk-to').value, '24:00');
  assert.equal($('blk-mdays').value, '-2,-1,1');
  assert.equal($('blk-tz').value, 'Asia/Kolkata');
  assert.equal($('blk-daily-fields').hidden, false);
  assert.equal($('blk-once-fields').hidden, true);
  assert.equal(sel.value, '', 'the picker resets so the same preset can be chosen again');
});

test('creating from the end-of-day preset sends the weekdays, and nothing the server would refuse', async () => {
  const { fns, calls } = await ready();
  const sel = $('blk-preset');
  sel.value = 'eod-batch';
  fns.blackoutPreset(sel);
  ['mon', 'tue', 'wed', 'thu', 'fri'].forEach((d) => assert.equal($('blk-wd-' + d).checked, true, d));
  assert.equal($('blk-wd-sat').checked, false);

  calls.length = 0;
  fns.blackoutCreate();
  await new Promise((r) => setTimeout(r, 0));
  const post = calls.find((c) => c.opts.method === 'POST');
  assert.ok(post, 'a POST was sent: ' + $('blk-err').textContent);
  assert.equal(post.url, '/api/scheduled-blackouts');
  const body = JSON.parse(post.opts.body);
  assert.equal(body.kind, 'daily');
  assert.equal(body.timeFrom, '18:00');
  assert.equal(body.timeTo, '23:00');
  assert.equal(body.weekdays, 'mon,tue,wed,thu,fri');
  assert.equal('monthDays' in body, false);
});

test('a form the model refuses sends nothing and says why', async () => {
  const { fns, calls } = await ready();
  $('blk-kind').value = 'daily';
  fns.blackoutKindChange($('blk-kind'));
  $('blk-name').value = 'Bad';
  $('blk-from').value = '00:00';
  $('blk-to').value = '24:00';
  $('blk-tz').value = 'UTC';
  $('blk-mdays').value = '0';
  calls.length = 0;
  fns.blackoutCreate();
  assert.equal(calls.some((c) => c.opts.method === 'POST'), false);
  assert.match($('blk-err').textContent, /Month days must be 1 to 31/);
});
