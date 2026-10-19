import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDispatchFields, DISPATCH_MIN_MS, DISPATCH_MAX_MS } from '../../src/features/scenario-library-route.js';

const now = Date.UTC(2026, 9, 19, 12, 0, 0);
// datetime-local values carry no zone and are read as local time, so the helper
// writes local components, exactly as the browser control does.
const pad = (n) => String(n).padStart(2, '0');
const at = (ms) => {
  const d = new Date(now + ms);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

test('unticked dispatch adds nothing, so the run stays a normal run', () => {
  assert.deepEqual(buildDispatchFields({ dispatch: false }, now, 'k'), { ok: true, fields: {} });
  assert.deepEqual(buildDispatchFields({}, now, 'k'), { ok: true, fields: {} });
});

test('ticked dispatch sends the window in UTC, the key, and the campaign when given', () => {
  const r = buildDispatchFields({ dispatch: true, testWindowEnd: at(60 * 60 * 1000), campaignId: ' camp-1 ' }, now, 'key-1');
  assert.equal(r.ok, true);
  assert.equal(r.fields.dispatch, true);
  assert.equal(r.fields.idempotencyKey, 'key-1');
  assert.match(r.fields.testWindowEnd, /Z$/);
  assert.equal(r.fields.campaignId, 'camp-1');
});

test('a window outside the EmailGW dwell bounds is refused on the form', () => {
  assert.equal(buildDispatchFields({ dispatch: true, testWindowEnd: at(DISPATCH_MIN_MS - 60_000) }, now, 'k').ok, false);
  assert.equal(buildDispatchFields({ dispatch: true, testWindowEnd: at(DISPATCH_MAX_MS + 60_000) }, now, 'k').ok, false);
});

test('a ticked dispatch without a window or key is refused', () => {
  assert.equal(buildDispatchFields({ dispatch: true }, now, 'k').ok, false);
  const noKey = buildDispatchFields({ dispatch: true, testWindowEnd: at(60 * 60 * 1000) }, now, '');
  assert.equal(noKey.ok, false);
  assert.deepEqual(noKey.errors, ['idempotencyKey']);
});

test('campaign is optional and omitted when blank', () => {
  const r = buildDispatchFields({ dispatch: true, testWindowEnd: at(60 * 60 * 1000), campaignId: '  ' }, now, 'k');
  assert.equal('campaignId' in r.fields, false);
});
