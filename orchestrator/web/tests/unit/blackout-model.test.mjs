import { test } from 'node:test';
import assert from 'node:assert/strict';
import { blackoutFormToPayload, describeBlackout, minutesOfDay, isKnownTimezone, localToIso } from '../../src/features/blackout-model.js';

const onceForm = (over) => Object.assign({ name: 'RBI reporting', kind: 'once',
  startsAt: '2026-12-31T00:00', endsAt: '2027-01-02T00:00' }, over);
const dailyForm = (over) => Object.assign({ name: 'EoD batch', kind: 'daily',
  timeFrom: '18:00', timeTo: '19:00', timezone: 'Asia/Kolkata', validFrom: '', validTo: '' }, over);

test('a once window is sent as UTC instants, read on the browser clock', () => {
  const { payload, error } = blackoutFormToPayload(onceForm({}));
  assert.equal(error, '');
  assert.deepEqual(payload, { name: 'RBI reporting', kind: 'once',
    startsAt: new Date('2026-12-31T00:00').toISOString(), endsAt: new Date('2027-01-02T00:00').toISOString() });
});

test('a daily window keeps its times, timezone and optional date range', () => {
  const { payload, error } = blackoutFormToPayload(dailyForm({ validFrom: '2026-12-29', validTo: '2027-01-02' }));
  assert.equal(error, '');
  assert.deepEqual(payload, { name: 'EoD batch', kind: 'daily', timeFrom: '18:00', timeTo: '19:00',
    timezone: 'Asia/Kolkata', validFrom: '2026-12-29', validTo: '2027-01-02' });
});

test('each mistake is refused with a message the operator can act on', () => {
  const cases = [
    [onceForm({ name: '  ' }), 'Give the window a name.'],
    [onceForm({ endsAt: '' }), 'Set both the start and the end.'],
    [onceForm({ endsAt: '2026-12-30T00:00' }), 'The end must be after the start.'],
    [dailyForm({ timeTo: '18:00' }), 'The from and to times must differ.'],
    [dailyForm({ timeFrom: '25:00' }), 'Times must be HH:MM.'],
    [dailyForm({ timezone: '' }), 'Give a timezone, for example UTC or Asia/Kolkata.'],
    [dailyForm({ timezone: 'Mars/Olympus' }), 'Unknown timezone "Mars/Olympus". Use an IANA name such as UTC or Asia/Kolkata.'],
    [dailyForm({ validFrom: '29/12/2026' }), 'Dates must be YYYY-MM-DD.'],
    [dailyForm({ validFrom: '2026-12-31', validTo: '2026-12-01' }), 'The last date is before the first.'],
    [{ name: 'x', kind: 'weekly' }, 'Pick once or daily.'],
  ];
  for (const [form, want] of cases) {
    const r = blackoutFormToPayload(form);
    assert.equal(r.payload, null, 'no payload for: ' + want);
    assert.equal(r.error, want);
  }
});

test('describeBlackout reads the Go field names and says when an overnight window applies', () => {
  assert.equal(describeBlackout({ Kind: 'once', StartsAt: '2026-12-31T00:00:00Z', EndsAt: '2027-01-02T00:00:00Z' }),
    'Once: 2026-12-31 00:00 UTC to 2027-01-02 00:00 UTC');
  assert.equal(describeBlackout({ Kind: 'daily', TimeFrom: '22:00', TimeTo: '06:00', Timezone: 'UTC', ValidFrom: '', ValidTo: '' }),
    'Daily 22:00 to 06:00 UTC (overnight)');
  assert.equal(describeBlackout({ Kind: 'daily', TimeFrom: '18:00', TimeTo: '19:00', Timezone: 'Asia/Kolkata',
    ValidFrom: '2026-12-29', ValidTo: '' }), 'Daily 18:00 to 19:00 Asia/Kolkata, 2026-12-29 to open');
});

test('helpers: times, timezones and local-time conversion', () => {
  assert.equal(minutesOfDay('06:30'), 390);
  assert.equal(minutesOfDay('6:30'), null);
  assert.equal(isKnownTimezone('UTC'), true);
  assert.equal(isKnownTimezone('Mars/Olympus'), false);
  assert.equal(localToIso(''), '');
});
