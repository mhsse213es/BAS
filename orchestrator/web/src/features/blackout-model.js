// Pure helpers for the change-freeze (blackout) window panel: the form becomes the request body
// POST /api/scheduled-blackouts expects, the form is checked the way the server checks it (the server stays
// the authority and refuses anything it rejects), and a window is described in words. No DOM, no network.
//
// The list endpoint returns jobs.Blackout with no JSON tags, so a window read back from it uses the Go field
// names (Name, Kind, StartsAt, EndsAt, TimeFrom, TimeTo, Timezone, ValidFrom, ValidTo), not camelCase.

const TIME = /^([01]\d|2[0-3]):[0-5]\d$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

// minutesOfDay parses "HH:MM" into minutes after midnight, or null when it is not a time.
export function minutesOfDay(s) {
  if (typeof s !== 'string' || !TIME.test(s)) return null;
  const parts = s.split(':').map(Number);
  return parts[0] * 60 + parts[1];
}

// endMinutesOfDay is minutesOfDay for the end of a window, which may be "24:00" (the end of the day).
export function endMinutesOfDay(s) {
  return s === '24:00' ? 24 * 60 : minutesOfDay(s);
}

const WEEKDAY_ORDER = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'];
const WEEKDAY_LABEL = { mon: 'Mon', tue: 'Tue', wed: 'Wed', thu: 'Thu', fri: 'Fri', sat: 'Sat', sun: 'Sun' };

// parseMonthDays reads "-2, -1, 1" into numbers (1..31, or -1..-31 from the end), or null when any part is not one.
export function parseMonthDays(s) {
  const text = String(s || '').trim();
  if (!text) return [];
  const out = [];
  for (const tok of text.split(',')) {
    const t = tok.trim();
    if (!/^-?\d+$/.test(t)) return null;
    const n = Number(t);
    if (n === 0 || n > 31 || n < -31) return null;
    out.push(n);
  }
  return out;
}

// isKnownTimezone reports whether the browser's time-zone database knows the IANA name.
export function isKnownTimezone(tz) {
  if (typeof tz !== 'string' || !tz) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch (e) {
    return false;
  }
}

// localToIso turns a datetime-local value ("YYYY-MM-DDTHH:MM", read on the browser's own clock) into a UTC ISO string.
export function localToIso(s) {
  if (!s) return '';
  const d = new Date(s);
  return isNaN(d.getTime()) ? '' : d.toISOString();
}

function refuse(error) {
  return { payload: null, error: error };
}

// blackoutFormToPayload checks the form and builds the request body. The result is { payload, error }: payload is
// null and error says what to fix when the form cannot be sent.
export function blackoutFormToPayload(f) {
  const name = String((f && f.name) || '').trim();
  if (!name) return refuse('Give the window a name.');
  const kind = f.kind;
  if (kind === 'once') {
    const startsAt = localToIso(f.startsAt);
    const endsAt = localToIso(f.endsAt);
    if (!startsAt || !endsAt) return refuse('Set both the start and the end.');
    if (Date.parse(endsAt) <= Date.parse(startsAt)) return refuse('The end must be after the start.');
    return { payload: { name: name, kind: 'once', startsAt: startsAt, endsAt: endsAt }, error: '' };
  }
  if (kind === 'daily') {
    if (minutesOfDay(f.timeFrom) === null || endMinutesOfDay(f.timeTo) === null) {
      return refuse('Times must be HH:MM (the end may be 24:00).');
    }
    if (f.timeFrom === f.timeTo) return refuse('The from and to times must differ.');
    const tz = String(f.timezone || '').trim();
    if (!tz) return refuse('Give a timezone, for example UTC or Asia/Kolkata.');
    if (!isKnownTimezone(tz)) {
      return refuse('Unknown timezone "' + tz + '". Use an IANA name such as UTC or Asia/Kolkata.');
    }
    const validFrom = f.validFrom || '';
    const validTo = f.validTo || '';
    if ((validFrom && !DATE.test(validFrom)) || (validTo && !DATE.test(validTo))) {
      return refuse('Dates must be YYYY-MM-DD.');
    }
    if (validFrom && validTo && validTo < validFrom) return refuse('The last date is before the first.');
    const days = parseMonthDays(f.monthDays);
    if (days === null) return refuse('Month days must be 1 to 31, or -1 to -31 counted from the end of the month.');
    const payload = {
      name: name, kind: 'daily', timeFrom: f.timeFrom, timeTo: f.timeTo, timezone: tz,
      validFrom: validFrom, validTo: validTo
    };
    const weekdays = WEEKDAY_ORDER.filter(function(d) { return (f.weekdays || []).indexOf(d) !== -1; });
    if (weekdays.length) payload.weekdays = weekdays.join(',');
    if (days.length) payload.monthDays = days.join(',');
    return { payload: payload, error: '' };
  }
  return refuse('Pick once or daily.');
}

function utcLabel(iso) {
  return iso ? iso.slice(0, 16).replace('T', ' ') + ' UTC' : '';
}

// describeBlackout says in words when a window applies. It reads the Go field names the list endpoint returns.
export function describeBlackout(b) {
  if (!b) return '';
  if (b.Kind === 'once') return 'Once: ' + utcLabel(b.StartsAt) + ' to ' + utcLabel(b.EndsAt);
  if (b.Kind === 'daily') {
    const overnight = minutesOfDay(b.TimeFrom) > endMinutesOfDay(b.TimeTo) ? ' (overnight)' : '';
    let text = 'Daily ' + b.TimeFrom + ' to ' + b.TimeTo + ' ' + b.Timezone + overnight;
    const wd = describeWeekdays(b.Weekdays);
    if (wd) text += ', ' + wd;
    const md = describeMonthDays(b.MonthDays);
    if (md) text += ', ' + md;
    if (b.ValidFrom || b.ValidTo) text += ', ' + (b.ValidFrom || 'open') + ' to ' + (b.ValidTo || 'open');
    return text;
  }
  return b.Kind || '';
}

function describeWeekdays(csv) {
  const have = String(csv || '').split(',').map(function(x) { return x.trim().toLowerCase(); }).filter(Boolean);
  if (!have.length) return '';
  const days = WEEKDAY_ORDER.filter(function(d) { return have.indexOf(d) !== -1; });
  if (days.join(',') === 'mon,tue,wed,thu,fri') return 'Mon to Fri';
  return days.map(function(d) { return WEEKDAY_LABEL[d]; }).join(', ');
}

function describeMonthDays(csv) {
  const days = parseMonthDays(csv);
  if (!days || !days.length) return '';
  const names = days.map(function(n) {
    if (n === -1) return 'last';
    if (n === -2) return '2nd last';
    if (n < 0) return Math.abs(n) + 'th last';
    return String(n);
  });
  return 'on day ' + names.join(', ') + ' of the month';
}

// Presets are starting points for the form, not rules: every field stays editable, and none of them chooses the
// timezone. Regulatory reporting dates change, so the reporting window is a one-time window the operator dates.
export const PRESETS = [
  { key: 'eod-batch', label: 'End-of-day batch (Mon to Fri)',
    fields: { name: 'End-of-day batch', kind: 'daily', timeFrom: '18:00', timeTo: '23:00', weekdays: ['mon', 'tue', 'wed', 'thu', 'fri'], monthDays: '' } },
  { key: 'bod-batch', label: 'Beginning-of-day batch (Mon to Fri)',
    fields: { name: 'Beginning-of-day batch', kind: 'daily', timeFrom: '05:00', timeTo: '09:00', weekdays: ['mon', 'tue', 'wed', 'thu', 'fri'], monthDays: '' } },
  { key: 'month-end', label: 'Month-end (last 2 days and the 1st)',
    fields: { name: 'Month-end freeze', kind: 'daily', timeFrom: '00:00', timeTo: '24:00', weekdays: [], monthDays: '-2,-1,1' } },
  { key: 'reporting-window', label: 'Regulatory reporting window (set the dates)',
    fields: { name: 'Regulatory reporting window', kind: 'once' } },
];

// applyPreset returns the form with a preset's fields laid over it. An unknown key returns the form unchanged.
export function applyPreset(form, key) {
  const p = PRESETS.find(function(x) { return x.key === key; });
  return p ? Object.assign({}, form, p.fields) : form;
}
