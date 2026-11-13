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
    if (minutesOfDay(f.timeFrom) === null || minutesOfDay(f.timeTo) === null) return refuse('Times must be HH:MM.');
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
    return {
      payload: {
        name: name, kind: 'daily', timeFrom: f.timeFrom, timeTo: f.timeTo, timezone: tz,
        validFrom: validFrom, validTo: validTo
      },
      error: ''
    };
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
    const overnight = minutesOfDay(b.TimeFrom) > minutesOfDay(b.TimeTo) ? ' (overnight)' : '';
    let text = 'Daily ' + b.TimeFrom + ' to ' + b.TimeTo + ' ' + b.Timezone + overnight;
    if (b.ValidFrom || b.ValidTo) text += ', ' + (b.ValidFrom || 'open') + ' to ' + (b.ValidTo || 'open');
    return text;
  }
  return b.Kind || '';
}
