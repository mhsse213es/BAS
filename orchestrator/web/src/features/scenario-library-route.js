// Routes one Scenario Library entry to exactly one execution path. The route is
// decided by the server-set type and status only. Nothing is inferred from a
// name or an ID, and anything malformed, unknown, or not executable has no path.

export const LIBRARY_TYPE_AGENT = 'agent';
export const LIBRARY_TYPE_PHISHING = 'phishing';

const RUNNABLE_STATUSES = ['executable', 'experimental'];

export function libraryEntryRoute(entry) {
  if (!entry || typeof entry !== 'object') return { kind: 'none' };
  if (!RUNNABLE_STATUSES.includes(entry.status)) return { kind: 'none' };
  if (entry.type === LIBRARY_TYPE_AGENT) return { kind: 'agent', id: entry.id };
  if (entry.type === LIBRARY_TYPE_PHISHING) return { kind: 'phishing', id: entry.id };
  return { kind: 'none' };
}

// Builds the POST body for a phishing run from the library form. Only the
// schema's own fields are sent, values are trimmed, and numbers become numbers.
// The server validates every parameter again: this check is for the form alone.
export function buildPhishingRunRequest(entry, values) {
  const route = libraryEntryRoute(entry);
  if (route.kind !== LIBRARY_TYPE_PHISHING) return { ok: false, errors: ['not-a-runnable-phishing-entry'] };
  const specs = Array.isArray(entry.parameters) ? entry.parameters : [];
  const parameters = {};
  const errors = [];
  for (const spec of specs) {
    const raw = values && typeof values[spec.name] === 'string' ? values[spec.name].trim() : '';
    if (raw === '') {
      if (spec.required) errors.push(spec.name);
      continue;
    }
    if (spec.kind === 'number') {
      const n = Number(raw);
      if (!Number.isInteger(n) || n <= 0) { errors.push(spec.name); continue; }
      parameters[spec.name] = n;
    } else if (spec.kind === 'email') {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(raw)) { errors.push(spec.name); continue; }
      parameters[spec.name] = raw;
    } else {
      parameters[spec.name] = raw;
    }
  }
  if (errors.length) return { ok: false, errors };
  return { ok: true, body: { scenarioId: route.id, parameters } };
}
