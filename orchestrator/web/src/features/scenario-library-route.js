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
