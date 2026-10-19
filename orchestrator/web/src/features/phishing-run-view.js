// Describes one phishing run for display. Pure functions only, so the wording rules
// are unit-tested without a browser.
//
// Rules this file enforces:
//  - PH-ID-001 user behavior is a behavioral observation, never a control verdict.
//  - Inconclusive is shown as "not graded", visibly different from pass and fail.
//  - A provisional PH-ID-001 result is labelled provisional until its window closes.

export const TONE_PASS = 'pass';
export const TONE_FAIL = 'fail';
export const TONE_INCONCLUSIVE = 'inconclusive';
export const TONE_BEHAVIOR = 'behavior';
export const TONE_NEUTRAL = 'neutral';

const BEHAVIOR_SUFFIX = 'Behavioral observation, not a control verdict.';

function parseResult(raw) {
  if (raw == null || raw === '') return null;
  if (typeof raw === 'object') return raw;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

// Maps one verdict to a tone and a label. Anything unknown is neutral, never a pass.
export function verdictTone(verdict) {
  switch (verdict) {
    case 'pass': return { tone: TONE_PASS, label: 'Pass' };
    case 'fail': return { tone: TONE_FAIL, label: 'Fail' };
    case 'inconclusive': return { tone: TONE_INCONCLUSIVE, label: 'Inconclusive: not graded' };
    case 'not_applicable': return { tone: TONE_BEHAVIOR, label: 'Observed' };
    case 'not_tested': return { tone: TONE_INCONCLUSIVE, label: 'Not tested: not graded' };
    default: return { tone: TONE_NEUTRAL, label: 'Unknown' };
  }
}

// PH-ID-001 is the behavioral scenario. Its user-interaction row is a behavior, so it
// is labelled as one and never as a control verdict.
function userInteractionRow(result) {
  const d = result.UserInteraction;
  if (!d) return null;
  const { tone } = verdictTone(d.Verdict);
  if (d.Verdict === 'not_applicable') {
    return {
      label: 'Observed user behavior',
      text: `${d.Reason || ''} ${BEHAVIOR_SUFFIX}`.trim(),
      tone: TONE_BEHAVIOR,
    };
  }
  if (d.Verdict === 'inconclusive') {
    return {
      label: 'Behavior: inconclusive, not graded',
      text: `${d.Reason || 'no behavioral telemetry'} ${BEHAVIOR_SUFFIX}`.trim(),
      tone: TONE_INCONCLUSIVE,
    };
  }
  return { label: 'Observed user behavior', text: d.Reason || '', tone };
}

const CONTROL_DIMENSIONS = [
  ['Delivery', 'Delivery'],
  ['Enforcement', 'Enforcement'],
  ['Detection', 'Detection'],
  ['Response', 'Response'],
];

// describePhishingRun turns one run from GET /api/phishing-runs into display rows.
export function describePhishingRun(run) {
  const status = run.status || 'unknown';
  const out = {
    id: run.id,
    scenarioId: run.scenarioId,
    status,
    error: run.error || '',
    rows: [],
    provisional: false,
    note: '',
  };
  const parsed = parseResult(run.result);

  if (status === 'failed') {
    out.note = run.error ? `Not graded: ${run.error}` : 'Not graded.';
    return out;
  }
  if (status === 'pending' || status === 'running') {
    out.note = 'Still running. No final result yet.';
    return out;
  }
  if (!parsed) {
    out.note = 'No result recorded.';
    return out;
  }
  if (parsed.dispatch && !parsed.Response && !parsed.UserInteraction && !parsed.Delivery) {
    out.note = 'Dispatched to EmailGW. Waiting for its result.';
    return out;
  }

  const ui = userInteractionRow(parsed);
  if (ui) out.rows.push(ui);
  for (const [key, label] of CONTROL_DIMENSIONS) {
    const d = parsed[key];
    if (!d || !d.Verdict) continue;
    const { tone, label: verdictLabel } = verdictTone(d.Verdict);
    out.rows.push({ label, text: `${verdictLabel}. ${d.Reason || ''}`.trim(), tone });
  }

  if (parsed.Collection && parsed.Collection.windowEnd) {
    const end = Date.parse(parsed.Collection.windowEnd);
    if (!Number.isNaN(end) && Date.now() < end) {
      out.provisional = true;
      out.note = 'Provisional: the observation window is still open.';
    }
  }
  return out;
}
