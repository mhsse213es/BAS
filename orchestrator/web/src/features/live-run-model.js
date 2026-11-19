// Live run panel: the figures and lines it prints, kept apart from the DOM so they can be tested.
// Everything here comes from the run record the Live Runs page already loaded and from the run events
// the panel already streams. Nothing is estimated or made up: with no run record the panel shows "—".

export var LOG_LIMIT = 200;

var VERDICT_LABEL = { pass: 'Prevented', fail: 'Not Prevented', blocked: 'Blocked (AV)', error: 'Error', schedule: 'Timeout', execute: 'Timeout', skipped: 'Skipped (Scheduler)', vetoed: 'Vetoed (Policy)' };

// fmtDuration: 42s, 18m 40s, 1h 05m. A negative span (this browser's clock is behind the server's) prints 0s.
export function fmtDuration(ms) {
  if (typeof ms !== 'number' || isNaN(ms)) return '—';
  var s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return s + 's';
  var m = Math.floor(s / 60);
  if (m < 60) return m + 'm ' + String(s % 60).padStart(2, '0') + 's';
  var h = Math.floor(m / 60);
  return h + 'h ' + String(m % 60).padStart(2, '0') + 'm';
}

var LIVE = { running: 1, pending: 1, queued: 1 };

// runDuration: time since the run started while it is live, start to completion once it has finished.
export function runDuration(run, now) {
  if (!run || !run.startedAt) return '—';
  var start = new Date(run.startedAt).getTime();
  if (isNaN(start)) return '—';
  var st = String(run.status || '').toLowerCase();
  if (!LIVE[st] && run.completedAt) {
    var end = new Date(run.completedAt).getTime();
    return isNaN(end) ? '—' : fmtDuration(end - start);
  }
  return fmtDuration((now == null ? Date.now() : now) - start);
}

// liveStatus: the chip at the top of the panel. A paused or resumed event seen on the stream wins over a run record
// that has not been reloaded yet (st.paused is undefined until such an event arrives).
export function liveStatus(run, st) {
  st = st || {};
  if (!run) {
    if (st.running > 0) return { key: 'running', label: 'Running', tone: 'info', live: true };
    if (st.total > 0 && st.done >= st.total) return { key: 'finished', label: 'Finished', tone: 'ok', live: false };
    return { key: 'waiting', label: 'Waiting', tone: 'warn', live: true };
  }
  var s = String(run.status || '').toLowerCase();
  if (s === 'pending' || s === 'queued') return { key: 'queued', label: 'Queued', tone: 'warn', live: true };
  if (s === 'running') {
    var paused = st.paused != null ? st.paused : !!run.paused;
    if (run.agentDisconnected) return { key: 'disconnected', label: 'Agent Disconnected', tone: 'bad', live: true };
    if (paused) return { key: 'paused', label: 'Paused', tone: 'warn', live: true };
    return { key: 'running', label: 'Running', tone: 'info', live: true };
  }
  if (s === 'completed') return { key: 'completed', label: 'Completed', tone: 'ok', live: false };
  if (s === 'partial' || s === 'cancelled') return { key: s, label: s === 'partial' ? 'Partial' : 'Cancelled', tone: 'warn', live: false };
  if (s === 'failed') return { key: 'failed', label: 'Failed', tone: 'bad', live: false };
  return { key: s || 'unknown', label: s ? s.charAt(0).toUpperCase() + s.slice(1) : 'Unknown', tone: 'info', live: false };
}

export function progressPct(st) {
  if (!st || !st.total) return 0;
  return Math.max(0, Math.min(100, Math.round(st.done / st.total * 100)));
}

function fmtStepMs(ms) {
  if (typeof ms !== 'number') return '';
  return ms >= 1000 ? (Math.round(ms / 100) / 10) + ' s' : ms + ' ms';
}

// stepNote: the one line under a step title.
export function stepNote(s) {
  s = s || {};
  if (s.state === 'running') return 'Running…';
  if (s.state === 'queued' || !s.state) return 'Pending';
  if (s.state === 'killed') return 'Stopped';
  var dur = fmtStepMs(s.durationMs);
  if (s.state === 'timeout') return 'Timed out' + (dur ? ' · ' + dur : '');
  var label = (s.verdict && VERDICT_LABEL[s.verdict]) || 'Done';
  return label + (dur ? ' · ' + dur : '');
}

// stepMark: which marker the timeline draws for a step.
export function stepMark(s) {
  s = s || {};
  if (s.state === 'running') return 'run';
  if (s.state === 'queued' || !s.state) return 'wait';
  if (s.state === 'timeout' || s.state === 'killed' || s.verdict === 'fail' || s.verdict === 'error') return 'fail';
  if (s.verdict === 'blocked' || s.verdict === 'vetoed') return 'warn';
  return 'done';
}

function hms(iso) {
  if (!iso) return '';
  var d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  return [d.getHours(), d.getMinutes(), d.getSeconds()].map(function(n) { return String(n).padStart(2, '0'); }).join(':');
}

// logLine: one persisted run event as one log line, or null for an event that is not worth a line
// (queueing every step of a large sweep would bury the lines that matter) or that we do not know.
export function logLine(e) {
  if (!e || !e.type) return null;
  var time = hms(e.ts);
  var tech = e.techniqueId ? e.techniqueId + (e.stepName ? ' — ' + e.stepName : '') : (e.stepName || 'step');
  var p = e.payload || {};
  switch (e.type) {
    case 'run_started': return { time: time, text: 'Run started' + (p.stepsTotal ? ' (' + p.stepsTotal + ' steps)' : ''), tone: 'inf' };
    case 'started': return { time: time, text: 'Started ' + tech, tone: 'inf' };
    case 'completed': {
      var v = p.verdict;
      var tone = v === 'pass' ? 'ok' : (v === 'fail' || v === 'error') ? 'bad' : (v === 'blocked' || v === 'vetoed') ? 'warn' : 'inf';
      var dur = fmtStepMs(p.durationMs);
      return { time: time, text: tech + ' — ' + ((v && VERDICT_LABEL[v]) || 'Done') + (dur ? ' (' + dur + ')' : ''), tone: tone };
    }
    case 'timeout': return { time: time, text: tech + ' — Timed out', tone: 'bad' };
    case 'killed': return { time: time, text: tech + ' — Stopped', tone: 'warn' };
    case 'paused': return { time: time, text: 'Paused', tone: 'warn' };
    case 'resumed': return { time: time, text: 'Resumed', tone: 'inf' };
    default: return null;
  }
}

// appendLog: add a line and keep only the newest LOG_LIMIT.
export function appendLog(lines, line) {
  if (!line) return lines;
  var next = lines.concat([line]);
  return next.length > LOG_LIMIT ? next.slice(next.length - LOG_LIMIT) : next;
}
