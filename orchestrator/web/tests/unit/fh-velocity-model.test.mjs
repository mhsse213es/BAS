import { test } from 'node:test';
import assert from 'node:assert/strict';
import { velocityModel, fmtDuration, STAGE_ORDER } from '../../src/features/fh-velocity-model.js';

// One SLAReport per stage, as GET /api/intel/factory/sla?stage=<s> returns it.
// Percentiles are per (source, content_type) validated segment; queue/generation
// legs can be absent for a leg that validated without a recorded eligible.
const reports = {
  queue: {
    stage: 'queue',
    segments: [{ source: 'OTX', content_type: 'emulates', cohort: 'validated', n: 4, p50_seconds: 300, p95_seconds: 900 }],
    open_count: 2, oldest_open_seconds: 90000, bottleneck: 'validation', incomplete_window: false,
  },
  generation: {
    stage: 'generation',
    segments: [{ source: 'OTX', content_type: 'emulates', cohort: 'validated', n: 4, p50_seconds: 120, p95_seconds: 240 }],
    open_count: 2, oldest_open_seconds: 90000, bottleneck: 'validation', incomplete_window: false,
  },
  validation: {
    stage: 'validation',
    segments: [{ source: 'OTX', content_type: 'emulates', cohort: 'validated', n: 4, p50_seconds: 600, p95_seconds: 1800 }],
    open_count: 2, oldest_open_seconds: 90000, bottleneck: 'validation', incomplete_window: false,
  },
  end_to_end: {
    stage: 'end_to_end',
    segments: [
      { source: 'OTX', content_type: 'emulates', cohort: 'validated', n: 4, p50_seconds: 7200, p95_seconds: 15000 },
      { source: 'OTX', content_type: 'emulates', cohort: 'failed', n: 1 },
    ],
    open_count: 2, oldest_open_seconds: 90000, bottleneck: 'validation', incomplete_window: false,
  },
};

test('STAGE_ORDER is the pipeline order, end_to_end last', () => {
  assert.deepEqual(STAGE_ORDER, ['queue', 'generation', 'validation', 'end_to_end']);
});

test('velocityModel builds one row per validated segment with each stage p50/p95', () => {
  const m = velocityModel(reports);
  assert.equal(m.hasData, true);
  assert.equal(m.rows.length, 1);
  const row = m.rows[0];
  assert.equal(row.source, 'OTX');
  assert.equal(row.contentType, 'emulates');
  assert.equal(row.n, 4); // the end_to_end validated count
  assert.equal(row.stages.queue.p50, 300);
  assert.equal(row.stages.generation.p50, 120);
  assert.equal(row.stages.validation.p50, 600);
  assert.equal(row.stages.validation.p95, 1800);
  assert.equal(row.stages.end_to_end.p50, 7200);
});

test('velocityModel summary: cohort counts, oldest-open, bottleneck, incomplete', () => {
  const m = velocityModel(reports);
  assert.equal(m.summary.validatedN, 4);
  assert.equal(m.summary.failedN, 1);
  assert.equal(m.summary.openN, 2);
  assert.equal(m.summary.oldestOpenSeconds, 90000);
  assert.equal(m.summary.bottleneck, 'validation');
  assert.equal(m.summary.incomplete, false);
});

test('velocityModel: a stage with no validated figure for a segment is null, not fabricated', () => {
  // end_to_end + validation present, but the leg never recorded eligible so
  // queue/generation have no validated segment for it.
  const partial = {
    queue: { stage: 'queue', segments: [], open_count: 0, bottleneck: '', incomplete_window: true },
    generation: { stage: 'generation', segments: [], open_count: 0, bottleneck: '', incomplete_window: true },
    validation: { stage: 'validation', segments: [{ source: 'MISP', content_type: 'generated_for', cohort: 'validated', n: 1, p50_seconds: 540, p95_seconds: 540 }], open_count: 0, bottleneck: '', incomplete_window: true },
    end_to_end: { stage: 'end_to_end', segments: [{ source: 'MISP', content_type: 'generated_for', cohort: 'validated', n: 1, p50_seconds: 9000, p95_seconds: 9000 }], open_count: 0, bottleneck: '', incomplete_window: true },
  };
  const m = velocityModel(partial);
  assert.equal(m.rows.length, 1);
  assert.equal(m.rows[0].stages.queue, null);
  assert.equal(m.rows[0].stages.generation, null);
  assert.equal(m.rows[0].stages.validation.p50, 540);
  assert.equal(m.summary.incomplete, true);
});

test('velocityModel: no validated coverage yet -> hasData false', () => {
  const none = {
    queue: { stage: 'queue', segments: [{ source: 'OTX', content_type: '', cohort: 'open', n: 3 }], open_count: 3, oldest_open_seconds: 1000, bottleneck: '', incomplete_window: false },
    generation: { stage: 'generation', segments: [], open_count: 3, bottleneck: '', incomplete_window: false },
    validation: { stage: 'validation', segments: [], open_count: 3, bottleneck: '', incomplete_window: false },
    end_to_end: { stage: 'end_to_end', segments: [{ source: 'OTX', content_type: '', cohort: 'open', n: 3 }], open_count: 3, oldest_open_seconds: 1000, bottleneck: '', incomplete_window: false },
  };
  const m = velocityModel(none);
  assert.equal(m.hasData, false);
  assert.equal(m.rows.length, 0);
  assert.equal(m.summary.openN, 3);
});

test('velocityModel tolerates null/missing reports without throwing', () => {
  const m = velocityModel({});
  assert.equal(m.hasData, false);
  assert.equal(m.rows.length, 0);
  assert.equal(m.summary.validatedN, 0);
  assert.equal(m.summary.openN, 0);
  assert.doesNotThrow(() => velocityModel(null));
});

test('fmtDuration: seconds, minutes, hours, days, and null', () => {
  assert.equal(fmtDuration(null), '—');
  assert.equal(fmtDuration(undefined), '—');
  assert.equal(fmtDuration(45), '45s');
  assert.equal(fmtDuration(600), '10m');
  assert.equal(fmtDuration(7200), '2.0h');
  assert.equal(fmtDuration(90000), '25.0h'); // under the 48h cutoff, still hours
  assert.equal(fmtDuration(259200), '3.0d');
});
