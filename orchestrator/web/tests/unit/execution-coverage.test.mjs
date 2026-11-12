import { test } from 'node:test';
import assert from 'node:assert/strict';

const E = await import('../../src/features/execution-coverage.js');

const doc = {
  scheduled: 100, executed: 80, prevented: 0, partiallyExecuted: 0, notExecuted: 10,
  unsupported: 0, timedOut: 5, executionError: 3, cancelled: 0, skipped: 2, coveragePct: 80,
};

test('shows the coverage percentage and the scheduled count', () => {
  const html = E.executionCoverageHtml(doc);
  assert.match(html, />80%</);
  assert.match(html, /80 of 100 scheduled steps/);
});

test('lists each outcome that has a count, with its customer-facing label', () => {
  const html = E.executionCoverageHtml(doc);
  assert.match(html, /Executed<\/span><b>80/);
  assert.match(html, /Not executed<\/span><b>10/);
  assert.match(html, /Timed out<\/span><b>5/);
  assert.match(html, /Execution error<\/span><b>3/);
  assert.match(html, /Skipped<\/span><b>2/);
});

test('leaves out outcomes with a zero count', () => {
  const html = E.executionCoverageHtml(doc);
  assert.doesNotMatch(html, /Prevented/);
  assert.doesNotMatch(html, /Unsupported/);
  assert.doesNotMatch(html, /Cancelled/);
});

test('escapes nothing it does not need to, and never shows NaN', () => {
  const html = E.executionCoverageHtml({ scheduled: 0, coveragePct: 0 });
  assert.doesNotMatch(html, /NaN/);
  assert.match(html, />0%</);
});

test('no report payload gives nothing to show, not a fake 0%', () => {
  assert.equal(E.executionCoverageHtml(undefined), '');
  assert.equal(E.executionCoverageHtml(null), '');
});
