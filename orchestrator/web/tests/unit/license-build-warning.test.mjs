import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupDom, load } from './dom.mjs';

setupDom();
const fns = await load(['licenseBuildNotice']);

test('no notice when the licence matches or is below the build', () => {
  assert.equal(fns.licenseBuildNotice({ tier: 'Core', buildTier: 'Core', buildMismatch: '' }), '');
  assert.equal(fns.licenseBuildNotice({ tier: 'Core', buildTier: 'Enterprise' }), '');
  assert.equal(fns.licenseBuildNotice({}), '');
  assert.equal(fns.licenseBuildNotice(null), '');
});

test('a licence above the build shows the server\'s warning, as text only', () => {
  const html = fns.licenseBuildNotice({ tier: 'Enterprise', buildTier: 'Core', buildMismatch: 'Built for Core, licence is <b>Enterprise</b>.' });
  assert.ok(html.includes('Built for Core'), html);
  assert.ok(!html.includes('<b>'), 'the message must be escaped, never interpreted as markup');
  assert.ok(/mismatch|package/i.test(html), html);
});
