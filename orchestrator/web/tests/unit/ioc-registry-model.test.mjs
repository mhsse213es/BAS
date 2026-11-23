import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as M from '../../src/features/ioc-model.js';

test('agoText switches to days from two days on', () => {
  const now = Date.parse('2026-11-23T12:00:00Z');
  assert.equal(M.agoText('2026-11-23T11:59:50Z', now), 'just now');
  assert.equal(M.agoText('2026-11-23T11:15:00Z', now), '45m ago');
  assert.equal(M.agoText('2026-11-23T09:00:00Z', now), '3h ago');
  assert.equal(M.agoText('2026-11-21T00:00:00Z', now), '2d ago');
  assert.equal(M.agoText('2026-10-24T12:00:00Z', now), '30d ago');
  assert.equal(M.agoText('', now), '—');
});

test('filtersActive ignores blank search and the suppressed display choice', () => {
  assert.equal(M.filtersActive({}), false);
  assert.equal(M.filtersActive({ search: '   ' }), false);
  assert.equal(M.filtersActive({ type: 'ip' }), true);
  assert.equal(M.filtersActive({ search: 'x' }), true);
});

test('guessType recognises the common indicator shapes', () => {
  assert.equal(M.guessType('203.0.113.9'), 'ip');
  assert.equal(M.guessType('2001:db8::1'), 'ip');
  assert.equal(M.guessType('https://evil.example/x'), 'url');
  assert.equal(M.guessType('a@b.example'), 'email');
  assert.equal(M.guessType('d41d8cd98f00b204e9800998ecf8427e'), 'file_hash');
  assert.equal(M.guessType('HKCU\Software\Run'), 'registry_key');
  assert.equal(M.guessType('evil-domain.com'), 'domain');
  assert.equal(M.guessType('rundll32.exe'), 'domain'); // looks like a hostname; the user can change it
  assert.equal(M.guessType('powershell -enc AAA'), '');
  assert.equal(M.guessType(''), '');
});

test('isDuplicate matches on type and exact value', () => {
  const rows = [{ type: 'domain', value: 'a.example', status: 'draft' }];
  assert.equal(M.isDuplicate(rows, 'domain', ' a.example ').status, 'draft');
  assert.equal(M.isDuplicate(rows, 'ip', 'a.example'), null);
});

test('parseImportLines refuses unknown types before anything is sent', () => {
  assert.deepEqual(M.parseImportLines('domain,a.example\nIP,192.0.2.1').entries, [{ type: 'domain', value: 'a.example' }, { type: 'ip', value: '192.0.2.1' }]);
  assert.deepEqual(M.parseImportLines('File Hash,abc').entries, [{ type: 'file_hash', value: 'abc' }]);
  assert.match(M.parseImportLines('domain,a\nfoo,b').error, /Line 2: unknown type "foo"/);
  assert.match(M.parseImportLines('badline').error, /Line 1 is not "type,value"/);
  assert.match(M.parseImportLines('  \n ').error, /at least one/);
  assert.equal(M.parseImportLines('command_line,a,b,c').entries[0].value, 'a,b,c');
});
