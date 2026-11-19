// The ATT&CK techniques the loaded scenarios use, grouped by tactic, plus clean-up of MITRE's description text.
// Pure: names and tactics come from GET /api/attack/matrix (MITRE's dataset), usage comes from the scenarios.

import { techniquesOf } from './scn-model.js';

function arr(v) { return Array.isArray(v) ? v : []; }

// techniqueIndex({scenarios, matrix}) -> { total, tacticCount, tactics:[{id,name,items:[{id,name,count}]}], unknown:[{id,count}], users:{id:[{id,name}]} }
// A technique in several tactics is listed under each, but counted once in `total`. A technique id the dataset does
// not know is kept in `unknown` rather than dropped or guessed at.
export function techniqueIndex(o) {
  var users = {};
  arr(o.scenarios).forEach(function(s) {
    techniquesOf(s).forEach(function(t) {
      (users[t] = users[t] || []).push({ id: s.id, name: s.name || s.id });
    });
  });
  var known = {};
  var tactics = arr(o.matrix && o.matrix.tactics).map(function(tac) {
    var items = arr(tac.techniques).filter(function(t) { return users[t.id]; }).map(function(t) {
      known[t.id] = 1;
      return { id: t.id, name: t.name, count: users[t.id].length };
    });
    items.sort(function(a, b) { return a.id < b.id ? -1 : a.id > b.id ? 1 : 0; });
    return { id: tac.id, name: tac.name, items: items };
  }).filter(function(tac) { return tac.items.length; });
  var unknown = Object.keys(users).filter(function(id) { return !known[id]; }).sort()
    .map(function(id) { return { id: id, count: users[id].length }; });
  return { total: Object.keys(users).length, tacticCount: tactics.length, tactics: tactics, unknown: unknown, users: users };
}

// filterIndex keeps the techniques whose id or name contains q (case-insensitive); an empty q keeps everything.
export function filterIndex(idx, q) {
  q = String(q || '').trim().toLowerCase();
  if (!q) return idx;
  var hit = function(t) { return t.id.toLowerCase().indexOf(q) >= 0 || String(t.name || '').toLowerCase().indexOf(q) >= 0; };
  return {
    total: idx.total, tacticCount: idx.tacticCount, users: idx.users,
    tactics: idx.tactics.map(function(t) { return { id: t.id, name: t.name, items: t.items.filter(hit) }; }).filter(function(t) { return t.items.length; }),
    unknown: idx.unknown.filter(function(u) { return u.id.toLowerCase().indexOf(q) >= 0; }),
  };
}

// MITRE text carries "(Citation: Name)" markers and [text](url) links. Show the words, not the markup.
export function cleanDescription(s) {
  return String(s || '')
    .replace(/\s*\(Citation:[^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\((?:[^)]+)\)/g, '$1')
    .replace(/<\/?code>/g, '')
    .replace(/[ \t]+\n/g, '\n')
    .trim();
}

// The paragraphs of a cleaned description, so each renders as its own block.
export function paragraphs(s) {
  return cleanDescription(s).split(/\n{2,}|\n/).map(function(p) { return p.trim(); }).filter(Boolean);
}

// Only MITRE's own links are offered as links; anything else is shown as text.
export function safeMitreUrl(u) {
  return /^https:\/\/attack\.mitre\.org\//.test(String(u || '')) ? u : '';
}
