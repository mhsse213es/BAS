// Markup for the scenario drawer's Overview tab. Pure: it takes the structured description (scn-structure.js) and the
// scenario's facts and returns HTML, so it can be tested and previewed without the console. Every dynamic value goes
// through x(); behaviour is attached with data-on-* only.
import { x } from '../core/escape.js';
import { on } from '../core/actions.js';
import { structureDescription } from './scn-structure.js';

function svg(inner) {
  return '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + inner + '</svg>';
}
var ICON = {
  shield: svg('<path d="M12 3l8 3v6c0 4.5-3.3 8-8 9-4.7-1-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>'),
  note: svg('<circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v5h1"/>'),
  info: svg('<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 9h8M8 13h8M8 17h5"/>'),
  layers: svg('<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>'),
  verdict: svg('<path d="M5 12l4 4 10-10"/>'),
  monitor: svg('<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>'),
  play: svg('<circle cx="12" cy="12" r="9"/><path d="M10 8.5l5 3.5-5 3.5z"/>'),
  steps: svg('<path d="M4 6h10M4 12h14M4 18h8"/>'),
  target: svg('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3"/>'),
  user: svg('<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4-6 8-6s7 2 8 6"/>'),
  sign: svg('<path d="M12 3l8 3v6c0 4.5-3.3 8-8 9-4.7-1-8-4.5-8-9V6z"/>'),
  source: svg('<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>'),
  check: svg('<path d="M5 12l4 4 10-10"/>'),
  flask: svg('<path d="M9 3h6M10 3v6l-5 9a2 2 0 002 3h10a2 2 0 002-3l-5-9V3"/>')
};

// Inline formatting for a piece of description text: technique ids, verdict words and code-like names get their own
// look; everything else is escaped text. Matching runs on the raw text so nothing is escaped twice.
var INLINE = /(T\d{4}(?:\.\d{3})?)|\b(PASS|FAIL|ERROR|SKIPPED|SKIP|BLOCKED|ALLOWED)\b|((?:[A-Za-z0-9_.-]+\/)+[A-Za-z0-9_.-]+\.(?:yaml|json|md|ps1|sh)|\b[a-z][a-z0-9]*(?:_[a-z0-9]+){1,}\b|\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){1,}\b)/g;
var VERDICT_TONE = { PASS: 'ok', BLOCKED: 'ok', DETECTED: 'info', FAIL: 'bad', ALLOWED: 'bad', ERROR: 'warn', SKIP: 'mute', SKIPPED: 'mute', PARTIAL: 'warn', INCONCLUSIVE: 'warn', NOTDETECTED: 'bad' };

export function inlineHtml(text) {
  var s = String(text == null ? '' : text), out = '', last = 0, m;
  INLINE.lastIndex = 0;
  while ((m = INLINE.exec(s)) !== null) {
    out += x(s.slice(last, m.index));
    if (m[1]) out += '<code class="ov-tech">' + x(m[1]) + '</code>';
    else if (m[2]) out += '<span class="ov-v ov-' + (VERDICT_TONE[m[2]] || 'mute') + '">' + x(m[2]) + '</span>';
    else out += '<code class="ov-code">' + x(m[3]) + '</code>';
    last = m.index + m[0].length;
  }
  return out + x(s.slice(last));
}

function p(text) { return '<p>' + inlineHtml(text) + '</p>'; }

function stagesHtml(items) {
  return '<ol class="ov-stages">' + items.map(function(it) {
    var sub = /[a-z]$/i.test(it.n);
    return '<li' + (sub ? ' class="sub"' : '') + '><span class="ov-n">' + x(it.n) + '</span><div><b>' + inlineHtml(it.title) + '</b>' +
      (it.detail ? '<span>' + inlineHtml(it.detail) + '</span>' : '') + '</div></li>';
  }).join('') + '</ol>';
}

var TIER_TONE = [[/posture|default|safe/i, 'ok'], [/telemetry|opt-in|approval/i, 'warn'], [/lab|isolated|full-fidelity/i, 'bad']];
function tierTone(name) { for (var i = 0; i < TIER_TONE.length; i++) if (TIER_TONE[i][0].test(name)) return TIER_TONE[i][1]; return 'info'; }
function bulletsHtml(b, asTiers) {
  return '<ul class="ov-bullets' + (asTiers ? ' tiers' : '') + '">' + b.map(function(it) {
    var tone = asTiers && it.name ? ' t-' + tierTone(it.name) : '';
    return '<li class="' + tone.trim() + '">' + (it.name ? '<b>' + inlineHtml(it.name) + '</b>' : '') + '<span>' + inlineHtml(it.text) + '</span></li>';
  }).join('') + '</ul>';
}

function sectionBody(s) {
  var h = '';
  if (s.verdicts) {
    h += '<div class="ov-verdicts">' + s.verdicts.map(function(v) {
      return '<div class="ov-verdict"><span class="ov-v ov-' + (VERDICT_TONE[v.verdict] || 'mute') + '">' + x(v.verdict) + '</span><span>' + inlineHtml(v.text) + '</span></div>';
    }).join('') + '</div>';
  }
  if (s.chips) h += '<div class="ov-chips">' + s.chips.map(function(c) { return '<span class="ov-chip">' + inlineHtml(c) + '</span>'; }).join('') + '</div>';
  h += s.paras.map(p).join('');
  if (s.items.length) h += stagesHtml(s.items);
  if (s.defs.length) h += '<dl class="ov-defs">' + s.defs.map(function(d) { return '<dt>' + inlineHtml(d.key) + '</dt><dd>' + inlineHtml(d.text) + '</dd>'; }).join('') + '</dl>';
  if (s.bullets.length) h += bulletsHtml(s.bullets, s.kind === 'tiers');
  return h;
}

var KIND_ICON = { safety: 'shield', note: 'note', verdicts: 'verdict', tiers: 'layers', stages: 'steps', chips: 'layers', info: 'info', defs: 'info', text: 'info' };
export function sectionHtml(s) {
  return '<section class="ov-card k-' + x(s.kind) + '"><header><span class="ov-ico">' + (ICON[KIND_ICON[s.kind] || 'info']) + '</span><h4>' + x(s.title) + '</h4></header><div class="ov-body">' + sectionBody(s) + '</div></section>';
}

// describeHtml: the hero (badges, lead sentence, remaining intro paragraphs) followed by one card per section.
export function describeHtml(text, afterHero) {
  var d = structureDescription(text);
  var badges = d.badges.map(function(b) { return '<span class="ov-badge b-' + x(b.tone) + '">' + (b.tone === 'warn' ? ICON.flask : '') + x(b.label) + '</span>'; }).join('');
  var hero = '';
  if (d.lead || badges || d.body.length) {
    hero = '<div class="ov-hero">' + (badges ? '<div class="ov-badges">' + badges + '</div>' : '') +
      (d.lead ? '<p class="ov-lead' + (d.lead.length > 220 ? ' long' : '') + '">' + inlineHtml(d.lead) + '</p>' : '') +
      (d.body.length ? '<div class="ov-about">' + d.body.map(p).join('') + '</div>' : '') + '</div>';
  }
  return hero + (afterHero || '') + d.sections.map(sectionHtml).join('');
}

// factsHtml: the scenario's facts as tiles. facts = [{ icon, label, value, mono }].
export function factsHtml(facts) {
  return '<div class="ov-facts">' + facts.map(function(f) {
    return '<div class="ov-fact"><span class="ov-fico">' + (ICON[f.icon] || '') + '</span><div><span class="ov-flbl">' + x(f.label) + '</span><b' + (f.mono ? ' class="mono"' : '') + '>' + x(f.value) + '</b></div></div>';
  }).join('') + '</div>';
}

// techniqueChipsHtml: each technique id as a chip that opens its MITRE details.
export function techniqueChipsHtml(ids) {
  if (!ids.length) return '';
  return '<section class="ov-card k-tech"><header><span class="ov-ico">' + ICON.target + '</span><h4>ATT&amp;CK techniques <em>' + ids.length + '</em></h4></header><div class="ov-body"><div class="ov-chips">' +
    ids.map(function(id) { return '<button type="button" class="ov-chip ov-tchip"' + on('click', 'openTechniqueDetail', id) + ' title="Show MITRE details for ' + x(id) + '">' + x(id) + '</button>'; }).join('') + '</div></div></section>';
}

// checklistHtml: the prerequisites as a tidy list with a tick on each.
export function checklistHtml(title, items) {
  return '<section class="ov-card k-reqs"><header><span class="ov-ico">' + ICON.check + '</span><h4>' + x(title) + '</h4></header><div class="ov-body"><ul class="ov-checks">' +
    items.map(function(i) { return '<li>' + ICON.check + '<span>' + inlineHtml(i) + '</span></li>'; }).join('') + '</ul></div></section>';
}
