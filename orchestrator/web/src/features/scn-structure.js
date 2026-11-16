// Turns a scenario description into a structured overview model. Descriptions are written as plain text with their own
// conventions: lines that are real paragraph breaks, "LABEL:" headings (ALL CAPS or a known name such as "Safety:"),
// numbered stage lines, "- " tier bullets and "PASS = ..." verdict legends. This reads those conventions line by line
// (parseDescription in scn-describe.js flattens every newline first, which is why most descriptions looked like one wall
// of text). The stored text is never changed; only how the Overview presents it.

// Labels that head a section when they are not written in capitals.
var KNOWN = ['Safety', 'Production-safe', 'Guardrails', 'Expected verdicts', 'Verdicts', 'Notes', 'Note', 'Fidelity',
  'Coverage', 'Covers', 'Per-OS', 'Preconditions', 'Prerequisites', 'Confidence', 'Not assessed by this scenario', 'Not assessed', 'Tiers', 'Families',
  'Scope', 'Known scope limitation', 'Limitations', 'Ordering caveat', 'Caveat', 'Source grounding', 'Requires',
  'Verification', 'Unverified until run in the lab'];

var CAPS = '[A-Z][A-Z0-9]*(?:[ ,/&()\'-]+[A-Z][A-Z0-9]*)*';
var KNOWN_RE = KNOWN.map(function(k) { return k.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&'); }).join('|');
// A label counts only at the start of a line or after the end of a sentence, so "the note: x" inside prose is left alone.
function headingRe() { return new RegExp('(?:^|(?<=[.!?)]\\s))(' + CAPS + '|' + KNOWN_RE + '):(?=\\s|$)', 'gi'); }

function isHeading(title) {
  var t = title.trim();
  if (/^[A-Z][A-Z0-9 ,/&()'-]+$/.test(t)) return t.length >= 5 && /[A-Z]{3}/.test(t);
  return KNOWN.some(function(k) { return k.toLowerCase() === t.toLowerCase(); });
}

var KEEP_UPPER = { SEBI: 1, RBI: 1, DLP: 1, OS: 1, IOC: 1, IOCS: 1, EDR: 1, AV: 1, API: 1, MITRE: 1, ATT: 1, CK: 1, PCI: 1, TLS: 1, DNS: 1, SMB: 1, LDAP: 1, AD: 1, MFA: 1, SSH: 1, CIS: 1, STIG: 1, CSCRF: 1, SWIFT: 1, ATM: 1, UPI: 1, VSS: 1 };
function pretty(title) {
  var t = title.trim().replace(/\s+/g, ' ');
  if (!/^[A-Z][A-Z0-9 ,/&()'-]+$/.test(t)) return t.charAt(0).toUpperCase() + t.slice(1);
  var words = t.split(' ').map(function(w) { return KEEP_UPPER[w.replace(/[^A-Z0-9]/g, '')] ? w : w.toLowerCase(); });
  var s = words.join(' ');
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function kindOf(title) {
  var t = title.toLowerCase();
  if (/safety|production-safe|guardrail/.test(t)) return 'safety';
  if (/verdict/.test(t)) return 'verdicts';
  if (/^tiers$/.test(t)) return 'tiers';
  if (/^(covers|coverage|families)$/.test(t)) return 'chips';
  if (/note|caveat|unverified|not assessed|limitation|fidelity|confidence|ordering|source grounding|not modeled|attribution/.test(t)) return 'note';
  if (/precondition|prerequisite|requires|per-os|scope|verification/.test(t)) return 'info';
  return 'text';
}

function section(title) { return { title: title, kind: title ? kindOf(title) : 'intro', paras: [], items: [], bullets: [], defs: [] }; }

// Splits the stage line "Initial Access          — RDP posture check (T1021.001)" into name and detail.
function splitStage(text) {
  var t = text.replace(/\s{2,}-\s{2,}/g, ' — ').replace(/\s+/g, ' ').trim();
  var cut = t.indexOf(' — ');
  if (cut > 0 && cut <= 90) return { title: t.slice(0, cut).trim(), detail: t.slice(cut + 3).trim() };
  return { title: t, detail: '' };
}

// Reads the description into sections: the intro (title null) followed by each headed section.
function readSections(raw) {
  var text = String(raw == null ? '' : raw).replace(/\r/g, '').replace(/\s+--\s+/g, ' — ').replace(/\s{2,}-\s{2,}/g, ' — ');
  var lines = text.split('\n');
  var all = [section(null)];
  var cur = all[0];
  var last = null; // what the previous non-blank line was: 'para' | 'item' | 'bullet'

  function addText(piece, indent) {
    var t = piece.trim();
    if (!t) return;
    // "Two models are present: - the first ... - the second" carries its bullets inline; read them as a list.
    var inline = /^(.*?:)\s+-\s+(?=[A-Za-z(])(.*)$/.exec(t);
    if (inline && indent === 0 && !/^[-•*]\s/.test(t)) {
      addText(inline[1], indent);
      t = '- ' + inline[2];
    }
    var item = /^(\d{1,2}[a-z]?)\.\s+(.*)$/.exec(t);
    var bullet = /^[-•*]\s+(.*)$/.exec(t);
    // An indented "KEY   description" row, as in a list of escalation classes, is a definition row.
    var def = indent > 0 && !item && !bullet && !/^\S+\s*=/.test(t) ? /^(\S{2,14})\s{2,}(\S.*)$/.exec(t) : null;
    // Once a list of coded rows has started, "ESC11 text" with a single space is the next row, not a wrapped line.
    if (!def && indent > 0 && last === 'def') def = /^([A-Z]{2,6}\d{1,3})\s+(\S.*)$/.exec(t);
    if (def) { cur.defs.push({ key: def[1], text: def[2] }); last = 'def'; return; }
    if (item) { cur.items.push({ n: item[1], text: item[2] }); last = 'item'; return; }
    if (bullet) { cur.bullets.push({ text: bullet[1] }); last = 'bullet'; return; }
    var prev = last === 'item' ? cur.items[cur.items.length - 1] : last === 'bullet' ? cur.bullets[cur.bullets.length - 1] : last === 'def' ? cur.defs[cur.defs.length - 1] : last === 'para' ? { text: cur.paras[cur.paras.length - 1] } : null;
    // An indented line continues the item above; so does a line that starts lower-case after one that did not end a sentence.
    var continues = prev && (indent > 0 || (/^[a-z(]/.test(t) && !/[.!?:;)"”]$/.test(prev.text)));
    if (continues && last === 'para') { cur.paras[cur.paras.length - 1] += ' ' + t; return; }
    if (continues) { prev.text += ' ' + t; return; }
    // A labelled one-line section ("SAFETY: reads configuration only.") ends with its paragraph; the next unlabelled
    // paragraph belongs to the description again, not to that label.
    if (cur !== all[0] && cur.sameLine && indent === 0 && !cur.items.length && !cur.bullets.length && !cur.defs.length) { cur = all[0]; }
    cur.paras.push(t); last = 'para';
  }

  lines.forEach(function(line) {
    if (!line.trim()) { last = null; return; }
    var indent = line.length - line.replace(/^\s+/, '').length;
    var t = line.trim();
    var re = headingRe(), m, cuts = [];
    while ((m = re.exec(t)) !== null) {
      if (isHeading(m[1])) cuts.push({ at: m.index, title: m[1], end: m.index + m[0].length });
    }
    if (!cuts.length) { addText(t, indent); return; }
    if (cuts[0].at > 0) addText(t.slice(0, cuts[0].at), indent);
    cuts.forEach(function(c, i) {
      cur = section(c.title); all.push(cur); last = null;
      var rest = t.slice(c.end, i + 1 < cuts.length ? cuts[i + 1].at : t.length);
      var holder = cur;
      addText(rest, 0);
      // Marked only after its own first paragraph is in, so that paragraph stays with it.
      holder.sameLine = !!rest.trim() && !/^\s*(?:\d{1,2}[a-z]?\.|[-•*])\s/.test(rest);
      cur = holder;
    });
  });
  return all;
}

var SENT_END = /^(.{24,}?[.!?])\s+(?=[A-Z(\["])/;
var ABBREV = /(?:e\.g|i\.e|vs|etc|approx|incl|no|cf)\.$/i;
// firstSentence splits "Lead sentence. Rest." without cutting at "e.g." or "vs.".
function firstSentence(t) {
  var rest = t, acc = '';
  for (var guard = 0; guard < 6; guard++) {
    var m = SENT_END.exec(rest);
    if (!m) return acc ? { lead: acc.trim(), rest: rest.trim() } : { lead: t, rest: '' };
    acc += (acc ? ' ' : '') + m[1];
    if (!ABBREV.test(m[1])) return { lead: acc.trim(), rest: rest.slice(m[0].length).trim() };
    rest = rest.slice(m[0].length);
  }
  return { lead: t, rest: '' };
}

// Splits after each "; " that is not inside brackets, so a parenthetical aside is never cut in half.
function splitOutsideParens(t) {
  var out = [], depth = 0, from = 0;
  for (var i = 0; i < t.length; i++) {
    var c = t.charAt(i);
    if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth = Math.max(0, depth - 1);
    else if (c === ';' && depth === 0 && /\s/.test(t.charAt(i + 1))) { out.push(t.slice(from, i + 1).trim()); from = i + 1; }
  }
  out.push(t.slice(from).trim());
  return out.filter(Boolean);
}

// A block that follows a label ("SAFETY: the USB step ...") starts lower-case because the label took the capital.
// Capitalise a plain leading word; anything code-like (sftp.exe, pg_read_all_data) is left exactly as written.
export function cap(t) {
  var m = /^([a-z]{2,})(?=[\s,;:])/.exec(t);
  return m ? m[1].charAt(0).toUpperCase() + t.slice(1) : t;
}

// chunk breaks a long paragraph into readable blocks of a few sentences each.
export function chunk(t, max) {
  max = max || 300;
  if (t.length <= max + 120) return [t];
  var out = [], cur = '';
  var parts = t.split(/(?<=[.!?])\s+(?=[A-Z(\["])/);
  parts.forEach(function(s) {
    if (cur && cur.length + s.length + 1 > max && !ABBREV.test(cur)) { out.push(cur); cur = s; } else cur = cur ? cur + ' ' + s : s;
  });
  if (cur) out.push(cur);
  // A run-on with no full stops is cut at its semicolons, so it still reads as a few short blocks.
  var res = [];
  out.forEach(function(p) {
    if (p.length <= max + 200) { res.push(p); return; }
    var acc = '';
    splitOutsideParens(p).forEach(function(q) {
      if (acc && acc.length + q.length + 1 > max) { res.push(acc); acc = q; } else acc = acc ? acc + ' ' + q : q;
    });
    if (acc) res.push(acc);
  });
  return res;
}

var VERDICT = /\b(PASS|FAIL|ERROR|SKIPPED|SKIP|BLOCKED|ALLOWED|DETECTED|NOT[ _]?DETECTED|PARTIAL|INCONCLUSIVE)\s*=\s*/g;
// verdictRows reads "PASS = the control held; FAIL = it did not" into rows; null when the text is not a legend.
export function verdictRows(text) {
  var marks = [], m;
  VERDICT.lastIndex = 0;
  while ((m = VERDICT.exec(text)) !== null) marks.push({ v: m[1].replace(/[ _]/g, ''), at: m.index, end: m.index + m[0].length });
  if (marks.length < 2) return null;
  return marks.map(function(k, i) {
    var body = text.slice(k.end, i + 1 < marks.length ? marks[i + 1].at : text.length).trim().replace(/[;,]\s*(?:and|or)?\s*$/i, '').replace(/\s+(?:and|or)$/i, '').trim();
    return { verdict: k.v.toUpperCase(), text: cap(body) };
  });
}

// chipItems reads "a, b, c and d" into separate items; null when it is not a plain list of short names.
export function chipItems(text) {
  var t = text.replace(/\.\s*$/, '').trim();
  var parts = t.split(/,\s*(?:and\s+)?|\s+and\s+(?=[^,]*$)/).map(function(p) { return p.trim(); }).filter(Boolean);
  if (parts.length < 3 || parts.some(function(p) { return p.length > 64; })) return null;
  return parts;
}

// A leading tag counts only when it is its own sentence ("Lab-only. Checks ..."); "Read-only audit of ..." is just prose.
var BADGES = [[/^lab-only\.\s+/i, 'Lab only', 'warn'], [/^posture-only\.\s+/i, 'Posture only', 'ok'], [/^read-only\.\s+/i, 'Read only', 'ok'], [/^telemetry-only\.\s+/i, 'Telemetry only', 'info']];

// structureDescription: { badges, lead, body[], sections[] }. Every section has { title, kind, paras[], items[], bullets[] }
// plus, when the text allows it, verdicts[] or chips[]. Nothing is dropped: text that fits no pattern stays in paras.
export function structureDescription(raw) {
  var all = readSections(raw);
  var intro = all[0];
  var badges = [], lead = '', body = [];
  var paras = intro.paras.slice();
  if (paras.length) {
    var first = paras[0];
    BADGES.forEach(function(b) { if (b[0].test(first)) { badges.push({ label: b[1], tone: b[2] }); first = first.replace(b[0], ''); } });
    var fs = firstSentence(first);
    lead = fs.lead;
    paras[0] = fs.rest;
    paras.forEach(function(p) { if (p) chunk(p).forEach(function(c) { body.push(c); }); });
  }
  // A list written before any heading (stage lines, bullets, definition rows) becomes a section of its own.
  var head = [];
  if (intro.items.length || intro.bullets.length || intro.defs.length) {
    var d0 = section('Details');
    d0.items = intro.items; d0.bullets = intro.bullets; d0.defs = intro.defs; d0.kind = intro.items.length ? 'stages' : 'text';
    head.push(d0);
  }
  var sections = head.concat(all.slice(1)).map(function(s) {
    var out = { title: pretty(s.title), kind: s.kind, paras: [], items: [], bullets: [], defs: [] };
    s.paras.forEach(function(p) { chunk(p).forEach(function(c, i) { out.paras.push(i === 0 ? cap(c) : c); }); });
    out.items = s.items.map(function(it) { var sp = splitStage(it.text); return { n: it.n, title: sp.title, detail: sp.detail }; });
    out.defs = s.defs.slice();
    out.bullets = s.bullets.map(function(b) {
      var m = /^([^:]{2,60}):\s+(.*)$/.exec(b.text);
      return m ? { name: m[1].trim(), text: cap(m[2].trim()) } : { name: '', text: cap(b.text) };
    });
    var joined = s.paras.join(' ');
    if (out.kind === 'verdicts') { var v = verdictRows(joined); if (v) { out.verdicts = v; out.paras = []; } }
    if (out.kind === 'chips' && !out.items.length && !out.bullets.length) { var c = chipItems(joined); if (c) { out.chips = c; out.paras = []; } }
    if (out.kind === 'text' && out.items.length) out.kind = 'stages';
    if (out.defs.length && out.kind === 'text') out.kind = 'defs';
    if (out.kind === 'note' && out.items.length) out.kind = 'stages';
    return out;
  });
  return { badges: badges, lead: lead, body: body, sections: sections };
}
