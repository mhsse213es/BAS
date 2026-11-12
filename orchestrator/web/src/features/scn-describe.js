// Turns a scenario description into a structured overview: an intro, then headed sections. A section that is a
// numbered list becomes stage items, each with a name and a detail. Works on any scenario text; the stored
// description is never changed, only how the overview presents it.

// A heading is an all-caps phrase of at least five characters that ends in a colon, e.g. "KILL CHAIN STAGES:",
// "ATTRIBUTION / CONFIDENCE:", "SAFETY:".
const HEADING = /(?:^|\s)((?:[A-Z][A-Z0-9]*)(?:[ ,\/&-]+[A-Z][A-Z0-9]*)*):(?=\s)/g;
const STAGE_START = /(?:^|\s)(?=\d{1,2}\.\s)/;

function isHeading(title) {
  return title.length >= 5 && /[A-Z]{3}/.test(title);
}

function toItems(body) {
  const parts = body.split(/\s(?=\d{1,2}\.\s)/).map(p => p.trim()).filter(Boolean);
  return parts.map(p => {
    const text = p.replace(/^\d{1,2}\.\s+/, '');
    const cut = text.indexOf(' — ');
    if (cut > 0 && cut <= 90) return { title: text.slice(0, cut).trim(), detail: text.slice(cut + 3).trim() };
    return { title: text, detail: '' };
  });
}

export function parseDescription(raw) {
  const text = String(raw || '').replace(/\s+--\s+/g, ' — ').replace(/\s+/g, ' ').trim();
  if (!text) return { intro: '', sections: [] };
  const heads = [];
  let m;
  HEADING.lastIndex = 0;
  while ((m = HEADING.exec(text)) !== null) {
    const title = m[1].trim();
    if (!isHeading(title)) continue;
    heads.push({ title, start: m.index, bodyStart: m.index + m[0].length });
  }
  if (!heads.length) return { intro: text, sections: [] };
  const intro = text.slice(0, heads[0].start).trim();
  const sections = heads.map((h, i) => {
    const end = i + 1 < heads.length ? heads[i + 1].start : text.length;
    const body = text.slice(h.bodyStart, end).trim();
    if (STAGE_START.test(body) && /(?:^|\s)1\.\s/.test(body)) return { title: h.title, items: toItems(body) };
    return { title: h.title, paragraphs: body ? [body] : [] };
  });
  return { intro, sections };
}
