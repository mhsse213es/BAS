// Pure comparison logic for the G1e dual-build harness (spec section 5).
export const SEP = '\u0001';
const KEYS = new Set(['checkpoint', 'path', 'property', 'mask', 'reason']);

export function compareStyles(checkpoint, base, head, props) {
  const diffs = [];
  for (const path of Object.keys(base)) {
    if (!(path in head)) diffs.push({ checkpoint, path, property: '(element)', base: 'present', head: 'missing' });
  }
  for (const path of Object.keys(head)) {
    if (!(path in base)) diffs.push({ checkpoint, path, property: '(element)', base: 'missing', head: 'present' });
  }
  for (const [path, b] of Object.entries(base)) {
    const h = head[path];
    if (h === undefined || h === b) continue;
    const bv = b.split(SEP);
    const hv = h.split(SEP);
    props.forEach((property, i) => {
      if (bv[i] !== hv[i]) diffs.push({ checkpoint, path, property, base: bv[i], head: hv[i] });
    });
  }
  return diffs;
}

export function validateAllowlist(entries) {
  if (!Array.isArray(entries)) throw new Error('allowlist must be an array');
  for (const e of entries) {
    for (const k of Object.keys(e)) if (!KEYS.has(k)) throw new Error(`allowlist: unknown key ${k}`);
    if (typeof e.reason !== 'string' || !e.reason.trim()) throw new Error(`allowlist: entry without reason: ${JSON.stringify(e)}`);
    if (typeof e.checkpoint !== 'string') throw new Error(`allowlist: entry without checkpoint: ${JSON.stringify(e)}`);
  }
  return entries;
}

export function isAllowed(diff, entries) {
  return entries.some((e) => e.mask === undefined && e.checkpoint === diff.checkpoint
    && (e.path === undefined || e.path === diff.path)
    && (e.property === undefined || e.property === diff.property));
}

export function masksFor(checkpoint, entries) {
  return entries.filter((e) => e.checkpoint === checkpoint && e.mask !== undefined).map((e) => e.mask);
}

export function formatDiff(d) {
  return `${d.checkpoint}  ${d.path}  ${d.property}: ${d.base} -> ${d.head}`;
}
