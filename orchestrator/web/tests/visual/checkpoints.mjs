// Extra G1e checkpoints beyond every tab and every smoke drawer.
// CHECKPOINTS: reveal and data states reachable under the smoke fixtures:
//   { name, tab, steps: [{ click: sel } | { fill: [sel, text] } | { select: [sel, value] }] }
export const CHECKPOINTS = [];
// Reveal sites (docs/superpowers/specs/g1e-reveal-inventory.md) not reachable
// under fixtures: { 'features/x.js:123': 'reason' }.
export const UNREACHABLE_SITES = {};
// g1-v rules (src/core/css-var-rules.js) not rendered by any checkpoint:
// { 'g1-v-0a1b2c3d': 'reason' }.
export const UNREACHABLE_RULES = {};
