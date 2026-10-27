// Pure model for the Theme & Display preferences (compact density, reduced motion, accent colour).
// No DOM access here; display-prefs.js applies the result.

// [hex, name]: the colours the picker offers.
export const ACCENTS = [
  ['#3b82f6', 'Blue'],
  ['#22d3ee', 'Cyan'],
  ['#10b981', 'Green'],
  ['#a78bfa', 'Violet'],
  ['#ff007f', 'Magenta'],
];

// normalizeAccent returns the offered colour matching hex (lower-cased), or null.
export function normalizeAccent(hex) {
  var h = String(hex == null ? '' : hex).toLowerCase();
  return ACCENTS.some(function(a) { return a[0] === h; }) ? h : null;
}

// accentVars derives the CSS custom properties that make up an accent from its hex value.
export function accentVars(hex) {
  var n = parseInt(hex.slice(1), 16);
  var r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  var rgb = r + ',' + g + ',' + b;
  var lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return {
    '--accent': hex,
    '--accent-dim': 'rgba(' + rgb + ',0.14)',
    '--accent-glow': 'rgba(' + rgb + ',0.25)',
    '--accent-border': 'rgba(' + rgb + ',0.4)',
    '--on-accent': lum > 0.6 ? '#06121f' : '#ffffff',
  };
}

// readDisplayPrefs reads the saved preferences through getItem (localStorage.getItem or a stub).
export function readDisplayPrefs(getItem) {
  return {
    compact: getItem('audspect_compact') === '1',
    reduce: getItem('audspect_reduce_motion') === '1',
    accent: normalizeAccent(getItem('audspect_accent')),
  };
}
