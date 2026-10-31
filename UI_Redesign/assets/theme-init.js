/* Loaded in <head> before first paint so the theme never flashes.
   External file on purpose: the console's CSP is script-src 'self' (no inline scripts). */
(function () {
  var t = 'dark';
  try { t = localStorage.getItem('aud-theme') || 'dark'; } catch (e) { /* storage blocked */ }
  var q = /[?&]theme=(light|dark)\b/.exec(location.search); // ?theme=light for review links
  if (q) t = q[1];
  document.documentElement.setAttribute('data-theme', t);
})();
