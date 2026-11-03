import { showToast } from './util.js';

// A page's Refresh button reloads several panels, and a panel that fails often keeps its old data or shows a small
// "unavailable" box, so a click can look like nothing happened. refreshPanels runs the loaders (each returns its
// request promise), and a loader that fails calls noteRefreshFailure(); the user is told how it went.
var failed = 0;

export function noteRefreshFailure() { failed++; }

export function refreshPanels(label, loaders) {
  failed = 0;
  showToast('Refreshing ' + label + '…', 'ok');
  var runs = loaders.map(function(fn) {
    try { return Promise.resolve(fn()).catch(function() { failed++; }); }
    catch (e) { failed++; return Promise.resolve(); }
  });
  return Promise.all(runs).then(function() {
    var n = loaders.length;
    if (failed > 0) showToast(failed + ' of ' + n + ' ' + label + ' panels could not be refreshed. Showing what was loaded before.', 'err');
    else showToast(label.charAt(0).toUpperCase() + label.slice(1) + ' refreshed.', 'ok');
  });
}
