// Keeps the Live Runs cards moving while a run executes.
//
// The cards read the runs list. That list was only re-fetched when a run finished or paused; the step-by-step run events
// updated the open drawer alone. A card therefore kept its first values ("Starting…", 0 steps, an empty bar) until
// someone opened the run. A run event now asks for a refresh, throttled so a burst of events costs one fetch.

// createThrottledRefresh returns request(): the first call schedules fn after whatever is left of minGapMs since fn last
// ran (at once if it has been longer); calls made while one is already scheduled are folded into it.
export function createThrottledRefresh(fn, minGapMs, deps) {
  deps = deps || {};
  var now = deps.now || Date.now;
  var setT = deps.setTimeout || setTimeout;
  var timer = null, last = -Infinity;
  return function request() {
    if (timer !== null) return;
    var wait = Math.max(0, minGapMs - (now() - last));
    timer = setT(function() {
      timer = null;
      last = now();
      fn();
    }, wait);
  };
}

// isRunsTabActive: only the Live Runs page needs the list; other pages fetch their own data when opened.
export function isRunsTabActive(doc) {
  var nav = doc && doc.querySelector ? doc.querySelector('[data-tab="runs"]') : null;
  return !!(nav && nav.classList && nav.classList.contains('active'));
}
