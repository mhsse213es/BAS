import { state } from '../core/state.js';
import { refreshPanels } from '../core/refresh.js';
import { _vexResumeActiveRun, loadVariantCoverage, loadVariantStats, populateVexAgents, populateVexTechniques, startVexSweepPolling } from './variants.js';


// ── Variant Executor ───────────────────────────────────────────────────────

          // tracks sweep/queue polling interval (cancellable)
 // underlying scenario_run id of the current vex dispatch
          // consecutive pollVariantRun failures -- see VEX_POLL_MAX_FAILURES
// VEX_POLL_MAX_FAILURES bounds pollVariantRun's retry: a single transient
// network blip must not stop the poll (the run keeps executing server-side
// regardless of whether the status check succeeds), but failing forever
// with an empty catch left the panel stuck on "Executing variants..."
// indefinitely with zero feedback if the connection or session broke mid-run.
export var VEX_POLL_MAX_FAILURES = 5;
     // set by stopVex(); checked at every queue step

// The hero Refresh button: reload the data panels and say how it went. The sweep poller and the resume of an
// in-flight run are left alone; a refresh should not restart them.
export function refreshVariantTab() {
  refreshPanels('variants', [loadVariantStats, loadVariantCoverage, populateVexAgents, populateVexTechniques]);
}

export function loadVariantTab() {
  loadVariantStats();
  loadVariantCoverage();
  populateVexAgents();
  populateVexTechniques();
  startVexSweepPolling();
  _vexResumeActiveRun();
}