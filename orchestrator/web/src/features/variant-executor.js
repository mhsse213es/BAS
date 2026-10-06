import { state } from '../core/state.js';
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

export function loadVariantTab() {
  loadVariantStats();
  loadVariantCoverage();
  populateVexAgents();
  populateVexTechniques();
  startVexSweepPolling();
  _vexResumeActiveRun();
}