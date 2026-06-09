package sched

import "context"

// RunSerial executes jobs strictly one at a time, in submission order, ignoring
// resource profiles entirely (no locks, one worker, no overlap). It is the
// ground-truth reference the parallel scheduler must match.
//
// The accuracy contract of the whole engine rests on one invariant: a scenario's
// per-step verdicts must be identical whether produced by RunSerial or by Run. If
// they ever differ, a step's ResourceProfile is mislabeled — two steps that truly
// contend for a resource were allowed to overlap — and parallelism is unsafe for
// that scenario. The equivalence harness (see equiv_test.go) turns this invariant
// into a CI gate so no label change can silently trade accuracy for speed.
func RunSerial(ctx context.Context, jobs []Job) {
	for i := range jobs {
		if ctx.Err() != nil {
			return
		}
		jobs[i].Run(ctx)
	}
}
