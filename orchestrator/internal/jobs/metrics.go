package jobs

// MetricsEvent is internal/jobs's own copy of the metrics-event shape --
// the same reasoning as NotifyEvent (notify.go): internal/jobs must not
// import a metrics library or internal/api directly, so SetMetrics is an
// injected hook, keeping this package a leaf dependency.
type MetricsEvent struct {
	Type    string
	JobType string
	// DurationSecs and HasDuration are only meaningful when
	// Type == MetricsEventJobCompleted. HasDuration is false only when the
	// post-transition Store.Get() lookup needed to read back the
	// DB-stamped started_at/completed_at failed -- distinct from
	// DurationSecs == 0, which is the real (if common) case of a job
	// resolving straight to a terminal state in the same tick it left
	// "requested" (SetJobState's COALESCE stamps both timestamps together
	// in one UPDATE, so they read as equal).
	DurationSecs float64
	HasDuration  bool
}

// MetricsFn is called for every job state transition Tick() records.
// Like NotifyFn, it is optional: every call site in dispatch.go MUST
// guard with `if d.metrics != nil` (recordStateMetrics does this once,
// centrally).
type MetricsFn func(evt MetricsEvent)

func (d *Dispatcher) SetMetrics(fn MetricsFn) { d.metrics = fn }

const (
	MetricsEventJobStarted   = "job_started"
	MetricsEventJobCompleted = "job_completed"
)
