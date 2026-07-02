package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/models"
)

// Job status constants — full lifecycle state machine.
const (
	APJobQueued         = "queued"          // created, waiting for WS dispatch
	APJobDispatched     = "dispatched"      // WS sent, waiting for agent ACK (30s window)
	APJobRunning        = "running"         // agent acknowledged, execution in progress
	APJobCompleted      = "completed"       // results received and stored
	APJobFailed         = "failed"          // agent reported error
	APJobTimedOut       = "timed_out"       // exceeded expires_at without completion
	APJobDeliveryFailed = "delivery_failed" // no ACK within ackWindow
	APJobCancelled      = "cancelled"       // operator cancelled

	ackWindow = 30 * time.Second
)

// Execution stage enum — agent reports these in heartbeats to show granular progress.
const (
	APStageInitializing        = "initializing"         // post-ACK setup
	APStageProbing             = "probing"               // TCP reachability scan
	APStageEnumeratingAdmins   = "enumerating_admins"   // local admin group enumeration
	APStageEnumeratingSessions = "enumerating_sessions" // active session enumeration
	APStageRunningSharpHound   = "running_sharphound"   // SharpHound domain collection
	APStageBuildingGraph       = "building_graph"       // building graph object
	APStageUploading           = "uploading"            // uploading payload to server
)

// Failure reason taxonomy — use instead of arbitrary error strings.
const (
	APFailDeliveryFailed    = "delivery_failed"
	APFailTimeout           = "timeout"
	APFailAgentOffline      = "agent_offline"
	APFailUploadFailed      = "upload_failed"
	APFailCancelled         = "cancelled"
	APFailNetworkError      = "network_error"
	APFailAuthFailed        = "authentication_failed"
	APFailPermissionDenied  = "permission_denied"
)

// APJobProgress is carried in the jobs table progress column and in heartbeats.
type APJobProgress struct {
	Stage            string `json:"stage"`
	TargetsCompleted int    `json:"targetsCompleted"`
	TargetsTotal     int    `json:"targetsTotal"`
	ProgressPercent  int    `json:"progressPercent"` // 0–100, pre-computed by agent
}

// APJobMetrics is persisted in the progress column when a job completes.
type APJobMetrics struct {
	DurationMs  int64 `json:"durationMs"`
	NodeCount   int   `json:"nodeCount"`
	EdgeCount   int   `json:"edgeCount"`
	TargetCount int   `json:"targetCount"`
}

// APJob is the wire representation returned to the browser.
type APJob struct {
	ID              string         `json:"id"`
	AgentID         string         `json:"agentId"`
	Status          string         `json:"status"`
	CreatedAt       time.Time      `json:"createdAt"`
	DispatchedAt    *time.Time     `json:"dispatchedAt,omitempty"`
	AckAt           *time.Time     `json:"ackAt,omitempty"`
	StartedAt       *time.Time     `json:"startedAt,omitempty"` // first progress heartbeat
	CompletedAt     *time.Time     `json:"completedAt,omitempty"`
	LastHeartbeatAt *time.Time     `json:"lastHeartbeatAt,omitempty"`
	Attempts        int            `json:"attempts"`
	ExpiresAt       time.Time      `json:"expiresAt"`
	Error           string         `json:"error,omitempty"`
	Progress        *APJobProgress `json:"progress,omitempty"`
	Metrics         *APJobMetrics  `json:"metrics,omitempty"`
	TargetCount     int            `json:"targetCount"`
}

// computeJobTimeout returns a dynamic timeout based on target count:
// base 30s + 3s per target, clamped to [2m, 15m].
func computeJobTimeout(targetCount int) time.Duration {
	t := 30*time.Second + time.Duration(targetCount)*3*time.Second
	if t < 2*time.Minute {
		t = 2 * time.Minute
	}
	if t > 15*time.Minute {
		t = 15 * time.Minute
	}
	return t
}

// newJobID returns a random 32-hex-char ID for a job.
func newJobID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// createAPJob inserts a new job row and returns its ID.
func (h *Handler) createAPJob(ctx context.Context, agentID string, payload map[string]any, targetCount int) (string, error) {
	id := newJobID()
	raw, _ := json.Marshal(payload)
	expiresAt := time.Now().Add(computeJobTimeout(targetCount))
	_, err := h.db.Exec(ctx,
		`INSERT INTO attackpath_jobs
		 (id, agent_id, status, payload, expires_at, attempts)
		 VALUES ($1,$2,$3,$4,$5,0)`,
		id, agentID, APJobQueued, raw, expiresAt)
	return id, err
}

// loadAPJob reads one job by ID.
func (h *Handler) loadAPJob(ctx context.Context, id string) (*APJob, error) {
	var j APJob
	var progressRaw, metricsRaw, payloadRaw []byte
	err := h.db.QueryRow(ctx,
		`SELECT id, agent_id, status, payload, created_at, dispatched_at, ack_at,
		        started_at, completed_at, last_heartbeat_at, attempts, expires_at,
		        error, progress, metrics
		   FROM attackpath_jobs WHERE id=$1`, id,
	).Scan(&j.ID, &j.AgentID, &j.Status, &payloadRaw,
		&j.CreatedAt, &j.DispatchedAt, &j.AckAt, &j.StartedAt,
		&j.CompletedAt, &j.LastHeartbeatAt,
		&j.Attempts, &j.ExpiresAt, &j.Error, &progressRaw, &metricsRaw)
	if err != nil {
		return nil, err
	}
	if len(progressRaw) > 2 {
		var p APJobProgress
		if json.Unmarshal(progressRaw, &p) == nil && p.Stage != "" {
			j.Progress = &p
		}
	}
	if len(metricsRaw) > 2 {
		var m APJobMetrics
		if json.Unmarshal(metricsRaw, &m) == nil {
			j.Metrics = &m
		}
	}
	var payload struct {
		Targets []string `json:"targets"`
	}
	json.Unmarshal(payloadRaw, &payload)
	j.TargetCount = len(payload.Targets)
	return &j, nil
}

// broadcastJobUpdate pushes a job state change to all connected browser sessions.
func (h *Handler) broadcastJobUpdate(j *APJob) {
	h.hub.BroadcastBrowsers(models.WSMessage{
		Type:    models.MsgAPJobUpdate,
		AgentID: j.AgentID,
		Data:    mustMarshal(j),
	})
}

func mustMarshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// dispatchAPJobWS sends the WS command and marks the job as dispatched.
// Returns false if the agent is not connected.
func (h *Handler) dispatchAPJobWS(ctx context.Context, j *APJob, cmd map[string]any) bool {
	// Inject the jobId so the agent can ACK and include it in results.
	cmd["jobId"] = j.ID
	sent := h.hub.SendToAgent(j.AgentID, models.WSMessage{
		Type:    models.MsgCommandAttackPathCollect,
		AgentID: j.AgentID,
		Data:    mustMarshal(cmd),
	})
	if !sent {
		return false
	}
	now := time.Now()
	h.db.Exec(ctx,
		`UPDATE attackpath_jobs
		    SET status=$1, dispatched_at=$2, attempts=attempts+1
		  WHERE id=$3`,
		APJobDispatched, now, j.ID)
	j.Status = APJobDispatched
	j.DispatchedAt = &now
	h.broadcastJobUpdate(j)
	return true
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// CreateAttackPathJob creates a job record, dispatches the WS command, and
// returns the job. Replaces the old fire-and-forget DispatchAttackPathCollect.
// POST /api/attackpath/jobs  (Analyst+)
func (h *Handler) CreateAttackPathJob(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AgentID        string   `json:"agentId"`
		Targets        []string `json:"targets"`
		Segment        string   `json:"segment"`
		RunSharpHound  bool     `json:"runSharpHound"`
		SharpHoundArgs string   `json:"sharpHoundArgs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.AgentID == "" {
		jsonError(w, "agentId required", http.StatusBadRequest)
		return
	}

	cmd, shLoaded := buildCollectCmd(body.Targets, body.Segment, body.RunSharpHound, body.SharpHoundArgs)

	jobID, err := h.createAPJob(r.Context(), body.AgentID, cmd, len(body.Targets))
	if err != nil {
		jsonError(w, "create job: "+err.Error(), http.StatusInternalServerError)
		return
	}

	j, _ := h.loadAPJob(r.Context(), jobID)
	if j == nil {
		j = &APJob{ID: jobID, AgentID: body.AgentID, Status: APJobQueued}
	}

	h.broadcastJobUpdate(j)
	h.auditLog(r, "attackpath.job.create", body.AgentID,
		map[string]any{"jobId": jobID, "targets": len(body.Targets), "sharpHound": body.RunSharpHound}, "ok")

	// Try to dispatch immediately. If the agent isn't connected the job stays
	// queued and will be re-dispatched on the next heartbeat.
	h.dispatchAPJobWS(r.Context(), j, cmd)

	respond(w, map[string]any{
		"job":                 j,
		"sharpHoundDelivered": shLoaded,
	})
}

// AckAttackPathJob is called by the agent immediately on receiving the WS
// command. Transitions dispatched→running.
// POST /api/attackpath/jobs/{id}/ack  (agent-authed)
func (h *Handler) AckAttackPathJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	now := time.Now()
	res, err := h.db.Exec(r.Context(),
		`UPDATE attackpath_jobs
		    SET status=$1, ack_at=$2
		  WHERE id=$3 AND status IN ($4,$5)`,
		APJobRunning, now, id, APJobDispatched, APJobQueued)
	if err != nil || res.RowsAffected() == 0 {
		// Already running or completed — still 200 so the agent doesn't log noise.
		respond(w, map[string]any{"ok": true})
		return
	}
	j, _ := h.loadAPJob(r.Context(), id)
	if j != nil {
		h.broadcastJobUpdate(j)
	}
	respond(w, map[string]any{"ok": true})
}

// GetAttackPathJob returns a single job by ID. Viewer+.
// GET /api/attackpath/jobs/{id}
func (h *Handler) GetAttackPathJob(w http.ResponseWriter, r *http.Request) {
	j, err := h.loadAPJob(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	respond(w, j)
}

// ListAttackPathJobs returns jobs for an agent (optional agentId filter) ordered
// newest-first. Viewer+.
// GET /api/attackpath/jobs?agentId=X&limit=N
func (h *Handler) ListAttackPathJobs(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agentId")
	limit := 20

	var rows interface {
		Next() bool
		Scan(...any) error
		Close()
	}
	var err error
	if agentID != "" {
		rows, err = h.db.Query(r.Context(),
			`SELECT id, agent_id, status, payload, created_at, dispatched_at, ack_at,
			        started_at, completed_at, last_heartbeat_at, attempts, expires_at,
			        error, progress, metrics
			   FROM attackpath_jobs WHERE agent_id=$1
			  ORDER BY created_at DESC LIMIT $2`, agentID, limit)
	} else {
		rows, err = h.db.Query(r.Context(),
			`SELECT id, agent_id, status, payload, created_at, dispatched_at, ack_at,
			        started_at, completed_at, last_heartbeat_at, attempts, expires_at,
			        error, progress, metrics
			   FROM attackpath_jobs
			  ORDER BY created_at DESC LIMIT $1`, limit)
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var out []APJob
	for rows.Next() {
		var j APJob
		var progressRaw, metricsRaw, payloadRaw []byte
		if rows.Scan(&j.ID, &j.AgentID, &j.Status, &payloadRaw,
			&j.CreatedAt, &j.DispatchedAt, &j.AckAt, &j.StartedAt,
			&j.CompletedAt, &j.LastHeartbeatAt,
			&j.Attempts, &j.ExpiresAt, &j.Error, &progressRaw, &metricsRaw) != nil {
			continue
		}
		if len(progressRaw) > 2 {
			var p APJobProgress
			if json.Unmarshal(progressRaw, &p) == nil && p.Stage != "" {
				j.Progress = &p
			}
		}
		if len(metricsRaw) > 2 {
			var m APJobMetrics
			if json.Unmarshal(metricsRaw, &m) == nil {
				j.Metrics = &m
			}
		}
		var payload struct {
			Targets []string `json:"targets"`
		}
		json.Unmarshal(payloadRaw, &payload)
		j.TargetCount = len(payload.Targets)
		out = append(out, j)
	}
	if out == nil {
		out = []APJob{}
	}
	respond(w, out)
}

// CancelAttackPathJob marks a job cancelled. Operator (Analyst+).
// POST /api/attackpath/jobs/{id}/cancel
func (h *Handler) CancelAttackPathJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	res, err := h.db.Exec(r.Context(),
		`UPDATE attackpath_jobs SET status=$1, error=$2
		  WHERE id=$3 AND status NOT IN ($4,$5,$6)`,
		APJobCancelled, APFailCancelled, id, APJobCompleted, APJobCancelled, APJobFailed)
	if err != nil || res.RowsAffected() == 0 {
		jsonError(w, "job not found or already terminal", http.StatusNotFound)
		return
	}
	j, _ := h.loadAPJob(r.Context(), id)
	if j != nil {
		h.broadcastJobUpdate(j)
	}
	h.auditLog(r, "attackpath.job.cancel", id, nil, "ok")
	respond(w, map[string]any{"ok": true})
}

// RetryAttackPathJob creates a NEW job from the same payload and dispatches it.
// The old job is cancelled. POST /api/attackpath/jobs/{id}/retry  (Analyst+)
func (h *Handler) RetryAttackPathJob(w http.ResponseWriter, r *http.Request) {
	old, err := h.loadAPJob(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}

	// Cancel the old job silently.
	h.db.Exec(r.Context(),
		`UPDATE attackpath_jobs SET status=$1, error='superseded by retry'
		  WHERE id=$2 AND status NOT IN ($3,$4)`,
		APJobCancelled, old.ID, APJobCompleted, APJobCancelled)
	if j, _ := h.loadAPJob(r.Context(), old.ID); j != nil {
		h.broadcastJobUpdate(j)
	}

	// Read original payload to re-dispatch.
	var payloadRaw []byte
	h.db.QueryRow(r.Context(), `SELECT payload FROM attackpath_jobs WHERE id=$1`, old.ID).Scan(&payloadRaw)
	var cmd map[string]any
	json.Unmarshal(payloadRaw, &cmd)
	if cmd == nil {
		cmd = map[string]any{}
	}

	newID, err := h.createAPJob(r.Context(), old.AgentID, cmd, old.TargetCount)
	if err != nil {
		jsonError(w, "create retry job: "+err.Error(), http.StatusInternalServerError)
		return
	}

	newJob, _ := h.loadAPJob(r.Context(), newID)
	if newJob == nil {
		newJob = &APJob{ID: newID, AgentID: old.AgentID, Status: APJobQueued}
	}
	h.broadcastJobUpdate(newJob)
	h.dispatchAPJobWS(r.Context(), newJob, cmd)

	h.auditLog(r, "attackpath.job.retry", old.AgentID,
		map[string]any{"oldJob": old.ID, "newJob": newID}, "ok")
	respond(w, newJob)
}

// StartAPJobMonitor runs the background goroutine that enforces timeouts and
// re-delivers queued jobs when agents reconnect. Call once from main.
func (h *Handler) StartAPJobMonitor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.apJobTick(ctx)
			}
		}
	}()
}

func (h *Handler) apJobTick(ctx context.Context) {
	// 1. delivery_failed: dispatched with no ACK beyond ackWindow.
	ackCutoff := time.Now().Add(-ackWindow)
	rows, _ := h.db.Query(ctx,
		`UPDATE attackpath_jobs
		    SET status=$1, error=$2
		  WHERE status=$3 AND dispatched_at < $4
		  RETURNING id, agent_id`,
		APJobDeliveryFailed, APFailDeliveryFailed, APJobDispatched, ackCutoff)
	if rows != nil {
		for rows.Next() {
			var id, agentID string
			rows.Scan(&id, &agentID)
			if j, _ := h.loadAPJob(ctx, id); j != nil {
				h.broadcastJobUpdate(j)
				log.Printf("[apjob] %s delivery_failed for agent %s", id, agentID)
			}
		}
		rows.Close()
	}

	// 2. timed_out: any active job past its expires_at.
	rows2, _ := h.db.Query(ctx,
		`UPDATE attackpath_jobs
		    SET status=$1, error=$2
		  WHERE status IN ($3,$4,$5) AND expires_at < NOW()
		  RETURNING id, agent_id`,
		APJobTimedOut, APFailTimeout, APJobQueued, APJobDispatched, APJobRunning)
	if rows2 != nil {
		for rows2.Next() {
			var id, agentID string
			rows2.Scan(&id, &agentID)
			if j, _ := h.loadAPJob(ctx, id); j != nil {
				h.broadcastJobUpdate(j)
				log.Printf("[apjob] %s timed_out for agent %s", id, agentID)
			}
		}
		rows2.Close()
	}
}

// RedeliverQueuedAPJobs is called from the heartbeat handler when an agent is
// seen online. It re-dispatches any queued (never delivered) jobs for that agent.
// Only queued jobs are redelivered — running jobs need an explicit operator decision.
func (h *Handler) RedeliverQueuedAPJobs(ctx context.Context, agentID string) {
	rows, err := h.db.Query(ctx,
		`SELECT id FROM attackpath_jobs
		  WHERE agent_id=$1 AND status=$2 AND expires_at > NOW()
		  ORDER BY created_at ASC`,
		agentID, APJobQueued)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil {
			continue
		}
		var payloadRaw []byte
		h.db.QueryRow(ctx, `SELECT payload FROM attackpath_jobs WHERE id=$1`, id).Scan(&payloadRaw)
		var cmd map[string]any
		if json.Unmarshal(payloadRaw, &cmd) != nil {
			cmd = map[string]any{}
		}
		j := &APJob{ID: id, AgentID: agentID, Status: APJobQueued}
		if h.dispatchAPJobWS(ctx, j, cmd) {
			log.Printf("[apjob] re-delivered queued job %s to agent %s on reconnect", id, agentID)
		}
	}
}

// UpdateAPJobProgress updates the progress column from a heartbeat report and
// broadcasts it to browser sessions. Also sets started_at on the first call.
func (h *Handler) UpdateAPJobProgress(ctx context.Context, agentID, jobID string, p APJobProgress) {
	raw, _ := json.Marshal(p)
	now := time.Now()
	res, err := h.db.Exec(ctx,
		`UPDATE attackpath_jobs
		    SET progress=$1, last_heartbeat_at=$2, status=$3,
		        started_at = COALESCE(started_at, $2)
		  WHERE id=$4 AND agent_id=$5 AND status IN ($6,$7)`,
		raw, now, APJobRunning, jobID, agentID, APJobRunning, APJobDispatched)
	if err != nil || res.RowsAffected() == 0 {
		return
	}
	h.hub.BroadcastBrowsers(models.WSMessage{
		Type:    models.MsgAPJobProgress,
		AgentID: agentID,
		Data: mustMarshal(map[string]any{
			"jobId":    jobID,
			"agentId":  agentID,
			"progress": p,
		}),
	})
}

// CompleteAPJob marks a job completed, stores execution metrics, and broadcasts.
func (h *Handler) CompleteAPJob(ctx context.Context, agentID, jobID string, m APJobMetrics) {
	if jobID == "" {
		return
	}
	raw, _ := json.Marshal(m)
	now := time.Now()
	h.db.Exec(ctx,
		`UPDATE attackpath_jobs
		    SET status=$1, completed_at=$2, progress='{}', metrics=$3
		  WHERE id=$4 AND agent_id=$5 AND status NOT IN ($6,$7,$8)`,
		APJobCompleted, now, raw, jobID, agentID,
		APJobCompleted, APJobCancelled, APJobFailed)
	if j, _ := h.loadAPJob(ctx, jobID); j != nil {
		h.broadcastJobUpdate(j)
	}
}

// FailAPJob marks a job failed with a typed failure reason.
func (h *Handler) FailAPJob(ctx context.Context, agentID, jobID, reason string) {
	if jobID == "" {
		return
	}
	h.db.Exec(ctx,
		`UPDATE attackpath_jobs SET status=$1, error=$2
		  WHERE id=$3 AND agent_id=$4 AND status NOT IN ($5,$6)`,
		APJobFailed, fmt.Sprintf("%.500s", reason),
		jobID, agentID, APJobCompleted, APJobCancelled)
	if j, _ := h.loadAPJob(ctx, jobID); j != nil {
		h.broadcastJobUpdate(j)
	}
}
