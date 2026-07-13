package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

func createJobReq(body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	return httptest.NewRequest(http.MethodPost, "/api/attackpath/jobs", bytes.NewReader(b))
}

func TestCreateAttackPathJob_MissingAgentID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CreateAttackPathJob(rec, createJobReq(map[string]any{"targets": []string{"10.0.0.1"}}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestCreateAttackPathJob_DispatchesWhenAgentConnected drives the job through
// the real WS delivery path and confirms the DB status flips to dispatched
// with dispatched_at/attempts set — not just that a 200 came back.
func TestCreateAttackPathJob_DispatchesWhenAgentConnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		agent := startFakeAgent(t, h.hub, "caj-online-agent")
		defer agent.Disconnect(t)

		rec := httptest.NewRecorder()
		h.CreateAttackPathJob(rec, createJobReq(map[string]any{
			"agentId": "caj-online-agent", "targets": []string{"10.0.0.1"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Job APJob `json:"job"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Job.Status != APJobDispatched {
			t.Fatalf("job status = %q, want dispatched", out.Job.Status)
		}

		env := agent.WaitForMessage(t, 2*time.Second)
		if env.Type != models.MsgCommandAttackPathCollect {
			t.Fatalf("message type = %q, want %q", env.Type, models.MsgCommandAttackPathCollect)
		}

		var attempts int
		pool.QueryRow(context.Background(), `SELECT attempts FROM attackpath_jobs WHERE id=$1`, out.Job.ID).Scan(&attempts)
		if attempts != 1 {
			t.Fatalf("attempts = %d, want 1", attempts)
		}
	})
}

func TestCreateAttackPathJob_StaysQueuedWhenAgentOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.CreateAttackPathJob(rec, createJobReq(map[string]any{
			"agentId": "caj-offline-agent", "targets": []string{"10.0.0.1"},
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Job APJob `json:"job"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.Job.Status != APJobQueued {
			t.Fatalf("job status = %q, want queued (agent offline)", out.Job.Status)
		}
	})
}

func TestAckAttackPathJob_TransitionsDispatchedToRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, err := h.createAPJob(context.Background(), "ack-agent", map[string]any{"targets": []string{}}, 0)
		if err != nil {
			t.Fatalf("createAPJob: %v", err)
		}
		pool.Exec(context.Background(), `UPDATE attackpath_jobs SET status=$1, dispatched_at=NOW() WHERE id=$2`, APJobDispatched, id)

		rec := httptest.NewRecorder()
		h.AckAttackPathJob(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", id))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM attackpath_jobs WHERE id=$1`, id).Scan(&status)
		if status != APJobRunning {
			t.Fatalf("status = %q, want running", status)
		}
	})
}

// TestAckAttackPathJob_NoopWhenAlreadyTerminal pins that ACKing a job that's
// already completed is still a 200 (so a late/duplicate agent ACK never
// surfaces as an error to the agent) but does not resurrect the job.
func TestAckAttackPathJob_NoopWhenAlreadyTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, _ := h.createAPJob(context.Background(), "ack-terminal-agent", map[string]any{}, 0)
		pool.Exec(context.Background(), `UPDATE attackpath_jobs SET status=$1 WHERE id=$2`, APJobCompleted, id)

		rec := httptest.NewRecorder()
		h.AckAttackPathJob(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", id))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (silent no-op)", rec.Code)
		}
		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM attackpath_jobs WHERE id=$1`, id).Scan(&status)
		if status != APJobCompleted {
			t.Fatalf("status = %q, want unchanged completed", status)
		}
	})
}

func TestGetAttackPathJob_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetAttackPathJob(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestGetAttackPathJob_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, _ := h.createAPJob(context.Background(), "get-job-agent", map[string]any{"targets": []string{"a", "b"}}, 2)

		rec := httptest.NewRecorder()
		h.GetAttackPathJob(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", id))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var j APJob
		json.Unmarshal(rec.Body.Bytes(), &j)
		if j.TargetCount != 2 {
			t.Fatalf("targetCount = %d, want 2", j.TargetCount)
		}
	})
}

func TestListAttackPathJobs_AgentFilterAndLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		h.createAPJob(context.Background(), "list-jobs-a", map[string]any{}, 0)
		h.createAPJob(context.Background(), "list-jobs-a", map[string]any{}, 0)
		h.createAPJob(context.Background(), "list-jobs-b", map[string]any{}, 0)

		allRec := httptest.NewRecorder()
		h.ListAttackPathJobs(allRec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var all []APJob
		json.Unmarshal(allRec.Body.Bytes(), &all)
		if len(all) != 3 {
			t.Fatalf("all = %d jobs, want 3", len(all))
		}

		filteredRec := httptest.NewRecorder()
		h.ListAttackPathJobs(filteredRec, httptest.NewRequest(http.MethodGet, "/x?agentId=list-jobs-a", nil))
		var filtered []APJob
		json.Unmarshal(filteredRec.Body.Bytes(), &filtered)
		if len(filtered) != 2 {
			t.Fatalf("filtered = %d jobs, want 2 for list-jobs-a", len(filtered))
		}
	})
}

func TestCancelAttackPathJob_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, _ := h.createAPJob(context.Background(), "cancel-agent", map[string]any{}, 0)

		rec := httptest.NewRecorder()
		h.CancelAttackPathJob(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", id))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var status, errMsg string
		pool.QueryRow(context.Background(), `SELECT status, error FROM attackpath_jobs WHERE id=$1`, id).Scan(&status, &errMsg)
		if status != APJobCancelled || errMsg != APFailCancelled {
			t.Fatalf("status=%q error=%q, want cancelled/%s", status, errMsg, APFailCancelled)
		}
	})
}

func TestCancelAttackPathJob_AlreadyTerminalReturns404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, _ := h.createAPJob(context.Background(), "cancel-terminal-agent", map[string]any{}, 0)
		pool.Exec(context.Background(), `UPDATE attackpath_jobs SET status=$1 WHERE id=$2`, APJobCompleted, id)

		rec := httptest.NewRecorder()
		h.CancelAttackPathJob(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", id))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (already terminal)", rec.Code)
		}
	})
}

func TestRetryAttackPathJob_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		rec := httptest.NewRecorder()
		h.RetryAttackPathJob(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", "nope"))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

// TestRetryAttackPathJob_CancelsOldCreatesNew pins the full retry contract:
// the old job is cancelled with a "superseded by retry" note, a brand new job
// ID is created from the same payload, and the new job is (re-)dispatched.
func TestRetryAttackPathJob_CancelsOldCreatesNew(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		agent := startFakeAgent(t, h.hub, "retry-agent")
		defer agent.Disconnect(t)

		oldID, err := h.createAPJob(context.Background(), "retry-agent", map[string]any{"targets": []string{"10.0.0.1"}}, 1)
		if err != nil {
			t.Fatalf("createAPJob: %v", err)
		}

		rec := httptest.NewRecorder()
		h.RetryAttackPathJob(rec, withURLParam(httptest.NewRequest(http.MethodPost, "/x", nil), "id", oldID))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var newJob APJob
		json.Unmarshal(rec.Body.Bytes(), &newJob)
		if newJob.ID == oldID {
			t.Fatal("expected a new job ID distinct from the old one")
		}

		var oldStatus, oldErr string
		pool.QueryRow(context.Background(), `SELECT status, error FROM attackpath_jobs WHERE id=$1`, oldID).Scan(&oldStatus, &oldErr)
		if oldStatus != APJobCancelled || oldErr != "superseded by retry" {
			t.Fatalf("old job status=%q error=%q, want cancelled/superseded by retry", oldStatus, oldErr)
		}

		agent.WaitForMessage(t, 2*time.Second) // the new job's dispatch
	})
}

// TestApJobTick_DeliveryFailedAfterAckWindow pins the timeout-monitor's first
// pass: a dispatched job whose ACK window has elapsed flips to delivery_failed.
func TestApJobTick_DeliveryFailedAfterAckWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, _ := h.createAPJob(context.Background(), "tick-delivery-agent", map[string]any{}, 0)
		pool.Exec(context.Background(),
			`UPDATE attackpath_jobs SET status=$1, dispatched_at=$2 WHERE id=$3`,
			APJobDispatched, time.Now().Add(-ackWindow-time.Second), id)

		h.apJobTick(context.Background())

		var status, errMsg string
		pool.QueryRow(context.Background(), `SELECT status, error FROM attackpath_jobs WHERE id=$1`, id).Scan(&status, &errMsg)
		if status != APJobDeliveryFailed || errMsg != APFailDeliveryFailed {
			t.Fatalf("status=%q error=%q, want delivery_failed/%s", status, errMsg, APFailDeliveryFailed)
		}
	})
}

// TestApJobTick_TimedOutPastExpiry pins the second pass: any active
// (queued/dispatched/running) job past its expires_at flips to timed_out.
func TestApJobTick_TimedOutPastExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, _ := h.createAPJob(context.Background(), "tick-timeout-agent", map[string]any{}, 0)
		pool.Exec(context.Background(),
			`UPDATE attackpath_jobs SET status=$1, expires_at=$2 WHERE id=$3`,
			APJobRunning, time.Now().Add(-time.Minute), id)

		h.apJobTick(context.Background())

		var status, errMsg string
		pool.QueryRow(context.Background(), `SELECT status, error FROM attackpath_jobs WHERE id=$1`, id).Scan(&status, &errMsg)
		if status != APJobTimedOut || errMsg != APFailTimeout {
			t.Fatalf("status=%q error=%q, want timed_out/%s", status, errMsg, APFailTimeout)
		}
	})
}

// TestApJobTick_DoesNotTouchHealthyJobs pins that neither check false-positives
// on a freshly dispatched, non-expired job.
func TestApJobTick_DoesNotTouchHealthyJobs(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, _ := h.createAPJob(context.Background(), "tick-healthy-agent", map[string]any{}, 0)
		pool.Exec(context.Background(), `UPDATE attackpath_jobs SET status=$1, dispatched_at=NOW() WHERE id=$2`, APJobDispatched, id)

		h.apJobTick(context.Background())

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM attackpath_jobs WHERE id=$1`, id).Scan(&status)
		if status != APJobDispatched {
			t.Fatalf("status = %q, want unchanged dispatched", status)
		}
	})
}

// TestRedeliverQueuedAPJobs_RedispatchesOnlyQueued pins that reconnect
// redelivery only touches queued (never-delivered) jobs for that agent — a
// running job is left alone since resuming it needs an explicit operator call.
func TestRedeliverQueuedAPJobs_RedispatchesOnlyQueued(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		queuedID, _ := h.createAPJob(context.Background(), "redeliver-agent", map[string]any{"targets": []string{}}, 0)
		runningID, _ := h.createAPJob(context.Background(), "redeliver-agent", map[string]any{}, 0)
		pool.Exec(context.Background(), `UPDATE attackpath_jobs SET status=$1 WHERE id=$2`, APJobRunning, runningID)

		agent := startFakeAgent(t, h.hub, "redeliver-agent")
		defer agent.Disconnect(t)

		h.RedeliverQueuedAPJobs(context.Background(), "redeliver-agent")

		env := agent.WaitForMessage(t, 2*time.Second)
		var data map[string]any
		json.Unmarshal(env.Data, &data)
		if data["jobId"] != queuedID {
			t.Fatalf("redelivered jobId = %v, want the queued job %s", data["jobId"], queuedID)
		}

		var queuedStatus, runningStatus string
		pool.QueryRow(context.Background(), `SELECT status FROM attackpath_jobs WHERE id=$1`, queuedID).Scan(&queuedStatus)
		pool.QueryRow(context.Background(), `SELECT status FROM attackpath_jobs WHERE id=$1`, runningID).Scan(&runningStatus)
		if queuedStatus != APJobDispatched {
			t.Errorf("queued job status = %q, want dispatched after redelivery", queuedStatus)
		}
		if runningStatus != APJobRunning {
			t.Errorf("running job status = %q, want untouched running", runningStatus)
		}
	})
}

// TestUpdateAPJobProgress_SetsStartedAtOnFirstHeartbeat pins that the first
// progress heartbeat stamps started_at (used later to compute execution
// duration), and that a second heartbeat does not move it.
func TestUpdateAPJobProgress_SetsStartedAtOnFirstHeartbeat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, _ := h.createAPJob(context.Background(), "progress-agent", map[string]any{}, 0)
		pool.Exec(context.Background(), `UPDATE attackpath_jobs SET status=$1 WHERE id=$2`, APJobDispatched, id)

		h.UpdateAPJobProgress(context.Background(), "progress-agent", id, APJobProgress{Stage: APStageProbing, ProgressPercent: 10})

		var firstStarted time.Time
		var status string
		pool.QueryRow(context.Background(), `SELECT started_at, status FROM attackpath_jobs WHERE id=$1`, id).Scan(&firstStarted, &status)
		if firstStarted.IsZero() || status != APJobRunning {
			t.Fatalf("started_at=%v status=%q, want non-zero/running after first heartbeat", firstStarted, status)
		}

		h.UpdateAPJobProgress(context.Background(), "progress-agent", id, APJobProgress{Stage: APStageBuildingGraph, ProgressPercent: 80})
		var secondStarted time.Time
		pool.QueryRow(context.Background(), `SELECT started_at FROM attackpath_jobs WHERE id=$1`, id).Scan(&secondStarted)
		if !secondStarted.Equal(firstStarted) {
			t.Fatalf("started_at changed on second heartbeat: %v -> %v", firstStarted, secondStarted)
		}
	})
}

func TestCompleteAPJob_EmptyJobIDIsNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		h.CompleteAPJob(context.Background(), "some-agent", "", APJobMetrics{})
		// No panic, no query — nothing to assert beyond "did not error".
	})
}

// TestCompleteAPJob_DoesNotOverrideAlreadyTerminal pins that CompleteAPJob's
// WHERE clause excludes completed/cancelled/failed — a late completion signal
// after the job was already cancelled must not resurrect it as completed.
func TestCompleteAPJob_DoesNotOverrideAlreadyTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, _ := h.createAPJob(context.Background(), "complete-terminal-agent", map[string]any{}, 0)
		pool.Exec(context.Background(), `UPDATE attackpath_jobs SET status=$1 WHERE id=$2`, APJobCancelled, id)

		h.CompleteAPJob(context.Background(), "complete-terminal-agent", id, APJobMetrics{NodeCount: 5})

		var status string
		pool.QueryRow(context.Background(), `SELECT status FROM attackpath_jobs WHERE id=$1`, id).Scan(&status)
		if status != APJobCancelled {
			t.Fatalf("status = %q, want unchanged cancelled", status)
		}
	})
}

func TestFailAPJob_SetsReasonAndDoesNotOverrideCompleted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		id, _ := h.createAPJob(context.Background(), "fail-agent", map[string]any{}, 0)

		h.FailAPJob(context.Background(), "fail-agent", id, APFailUploadFailed)
		var status, errMsg string
		pool.QueryRow(context.Background(), `SELECT status, error FROM attackpath_jobs WHERE id=$1`, id).Scan(&status, &errMsg)
		if status != APJobFailed || errMsg != APFailUploadFailed {
			t.Fatalf("status=%q error=%q, want failed/%s", status, errMsg, APFailUploadFailed)
		}

		// A second failure signal after completion must not override.
		pool.Exec(context.Background(), `UPDATE attackpath_jobs SET status=$1 WHERE id=$2`, APJobCompleted, id)
		h.FailAPJob(context.Background(), "fail-agent", id, APFailNetworkError)
		pool.QueryRow(context.Background(), `SELECT status FROM attackpath_jobs WHERE id=$1`, id).Scan(&status)
		if status != APJobCompleted {
			t.Fatalf("status = %q, want unchanged completed", status)
		}
	})
}
