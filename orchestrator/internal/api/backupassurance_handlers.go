package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/backupassurance"
	"github.com/audspect/bas/internal/db"
)

// ── POST /api/backup-assurance/assessments ────────────────────────────────

type backupAssuranceCheckJSON struct {
	Check      string `json:"check"`
	Verdict    string `json:"verdict"`
	SkipReason string `json:"skipReason,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Simulated  bool   `json:"simulated"`
	Observer   string `json:"observer"`
}

type backupAssuranceAssessmentJSON struct {
	AssessmentID string                     `json:"assessmentId"`
	Results      []backupAssuranceCheckJSON `json:"results"`
}

func toAssessmentJSON(assessmentID string, results []backupassurance.CheckResult) backupAssuranceAssessmentJSON {
	out := backupAssuranceAssessmentJSON{AssessmentID: assessmentID, Results: make([]backupAssuranceCheckJSON, len(results))}
	for i, r := range results {
		out.Results[i] = backupAssuranceCheckJSON{
			Check: string(r.Check), Verdict: string(r.Verdict), SkipReason: string(r.SkipReason),
			Reason: r.Reason, Simulated: r.Simulated, Observer: r.Observer,
		}
	}
	return out
}

// fakeBackupAssuranceDependencies wires an all-fake-backed Dependencies for
// this sub-project -- every observer here returns a fixed captured value,
// standing in until a real backup-platform integration is a separately
// reviewed, lab-gated sub-project. Never promoted beyond this slice.
func fakeBackupAssuranceDependencies() backupassurance.Dependencies {
	return backupassurance.Dependencies{
		DeletionProtection:  &backupassurance.FakeDeletionProtectionObserver{Tested: true, Protected: true, Reason: "simulated: object-lock policy present"},
		Immutability:        &backupassurance.FakeImmutabilityObserver{Tested: true, Immutable: true, Reason: "simulated: immutability enabled"},
		OfflineIsolation:    &backupassurance.FakeOfflineIsolationObserver{Tested: true, Isolated: true, Reason: "simulated: offline copy unreachable from tested identity"},
		PrivilegeSeparation: &backupassurance.FakePrivilegeSeparationObserver{Tested: true, Separated: true, Reason: "simulated: backup admin uses separate credentials"},
		RestoreIntegrity:    &backupassurance.FakeRestoreIntegrityObserver{Tested: true, ValidResult: true, Reason: "simulated: restored files passed integrity checks"},
		RPORTO:              &backupassurance.FakeRPORTOObserver{Tested: true, Met: true, Reason: "simulated: recovery met defined RPO/RTO"},
	}
}

func (h *Handler) TriggerBackupAssuranceAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	results := backupassurance.AssessBackup(ctx, fakeBackupAssuranceDependencies())

	assessmentID, err := db.WriteBackupAssuranceAssessment(ctx, h.db, results)
	if err != nil {
		jsonError(w, "failed to persist assessment", http.StatusInternalServerError)
		return
	}
	jsonOK(w, toAssessmentJSON(assessmentID, results))
}

// ── GET /api/backup-assurance/assessments/{assessmentId} ──────────────────

func (h *Handler) GetBackupAssuranceAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	assessmentID := chi.URLParam(r, "assessmentId")

	results, err := db.ReadBackupAssuranceAssessment(ctx, h.db, assessmentID)
	switch {
	case errors.Is(err, db.ErrAssessmentNotFound):
		jsonError(w, "assessment not found", http.StatusNotFound)
		return
	case errors.Is(err, db.ErrAssessmentIncomplete):
		jsonError(w, "assessment data is incomplete", http.StatusInternalServerError)
		return
	case err != nil:
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	jsonOK(w, toAssessmentJSON(assessmentID, results))
}
