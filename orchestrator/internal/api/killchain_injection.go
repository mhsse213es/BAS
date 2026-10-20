package api

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/injectionapproval"
	"github.com/audspect/bas/internal/pipelinecheck"
)

// InjectionResult is the outcome of one gated injection. Status is EXECUTED, NOT_TESTED (the
// gate refused or the provider cannot write; nothing was written), or ERROR (the approval was
// used and the write then failed).
type InjectionResult struct {
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	RunID      string `json:"runId"`
	ApprovalID string `json:"approvalId"`
}

// runGatedInjection writes one test record only when a valid approval is consumed for exactly
// this payload and target. The order is fixed:
//
//  1. An approval ID must be supplied. A campaign launch never supplies one.
//  2. The provider must have a write adapter. Checked first so an unsupported provider does not
//     spend an approval.
//  3. The record is tagged with the run identifier and marker.
//  4. The scope must match the request. Checked before consumption, so a mismatched attempt
//     does not spend the approval.
//  5. The approval is consumed by the store, which verifies it again.
//  6. Only then is the record written.
func runGatedInjection(ctx context.Context, store db.KillChainStore, approvalID, consumer string,
	scope injectionapproval.Scope, class injectionapproval.Classification, now time.Time,
	inj pipelinecheck.Injector, req pipelinecheck.InjectionRequest) InjectionResult {
	res := InjectionResult{RunID: req.RunID, ApprovalID: approvalID}
	refuse := func(reason string) InjectionResult {
		res.Status, res.Reason = "NOT_TESTED", reason
		return res
	}

	if approvalID == "" {
		return refuse("no approval supplied; an injection is never approved by a campaign launch")
	}
	if inj == nil || !inj.Supported() {
		return refuse("no injection adapter for this provider in this build; nothing was written")
	}
	tagged, err := pipelinecheck.TagDocument(req.Document, req.RunID)
	if err != nil {
		return refuse(err.Error())
	}
	hash, err := pipelinecheck.PayloadHash(tagged)
	if err != nil {
		return refuse("could not hash the payload: " + err.Error())
	}
	if scope.Kind != injectionapproval.KindInjection || scope.Target != req.Index || scope.PayloadHash != hash {
		return refuse("the approved scope does not match this request's target or payload; no approval was used")
	}
	if err := store.ConsumeApproval(ctx, approvalID, consumer, scope, class, now); err != nil {
		return refuse(fmt.Sprintf("approval refused: %v", err))
	}

	req.Document = tagged
	outcome, err := inj.Inject(ctx, req)
	if err != nil {
		res.Status, res.Reason = "ERROR", "the approval was used and the write failed: "+err.Error()
		return res
	}
	res.Status, res.Reason = outcome.Status, outcome.Reason
	return res
}
