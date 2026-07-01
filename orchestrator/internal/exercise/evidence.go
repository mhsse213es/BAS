package exercise

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// EvidenceChain appends a new evidence record to the hash chain for an execution.
// Each record's sha256 = SHA256(payload_json) and prev_hash = sha256 of the
// previous record (or "" for the first). This creates a Merkle-style chain that
// makes post-hoc tampering detectable without a separate audit ledger.
type EvidenceChain struct {
	store *Store
}

func NewEvidenceChain(store *Store) *EvidenceChain { return &EvidenceChain{store: store} }

// Append records a new evidence event and returns the stored Evidence.
func (c *EvidenceChain) Append(ctx context.Context, execID, stepExecID, evType, actor, source string, payload map[string]interface{}) (*Evidence, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	// Reserve the next seq atomically.
	seq, err := c.store.NextSeq(ctx, execID)
	if err != nil {
		return nil, fmt.Errorf("next seq: %w", err)
	}

	// sha256 of the payload
	h := sha256.Sum256(payloadBytes)
	payHash := hex.EncodeToString(h[:])

	// prevHash = sha256 of the previous evidence record, or "" for seq 1
	_, prevHash, err := c.store.lastEvidenceHash(ctx, execID)
	if err != nil {
		return nil, fmt.Errorf("last hash: %w", err)
	}

	// The chained hash commits both the content and the chain position.
	// sha256(payload_hash + prev_hash) is stored as sha256 so verifiers
	// can recompute the chain without storing intermediate values.
	combined := sha256.Sum256([]byte(payHash + prevHash))
	chainHash := hex.EncodeToString(combined[:])

	ev := &Evidence{
		ExecutionID:     execID,
		StepExecutionID: stepExecID,
		Seq:             seq,
		EvidenceType:    evType,
		Actor:           actor,
		Source:          source,
		Payload:         payload,
		SHA256:          chainHash,
		PrevHash:        prevHash,
		RetentionPolicy: "90d",
	}
	if err := c.store.insertEvidence(ctx, ev); err != nil {
		return nil, fmt.Errorf("insert evidence: %w", err)
	}
	return ev, nil
}

// Verify walks the evidence chain for an execution and returns the first
// broken link, if any. Returns nil if the chain is intact.
func (c *EvidenceChain) Verify(ctx context.Context, execID string) error {
	records, err := c.store.ListEvidence(ctx, execID)
	if err != nil {
		return err
	}
	prevHash := ""
	for _, ev := range records {
		payloadBytes, _ := json.Marshal(ev.Payload)
		h := sha256.Sum256(payloadBytes)
		payHash := hex.EncodeToString(h[:])
		combined := sha256.Sum256([]byte(payHash + prevHash))
		expected := hex.EncodeToString(combined[:])
		if ev.SHA256 != expected {
			return fmt.Errorf("chain broken at seq %d (id=%s): expected %s got %s",
				ev.Seq, ev.ID, expected, ev.SHA256)
		}
		prevHash = ev.SHA256
	}
	return nil
}
