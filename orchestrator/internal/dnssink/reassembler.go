package dnssink

import (
	"encoding/base32"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// reassembler accumulates DNS-tunneled chunks per campaign ID, keyed by
// the campaign ID extracted from each query (see protocol.go's record
// type). Not meant to be shared across processes -- one reassembler per
// listener instance, matching this being a purpose-built, single-process
// component rather than a distributed DNS server.
type reassembler struct {
	mu        sync.Mutex
	campaigns map[string]*campaignState
	ttl       time.Duration
	maxChunks int
	now       func() time.Time
}

type campaignState struct {
	total   int // 0 until the header record is seen
	chunks  map[int]string
	expires time.Time
}

func newReassembler(ttl time.Duration, maxChunks int) *reassembler {
	return &reassembler{
		campaigns: map[string]*campaignState{},
		ttl:       ttl,
		maxChunks: maxChunks,
		now:       time.Now,
	}
}

// header records the declared total chunk count for a campaign, creating
// its state (or resetting it, if a header for the same campaign ID
// arrives again). Rejects a declared total that is non-numeric, zero,
// negative, or larger than maxChunks -- a header declaring an implausibly
// large count is refused outright rather than allocating buffer space
// for it.
func (r *reassembler) header(campaignID, totalStr string) error {
	total, err := strconv.Atoi(totalStr)
	if err != nil || total < 1 || total > r.maxChunks {
		return fmt.Errorf("invalid or oversized declared total %q (max %d)", totalStr, r.maxChunks)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.campaigns[campaignID] = &campaignState{
		total:   total,
		chunks:  map[int]string{},
		expires: r.now().Add(r.ttl),
	}
	return nil
}

// chunk records one data chunk for campaignID. Returns complete=true
// exactly when this was the chunk that completed a previously-declared
// total, in which case decoded holds the fully reassembled and
// base32-decoded payload. A duplicate/resent seq overwrites the earlier
// value without erroring -- real network conditions can cause a resend,
// and the verifier only needs "was the full sequence eventually seen",
// not exactly-once delivery.
func (r *reassembler) chunk(campaignID string, seq int, b32Chunk string) (decoded []byte, complete bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cs, ok := r.campaigns[campaignID]
	if !ok || cs.total == 0 {
		return nil, false, fmt.Errorf("chunk for unknown/header-less campaign %q", campaignID)
	}
	if seq < 1 || seq > cs.total {
		return nil, false, fmt.Errorf("chunk seq %d out of range for declared total %d", seq, cs.total)
	}
	cs.chunks[seq] = b32Chunk
	cs.expires = r.now().Add(r.ttl)
	if len(cs.chunks) < cs.total {
		return nil, false, nil
	}
	var sb strings.Builder
	for i := 1; i <= cs.total; i++ {
		sb.WriteString(cs.chunks[i])
	}
	dec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(sb.String())
	if err != nil {
		return nil, false, fmt.Errorf("decode reassembled payload: %w", err)
	}
	delete(r.campaigns, campaignID)
	return dec, true, nil
}

// evictExpired removes any campaign whose TTL has passed, bounding this
// reassembler's memory use regardless of how many campaigns start and
// never complete.
func (r *reassembler) evictExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for id, cs := range r.campaigns {
		if now.After(cs.expires) {
			delete(r.campaigns, id)
		}
	}
}
