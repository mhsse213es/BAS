package carbanakledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Row is one audit entry. Hash covers PrevHash and every field, so changing any
// earlier row breaks every hash after it.
type Row struct {
	RunID     string    `json:"run_id"`
	Step      string    `json:"step"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Decision  Decision  `json:"decision"`
	RuleFired string    `json:"rule_fired"`
	At        time.Time `json:"at"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// Log is an append-only, hash-chained audit log stored one JSON row per line.
// A single chain covers every run, so Verify checks the whole file.
type Log struct {
	mu   sync.Mutex
	path string
	rows []Row
}

func Open(path string) (*Log, error) {
	l := &Log{path: path}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Row
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("parse audit row %d: %w", len(l.rows), err)
		}
		l.rows = append(l.rows, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}
	return l, nil
}

func hashRow(r Row) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s|%s|%s",
		r.PrevHash, r.RunID, r.Step, r.Actor, r.Action, r.Decision, r.RuleFired,
		r.At.UTC().Format(time.RFC3339Nano))
	return hex.EncodeToString(h.Sum(nil))
}

func (l *Log) Append(runID, step, actor, action string, d Decision, rule string, at time.Time) (Row, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	prev := genesisHash
	if n := len(l.rows); n > 0 {
		prev = l.rows[n-1].Hash
	}
	r := Row{
		RunID: runID, Step: step, Actor: actor, Action: action,
		Decision: d, RuleFired: rule, At: at.UTC(), PrevHash: prev,
	}
	r.Hash = hashRow(r)

	b, err := json.Marshal(r)
	if err != nil {
		return Row{}, fmt.Errorf("encode audit row: %w", err)
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Row{}, fmt.Errorf("open audit log for append: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return Row{}, fmt.Errorf("append audit row: %w", err)
	}
	l.rows = append(l.rows, r)
	return r, nil
}

// Rows returns the rows for one run, in append order.
func (l *Log) Rows(runID string) []Row {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Row
	for _, r := range l.rows {
		if r.RunID == runID {
			out = append(out, r)
		}
	}
	return out
}

// Verify checks the whole chain. It returns intact=false and the index of the
// first row whose hash or link does not match.
func (l *Log) Verify() (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := genesisHash
	for i, r := range l.rows {
		if r.PrevHash != prev || hashRow(r) != r.Hash {
			return false, i
		}
		prev = r.Hash
	}
	return true, -1
}
