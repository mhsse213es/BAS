// Package auditarchive seals audit-log purge batches before any row is deleted. A batch is written as JSON
// Lines, and a manifest records its cutoff, id range, row count and SHA-256. The manifest is signed with an
// RSA-PSS key kept apart from the database, so the archive can be verified later without the signing secret.
// WriteArchive re-reads and verifies both files; the caller deletes rows only after it returns nil.
package auditarchive

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Alg names the signature scheme in every manifest.
const Alg = "RSASSA-PSS-SHA256"

// Row is one audit_logs record as archived.
type Row struct {
	ID       int64           `json:"id"`
	Ts       time.Time       `json:"ts"`
	ActorID  string          `json:"actor_id"`
	Action   string          `json:"action"`
	Resource string          `json:"resource"`
	Detail   json.RawMessage `json:"detail"`
	IP       string          `json:"ip"`
	Outcome  string          `json:"outcome"`
}

// Manifest describes one sealed batch. Signature covers every field except Signature.
type Manifest struct {
	BatchID    string    `json:"batch_id"`
	CutoffUTC  time.Time `json:"cutoff_utc"`
	FirstID    int64     `json:"first_id"`
	LastID     int64     `json:"last_id"`
	RowCount   int       `json:"row_count"`
	SHA256     string    `json:"sha256"`
	CreatedUTC time.Time `json:"created_utc"`
	Alg        string    `json:"alg"`
	Signature  string    `json:"signature"`
}

// EncodeRows writes rows as JSON Lines in the order given. Timestamps are UTC, so the same rows always give
// the same bytes.
func EncodeRows(rows []Row) ([]byte, error) {
	var buf bytes.Buffer
	for _, r := range rows {
		r.Ts = r.Ts.UTC()
		line, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// signedFields is the manifest without its signature: the bytes that are signed.
type signedFields struct {
	BatchID    string    `json:"batch_id"`
	CutoffUTC  time.Time `json:"cutoff_utc"`
	FirstID    int64     `json:"first_id"`
	LastID     int64     `json:"last_id"`
	RowCount   int       `json:"row_count"`
	SHA256     string    `json:"sha256"`
	CreatedUTC time.Time `json:"created_utc"`
	Alg        string    `json:"alg"`
}

func signedBytes(m Manifest) ([]byte, error) {
	return json.Marshal(signedFields{m.BatchID, m.CutoffUTC.UTC(), m.FirstID, m.LastID, m.RowCount, m.SHA256, m.CreatedUTC.UTC(), m.Alg})
}

func digest(b []byte) []byte {
	d := sha256.Sum256(b)
	return d[:]
}

// Seal fills in the archive's hash, row count and id range from body, then signs the manifest.
func Seal(body []byte, m Manifest, key *rsa.PrivateKey) (Manifest, error) {
	rows, first, last, err := parseBody(body)
	if err != nil {
		return Manifest{}, err
	}
	m.Alg = Alg
	m.RowCount = rows
	m.FirstID, m.LastID = first, last
	sum := sha256.Sum256(body)
	m.SHA256 = hex.EncodeToString(sum[:])
	sb, err := signedBytes(m)
	if err != nil {
		return Manifest{}, err
	}
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest(sb), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return Manifest{}, fmt.Errorf("sign manifest: %w", err)
	}
	m.Signature = base64.StdEncoding.EncodeToString(sig)
	return m, nil
}

// Verify checks the archive bytes against the manifest and its signature. It returns nil only when the hash,
// the row count, the id range and the signature all match.
func Verify(body []byte, m Manifest, pub *rsa.PublicKey) error {
	if m.Alg != Alg {
		return fmt.Errorf("unsupported alg %q", m.Alg)
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		return errors.New("archive sha256 does not match the manifest")
	}
	rows, first, last, err := parseBody(body)
	if err != nil {
		return err
	}
	if rows != m.RowCount || first != m.FirstID || last != m.LastID {
		return errors.New("archive row count or id range does not match the manifest")
	}
	sb, err := signedBytes(m)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest(sb), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		return fmt.Errorf("manifest signature invalid: %w", err)
	}
	return nil
}

// parseBody counts the rows and returns the first and last ids.
func parseBody(body []byte) (rows int, first, last int64, err error) {
	for _, line := range bytes.Split(bytes.TrimSuffix(body, []byte("\n")), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r Row
		if err := json.Unmarshal(line, &r); err != nil {
			return 0, 0, 0, fmt.Errorf("archive row %d: %w", rows+1, err)
		}
		if rows == 0 {
			first = r.ID
		}
		last = r.ID
		rows++
	}
	return rows, first, last, nil
}

// WriteArchive persists a sealed batch as <dir>/<batch>.jsonl and <dir>/<batch>.manifest.json. It re-reads and
// verifies both files before returning. On any failure it removes what it wrote, and the caller must not delete
// rows.
func WriteArchive(dir string, m Manifest, body []byte, pub *rsa.PublicKey) error {
	base := filepath.Join(dir, m.BatchID)
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	cleanup := func() {
		os.Remove(base + ".jsonl")
		os.Remove(base + ".manifest.json")
	}
	if err := writeSynced(base+".jsonl", body); err != nil {
		cleanup()
		return err
	}
	if err := writeSynced(base+".manifest.json", mb); err != nil {
		cleanup()
		return err
	}
	gotBody, err := os.ReadFile(base + ".jsonl")
	if err != nil {
		cleanup()
		return err
	}
	var gotM Manifest
	gotMB, err := os.ReadFile(base + ".manifest.json")
	if err == nil {
		err = json.Unmarshal(gotMB, &gotM)
	}
	if err != nil {
		cleanup()
		return err
	}
	if err := Verify(gotBody, gotM, pub); err != nil {
		cleanup()
		return fmt.Errorf("re-verify archive %s: %w", m.BatchID, err)
	}
	return nil
}

func writeSynced(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
