package auditarchive

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sampleRows() []Row {
	ts := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	return []Row{
		{ID: 1, Ts: ts, ActorID: "u1", Action: "login", Resource: "session", Detail: []byte(`{"a":1}`), IP: "10.0.0.1", Outcome: "ok"},
		{ID: 2, Ts: ts.Add(time.Minute), ActorID: "u2", Action: "run.create", Resource: "run/9", Detail: []byte(`{}`), Outcome: "ok"},
	}
}

func sealed(t *testing.T, k *rsa.PrivateKey) ([]byte, Manifest) {
	t.Helper()
	body, err := EncodeRows(sampleRows())
	if err != nil {
		t.Fatal(err)
	}
	m, err := Seal(body, Manifest{BatchID: "b-1", CutoffUTC: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC), FirstID: 1, LastID: 2, RowCount: 2, CreatedUTC: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}, k)
	if err != nil {
		t.Fatal(err)
	}
	return body, m
}

func TestEncodeRows_IsDeterministic(t *testing.T) {
	a, _ := EncodeRows(sampleRows())
	b, _ := EncodeRows(sampleRows())
	if string(a) != string(b) {
		t.Fatal("the same rows must encode to the same bytes")
	}
}

func TestSealThenVerify_RoundTrip(t *testing.T) {
	k := testKey(t)
	body, m := sealed(t, k)
	if err := Verify(body, m, &k.PublicKey); err != nil {
		t.Fatalf("a freshly sealed archive must verify: %v", err)
	}
}

func TestVerify_RejectsTamperedArchive(t *testing.T) {
	k := testKey(t)
	body, m := sealed(t, k)
	body[len(body)-3] ^= 0x01
	if err := Verify(body, m, &k.PublicKey); err == nil {
		t.Fatal("a changed archive body must fail verification")
	}
}

func TestVerify_RejectsTamperedManifest(t *testing.T) {
	k := testKey(t)
	body, m := sealed(t, k)
	m.RowCount = 99
	if err := Verify(body, m, &k.PublicKey); err == nil {
		t.Fatal("a changed manifest must fail verification")
	}
}

func TestVerify_RejectsWrongKey(t *testing.T) {
	k := testKey(t)
	other := testKey(t)
	body, m := sealed(t, k)
	if err := Verify(body, m, &other.PublicKey); err == nil {
		t.Fatal("an archive verified with a different key must fail")
	}
}

func TestWriteArchive_PersistsAndReVerifies(t *testing.T) {
	k := testKey(t)
	body, m := sealed(t, k)
	dir := t.TempDir()
	if err := WriteArchive(dir, m, body, &k.PublicKey); err != nil {
		t.Fatalf("WriteArchive: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "b-1.jsonl"))
	if err != nil || string(got) != string(body) {
		t.Fatalf("archive file not written as sealed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b-1.manifest.json")); err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
}

func TestWriteArchive_FailsWhenDirectoryMissing_NoDeletionPossible(t *testing.T) {
	k := testKey(t)
	body, m := sealed(t, k)
	if err := WriteArchive(filepath.Join(t.TempDir(), "missing"), m, body, &k.PublicKey); err == nil {
		t.Fatal("WriteArchive must fail when the archive directory does not exist; the caller must then not delete")
	}
}
