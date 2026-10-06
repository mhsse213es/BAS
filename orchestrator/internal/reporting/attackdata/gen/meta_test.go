package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func writeBundle(t *testing.T, name, body string) (string, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	return p, hex.EncodeToString(sum[:])
}

func TestReadDatasetMeta_FromCollectionObject(t *testing.T) {
	p, sum := writeBundle(t, "bundle.json", `{"type":"bundle","objects":[
		{"type":"x-mitre-collection","id":"x-mitre-collection--1","name":"Enterprise ATT&CK",
		 "x_mitre_version":"16.1","modified":"2024-11-12T14:00:00.188Z"},
		{"type":"attack-pattern","id":"attack-pattern--1","x_mitre_domains":["enterprise-attack"]}]}`)
	m, err := readDatasetMeta(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.AttackVersion == nil || *m.AttackVersion != "16.1" {
		t.Fatalf("version = %v", m.AttackVersion)
	}
	if m.Domain == nil || *m.Domain != "enterprise-attack" {
		t.Fatalf("domain = %v", m.Domain)
	}
	if m.SourceBundleSHA256 != sum || m.CollectionName != "Enterprise ATT&CK" ||
		m.CollectionModified != "2024-11-12T14:00:00.188Z" {
		t.Fatalf("meta = %+v", m)
	}
}

// The version comes only from the bundle's collection object -- never from
// the file name (or any comment).
func TestReadDatasetMeta_NoCollectionMeansNoVersion(t *testing.T) {
	p, sum := writeBundle(t, "enterprise-attack-16.1.json", `{"type":"bundle","objects":[
		{"type":"attack-pattern","id":"attack-pattern--1","x_mitre_version":"1.0","x_mitre_domains":["enterprise-attack"]}]}`)
	m, err := readDatasetMeta(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.AttackVersion != nil {
		t.Fatalf("version must be unknown without an x-mitre-collection, got %q", *m.AttackVersion)
	}
	if m.SourceBundleSHA256 != sum {
		t.Fatalf("sha = %s", m.SourceBundleSHA256)
	}
}

func TestReadDatasetMeta_CollectionWithoutVersion(t *testing.T) {
	p, _ := writeBundle(t, "enterprise-attack-16.1.json", `{"type":"bundle","objects":[
		{"type":"x-mitre-collection","id":"x-mitre-collection--1","name":"Enterprise ATT&CK"}]}`)
	m, err := readDatasetMeta(p)
	if err != nil {
		t.Fatal(err)
	}
	if m.AttackVersion != nil {
		t.Fatalf("version must be unknown, got %q", *m.AttackVersion)
	}
}
