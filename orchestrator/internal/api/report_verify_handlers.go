package api

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/audspect/bas/internal/reporting"
)

// maxAuditPackBytes bounds an uploaded pack for verification (50 MiB — packs
// with embedded PDFs run a few MB; this leaves generous headroom without
// letting an upload exhaust memory).
const maxAuditPackBytes = 50 << 20

// fileCheck is one file's verification outcome.
type fileCheck struct {
	Path     string `json:"path"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	OK       bool   `json:"ok"`
}

// verifyResult is the JSON returned by POST /api/report/verify.
type verifyResult struct {
	Verified            bool        `json:"verified"` // overall: every file OK AND (signature valid OR signing disabled)
	FilesChecked        int         `json:"filesChecked"`
	FilesOK             int         `json:"filesOk"`
	Mismatches          []fileCheck `json:"mismatches"`
	MissingFiles        []string    `json:"missingFiles"`        // in manifest but not in pack
	UnlistedFiles       []string    `json:"unlistedFiles"`       // in pack but not in manifest (excludes manifest/sig files)
	ManifestPresent     bool        `json:"manifestPresent"`
	AttestationPresent  bool        `json:"attestationPresent"`
	SignaturePresent    bool        `json:"signaturePresent"`
	SignatureValid      bool        `json:"signatureValid"`
	ManifestDigestMatch bool        `json:"manifestDigestMatch"`
	GeneratedBy         string      `json:"generatedBy,omitempty"`
	GeneratedAt         string      `json:"generatedAt,omitempty"`
	ToolVersion         string      `json:"toolVersion,omitempty"`
	Note                string      `json:"note,omitempty"`
}

// VerifyAuditPack re-checks an uploaded audit-pack ZIP: it recomputes the
// SHA-256 of every file against MANIFEST.sha256 and verifies the HMAC signature
// in attestation.json against this deployment's report-signing key. This makes
// the "submit to the console to verify" instruction in SIGNATURE.txt real.
//
// POST /api/report/verify   (multipart/form-data, field "file")
func (h *Handler) VerifyAuditPack(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxAuditPackBytes); err != nil {
		jsonError(w, "invalid multipart form", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "missing 'file' field (upload the audit-pack .zip)", http.StatusBadRequest)
		return
	}
	defer file.Close()

	buf, err := io.ReadAll(io.LimitReader(file, maxAuditPackBytes))
	if err != nil {
		jsonError(w, "read upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		jsonError(w, "not a valid ZIP archive", http.StatusBadRequest)
		return
	}

	// Read every entry into memory (bounded by maxAuditPackBytes total), keyed
	// by path relative to the pack root (the single top-level folder). The pack
	// always nests under one dir; strip it so paths match MANIFEST entries.
	files := map[string][]byte{}
	for _, ze := range zr.File {
		if ze.FileInfo().IsDir() {
			continue
		}
		rc, err := ze.Open()
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(rc, maxAuditPackBytes))
		rc.Close()
		files[stripTopDir(ze.Name)] = data
	}

	res := verifyResult{}
	manifestBytes, ok := files["MANIFEST.sha256"]
	res.ManifestPresent = ok
	if !ok {
		res.Note = "MANIFEST.sha256 not found — not an Audspect audit pack, or an older pack without integrity data."
		respond(w, res)
		return
	}

	// 1) Per-file integrity against the manifest.
	entries := reporting.ParseManifest(manifestBytes)
	listed := map[string]bool{}
	for _, e := range entries {
		listed[e.Path] = true
		res.FilesChecked++
		data, present := files[e.Path]
		if !present {
			res.MissingFiles = append(res.MissingFiles, e.Path)
			res.Mismatches = append(res.Mismatches, fileCheck{Path: e.Path, Expected: e.SHA256, Actual: "(missing)", OK: false})
			continue
		}
		sum := sha256.Sum256(data)
		actual := hex.EncodeToString(sum[:])
		if actual == e.SHA256 {
			res.FilesOK++
		} else {
			res.Mismatches = append(res.Mismatches, fileCheck{Path: e.Path, Expected: e.SHA256, Actual: actual, OK: false})
		}
	}
	// Files present in the pack but absent from the manifest (excluding the
	// integrity files themselves, which are never self-listed).
	for path := range files {
		switch path {
		case "MANIFEST.sha256", "SIGNATURE.txt", "attestation.json":
			continue
		}
		if !listed[path] {
			res.UnlistedFiles = append(res.UnlistedFiles, path)
		}
	}

	// 2) Signature authenticity via attestation.json.
	if sigBytes, ok := files["attestation.json"]; ok {
		res.AttestationPresent = true
		var att reporting.Attestation
		if json.Unmarshal(sigBytes, &att) == nil {
			res.GeneratedBy = att.GeneratedBy
			res.GeneratedAt = att.GeneratedAt.Format("2006-01-02T15:04:05Z07:00")
			res.ToolVersion = att.ToolVersion
			res.SignaturePresent = att.Signature != ""
			digestMatch, sigValid := reporting.VerifyManifestSignature(manifestBytes, att)
			res.ManifestDigestMatch = digestMatch
			res.SignatureValid = sigValid
		}
	}
	_ = files["SIGNATURE.txt"] // human-readable; not parsed

	// Overall verdict: every listed file matched, none missing, and the
	// signature is valid (or signing is disabled on this deployment, in which
	// case integrity still stands but authenticity cannot be asserted).
	filesGood := len(res.Mismatches) == 0 && len(res.MissingFiles) == 0 && res.FilesChecked > 0
	if !reporting.SigningEnabled() {
		res.Verified = filesGood
		res.Note = "This deployment has report signing disabled — file integrity verified, but signature authenticity could not be checked."
	} else if !res.AttestationPresent {
		res.Verified = false
		res.Note = "Pack has no attestation.json — integrity checked, but it predates signature support or was stripped."
	} else {
		res.Verified = filesGood && res.ManifestDigestMatch && res.SignatureValid
		if res.Verified {
			res.Note = "Authentic and unaltered: all files match and the signature is valid for this deployment."
		} else if !res.SignatureValid {
			res.Note = "Signature did NOT validate — the pack was not produced by this deployment, or was altered."
		} else {
			res.Note = "One or more files were altered, added, or removed since the pack was generated."
		}
	}

	h.auditLog(r, "report.verify", "", map[string]any{"verified": res.Verified, "filesChecked": res.FilesChecked}, "ok")
	respond(w, res)
}

// stripTopDir removes the single leading "dir/" segment audit packs nest under,
// so entry paths line up with the manifest's pack-root-relative paths.
func stripTopDir(name string) string {
	name = strings.TrimPrefix(name, "./")
	if i := strings.Index(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}
