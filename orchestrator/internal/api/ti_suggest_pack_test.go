package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedARTTestableTechnique inserts a techniques row plus a matching
// art_atomic_tests row — the shape techsFromIDs/tacticPackTechs require to
// consider a technique "ART-testable" and include it in a pack.
func seedARTTestableTechnique(t *testing.T, pool *pgxpool.Pool, techID, name, tactic string) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO techniques (technique_id, name, tactic) VALUES ($1,$2,$3)
		 ON CONFLICT (technique_id) DO NOTHING`,
		techID, name, tactic); err != nil {
		t.Fatalf("seed technique %s: %v", techID, err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO art_atomic_tests (technique_id, test_index, name, executor, command)
		 VALUES ($1, 0, 'test', 'powershell', 'echo test')`,
		techID); err != nil {
		t.Fatalf("seed art_atomic_tests %s: %v", techID, err)
	}
}

func seedKEVCVE(t *testing.T, pool *pgxpool.Pool, cveID, techID string, ransomware bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO cves (cve_id, source, known_ransomware) VALUES ($1,'cisa-kev',$2)
		 ON CONFLICT (cve_id) DO NOTHING`,
		cveID, ransomware); err != nil {
		t.Fatalf("seed cve: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO technique_cves (technique_id, cve_id) VALUES ($1,$2)
		 ON CONFLICT DO NOTHING`,
		techID, cveID); err != nil {
		t.Fatalf("seed technique_cves: %v", err)
	}
}

func suggestPackHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func TestGetSuggestPack_UnknownType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := suggestPackHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetSuggestPack(rec, tiReq("/api/ti/suggest-pack", "type=bogus"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

// TestGetSuggestPack_KEV pins the KEV pack's DB join (technique_cves+cves,
// filtered to ART-testable techniques) and its aggregate extra fields
// (totalKevCves/ransomwareCount).
func TestGetSuggestPack_KEV(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedARTTestableTechnique(t, pool, "T1210", "Exploitation of Remote Services", "lateral-movement")
		seedKEVCVE(t, pool, "CVE-2024-9999", "T1210", true)
		h := suggestPackHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetSuggestPack(rec, tiReq("/api/ti/suggest-pack", "type=kev"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			PackType        string     `json:"packType"`
			TechniqueCount  int        `json:"techniqueCount"`
			Techniques      []packTech `json:"techniques"`
			HasData         bool       `json:"hasData"`
			TotalKevCves    int        `json:"totalKevCves"`
			RansomwareCount int        `json:"ransomwareCount"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !out.HasData || out.TechniqueCount != 1 {
			t.Fatalf("out = %+v, want hasData=true techniqueCount=1", out)
		}
		if out.Techniques[0].TechniqueID != "T1210" || out.Techniques[0].KEVCount != 1 || !out.Techniques[0].RansomwareLinked {
			t.Fatalf("technique = %+v, want T1210 kevCount=1 ransomwareLinked=true", out.Techniques[0])
		}
		if out.TotalKevCves != 1 || out.RansomwareCount != 1 {
			t.Fatalf("totalKevCves=%d ransomwareCount=%d, want 1/1", out.TotalKevCves, out.RansomwareCount)
		}
	})
}

func TestGetSuggestPack_KEV_NoData(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := suggestPackHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetSuggestPack(rec, tiReq("/api/ti/suggest-pack", "type=kev"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var out struct {
			HasData        bool `json:"hasData"`
			TechniqueCount int  `json:"techniqueCount"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.HasData || out.TechniqueCount != 0 {
			t.Fatalf("out = %+v, want hasData=false techniqueCount=0", out)
		}
	})
}

// TestGetSuggestPack_Ransomware pins the ATT&CK-group-keyword-matching path:
// "Wizard Spider" (a real bundled STIX group) matches the ransomware
// keyword list, and one of its techniques (T1055.001, per
// attackdata.GroupTechniqueIndex) must be ART-testable to appear.
func TestGetSuggestPack_Ransomware(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedARTTestableTechnique(t, pool, "T1055.001", "Dynamic-link Library Injection", "defense-evasion")
		h := suggestPackHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetSuggestPack(rec, tiReq("/api/ti/suggest-pack", "type=ransomware"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out struct {
			HasData    bool       `json:"hasData"`
			Techniques []packTech `json:"techniques"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		var found bool
		for _, tech := range out.Techniques {
			if tech.TechniqueID == "T1055.001" {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected T1055.001 (Wizard Spider technique) in ransomware pack, got %+v", out.Techniques)
		}
	})
}

// TestGetSuggestPack_TacticPacks pins credential-theft and lateral-movement,
// both backed by tacticPackTechs (a direct tactic-column filter).
func TestGetSuggestPack_TacticPacks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedARTTestableTechnique(t, pool, "T1003.001", "LSASS Memory", "credential-access")
		seedARTTestableTechnique(t, pool, "T1021.001", "Remote Desktop Protocol", "lateral-movement")
		h := suggestPackHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetSuggestPack(rec, tiReq("/api/ti/suggest-pack", "type=credential-theft"))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var credOut struct {
			Techniques []packTech `json:"techniques"`
		}
		json.Unmarshal(rec.Body.Bytes(), &credOut)
		if len(credOut.Techniques) != 1 || credOut.Techniques[0].TechniqueID != "T1003.001" {
			t.Fatalf("credential-theft techniques = %+v, want just T1003.001", credOut.Techniques)
		}

		rec2 := httptest.NewRecorder()
		h.GetSuggestPack(rec2, tiReq("/api/ti/suggest-pack", "type=lateral-movement"))
		var latOut struct {
			Techniques []packTech `json:"techniques"`
		}
		json.Unmarshal(rec2.Body.Bytes(), &latOut)
		if len(latOut.Techniques) != 1 || latOut.Techniques[0].TechniqueID != "T1021.001" {
			t.Fatalf("lateral-movement techniques = %+v, want just T1021.001", latOut.Techniques)
		}
	})
}

// TestGetSuggestPack_IDListPacks pins living-off-the-land and
// powershell-abuse, both backed by idListPackTechs (a hardcoded ID
// allowlist) — only ART-testable techniques from the list survive, and
// non-listed techniques never leak in even if seeded.
func TestGetSuggestPack_IDListPacks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedARTTestableTechnique(t, pool, "T1218.011", "Mshta", "defense-evasion")                      // in both lotlTechIDs and psAbuseTechIDs
		seedARTTestableTechnique(t, pool, "T1059.001", "PowerShell", "execution")                       // in both lists
		seedARTTestableTechnique(t, pool, "T1584", "Compromise Infrastructure", "resource-development") // in neither list
		h := suggestPackHandler(t, pool)

		rec := httptest.NewRecorder()
		h.GetSuggestPack(rec, tiReq("/api/ti/suggest-pack", "type=living-off-the-land"))
		var lotlOut struct {
			Techniques []packTech `json:"techniques"`
		}
		json.Unmarshal(rec.Body.Bytes(), &lotlOut)
		ids := map[string]bool{}
		for _, tech := range lotlOut.Techniques {
			ids[tech.TechniqueID] = true
		}
		if !ids["T1218.011"] || !ids["T1059.001"] || ids["T1584"] {
			t.Fatalf("living-off-the-land techniques = %+v, want T1218.011+T1059.001 present, T1584 absent", lotlOut.Techniques)
		}
	})
}

// TestGetSuggestPack_SuggestedScenarioShape pins the ready-to-POST scenario
// body every pack response carries, regardless of type.
func TestGetSuggestPack_SuggestedScenarioShape(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedARTTestableTechnique(t, pool, "T1003.001", "LSASS Memory", "credential-access")
		h := suggestPackHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetSuggestPack(rec, tiReq("/api/ti/suggest-pack", "type=credential-theft"))
		var out struct {
			SuggestedID       string `json:"suggestedId"`
			SuggestedName     string `json:"suggestedName"`
			SuggestedScenario struct {
				ID            string   `json:"id"`
				Name          string   `json:"name"`
				Tags          []string `json:"tags"`
				ArtTechniques []string `json:"artTechniques"`
			} `json:"suggestedScenario"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.SuggestedScenario.ID != out.SuggestedID || out.SuggestedScenario.Name != out.SuggestedName {
			t.Errorf("suggestedScenario.id/name should match the top-level suggestedId/suggestedName: %+v", out)
		}
		if len(out.SuggestedScenario.ArtTechniques) != 1 || out.SuggestedScenario.ArtTechniques[0] != "T1003.001" {
			t.Errorf("suggestedScenario.artTechniques = %v, want [T1003.001]", out.SuggestedScenario.ArtTechniques)
		}
		if len(out.SuggestedScenario.Tags) == 0 {
			t.Error("suggestedScenario.tags should be populated from the pack metadata")
		}
	})
}
