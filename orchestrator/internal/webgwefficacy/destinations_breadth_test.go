package webgwefficacy

import (
	"net/url"
	"path"
	"strings"
	"testing"
)

// Breadth: the first catalog held two URL-filtering destinations and two file downloads. A real gateway policy has
// dozens of categories and a list of blocked file types, so these tests pin the wider coverage and keep it safe.

func byID(t *testing.T) map[string]TestDestination {
	t.Helper()
	m := map[string]TestDestination{}
	for _, d := range mustCatalog(t) {
		m[d.ID] = d
	}
	return m
}

func TestBreadth_URLFilteringCoversTheCategoriesAPolicyIsBuiltFrom(t *testing.T) {
	blocked, allowed := map[string]bool{}, map[string]bool{}
	for _, d := range mustCatalog(t) {
		if d.Category != CategoryURLFilter {
			continue
		}
		if d.ExpectedAction == ExpectedAllow {
			allowed[d.URLCategory] = true
		} else {
			blocked[d.URLCategory] = true
		}
	}
	for _, c := range []string{"gambling", "adult", "anonymizer", "peer-to-peer", "malware-hosting", "cryptomining", "hacking", "newly-registered-domain", "illegal-drugs"} {
		if !blocked[c] {
			t.Errorf("no blocked URL-filtering destination for category %q", c)
		}
	}
	for _, c := range []string{"news", "education", "government", "health", "search-engines", "software-updates", "finance"} {
		if !allowed[c] {
			t.Errorf("no allowed URL-filtering destination for category %q", c)
		}
	}
	if len(blocked)+len(allowed) < 16 {
		t.Errorf("URL filtering covers %d categories, want at least 16", len(blocked)+len(allowed))
	}
}

// File types: the same host serves every file, so the gateway's decision can only come from the file type or content.
func TestBreadth_FileDownloadsCoverBlockedAllowedAndEICARTypes(t *testing.T) {
	blocked, allowed := map[string]bool{}, map[string]bool{}
	for _, d := range mustCatalog(t) {
		if d.Category != CategorySafeFile {
			continue
		}
		u, _ := url.Parse(d.URL)
		ext := strings.TrimPrefix(strings.ToLower(path.Ext(u.Path)), ".")
		if d.ExpectedAction == ExpectedAllow {
			allowed[ext] = true
		} else {
			blocked[ext] = true
		}
	}
	for _, e := range []string{"exe", "scr", "bat", "cmd", "ps1", "vbs", "js", "jar", "msi", "dll", "iso", "lnk"} {
		if !blocked[e] {
			t.Errorf("no blocked download for the .%s file type", e)
		}
	}
	for _, e := range []string{"txt", "pdf", "docx", "xlsx", "csv", "png"} {
		if !allowed[e] {
			t.Errorf("no allowed download for the .%s file type", e)
		}
	}
	d := byID(t)
	for _, id := range []string{"WG-SF-001"} {
		if _, ok := d[id]; !ok {
			t.Errorf("%s (the original EICAR download) disappeared", id)
		}
	}
}

func TestBreadth_EICARDownloadsIncludeTheTextAndZippedVariants(t *testing.T) {
	var names []string
	for _, d := range mustCatalog(t) {
		u, _ := url.Parse(d.URL)
		if strings.HasPrefix(path.Base(u.Path), "eicar") {
			names = append(names, path.Base(u.Path))
			if d.ExpectedAction != ExpectedBlock {
				t.Errorf("%s: an EICAR download must be expected blocked, got %s", d.ID, d.ExpectedAction)
			}
		}
	}
	joined := strings.Join(names, " ")
	for _, want := range []string{"eicar.com", "eicar.com.txt", "eicarcom2.zip"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no EICAR download named %s (have %v)", want, names)
		}
	}
}

// Safety: a file name in the catalog can only ever mean the EICAR test file or a benign placeholder. Nothing else may
// be catalogued, and the host must sit under a reserved test TLD.
func TestBreadth_OnlyEICARAndBenignSampleNamesAreCatalogued(t *testing.T) {
	for _, d := range mustCatalog(t) {
		if d.Category != CategorySafeFile {
			continue
		}
		u, _ := url.Parse(d.URL)
		name := path.Base(u.Path)
		if !permittedFileName(name) {
			t.Errorf("%s: %q is not an EICAR name or a benign sample.<ext> name", d.ID, name)
		}
		if !hasReservedTLD(strings.ToLower(u.Hostname())) {
			t.Errorf("%s: host %q is not under a reserved test TLD", d.ID, u.Hostname())
		}
	}
}

func TestBreadth_PermittedFileNameRules(t *testing.T) {
	for _, ok := range []string{"eicar.com", "eicar.com.txt", "eicarcom2.zip", "sample.txt", "sample.exe", "sample.docx", "SAMPLE.PDF"} {
		if !permittedFileName(ok) {
			t.Errorf("%q should be permitted", ok)
		}
	}
	for _, bad := range []string{"payload.exe", "mimikatz.exe", "eicar.exe", "sample", "sample.rar", "sample.exe.php", "setup.msi", "", "sample.", "eicar.com.exe"} {
		if permittedFileName(bad) {
			t.Errorf("%q must not be permitted", bad)
		}
	}
}

func TestBreadth_EveryNewDestinationIDIsUniqueAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, d := range mustCatalog(t) {
		if seen[d.ID] {
			t.Errorf("duplicate ID %s", d.ID)
		}
		seen[d.ID] = true
		if !strings.HasPrefix(d.ID, "WG-") {
			t.Errorf("%s does not start with WG-", d.ID)
		}
	}
	if len(seen) != 43 {
		t.Errorf("catalog has %d destinations, want 43", len(seen))
	}
}
