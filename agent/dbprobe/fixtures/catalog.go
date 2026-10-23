// Package fixtures holds the named synthetic database fixtures, their seeding
// and their verified cleanup (spec 8 gate 4). Everything here is lab-only and
// deterministic: no clock, no randomness in the data, no real PANs or customer
// data (spec 2). The only randomness is the fixture id (crypto/rand), which
// names the dedicated dbsim_<id> schema.
package fixtures

import (
	"fmt"
	"sort"
	"strings"

	"audspect/agent/dbprobe"
)

// SyntheticMarker prefixes the value in every row's `synthetic` column so a
// fixture row can never be mistaken for real data.
const SyntheticMarker = "BAS-SIM-"

// Published payment-card TEST numbers (Luhn-valid so DAM classifiers fire), the
// same values as orchestrator/internal/dlpfixture/catalog.go (Visa, Mastercard,
// American Express). The agent module cannot import orchestrator code, so the
// small set is copied here; the orchestrator catalog is the source. This is a
// closed allow-list: TestNoRealPANPatterns fails on any other 13+ digit run, so
// a PAN can never be generated or drawn from a real BIN range.
const (
	testPANVisa       = "4111111111111111"
	testPANMastercard = "5555555555554444"
	testPANAmex       = "378282246310005"
	// Same SSN-shaped value as the dlpfixture "us-ssn-record" fixture (area 000
	// is never issued).
	testSSN = "000-12-3456"
)

// Kind names of the catalog fixtures (FixtureSpec.Kind / DBProbeSpec.FixtureID).
const (
	KindAccounts      = "accounts"
	KindClassifiedPII = "classified-pii"
	KindEmpty         = "empty"
	KindEdge          = "edge"
)

var builders = map[string]func() []dbprobe.FixtureTable{
	KindAccounts:      accountsTables,
	KindClassifiedPII: piiTables,
	KindEmpty:         emptyTables,
	KindEdge:          edgeTables,
}

// Lookup returns a fresh copy of the named catalog fixture. The data is
// identical on every call.
func Lookup(name string) (dbprobe.FixtureSpec, bool) {
	b, ok := builders[name]
	if !ok {
		return dbprobe.FixtureSpec{}, false
	}
	return dbprobe.FixtureSpec{Kind: name, Tables: b()}, true
}

// Names lists the catalog fixture names, sorted.
func Names() []string {
	out := make([]string, 0, len(builders))
	for n := range builders {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func marker(suffix string) string { return SyntheticMarker + suffix }

func accountsTables() []dbprobe.FixtureTable {
	t := dbprobe.FixtureTable{
		Name: "accounts",
		Columns: []dbprobe.FixtureColumn{
			{Name: "id", Type: dbprobe.FixtureColInt, PK: true},
			{Name: "synthetic", Type: dbprobe.FixtureColText},
			{Name: "account_ref", Type: dbprobe.FixtureColText},
			{Name: "display_name", Type: dbprobe.FixtureColText},
			{Name: "email", Type: dbprobe.FixtureColText},
			{Name: "balance_cents", Type: dbprobe.FixtureColInt},
		},
	}
	for i := 1; i <= 10; i++ {
		t.Rows = append(t.Rows, []any{
			i, marker("SYNTHETIC"),
			fmt.Sprintf("BAS-SIM-ACCT-%04d", i),
			fmt.Sprintf("BAS-SIM Test Account %02d", i),
			fmt.Sprintf("bas-sim-account%02d@example.invalid", i),
			i * 1250,
		})
	}
	return []dbprobe.FixtureTable{t}
}

func piiTables() []dbprobe.FixtureTable {
	t := dbprobe.FixtureTable{
		Name: "customers_pii",
		Columns: []dbprobe.FixtureColumn{
			{Name: "id", Type: dbprobe.FixtureColInt, PK: true},
			{Name: "synthetic", Type: dbprobe.FixtureColText},
			{Name: "full_name", Type: dbprobe.FixtureColText},
			{Name: "email", Type: dbprobe.FixtureColText},
			{Name: "phone", Type: dbprobe.FixtureColText},
			{Name: "ssn", Type: dbprobe.FixtureColText},
			{Name: "card_number", Type: dbprobe.FixtureColText},
		},
	}
	pans := []string{testPANVisa, testPANMastercard, testPANAmex}
	for i := 1; i <= 6; i++ {
		t.Rows = append(t.Rows, []any{
			i, marker("SYNTHETIC"),
			fmt.Sprintf("BAS-SIM Person %02d", i),
			fmt.Sprintf("bas-sim-person%02d@example.invalid", i),
			fmt.Sprintf("+1-555-01%02d", i), // 555-01XX is reserved for fiction
			testSSN,
			pans[(i-1)%len(pans)],
		})
	}
	return []dbprobe.FixtureTable{t}
}

func emptyTables() []dbprobe.FixtureTable {
	return []dbprobe.FixtureTable{{
		Name: "empty_table",
		Columns: []dbprobe.FixtureColumn{
			{Name: "id", Type: dbprobe.FixtureColInt, PK: true},
			{Name: "synthetic", Type: dbprobe.FixtureColText},
			{Name: "note", Type: dbprobe.FixtureColText},
		},
	}}
}

// edgeTables exercises NULLs, an empty string, text at the 4 KB cell cap, valid
// but unusual Unicode, and quote characters that only bound parameters survive.
func edgeTables() []dbprobe.FixtureTable {
	long := strings.Repeat("BAS-SIM-LONG-", dbprobe.MaxFixtureCellBytes/len("BAS-SIM-LONG-")+1)[:dbprobe.MaxFixtureCellBytes]
	return []dbprobe.FixtureTable{{
		Name: "edge_cases",
		Columns: []dbprobe.FixtureColumn{
			{Name: "id", Type: dbprobe.FixtureColInt, PK: true},
			{Name: "synthetic", Type: dbprobe.FixtureColText},
			{Name: "note", Type: dbprobe.FixtureColText},
			{Name: "payload", Type: dbprobe.FixtureColText},
		},
		Rows: [][]any{
			{1, marker("NULLS"), nil, nil},
			{2, marker("EMPTY-STRING"), "", ""},
			{3, marker("LONG-TEXT"), "4096-byte value", long},
			{4, marker("UNICODE"), "café naïve é 日本語 שלום \U0001F600 a‍b  ", "BAS-SIM-üñîçødé"},
			{5, marker("QUOTES"), "O'Brien \"quoted\" \\ back\\slash `tick` -- ; /* c */", "BAS-SIM-'; SELECT 1; --"},
		},
	}}
}
