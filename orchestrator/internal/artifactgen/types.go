package artifactgen

import "github.com/audspect/bas/internal/iocregistry"

// ArgKey identifies one ART input argument this package knows how to replace with a
// freshly generated value.
type ArgKey struct {
	TechniqueID string
	TestName    string // Atomic Red Team's atomic_tests[].name -- matches art.go's artAtomicTest.Name
	ArgName     string
}

// curated maps a known-safe argument to the IOC type its value represents. Starts
// empty -- populated by reviewing real ART atomic tests, one at a time, in future
// work. Never guess a mapping from the argument name alone (ART authors use
// inconsistent naming across tests); every entry here must be manually verified
// against the real atomic test's YAML and semantics before being added.
var curated = map[ArgKey]iocregistry.Type{}

// Lookup returns the IOC type for a curated argument, or false if this argument isn't
// curated (the caller leaves ART's static default substitution alone in that case).
func Lookup(techniqueID, testName, argName string) (iocregistry.Type, bool) {
	t, ok := curated[ArgKey{TechniqueID: techniqueID, TestName: testName, ArgName: argName}]
	return t, ok
}

// CuratedFor returns every curated ArgKey/Type pair for a technique, regardless of
// which of its atomic tests they belong to -- the dispatch-time substitution loop
// (handlers.go) tries each and skips any whose #{argName} token isn't present in the
// particular step's command (a technique can have multiple atomic tests; only the
// matching one contains a given token).
func CuratedFor(techniqueID string) map[ArgKey]iocregistry.Type {
	out := map[ArgKey]iocregistry.Type{}
	for k, t := range curated {
		if k.TechniqueID == techniqueID {
			out[k] = t
		}
	}
	return out
}

// SeedForTest temporarily adds a curated entry for tests in OTHER packages
// (internal/scenario, internal/api) that need to exercise the skip-list/substitution
// mechanism without a real, reviewed ART entry. Call the returned cleanup func (e.g.
// via defer) to remove it. Test-support only -- never called from production code.
func SeedForTest(key ArgKey, t iocregistry.Type) (cleanup func()) {
	curated[key] = t
	return func() { delete(curated, key) }
}
