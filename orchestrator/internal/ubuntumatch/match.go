package ubuntumatch

// Verdict is the outcome for one mapping on one host.
type Verdict string

const (
	// Exposed: an installed package is older than the reviewed fixed version.
	Exposed Verdict = "EXPOSED"
	// NotExposed: an installed package is at or above the reviewed fixed version.
	NotExposed Verdict = "NOT_EXPOSED"
	// Unknown: the result cannot be established from the data. Unknown is never
	// reported as "no fix" or as NOT_EXPOSED.
	Unknown Verdict = "UNKNOWN"
)

// Host is one Ubuntu host's inventory.
type Host struct {
	// Release is the Ubuntu codename, for example "jammy".
	Release string
	// Packages maps installed binary package name to its dpkg version.
	// It is the full dpkg inventory. A package missing from this map is not
	// reported as NOT_EXPOSED, because it may be missing from the inventory rather than the host.
	Packages map[string]string
}

// Result is one verdict for one mapping and one installed package.
type Result struct {
	CVE       string
	MappingID string
	Package   string
	Installed string
	Verdict   Verdict
	Reason    string
}

// Match evaluates every eligible mapping in the register against one host.
// Ineligible mappings produce no results at all.
func Match(reg *Register, host Host) []Result {
	var out []Result
	for _, m := range reg.Mappings {
		if !m.Eligible() {
			continue
		}
		out = append(out, matchMapping(m, host)...)
	}
	return out
}

func matchMapping(m Mapping, host Host) []Result {
	rf, ok := m.Releases[host.Release]
	if !ok {
		return []Result{{CVE: m.CVE, MappingID: m.ID, Verdict: Unknown,
			Reason: "mapping has no data for release " + host.Release}}
	}
	var out []Result
	for _, pkg := range rf.Corresponding {
		installed, present := host.Packages[pkg]
		if !present {
			out = append(out, Result{CVE: m.CVE, MappingID: m.ID, Package: pkg, Verdict: Unknown,
				Reason: "package not in inventory"})
			continue
		}
		fixes := fixesFor(rf.Fixed, pkg)
		if len(fixes) == 0 {
			out = append(out, Result{CVE: m.CVE, MappingID: m.ID, Package: pkg, Installed: installed,
				Verdict: Unknown, Reason: "no fixed version recorded for installed package"})
			continue
		}
		out = append(out, judge(m, pkg, installed, fixes))
	}
	if len(out) == 0 {
		out = append(out, Result{CVE: m.CVE, MappingID: m.ID, Verdict: Unknown,
			Reason: "no corresponding package recorded for release " + host.Release})
	}
	return out
}

// judge compares the installed version with every recorded fixed version for
// the package. A verdict is returned only if all of them agree.
func judge(m Mapping, pkg, installed string, fixes []PackageFix) Result {
	var first Verdict
	for i, f := range fixes {
		v := NotExposed
		if DpkgCompare(installed, f.Version) < 0 {
			v = Exposed
		}
		if i == 0 {
			first = v
		} else if v != first {
			return Result{CVE: m.CVE, MappingID: m.ID, Package: pkg, Installed: installed,
				Verdict: Unknown, Reason: "recorded fixed versions disagree on the verdict"}
		}
	}
	return Result{CVE: m.CVE, MappingID: m.ID, Package: pkg, Installed: installed,
		Verdict: first, Reason: "compared with reviewed fixed version"}
}

func fixesFor(all []PackageFix, pkg string) []PackageFix {
	var out []PackageFix
	for _, f := range all {
		if f.Package == pkg {
			out = append(out, f)
		}
	}
	return out
}
