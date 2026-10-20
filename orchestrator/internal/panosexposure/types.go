// Package panosexposure correlates one PAN-OS appliance's reported state with a
// vendor advisory and returns an exposure verdict for a single CVE.
//
// It is pure logic: no network, no database, no vendor data embedded. Affected
// version ranges and exposure conditions come from the advisory the caller
// supplies, so this package never asserts a vendor fact that the advisory does
// not state. A verdict of Vulnerable means the supplied advisory's exposure
// conditions are met by the supplied asset data. It does not mean the appliance
// has been exploited, and it does not replace the vendor's own advisory.
package panosexposure

// Product is the only product this package handles.
const Product = "pan-os"

// Tri is a three-valued configuration fact. A missing fact is Unknown, never
// assumed to be No or Yes.
type Tri string

const (
	TriYes     Tri = "yes"
	TriNo      Tri = "no"
	TriUnknown Tri = "unknown"
)

// Verdict is the exposure outcome for one asset and one advisory.
type Verdict string

const (
	// VerdictVulnerable: version affected and every exposure condition the
	// advisory names is confirmed present.
	VerdictVulnerable Verdict = "vulnerable"
	// VerdictMitigated: version affected, but a condition the advisory names is
	// confirmed absent (for example GlobalProtect disabled). Not reachable by
	// that path until the condition changes.
	VerdictMitigated Verdict = "mitigated"
	// VerdictNotAffected: version outside every affected range in the advisory.
	VerdictNotAffected Verdict = "not_affected"
	// VerdictUnknown: a fact needed for the decision is missing or unparseable.
	// Never reported as safe.
	VerdictUnknown Verdict = "unknown"
	// VerdictNotApplicable: the asset is not PAN-OS.
	VerdictNotApplicable Verdict = "not_applicable"
)

// Asset is one PAN-OS appliance as reported by the caller (inventory import,
// config export, or manual entry). Facts the caller cannot establish are Unknown.
type Asset struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname,omitempty"`
	Product  string `json:"product"`
	// Version as reported, for example "10.2.3" or "10.2.3-h1".
	Version string `json:"version"`
	// GlobalProtect portal or gateway enabled.
	GlobalProtect Tri `json:"globalProtect"`
	// Authentication override feature enabled on the GlobalProtect portal.
	AuthOverride Tri `json:"authOverride"`
	// The authentication-override cookie uses the same certificate as the
	// GlobalProtect HTTPS service.
	SharedOverrideCert Tri `json:"sharedOverrideCert"`
}

// VersionRange is a half-open range [Introduced, FixedIn). Both bounds are
// PAN-OS version strings in the same format as Asset.Version. An empty FixedIn
// means the advisory gives no fixed release for that range.
type VersionRange struct {
	Introduced string `json:"introduced"`
	FixedIn    string `json:"fixedIn"`
}

// Conditions lists which exposure conditions the advisory names. A condition
// is checked only when its flag is true.
type Conditions struct {
	RequireGlobalProtect bool `json:"requireGlobalProtect"`
	RequireAuthOverride  bool `json:"requireAuthOverride"`
	RequireSharedCert    bool `json:"requireSharedCert"`
}

// Advisory is the vendor data for one CVE, supplied by the caller. Source is
// the advisory URL or identifier, so every verdict can cite where its ranges
// came from.
type Advisory struct {
	CVE        string         `json:"cve"`
	Source     string         `json:"source"`
	Affected   []VersionRange `json:"affected"`
	Conditions Conditions     `json:"conditions"`
}

// Result is the verdict plus the evidence and limits behind it.
type Result struct {
	AssetID     string   `json:"assetId"`
	CVE         string   `json:"cve"`
	Verdict     Verdict  `json:"verdict"`
	Reason      string   `json:"reason"`
	Evidence    []string `json:"evidence"`
	Limitations []string `json:"limitations,omitempty"`
}
