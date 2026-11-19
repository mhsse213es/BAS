package openapi

import (
	"regexp"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/apibas/scope"
)

// Class is a candidate test class chosen from the shape of an operation. It is a reason to test, never a finding.
type Class string

const (
	ClassObjectLevel     Class = "object_level_authorization"   // a path parameter names an object
	ClassFunctionLevel   Class = "function_level_authorization" // an administrative, internal-looking or privileged-action route
	ClassPropertyLevel   Class = "property_level_authorization" // a write body carries a field that must not be client-set
	ClassUnauthenticated Class = "unauthenticated_access"       // the specification declares the operation public
	ClassDataExposure    Class = "sensitive_data_exposure"      // a success response carries a sensitive-looking field
	ClassResource        Class = "resource_consumption"         // a paging or size control the client sets
	ClassSSRF            Class = "server_side_request"          // a parameter or field that names a destination
	ClassUpload          Class = "file_upload"                  // a multipart or binary body
	ClassLifecycle       Class = "lifecycle"                    // deprecated, or an older API version beside a newer one
)

// ClassInfo says what a class is and which catalogue category it points at.
type ClassInfo struct {
	Class    Class
	Category string // the API BAS catalogue category prefix whose scenarios test this class
	Meaning  string
}

// Classes is the closed list of classes, in report order.
var Classes = []ClassInfo{
	{ClassObjectLevel, "AUTHZ", "an object identifier in the path: test that another identity cannot reach the object"},
	{ClassFunctionLevel, "AUTHZ", "an administrative route or a privileged action such as approve or settle: test that an ordinary identity cannot call it"},
	{ClassPropertyLevel, "AUTHZ", "a write body field such as a role, price or owner: test that the client cannot set it"},
	{ClassUnauthenticated, "AUTHN", "the specification declares no authentication: confirm it is meant to be public"},
	{ClassDataExposure, "DATA", "a response field that looks sensitive: test that it is returned only to those entitled to it"},
	{ClassResource, "ABUSE", "a client-set page or size control: test the documented maximum is enforced"},
	{ClassSSRF, "INTEG", "a field that names a destination: test the server refuses internal and unlisted hosts"},
	{ClassUpload, "ABUSE", "a file body: test size and type limits"},
	{ClassLifecycle, "DISC", "a deprecated or older version: test that retired routes are not served with weaker controls"},
}

var (
	idParam      = regexp.MustCompile(`(?i)(^id$|_id$|id$|^uuid$|^guid$)`)
	privSegment  = regexp.MustCompile(`(?i)^(admin|internal|manage|management|debug|actuator|staff|ops|backoffice|superuser|root|system|approve|settle|refund|disburse|release|override|impersonate)$`)
	healthPath   = regexp.MustCompile(`(?i)^/(health|healthz|ping|ready|readyz|live|livez|status|version|\.well-known)(/|$)|openapi|swagger|/docs?(/|$)`)
	versionPath  = regexp.MustCompile(`^/v([0-9]+)(/|$)`)
	pagingParam  = regexp.MustCompile(`(?i)^(limit|page|page_size|pagesize|per_page|perpage|size|offset|cursor|count|max)$`)
	destination  = regexp.MustCompile(`(?i)(^|_)(url|uri|callback|callback_url|webhook|webhook_url|redirect|redirect_uri|return_url|target|host|endpoint|href)$`)
	mutableField = regexp.MustCompile(`(?i)^(role|roles|is_?admin|admin|permissions?|scope|privileges?|price|amount|total|discount|balance|credit|status|owner|owner_?id|user_?id|tenant|tenant_?id|verified|approved)$`)
	sensitive    = regexp.MustCompile(`(?i)(password|passwd|secret|token|api_?key|ssn|national_?id|aadhaar|pan_?number|card|cvv|iban|account_?number|dob|date_?of_?birth|diagnosis|insurance|address|phone|email|private_?key)`)
)

func isWrite(method string) bool {
	return method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE"
}

// classify assigns candidate classes to every operation in the inventory.
func classify(inv *Inventory) {
	newest := map[string]int{} // path without version prefix -> highest version
	for _, o := range inv.Operations {
		if v, rest, ok := splitVersion(o.Path); ok && v > newest[rest] {
			newest[rest] = v
		}
	}
	for i := range inv.Operations {
		o := &inv.Operations[i]
		var cs []Class
		add := func(c Class) { cs = append(cs, c) }
		public := healthPath.MatchString(o.Path)

		for _, p := range o.PathParams {
			if idParam.MatchString(p) {
				add(ClassObjectLevel)
				break
			}
		}
		for _, seg := range strings.Split(o.Path, "/") {
			if privSegment.MatchString(seg) {
				add(ClassFunctionLevel)
				break
			}
		}
		if isWrite(o.Method) {
			for _, f := range o.BodyFields {
				if mutableField.MatchString(f) {
					add(ClassPropertyLevel)
					break
				}
			}
		}
		if o.Auth == AuthNone && !public {
			add(ClassUnauthenticated)
		}
		for _, f := range o.ResponseFields {
			if sensitive.MatchString(f) {
				add(ClassDataExposure)
				break
			}
		}
		if o.Method == "GET" {
			for _, q := range o.QueryParams {
				if pagingParam.MatchString(q) {
					add(ClassResource)
					break
				}
			}
		}
		if hasDestination(o) {
			add(ClassSSRF)
		}
		for _, ct := range o.BodyContentTypes {
			if strings.HasPrefix(ct, "multipart/") || ct == "application/octet-stream" {
				add(ClassUpload)
				break
			}
		}
		if o.Deprecated {
			add(ClassLifecycle)
		} else if v, rest, ok := splitVersion(o.Path); ok && v < newest[rest] {
			add(ClassLifecycle)
		}
		o.Classes = dedupeClasses(cs)
	}
}

func hasDestination(o *Operation) bool {
	for _, group := range [][]string{o.QueryParams, o.BodyFields} {
		for _, n := range group {
			if destination.MatchString(n) {
				return true
			}
		}
	}
	return false
}

func splitVersion(path string) (version int, rest string, ok bool) {
	m := versionPath.FindStringSubmatch(path)
	if m == nil {
		return 0, "", false
	}
	n := 0
	for _, c := range m[1] {
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return 0, "", false
		}
	}
	return n, strings.TrimPrefix(path, "/v"+m[1]), true
}

func dedupeClasses(in []Class) []Class {
	if len(in) == 0 {
		return nil
	}
	seen := map[Class]bool{}
	var out []Class
	for _, c := range Classes {
		for _, x := range in {
			if x == c.Class && !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// ByClass returns the operations carrying a class, in inventory order.
func (inv *Inventory) ByClass(c Class) []Operation {
	var out []Operation
	for _, o := range inv.Operations {
		for _, x := range o.Classes {
			if x == c {
				out = append(out, o)
				break
			}
		}
	}
	return out
}

// SuggestedScope proposes allowed path prefixes from the operations' static path prefixes: the first two static segments of each
// path, or one when the path has only one. It is a suggestion for a person to confirm. It never widens a target by itself, and
// a prefix the scope package would reject is dropped.
func (inv *Inventory) SuggestedScope() []string {
	set := map[string]bool{}
	for _, o := range inv.Operations {
		p := scope.StaticPrefix(o.Path)
		segs := strings.Split(strings.Trim(p, "/"), "/")
		if len(segs) > 2 {
			segs = segs[:2]
		}
		prefix := "/" + strings.Join(segs, "/")
		if prefix != "/" && scope.ValidPrefix(prefix) {
			set[prefix] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
