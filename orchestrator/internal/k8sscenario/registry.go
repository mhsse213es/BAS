package k8sscenario

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Cluster classes. The class decides which execution profiles a cluster may be targeted with
// (docs/k8s-bas/SPEC-first-wave.md section 2). Only an administrator sets it; the requester never does.
const (
	ClassLab           = "lab"
	ClassNonProduction = "non-production"
	ClassProduction    = "production"
)

// ClusterRecord is a registered cluster. Identity fields beyond the name and server URL (version,
// CA fingerprint, SPKI hash) are filled by live verification in a later step and are empty until then.
type ClusterRecord struct {
	ID            string
	DisplayName   string
	ServerURL     string
	Class         string
	// Identity, filled by verification. Zero until the cluster has been verified.
	Version       string
	CAFingerprint string
	SPKIHash      string
	VerifiedAt    time.Time
}

// nameRE allows letters, digits, dot, underscore, hyphen and space; 1 to 64 characters.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$`)

// ErrInvalidRegistration is returned, wrapped, for any registration that fails validation.
var ErrInvalidRegistration = errors.New("invalid cluster registration")

// CanonicalServerURL returns the server URL in the form used for identity: https scheme, lower-case host,
// no trailing slash, no path, query or fragment. Plain http is refused.
func CanonicalServerURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: server URL does not parse", ErrInvalidRegistration)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("%w: server URL must use https", ErrInvalidRegistration)
	}
	if u.Host == "" || u.User != nil {
		return "", fmt.Errorf("%w: server URL needs a host and no credentials", ErrInvalidRegistration)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%w: server URL must not carry a path, query or fragment", ErrInvalidRegistration)
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// ValidateRegistration checks a registration request before it is stored. It does not contact the cluster.
// adminSetsClass is true only when the caller is an administrator; anyone else cannot choose the class.
func ValidateRegistration(displayName, serverURL, class string, adminSetsClass bool) (ClusterRecord, error) {
	name := strings.TrimSpace(displayName)
	if !nameRE.MatchString(name) {
		return ClusterRecord{}, fmt.Errorf("%w: display name must be 1 to 64 letters, digits, dot, underscore, hyphen or space", ErrInvalidRegistration)
	}
	canon, err := CanonicalServerURL(serverURL)
	if err != nil {
		return ClusterRecord{}, err
	}
	if !adminSetsClass {
		return ClusterRecord{}, fmt.Errorf("%w: only an administrator sets the cluster class", ErrInvalidRegistration)
	}
	switch class {
	case ClassLab, ClassNonProduction, ClassProduction:
	default:
		return ClusterRecord{}, fmt.Errorf("%w: class must be lab, non-production or production", ErrInvalidRegistration)
	}
	return ClusterRecord{DisplayName: name, ServerURL: canon, Class: class}, nil
}

// AllowedProfiles returns the execution profiles a class may use. Production is Safe only, and Controlled is
// not enabled on production in this phase (SPEC-first-wave.md sections 1 and 2).
func AllowedProfiles(class string) []string {
	switch class {
	case ClassLab:
		return []string{"safe", "lab", "controlled"}
	case ClassNonProduction:
		return []string{"safe", "controlled"}
	case ClassProduction:
		return []string{"safe"}
	}
	return nil
}
