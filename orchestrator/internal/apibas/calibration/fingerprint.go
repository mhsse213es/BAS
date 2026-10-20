package calibration

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Fingerprint is a drift detector for the environment a calibration was measured on. It is
// built from attributes the operating system reports, never from an operator's typed name.
//
// It is not cryptographic proof of identity. Every value is read from a local source that
// anyone with administrator rights can change, so a deliberate spoof is not detected. What
// the fingerprint does is catch accidental or unrecorded change: a different CPU, memory
// size, operating system build, architecture, CPU count or Go toolchain.
type Fingerprint struct {
	// Attributes holds the values that were read. Each one came from an OS or runtime source.
	Attributes map[string]string `json:"attributes"`
	// Sources names where each value came from, so a reviewer can see what was verified.
	Sources map[string]string `json:"sources"`
	// Unavailable lists the OS-dependent attributes the platform could not read. They are
	// part of the digest, so a platform that starts or stops reporting one requalifies.
	Unavailable []string `json:"unavailable"`
	// Digest is a SHA-256 over the sorted attributes and the unavailable list.
	Digest string `json:"digest"`
}

// osAttributeNames lists the attributes that depend on the platform. Each one is either
// read by osAttributes or recorded as unavailable.
var osAttributeNames = []string{"cpu_model", "memory_total_bytes", "os_version"}

// CollectFingerprint reads the current environment.
func CollectFingerprint() Fingerprint {
	f := Fingerprint{
		Attributes: map[string]string{
			"goos":       runtime.GOOS,
			"goarch":     runtime.GOARCH,
			"go_version": runtime.Version(),
			"num_cpu":    strconv.Itoa(runtime.NumCPU()),
		},
		Sources: map[string]string{
			"goos":       "runtime",
			"goarch":     "runtime",
			"go_version": "runtime",
			"num_cpu":    "runtime",
		},
	}
	found := osAttributes()
	for _, name := range osAttributeNames {
		if a, ok := found[name]; ok && a.value != "" {
			f.Attributes[name] = a.value
			f.Sources[name] = a.source
		} else {
			f.Unavailable = append(f.Unavailable, name)
		}
	}
	sort.Strings(f.Unavailable)
	f.Digest = f.computeDigest()
	return f
}

// sourcedValue is one attribute read from one named source.
type sourcedValue struct {
	value  string
	source string
}

func (f Fingerprint) computeDigest() string {
	keys := make([]string, 0, len(f.Attributes))
	for k := range f.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "=" + f.Attributes[k] + "\n")
	}
	b.WriteString("unavailable=" + strings.Join(f.Unavailable, ",") + "\n")
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// Matches reports whether two fingerprints describe the same environment. A fingerprint
// with no digest never matches, so an unrecorded environment cannot pass as recorded.
func (f Fingerprint) Matches(o Fingerprint) bool {
	return f.Digest != "" && f.Digest == o.Digest
}

// DigestIsConsistent reports whether the stored digest follows from the stored attributes.
// An edited attribute without a matching digest, or the reverse, fails this check.
func (f Fingerprint) DigestIsConsistent() bool {
	return f.Digest != "" && f.Digest == f.computeDigest()
}
