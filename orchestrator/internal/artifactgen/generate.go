package artifactgen

import (
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"strings"

	"github.com/audspect/bas/internal/iocregistry"
)

// filenameStems are plausible legitimate-sounding base names -- avoids fully random
// garbage (which is itself a signature; iochandling.txt §6's own example rotates
// through names like "explorer_update.exe", "office_sync.exe", not random hex).
var filenameStems = []string{"explorer_update", "office_sync", "svc_healthcheck", "sys_diag", "print_helper"}

var serviceStems = []string{"WinDefend_Helper", "UpdateOrchestrator", "DiagTrackSvc", "NetProfSvc"}

var registryKeyStems = []string{"RunOnceHelper", "AppUpdateCheck", "SysMaintTask", "UserPrefSync"}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func pick(stems []string, seed []byte) string {
	return stems[int(seed[0])%len(stems)]
}

// Generate produces a fresh value for t, preserving origDefault's file extension when
// t is TypeFilename -- the generated name must still make sense to the technique (a
// dropper test expecting a .dll needs a .dll back, not a random extension). Types
// outside Phase C's scope (domain/ip/url/certificate/...) return origDefault unchanged.
func Generate(t iocregistry.Type, origDefault string) string {
	seed := make([]byte, 4)
	_, _ = rand.Read(seed)
	suffix := randHex(2)

	switch t {
	case iocregistry.TypeFilename:
		ext := filepath.Ext(origDefault)
		if ext == "" {
			ext = ".exe"
		}
		return pick(filenameStems, seed) + "_" + suffix + ext
	case iocregistry.TypeMutex:
		return `Global\` + pick(filenameStems, seed) + "-" + randHex(8)
	case iocregistry.TypeRegistryKey:
		return pick(registryKeyStems, seed) + "_" + suffix
	case iocregistry.TypeService:
		return pick(serviceStems, seed) + "_" + strings.ToUpper(suffix)
	default:
		return origDefault
	}
}
