package artifactgen

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/iocregistry"
)

func TestGenerate_Filename_PreservesExtension(t *testing.T) {
	got := Generate(iocregistry.TypeFilename, `C:\Windows\Temp\payload.dll`)
	if !strings.HasSuffix(got, ".dll") {
		t.Errorf("Generate(filename, ...payload.dll) = %q, want it to end in .dll", got)
	}
}

func TestGenerate_Filename_DefaultsToExeWhenNoExtension(t *testing.T) {
	got := Generate(iocregistry.TypeFilename, "no_extension_here")
	if !strings.HasSuffix(got, ".exe") {
		t.Errorf("Generate(filename, no-ext default) = %q, want it to end in .exe", got)
	}
}

func TestGenerate_Mutex_StartsWithGlobalPrefix(t *testing.T) {
	got := Generate(iocregistry.TypeMutex, "")
	if !strings.HasPrefix(got, `Global\`) {
		t.Errorf(`Generate(mutex, "") = %q, want it to start with Global\`, got)
	}
}

func TestGenerate_RegistryKeyAndService_NonEmpty(t *testing.T) {
	if got := Generate(iocregistry.TypeRegistryKey, ""); got == "" {
		t.Error("Generate(registry_key, \"\") returned empty string")
	}
	if got := Generate(iocregistry.TypeService, ""); got == "" {
		t.Error("Generate(service, \"\") returned empty string")
	}
}

func TestGenerate_TwoCalls_ProduceDifferentValues(t *testing.T) {
	a := Generate(iocregistry.TypeFilename, "x.exe")
	b := Generate(iocregistry.TypeFilename, "x.exe")
	if a == b {
		t.Errorf("two consecutive Generate calls returned the same value %q -- random suffix isn't varying", a)
	}
}

func TestGenerate_UnknownType_ReturnsOrigDefault(t *testing.T) {
	got := Generate(iocregistry.TypeDomain, "unchanged.example")
	if got != "unchanged.example" {
		t.Errorf("Generate(domain, ...) = %q, want the unchanged origDefault (domain is out of scope for Phase C)", got)
	}
}
