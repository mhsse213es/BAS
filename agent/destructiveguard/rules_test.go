package destructiveguard

import "testing"

func TestClassify_VssadminDeleteShadows(t *testing.T) {
	for _, cmd := range []string{
		`vssadmin delete shadows /all /quiet`,
		`vssadmin.exe delete shadows /Shadow={id} /Quiet`,
		`& "vssadmin.exe" DELETE SHADOWS /all`, // case/quoting variation
		`  vssadmin   delete   shadows  /all  `, // whitespace variation
	} {
		if got := Classify(cmd); got != ClassDestructive {
			t.Errorf("Classify(%q) = %q, want %q", cmd, got, ClassDestructive)
		}
	}
}

func TestClassify_WbadminDeleteCatalog(t *testing.T) {
	if got := Classify(`wbadmin.exe delete catalog -quiet`); got != ClassDestructive {
		t.Errorf("Classify(wbadmin delete catalog) = %q, want %q", got, ClassDestructive)
	}
}

func TestClassify_BcdeditRecoveryDisable(t *testing.T) {
	if got := Classify(`bcdedit /set {default} recoveryenabled no`); got != ClassDestructive {
		t.Errorf("Classify(bcdedit recoveryenabled no) = %q, want %q", got, ClassDestructive)
	}
}

func TestClassify_CipherWipe(t *testing.T) {
	if got := Classify(`cipher /w:C:\`); got != ClassDestructive {
		t.Errorf("Classify(cipher /w) = %q, want %q", got, ClassDestructive)
	}
}

func TestClassify_SafeEnumerationIsNonDestructive(t *testing.T) {
	if got := Classify(`vssadmin list shadows`); got != ClassNonDestructive {
		t.Errorf("Classify(vssadmin list shadows) = %q, want %q", got, ClassNonDestructive)
	}
	if got := Classify(`Get-Process | Select-Object Name`); got != ClassNonDestructive {
		t.Errorf("Classify(Get-Process) = %q, want %q", got, ClassNonDestructive)
	}
}
