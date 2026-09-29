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

// A Write-Output/Write-Host narration line that merely DESCRIBES what a
// real attacker would run must not itself be classified destructive --
// this is real, shipped content (scenarios/blackcat-kill-chain.yaml, the
// exact string), and its actual command block only enumerates. Before
// this fix, the substring inside the quoted narration matched the same
// pattern as a real invocation, false-vetoing a step the catalog
// correctly marks non_destructive (final whole-branch review, I2).
func TestClassify_NarrationTextIsNotAnInvocation(t *testing.T) {
	narration := `Write-Output "EXEC T1490: $shadowCount VSS shadow copy(ies) enumerated. BlackCat would now run 'vssadmin delete shadows /all /quiet' to destroy backups. Sysmon EID 1 vssadmin.exe logged. [BAS-SIM-BLACKCAT-S7]"`
	if got := Classify(narration); got != ClassNonDestructive {
		t.Errorf("Classify(narration text) = %q, want %q -- a Write-Output line describing what an attacker WOULD do is not itself an invocation", got, ClassNonDestructive)
	}
}

// The `format` pattern must not fire on PowerShell's own -Format/
// Format-Table/Format-List cmdlets, or on `wmic ... /format:list` (real,
// shipped content: scenarios/volt-typhoon-lotl.yaml) merely because some
// unrelated "x:" substring (a drive path, $env:something) appears later
// in the same command (final whole-branch review, I2).
func TestClassify_WmicFormatListIsNotDiskFormat(t *testing.T) {
	cmd := `& wmic.exe os get Caption,Version,OSArchitecture /format:list 2>&1 | Out-String`
	if got := Classify(cmd); got != ClassNonDestructive {
		t.Errorf("Classify(wmic /format:list) = %q, want %q", got, ClassNonDestructive)
	}
}

// Real destructive invocation forms already present in this codebase's
// own scenario library that the seed rule set did not cover (final
// whole-branch review, I1) -- akira-kill-chain.yaml's Stage 8 (WMI-based
// deletion, CISA AA24-109A's documented Akira command style) and the
// two other VSS-kill primitives an attacker could reach for instead of
// vssadmin.exe.
func TestClassify_AlternateVSSKillForms(t *testing.T) {
	for _, cmd := range []string{
		`Get-WmiObject Win32_ShadowCopy | ForEach-Object {$_.Delete()}`,
		`wmic shadowcopy delete`,
		`vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB`,
	} {
		if got := Classify(cmd); got != ClassDestructive {
			t.Errorf("Classify(%q) = %q, want %q", cmd, got, ClassDestructive)
		}
	}
}

// Trivial syntactic obfuscation (PowerShell backtick escape / cmd.exe
// caret escape inserted mid-token) must not defeat the backstop -- these
// are cheap to strip without a real parser, unlike string concatenation
// or -EncodedCommand, which stay explicitly out of scope (final
// whole-branch review, I1).
func TestClassify_BacktickAndCaretObfuscationDoesNotDefeatMatch(t *testing.T) {
	for _, cmd := range []string{
		"v`ssadmin delete shadows /all /quiet",
		"v^ssadmin delete shadows /all /quiet",
	} {
		if got := Classify(cmd); got != ClassDestructive {
			t.Errorf("Classify(%q) = %q, want %q (backtick/caret obfuscation must not bypass the backstop)", cmd, got, ClassDestructive)
		}
	}
}

// The narration-stripping fix for I2 (TestClassify_NarrationTextIsNotAnInvocation
// above) drops an ENTIRE line once it starts with a narration keyword. A line
// that starts with narration text but chains a real command onto the same
// line via a statement separator must NOT be dropped whole -- otherwise the
// chained real command is invisible to every pattern below it, a complete
// bypass reachable by anything that controls Command/Cleanup/payload text
// (i.e. exactly B5's threat model: a compromised orchestrator). Found by the
// fix-pass's own scoped re-review.
func TestClassify_NarrationPrefixDoesNotHideChainedRealCommand(t *testing.T) {
	for _, cmd := range []string{
		`Write-Output "starting cleanup"; wbadmin delete catalog -quiet`,
		"echo y| vssadmin delete shadows /all /quiet",
	} {
		if got := Classify(cmd); got != ClassDestructive {
			t.Errorf("Classify(%q) = %q, want %q (a real command chained after narration text on the same line must not be hidden)", cmd, got, ClassDestructive)
		}
	}
}

// The tightened `format` pattern (I2 fix) requires the drive letter/`/fs`
// switch immediately after "format", but a real invocation commonly has
// flags (e.g. the quick-format `/q`) in between -- the OLD broad regex
// actually caught this form, so the I2 fix traded a false positive for a
// false negative here. Found by the fix-pass's own scoped re-review.
func TestClassify_FormatWithFlagsBetweenCommandAndTarget(t *testing.T) {
	if got := Classify("format /q c: /fs:ntfs /y"); got != ClassDestructive {
		t.Errorf("Classify(format with /q flag) = %q, want %q", got, ClassDestructive)
	}
}
