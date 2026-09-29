// Package destructiveguard is the agent's independent, vendor-curated,
// binary-compiled local backstop against catastrophic commands -- the
// second of B5's two defense-in-depth layers (see
// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md).
// This package is NEVER modifiable through an orchestrator command, a
// B4-signed envelope field, scenario YAML, an environment variable, or
// (in a later phase) a local grant -- the grant authorizes a
// catalog-defined action; it never redefines what this package
// considers catastrophic.
//
// Deliberately NOT a PowerShell/shell semantic parser -- that's brittle
// and creates a false sense of completeness. A small, deterministic rule
// set matched against the normalized executable + arguments instead.
package destructiveguard

import (
	"regexp"
	"strings"
)

type Class string

const (
	ClassNonDestructive         Class = "non_destructive"
	ClassPotentiallyDestructive Class = "potentially_destructive"
	ClassDestructive            Class = "destructive"
)

// rule pairs a compiled pattern with what it means. Patterns match
// against the NORMALIZED command (see normalize below), so they never
// need to account for casing, quoting, or a leading "& " call-operator
// by themselves.
type rule struct {
	pattern *regexp.Regexp
	class   Class
}

// rules is the seed set. Each pattern is deliberately narrow and
// anchored to a real, verified destructive command found in this
// codebase's own scenario library during the B5 design investigation
// (see the design spec's "Local backstop rule engine" section) --
// extend it with the same rigor (a real verified command, not a guess)
// as this list grows.
var rules = []rule{
	{regexp.MustCompile(`\bvssadmin(\.exe)?\b.*\bdelete\b.*\bshadows\b`), ClassDestructive},
	{regexp.MustCompile(`\bvssadmin(\.exe)?\b.*\bresize\b.*\bshadowstorage\b`), ClassDestructive},
	{regexp.MustCompile(`\bwbadmin(\.exe)?\b.*\bdelete\b.*\bcatalog\b`), ClassDestructive},
	{regexp.MustCompile(`\bwbadmin(\.exe)?\b.*\bdelete\b.*\bsystemstatebackup\b`), ClassDestructive},
	{regexp.MustCompile(`\bbcdedit(\.exe)?\b.*\brecoveryenabled\b\s+no\b`), ClassDestructive},
	{regexp.MustCompile(`\bbcdedit(\.exe)?\b.*\bbootstatuspolicy\b\s+ignoreallfailures\b`), ClassDestructive},
	{regexp.MustCompile(`\bcipher(\.exe)?\b.*(^|\s)/w\b`), ClassDestructive},
	// Disk format: "format" as its own command token, optionally followed
	// by flags (e.g. the quick-format /q), then a drive letter or an /fs
	// switch -- NOT PowerShell's Format-Table/Format-List/-Format, and NOT
	// "/format:list" (wmic's own output-format switch, real shipped
	// content in scenarios/volt-typhoon-lotl.yaml). The old
	// `\bformat\b.*[a-z]:` matched "format" anywhere followed by ANY "x:"
	// substring later in the command (a drive path, $env:, etc.), which
	// was far too broad (final whole-branch review, I2); tightening it to
	// require the target immediately after "format" then regressed the
	// common `format /q c: ...` form, since a real invocation often has
	// flags between the two (fix-pass's own scoped re-review). The
	// `(\s+/[a-z]+)*` repetition absorbs any number of such flags without
	// reopening the wmic/PowerShell false positive, since "format" must
	// still be preceded by `^`/`;`/whitespace, not `/` (the "/format:list"
	// case), for the whole pattern to anchor at all.
	{regexp.MustCompile(`(^|[;\s])format(\.com|\.exe)?(\s+/[a-z]+)*\s+(/fs|[a-z]:)`), ClassDestructive},
	// Win32_ShadowCopy.Delete() (Akira's documented command style, CISA
	// AA24-109A -- akira-kill-chain.yaml Stage 8) and wmic's own shadow-
	// copy-delete verb: alternate VSS-kill primitives distinct from
	// vssadmin.exe, missed by the seed rule set (final whole-branch
	// review, I1).
	{regexp.MustCompile(`win32_shadowcopy.*\.delete\(\)`), ClassDestructive},
	{regexp.MustCompile(`\bwmic\b.*\bshadowcopy\b.*\bdelete\b`), ClassDestructive},
}

// narrationPrefix matches a line that only PRINTS text -- Write-Output,
// Write-Host, Write-Verbose, or a bare echo -- rather than executing
// anything. A narration line describing what a real attacker WOULD run
// (e.g. "BlackCat would now run 'vssadmin delete shadows...'", real
// shipped content in scenarios/blackcat-kill-chain.yaml) is not itself an
// invocation and must never be classified as one (final whole-branch
// review, I2). Checked against each line BEFORE quote-stripping, since
// quote-stripping is what makes a quoted narrated command indistinguishable
// from a real one.
var narrationPrefix = regexp.MustCompile(`(?i)^\s*(write-output|write-host|write-verbose|echo)\b`)

// chainOrSubstitution matches a statement separator (POSIX/cmd.exe/
// PowerShell ; | & && ||, all covered by the single characters ; | &) or a
// command-substitution opener (backtick, $(). A line starting with a
// narration keyword but ALSO containing one of these is not pure
// narration -- it may chain a real command onto the same line (e.g.
// `Write-Output "cleanup"; vssadmin delete shadows /all /quiet`, or
// `echo y| vssadmin delete shadows /all /quiet`, a common scripted-
// confirmation idiom) or embed one via substitution
// (`Write-Output "$(vssadmin delete shadows /all /quiet)"`). Such a line
// is deliberately NOT stripped, erring toward over-scanning (a genuinely
// safe narration line that happens to contain one of these characters in
// its prose still gets scanned, and in the worst case just doesn't match
// any destructive pattern) rather than under-scanning (a chained real
// command hidden entirely -- a complete local-backstop bypass reachable
// by anything that controls Command/Cleanup/payload text, exactly B5's
// threat model of a compromised orchestrator). Found by the fix-pass's
// own scoped re-review of the original I2 fix.
var chainOrSubstitution = regexp.MustCompile("[;|&`]|\\$\\(")

// stripNarrationLines removes every line that only prints text, so the
// destructive patterns below are only ever evaluated against lines that
// can actually execute something. A line matching narrationPrefix but
// also chainOrSubstitution is kept, not stripped -- see that var's doc
// comment.
func stripNarrationLines(command string) string {
	lines := strings.Split(command, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if narrationPrefix.MatchString(line) && !chainOrSubstitution.MatchString(line) {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// normalize case-folds and collapses whitespace so trivial quoting/
// casing/spacing variations can't defeat a pattern. Deliberately does
// NOT attempt real shell tokenization (that's the semantic-parser
// approach this package exists to avoid) -- it only strips the
// characters a scenario author or attacker would plausibly vary without
// changing what the command actually does: surrounding quotes/call
// operators, PowerShell's backtick escape / cmd.exe's caret escape
// (both trivially insertable mid-token without changing what runs), and
// repeated whitespace. String concatenation (('vss'+'admin')) and
// -EncodedCommand stay explicitly out of scope -- defeating those needs
// real parsing/evaluation, not normalization (final whole-branch review,
// I1; the design spec's own "no full semantic parser" decision).
func normalize(command string) string {
	s := strings.ToLower(command)
	s = strings.ReplaceAll(s, "&", " ")
	s = strings.ReplaceAll(s, `"`, " ")
	s = strings.ReplaceAll(s, "'", " ")
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "^", "")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// Classify evaluates command against the local rule set and returns the
// most restrictive matching class, or ClassNonDestructive if nothing
// matches. Combined most-restrictive-wins with the signed catalog
// classification by the caller (agent/agent.go's B5 gate, Task 7) --
// this function never sees or considers that signed classification
// itself.
func Classify(command string) Class {
	n := normalize(stripNarrationLines(command))
	for _, r := range rules {
		if r.pattern.MatchString(n) {
			return r.class
		}
	}
	return ClassNonDestructive
}
