package scenario

import "strings"

// ExecutionClass is the destructiveness tier B5 (the agent-side
// destructive-action guardrail) enforces per step. See
// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md.
//
// This is a SEPARATE concern from ResourceProfile's Risk field
// (resource.go) -- that classifies concurrency-locking risk
// (observation/modification/persistence); this classifies whether
// executing the step can cause irreversible real-world damage. The two
// catalogs are deliberately never merged.
type ExecutionClass string

const (
	ClassNonDestructive         ExecutionClass = "non_destructive"
	ClassPotentiallyDestructive ExecutionClass = "potentially_destructive"
	ClassDestructive            ExecutionClass = "destructive"
)

// ExecutionClassification is the catalog's resolved answer for one
// (technique_id, action_key) pair.
type ExecutionClassification struct {
	Class ExecutionClass
	// DestructiveAction is a stable, audit/report-facing identifier for
	// what this action does (often just the action_key itself).
	DestructiveAction string
	// BlastRadius is a human-readable description for audit/reporting --
	// never itself consulted for enforcement.
	BlastRadius string
}

// unclassified is the fail-closed answer for any (technique_id,
// action_key) pair this catalog has no entry for -- see the spec's
// "Resolution rules": no fallback from an unknown pair to a
// technique-wide generic classification, ever.
var unclassified = ExecutionClassification{
	Class:             ClassDestructive,
	DestructiveAction: "unclassified",
	BlastRadius:       "No catalog entry exists for this technique/action -- treated as destructive per the fail-closed default.",
}

// executionClassifications is the Audspect-controlled catalog, keyed
// technique_id -> action_key -> classification. Populated exhaustively by
// Task 10's full-library audit; this task seeds it only with the entries
// already verified against real scenario command text during this
// plan's own design investigation.
var executionClassifications = map[string]map[string]*ExecutionClassification{
	"T1490": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only enumeration of VSS shadow copies / backup catalog (vssadmin list shadows, wbadmin get versions). No state changed.",
		},
		"backup_readiness_check": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only query of VSS service status and scheduled backup tasks (Get-Service, Get-ScheduledTask). No state changed.",
		},
		"vss_delete": {
			Class:             ClassDestructive,
			DestructiveAction: "vss_delete",
			BlastRadius:       "Deletes VSS shadow copies (vssadmin/wbadmin/WMI Win32_ShadowCopy.Delete()) -- irreversible, removes the ransomware-recovery path.",
		},
		"wbadmin_delete_catalog": {
			Class:             ClassDestructive,
			DestructiveAction: "wbadmin_delete_catalog",
			BlastRadius:       "Deletes the Windows Server Backup catalog (wbadmin delete catalog) -- irreversible.",
		},
		"bootloader_recovery_disable": {
			Class:             ClassDestructive,
			DestructiveAction: "bootloader_recovery_disable",
			BlastRadius:       "Disables Windows Recovery Environment via bcdedit (recoveryenabled no / bootstatuspolicy ignoreallfailures) -- removes the final recovery path.",
		},
	},
	"T1489": {
		"backup_service_stop": {
			Class:             ClassDestructive,
			DestructiveAction: "backup_service_stop",
			BlastRadius:       "Runs 'net stop' against wbengine (Windows Backup Engine) and vss (Volume Shadow Copy service) -- if it succeeds, disables the host's native backup infrastructure until manually restarted; an interruption mid-step (crash, kill) could leave backups disabled with no automatic recovery.",
		},
	},
	"T1562.001": {
		"stop_auditd": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "Attempts to stop the Linux auditd service via systemctl -- if it succeeds, briefly disables audit logging until cleanup restarts it. No data loss, but a genuine (if self-limiting) security-control impairment, so not classified fully safe.",
		},
	},
	"T1569.002": {
		"service_create_start_stop_delete": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "Creates a BAS-owned, uniquely-named decoy Windows service (rundll32 binpath), starts it, stops it, deletes it. Self-contained -- never touches a pre-existing real service -- but exercises real service-management APIs under admin privilege, so it is not classified fully safe.",
		},
	},
	"T1003.003": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only enumeration: vssadmin list shadows plus an ntdsutil availability probe. No shadow copy created, no NTDS.dit dump.",
		},
	},
	// T1082 seeded here as the resolver test's "default" example --
	// mirrors resource.go's own discoveryProfiles entry for the same
	// technique (already proven read-only there). Real coverage of every
	// discoveryProfiles technique is Task 10's job, not duplicated by hand
	// here for each one.
	"T1082": {
		"default": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only system information query.",
		},
	},
}

// discoveryDefaultClassification is the shared value for every
// discoveryProfiles-derived "default" entry below (final whole-branch
// review finding C2 / plan's own Task 10 Step 2): resource.go's
// discoveryProfiles map is 15 ATT&CK discovery techniques already
// audited against real production ART command text and proven
// non-mutating (see that map's own doc comment) -- reused here so a step
// with no hand-authored action_key annotation for one of these
// techniques doesn't fail closed to destructive. One entry per
// technique, not one shared map, keeps ResolveExecutionClass's per-
// technique lookup untouched. T1120 is deliberately excluded even though
// it's IN discoveryProfiles: that map labels it read-only for
// RESOURCE/concurrency purposes only (ResourceProfile's Risk field, a
// different concern -- see this file's own package doc), but one of its
// four real atomics ("WinPwn - printercheck") downloads and executes an
// arbitrary third-party script
// (iex(new-object net.webclient).downloadstring(...)) -- genuinely
// unverifiable destructiveness, the exact ambiguity this catalog exists
// to fail closed on. T1082 already has its own entry above (Task 1's
// seed) and isn't repeated here.
var discoveryDefaultClassification = &ExecutionClassification{
	Class:             ClassNonDestructive,
	DestructiveAction: "",
	BlastRadius:       "Read-only ATT&CK discovery technique from resource.go's discoveryProfiles set, already audited against real production ART command text and proven non-mutating (see discoveryProfiles' own doc comment). No state changed.",
}

func init() {
	for _, tid := range []string{
		"T1012", "T1057", "T1007", "T1518", "T1010", "T1033",
		"T1124", "T1016", "T1049", "T1018", "T1087", "T1069", "T1652",
	} {
		executionClassifications[tid] = map[string]*ExecutionClassification{
			"default": discoveryDefaultClassification,
		}
	}
}

// ResolveExecutionClass returns the catalog's classification for a step's
// (technique_id, action_key) pair. An empty action_key resolves against
// the technique's own "default" entry. Any miss -- unknown technique,
// unknown action_key under a known technique, or no "default" entry for
// an empty action_key -- fails closed to ClassDestructive. No fallback to
// a technique-wide generic classification exists at any point in this
// resolution.
func ResolveExecutionClass(techniqueID, actionKey string) ExecutionClassification {
	tid := strings.ToUpper(strings.TrimSpace(techniqueID))
	key := strings.ToLower(strings.TrimSpace(actionKey))
	if key == "" {
		key = "default"
	}
	actions, ok := executionClassifications[tid]
	if !ok {
		return unclassified
	}
	c, ok := actions[key]
	if !ok {
		return unclassified
	}
	return *c
}

// AttachExecutionClassifications labels every step with its resolved
// execution classification in place, mirroring AttachProfiles
// (resource.go) exactly. Called from BuildSteps immediately after
// AttachProfiles -- the single compilation choke point every step
// (hand-authored, ART-sourced, Caldera-sourced) passes through before
// ever reaching an agent.
func AttachExecutionClassifications(steps []ScenarioStep) {
	for i := range steps {
		c := ResolveExecutionClass(steps[i].TechniqueID, steps[i].ActionKey)
		steps[i].ExecutionClass = c.Class
		steps[i].DestructiveAction = c.DestructiveAction
		steps[i].BlastRadius = c.BlastRadius
	}
}
