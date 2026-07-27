# Purple Team Exercise Templates — Design Spec

**Status:** Approved for planning
**Author:** Audspect (brainstormed 2026-07-27)
**Scope:** Phase B of the "Purple Team packs" roadmap item ([[project_scenario_roadmap]]). Content only — builds on the completed Phase A0 ([[project_outcome_validation_framework]]-adjacent automatic-verdict persistence) and Phase A1 (BAS→Exercise Detection Bridge) infrastructure. No changes to the Exercise Engine's execution logic, trigger logic, or evidence bridging.

## Problem

The Exercise Engine ships exactly one generic technical template, `builtin-soc-drill`, which requires the operator to supply an arbitrary `ScenarioID`/`AgentID` at launch time. There is no out-of-the-box, purpose-built Purple Team exercise for any of this platform's five flagship BAS scenarios (`apt29-kill-chain`, `volt-typhoon-lotl`, `kerberoasting-ad-drill`, `collection-staging-exfil`, `dlp-exfiltration-validation`) — despite all five already having detection profiles wired and, as of Phase A1, a working detection bridge that makes `wait_for_detection` actually observe real BAS-run verdicts.

Separately, `Template` has no structured way to express what makes one exercise different from another beyond a one-line `Description` string — no success criteria, no learning objectives, no recommended participants/duration, nothing that would let an operator or a future UI distinguish five otherwise-identical-looking drills at a glance.

## Non-goals

- **No Sigma/Detection Rule Library content.** `internal/rulelib` has exactly 2 seed rules today, covering 2 techniques — nowhere near the coverage needed for the techniques these five scenarios actually exercise (Kerberoasting, DLP channels, LOTL discovery, etc.). Writing that content is its own future "Detection Content Pack" workstream, scoped and staffed independently of exercise authoring. `ExpectedDetection.RuleIDs`/`verification.Record.RuleIDs`/the exercise evidence payload's `rule_ids` field all stay exactly as built in Phase A — present, flowing end-to-end, legitimately empty for any expectation with no curated rule. Empty means "no curated rule exists for this," not "not implemented yet."
- **No new BAS scenario content.** All five templates reference existing, already-shipped, already-signed scenarios via `ScenarioID`. Nothing in `scenarios/*.yaml` changes.
- **No changes to Exercise Engine execution/trigger/bridge logic.** Every new template reuses `builtin-soc-drill`'s exact proven execution graph (`agent_task→wait_for_agent→wait_for_detection→approval→notify`). If a bug exists in that graph, it's already exercised by `builtin-soc-drill`'s and Phase A1's existing tests — this spec adds no new engine surface area.
- **No UI work.** `Template.Metadata` is new structured data with no consumer yet; a future UI iteration renders it. This spec only ensures the data exists and round-trips correctly.

## Architecture

**One structural change:** `Template` gains a `Metadata TemplateMetadata` field, persisted via one new additive JSON column — exactly the pattern `variables_json`/`steps_json` already established for this same table.

```go
// TemplateMetadata is structured descriptive content distinguishing one
// exercise template from another beyond its one-line Description — success
// criteria, learning objectives, and logistics an operator or a future
// template-picker UI can render without parsing free text. Optional on
// every field: a template with no populated metadata (every pre-Phase-B
// built-in) renders with all fields empty, not an error.
type TemplateMetadata struct {
	SuccessCriteria         string   `json:"success_criteria,omitempty"`
	LearningObjectives      []string `json:"learning_objectives,omitempty"`
	ExpectedTechniques      []string `json:"expected_techniques,omitempty"`      // MITRE ATT&CK technique IDs
	ExpectedDetections      []string `json:"expected_detections,omitempty"`      // provider/control display names
	RecommendedParticipants []string `json:"recommended_participants,omitempty"` // roles, e.g. "SOC Analyst"
	RecommendedDuration     string   `json:"recommended_duration,omitempty"`     // e.g. "1-2 hours"
	DiscussionPrompts       []string `json:"discussion_prompts,omitempty"`
}
```

**Everything else is content**: five new entries in `BuiltinTemplates` (`internal/exercise/templates.go`), category `"purple-team"` (new — distinguishes these from `builtin-soc-drill`'s generic `"soc-readiness"`), each cloning `builtin-soc-drill`'s exact `Variables`/`Steps` shape with per-template `ScenarioID` defaults, descriptions, and `Metadata`.

## Verification dependencies (discovered during spec-writing, applies to all five)

The provider registry (`orchestrator/internal/scenario/providers.go`) defaults only EDR-category providers (`microsoft_defender`, `crowdstrike`, `sentinelone`, `trellix`, `sophos`, `carbon_black`, `cortex_xdr`) to `VerificationAutomatic`. Every SIEM (`microsoft_sentinel`, `splunk`, `qradar`, `elastic`), Identity (`microsoft_defender_identity`, `entra_id_protection`), DLP (`microsoft_purview`), and ruleset (`sigma`) provider defaults to `VerificationManual`. Checked every detection-profile YAML these five templates' scenarios reference (`windows_kerberoast`, `windows_asrep_roast`, `windows_archive_staging`, `windows_cloud_egress`, `windows_sam_theft`, and the four used by `apt29-kill-chain`/`volt-typhoon-lotl`) — none override `verification: automatic` per-expectation, except `windows_dlp_exfiltration` (all 5 entries explicitly set it).

Practical effect: **only the EDR-domain expectations in each scenario, plus all of DLP's, resolve automatically** via Phase A0's poller and get bridged by Phase A1. SIEM/Identity/Purview-DLP expectations stay `Pending` unless either (a) a SOC analyst manually attests via the existing Detection Verification UI during the exercise window — a normal, intended part of running a live purple-team drill, not a workaround — or (b) a configured SP3 API connector (`internal/detectverify`; Sentinel and Defender XDR exist today, QRadar/Splunk/CrowdStrike/Trellix don't yet) independently attests via its own `Store.Attest` call.

This is not a defect in this spec's design — Phase A0/A1 built exactly what they said they'd build, and connector coverage is SP3's own separate, already-tracked workstream. It does mean these five templates' `Metadata.SuccessCriteria` must be honest about what the technical gate (`wait_for_detection`) actually guarantees versus what requires manual attestation or a connector, and the Kerberoasting template's gate is deliberately narrowed to `security_control_detected` only so an EDR alert can't silently stand in for the identity-layer signal the drill is actually testing.

## The five templates

All five share this variable set (identical names/types/defaults to `builtin-soc-drill`, except `ScenarioID`'s `Default`, which is new — `builtin-soc-drill` has no default since it's meant to run any scenario; these five are meant to run one specific scenario each, so defaulting it is correct and still overridable):

```go
Variables: []VarDef{
	{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
	{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "<per-template>", Description: "Scenario to execute"},
	{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
	{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
},
```

And this exact `Steps` shape (step IDs reused verbatim across all five, matching `builtin-soc-drill`'s own naming — step IDs are scoped per-template, not global, so no collision):

```go
Steps: []PlanStep{
	{
		ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger BAS simulation",
		Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
	},
	{
		ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
		DependsOn: []string{"drill_sim"},
		Config:    StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
		TimeoutSecs: 1800,
	},
	{
		ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
		DependsOn: []string{"wait_sim_done"},
		TimeoutSecs: 1800,
		Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
			DetectionTypes:   []string{"edr_detected", "siem_alerted", "security_control_detected"},
			ExecutionStepID:  "drill_sim",
		}},
	},
	{
		ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
		DependsOn: []string{"wait_detect"},
		TimeoutSecs: 7200,
		Config: StepConfig{
			ApprovalPrompt: "<per-template>",
			ApproverRoles:  []string{"admin", "analyst"},
		},
	},
	{
		ID: "drill_complete", Type: StepTypeNotify, Label: "<per-template>",
		DependsOn: []string{"approval_response"},
		Config:    StepConfig{NotifyMsg: "<per-template>"},
	},
},
```

Note `DetectionTypes` includes `"security_control_detected"` (Phase A1's fourth evidence type, for identity/network/cloud/email/dlp domains) alongside the two `builtin-soc-drill` already used — required for the Kerberoasting (identity) and DLP (dlp) templates to ever satisfy `minCount`; without it those two templates' `wait_for_detection` would only count endpoint/SIEM evidence and could never complete even when the bridge correctly appends `security_control_detected` evidence.

### 1. APT29 Kill Chain Purple Team Drill

```go
{
	ID:          "builtin-purple-apt29",
	Name:        "APT29 Kill Chain Purple Team Drill",
	Version:     1,
	Category:    "purple-team",
	Description: "Runs the APT29 (Cozy Bear) kill-chain simulation — GPO discovery, encoded PowerShell execution, registry run-key persistence, scheduled-task persistence, DNS-over-HTTPS C2 — and measures SOC detection latency across the full multi-stage chain.",
	Author:      "Audspect",
	BuiltIn:     true,
	Variables: []VarDef{
		{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
		{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "apt29-kill-chain", Description: "Scenario to execute"},
		{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
		{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
	},
	Metadata: TemplateMetadata{
		SuccessCriteria: "The technical gate confirms at least one kill-chain stage was detected within the detection timeout (MTTD/MTTR recorded); full stage-by-stage coverage across all five stages is then reviewed by the SOC at the approval step using the complete evidence chain, not just the count that satisfied the gate. Only microsoft_defender (EDR-domain) evidence resolves automatically today — the microsoft_sentinel (SIEM) stage's detection requires either a configured Sentinel API connector or a SOC analyst manually attesting via the Detection Verification UI during the exercise.",
		LearningObjectives: []string{
			"Validate multi-stage kill-chain visibility across endpoint and SIEM",
			"Measure detection latency for a nation-state-style intrusion pattern",
			"Identify which chain stage, if any, breaks detection coverage",
		},
		ExpectedTechniques: []string{"T1482", "T1059.001", "T1547.001", "T1053.005", "T1071.004"},
		ExpectedDetections: []string{"Microsoft Defender", "Microsoft Sentinel"},
		RecommendedParticipants: []string{"SOC Analyst", "Detection Engineer", "IR Lead (approval)"},
		RecommendedDuration:     "1-2 hours",
		DiscussionPrompts: []string{
			"Which stage of the chain, if any, went undetected?",
			"What logging or rule change would close that gap fastest?",
			"Did any single stage's detection alone give away the whole chain, or did the SOC need to correlate across stages?",
		},
	},
	Steps: []PlanStep{
		{
			ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger APT29 kill-chain simulation",
			Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
		},
		{
			ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
			DependsOn: []string{"drill_sim"},
			Config:    StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
			TimeoutSecs: 1800,
		},
		{
			ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
			DependsOn: []string{"wait_sim_done"},
			TimeoutSecs: 1800,
			Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
				DetectionTypes:  []string{"edr_detected", "siem_alerted", "security_control_detected"},
				ExecutionStepID: "drill_sim",
			}},
		},
		{
			ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
			DependsOn: []string{"wait_detect"},
			TimeoutSecs: 7200,
			Config: StepConfig{
				ApprovalPrompt: "Has the SOC completed triage, containment, and documented the incident across all detected kill-chain stages?",
				ApproverRoles:  []string{"admin", "analyst"},
			},
		},
		{
			ID: "drill_complete", Type: StepTypeNotify, Label: "APT29 drill complete — check MTTD/MTTR",
			DependsOn: []string{"approval_response"},
			Config:    StepConfig{NotifyMsg: "APT29 Kill Chain Purple Team Drill complete. Review the technical score, MTTD/MTTR, and per-stage detection coverage."},
		},
	},
},
```

### 2. Volt Typhoon LOTL Purple Team Drill

```go
{
	ID:          "builtin-purple-volt-typhoon",
	Name:        "Volt Typhoon LOTL Purple Team Drill",
	Version:     1,
	Category:    "purple-team",
	Description: "Runs the Volt Typhoon living-off-the-land simulation — network config discovery, SAM theft, LOLBin download cradles, scheduled-task persistence, log manipulation — with no malware involved, testing whether the SOC can detect abuse of built-in Windows tools.",
	Author:      "Audspect",
	BuiltIn:     true,
	Variables: []VarDef{
		{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
		{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "volt-typhoon-lotl", Description: "Scenario to execute"},
		{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
		{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
	},
	Metadata: TemplateMetadata{
		SuccessCriteria: "The technical gate confirms at least one LOTL technique was detected within the detection timeout; full coverage across all techniques is reviewed by the SOC at the approval step using the complete evidence chain. Only microsoft_defender (EDR-domain) evidence resolves automatically today — the microsoft_sentinel/Sigma (SIEM) techniques require either a configured Sentinel API connector or a SOC analyst manually attesting via the Detection Verification UI during the exercise.",
		LearningObjectives: []string{
			"Validate detection coverage for native-tool abuse, not just malware",
			"Identify which built-in Windows utilities your EDR alerts on by default vs. only with custom rules",
			"Measure SOC readiness against a nation-state LOTL tradecraft pattern",
		},
		ExpectedTechniques: []string{"T1082", "T1016", "T1090.001", "T1087.001", "T1003.002", "T1003.003", "T1105", "T1218.005", "T1053.005", "T1070.001"},
		ExpectedDetections: []string{"Microsoft Defender", "Microsoft Sentinel", "Sigma-based SIEM rule"},
		RecommendedParticipants: []string{"SOC Analyst", "Detection Engineer", "IR Lead (approval)"},
		RecommendedDuration:     "1-2 hours",
		DiscussionPrompts: []string{
			"Which built-in Windows tools does your EDR alert on by default vs. only with custom rules?",
			"Would this activity have blended into normal admin behavior in your environment?",
			"Which detection, if any, was the first real signal — and how long did it take to fire?",
		},
	},
	Steps: []PlanStep{
		{
			ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger Volt Typhoon LOTL simulation",
			Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
		},
		{
			ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
			DependsOn: []string{"drill_sim"},
			Config:    StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
			TimeoutSecs: 1800,
		},
		{
			ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
			DependsOn: []string{"wait_sim_done"},
			TimeoutSecs: 1800,
			Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
				DetectionTypes:  []string{"edr_detected", "siem_alerted", "security_control_detected"},
				ExecutionStepID: "drill_sim",
			}},
		},
		{
			ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
			DependsOn: []string{"wait_detect"},
			TimeoutSecs: 7200,
			Config: StepConfig{
				ApprovalPrompt: "Has the SOC completed triage, containment, and documented the incident for this LOTL activity?",
				ApproverRoles:  []string{"admin", "analyst"},
			},
		},
		{
			ID: "drill_complete", Type: StepTypeNotify, Label: "Volt Typhoon drill complete — check MTTD/MTTR",
			DependsOn: []string{"approval_response"},
			Config:    StepConfig{NotifyMsg: "Volt Typhoon LOTL Purple Team Drill complete. Review the technical score, MTTD/MTTR, and which native-tool techniques went undetected."},
		},
	},
},
```

### 3. Kerberoasting & AD Credential Theft Purple Team Drill

```go
{
	ID:          "builtin-purple-kerberoasting",
	Name:        "Kerberoasting & AD Credential Theft Purple Team Drill",
	Version:     1,
	Category:    "purple-team",
	Description: "Runs the Kerberoasting and AS-REP roasting simulation against Active Directory — service-account ticket requests, AD enumeration, GPO discovery — and measures identity-layer detection coverage independent of endpoint EDR.",
	Author:      "Audspect",
	BuiltIn:     true,
	Variables: []VarDef{
		{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
		{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "kerberoasting-ad-drill", Description: "Scenario to execute"},
		{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
		{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
	},
	Metadata: TemplateMetadata{
		SuccessCriteria: "An identity-layer detection (Kerberos ticket requests, AD enumeration) is confirmed within the detection timeout — deliberately gated on identity-domain evidence only, not endpoint EDR, so an unrelated EDR alert can't silently satisfy this drill's real question. Microsoft Defender for Identity (and Sigma/SIEM providers generally) default to manual verification in this platform; confirming this signal today means either a SOC analyst manually attesting via the Detection Verification UI during the exercise, or a configured identity/SIEM API connector. A timeout with no manual attestation is itself the finding: identity-layer verification isn't wired up yet.",
		LearningObjectives: []string{
			"Validate identity/AD detection coverage independent of endpoint telemetry",
			"Confirm Microsoft Defender for Identity (or equivalent) is actually alerting on Kerberoasting/AS-REP roasting patterns",
			"Identify which service accounts are exposed to ticket-request-based credential theft",
			"Surface whether identity-layer verification is automated (API connector) or still manual-only in this environment",
		},
		ExpectedTechniques: []string{"T1558.003", "T1558.004", "T1087.002", "T1482", "T1069.002", "T1615", "T1552.006"},
		ExpectedDetections: []string{"Microsoft Defender for Identity", "Microsoft Defender"},
		RecommendedParticipants: []string{"SOC Analyst", "Identity/AD Administrator", "IR Lead (approval)"},
		RecommendedDuration:     "1-2 hours",
		DiscussionPrompts: []string{
			"Did the identity-layer control detect this before or independent of endpoint EDR?",
			"Which service accounts used in this drill have weak/crackable passwords in production?",
			"How quickly could an analyst distinguish this from legitimate Kerberos ticket activity?",
			"If wait_detect timed out: was that because nothing fired, or because no one attested it during the window?",
		},
	},
	Steps: []PlanStep{
		{
			ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger Kerberoasting/AD simulation",
			Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
		},
		{
			ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
			DependsOn: []string{"drill_sim"},
			Config:    StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
			TimeoutSecs: 1800,
		},
		{
			ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for identity-layer detection",
			DependsOn: []string{"wait_sim_done"},
			TimeoutSecs: 1800,
			Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
				DetectionTypes:  []string{"security_control_detected"}, // identity-only, deliberately excludes edr_detected — see "Verification dependencies" below
				ExecutionStepID: "drill_sim",
			}},
		},
		{
			ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
			DependsOn: []string{"wait_detect"},
			TimeoutSecs: 7200,
			Config: StepConfig{
				ApprovalPrompt: "Has the SOC/identity team completed triage and confirmed which service accounts were affected?",
				ApproverRoles:  []string{"admin", "analyst"},
			},
		},
		{
			ID: "drill_complete", Type: StepTypeNotify, Label: "Kerberoasting drill complete — check identity detection coverage",
			DependsOn: []string{"approval_response"},
			Config:    StepConfig{NotifyMsg: "Kerberoasting & AD Credential Theft Purple Team Drill complete. Review identity-layer detection coverage and MTTD/MTTR."},
		},
	},
},
```

### 4. Collection→Staging→Exfiltration Purple Team Drill

```go
{
	ID:          "builtin-purple-collection-exfil",
	Name:        "Collection to Exfiltration Purple Team Drill",
	Version:     1,
	Category:    "purple-team",
	Description: "Runs the collection-staging-exfiltration simulation — file discovery, local staging, archive creation, and network egress over multiple channels — and measures whether exfil-path telemetry is captured end-to-end, not just at the initial discovery step.",
	Author:      "Audspect",
	BuiltIn:     true,
	Variables: []VarDef{
		{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
		{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "collection-staging-exfil", Description: "Scenario to execute"},
		{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
		{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
	},
	Metadata: TemplateMetadata{
		SuccessCriteria: "The technical gate confirms at least one exfil-path signal (archive staging or network egress — the two steps in this scenario with detection profiles attached) was detected within the detection timeout; full chain-stage coverage is reviewed by the SOC at the approval step using the complete evidence chain. Only microsoft_defender (EDR-domain) evidence resolves automatically today — the microsoft_purview (DLP-domain, per this platform's provider registry) and microsoft_sentinel (SIEM) signals require either a configured API connector or a SOC analyst manually attesting via the Detection Verification UI during the exercise.",
		LearningObjectives: []string{
			"Validate end-to-end exfil-chain visibility, not just discovery-stage detection",
			"Confirm DLP/CASB (Microsoft Purview) and network egress controls catch staged data leaving the host",
			"Identify which exfil channel (local staging vs. archive vs. cloud egress) is weakest",
		},
		ExpectedTechniques: []string{"T1083", "T1074.001", "T1560.001", "T1048.001", "T1048.003", "T1567.002"},
		ExpectedDetections: []string{"Microsoft Defender", "Microsoft Purview", "Microsoft Sentinel"},
		RecommendedParticipants: []string{"SOC Analyst", "Detection Engineer", "IR Lead (approval)"},
		RecommendedDuration:     "1-2 hours",
		DiscussionPrompts: []string{
			"Was the initial file discovery detected, or only the later staging/egress steps?",
			"Which exfil channel in this chain would be hardest to detect in your environment?",
			"Did DLP/CASB tooling catch the archive or cloud-upload step independent of endpoint EDR?",
		},
	},
	Steps: []PlanStep{
		{
			ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger collection-to-exfiltration simulation",
			Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
		},
		{
			ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
			DependsOn: []string{"drill_sim"},
			Config:    StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
			TimeoutSecs: 1800,
		},
		{
			ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC/DLP detection",
			DependsOn: []string{"wait_sim_done"},
			TimeoutSecs: 1800,
			Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
				DetectionTypes:  []string{"edr_detected", "siem_alerted", "security_control_detected"},
				ExecutionStepID: "drill_sim",
			}},
		},
		{
			ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
			DependsOn: []string{"wait_detect"},
			TimeoutSecs: 7200,
			Config: StepConfig{
				ApprovalPrompt: "Has the SOC completed triage and confirmed which stage of the exfil chain was (or wasn't) detected?",
				ApproverRoles:  []string{"admin", "analyst"},
			},
		},
		{
			ID: "drill_complete", Type: StepTypeNotify, Label: "Exfil drill complete — check per-stage coverage",
			DependsOn: []string{"approval_response"},
			Config:    StepConfig{NotifyMsg: "Collection to Exfiltration Purple Team Drill complete. Review per-stage detection coverage, MTTD/MTTR."},
		},
	},
},
```

### 5. DLP Exfiltration Purple Team Drill

```go
{
	ID:          "builtin-purple-dlp-exfil",
	Name:        "DLP Exfiltration Purple Team Drill",
	Version:     1,
	Category:    "purple-team",
	Description: "Runs the DLP exfiltration validation simulation — synthetic regulated data (PAN/Aadhaar/SWIFT/UPI/credit-card) attempted over USB, clipboard, print, archive, and local-staging channels — and measures whether DLP policy actually blocks each channel, not just logs it.",
	Author:      "Audspect",
	BuiltIn:     true,
	Variables: []VarDef{
		{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
		{Name: "ScenarioID", Type: VarTypeString, Required: true, Default: "dlp-exfiltration-validation", Description: "Scenario to execute"},
		{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
		{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
	},
	Metadata: TemplateMetadata{
		SuccessCriteria: "DLP policy blocks regulated-data exfiltration across all five channels (USB, clipboard, print, archive, local-staging) within the detection timeout — a policy that only logs/warns does not meet this criterion (see the DLP Validation Suite's asymmetric truth table: a local verifier can only prove Block, not softer outcomes).",
		LearningObjectives: []string{
			"Validate DLP policy actually blocks (not just logs) regulated-data exfiltration",
			"Confirm coverage across all agent-native channels an insider or malware could use, not only network egress",
			"Identify which channel, if any, DLP policy doesn't yet cover",
		},
		ExpectedTechniques: []string{"T1052.001", "T1115", "T1052", "T1560.001", "T1074.001"},
		ExpectedDetections: []string{"Trellix DLP"},
		RecommendedParticipants: []string{"SOC Analyst", "DLP/Compliance Administrator", "IR Lead (approval)"},
		RecommendedDuration:     "1-2 hours",
		DiscussionPrompts: []string{
			"Which of the five channels, if any, was NOT blocked by DLP policy?",
			"Is the gap a policy-coverage gap or an agent-visibility gap?",
			"Would this synthetic data pattern (PAN/Aadhaar/SWIFT/UPI/credit-card) be representative of what your DLP policy is actually tuned to catch in production?",
		},
	},
	Steps: []PlanStep{
		{
			ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger DLP exfiltration simulation",
			Config: StepConfig{AgentTask: &AgentTaskConfig{AgentID: "${AgentID}", ScenarioID: "${ScenarioID}"}},
		},
		{
			ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
			DependsOn: []string{"drill_sim"},
			Config:    StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
			TimeoutSecs: 1800,
		},
		{
			ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for DLP block confirmation",
			DependsOn: []string{"wait_sim_done"},
			TimeoutSecs: 1800,
			Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
				DetectionTypes:  []string{"security_control_detected"},
				MinCount:        5, // all 5 channels — matches SuccessCriteria's "across all five channels", unlike the other 4 templates' default MinCount:1 (their multi-stage chains treat any single detected stage as meaningful partial signal; DLP's 5 channels are one coherent claim). A real run with fewer than 5 blocked still completes gracefully via the existing 1800s timeout — SetStepStatus(..., StepCompleted, "timeout") — not a hang, and the partial count itself is evidence for the approval step's human reviewer.
				ExecutionStepID: "drill_sim",
			}},
		},
		{
			ID: "approval_response", Type: StepTypeApproval, Label: "SOC/Compliance: confirm DLP coverage reviewed",
			DependsOn: []string{"wait_detect"},
			TimeoutSecs: 7200,
			Config: StepConfig{
				ApprovalPrompt: "Has the SOC/DLP team reviewed which of the five channels were blocked vs. not blocked?",
				ApproverRoles:  []string{"admin", "analyst"},
			},
		},
		{
			ID: "drill_complete", Type: StepTypeNotify, Label: "DLP drill complete — check per-channel block coverage",
			DependsOn: []string{"approval_response"},
			Config:    StepConfig{NotifyMsg: "DLP Exfiltration Purple Team Drill complete. Review per-channel block coverage across USB, clipboard, print, archive, and local-staging."},
		},
	},
},
```

Note the DLP template's `wait_detect.Config.WaitForDetection.DetectionTypes` is `["security_control_detected"]` only (not `edr_detected`/`siem_alerted`) — DLP's `Domain` is `"dlp"`, which `ResolveDetectionEvidence` always maps to `security_control_detected` (see Phase A1's domain-mapping table); including the other two types would be dead weight, never matched.

## Migration

One additive column, following this codebase's existing pattern:

```sql
ALTER TABLE exercise_templates ADD COLUMN IF NOT EXISTS metadata_json jsonb NOT NULL DEFAULT '{}';
```

`orchestrator/internal/exercise/store.go`'s `UpsertTemplate` (its `INSERT INTO exercise_templates (...)`), `GetTemplate`, and `ListTemplates` all gain `metadata_json` in their SQL and scan targets, marshaled/unmarshaled the same way `variables_json`/`steps_json` already are.

## Testing approach

- **`TestBuiltinTemplates_PurpleTeamDetectionBridgeWiring`**: extends the pattern `TestBuiltinTemplates_DetectionBridgeWiring` (Phase A1) already established — for each of the 5 new templates, assert the `wait_detect` step's `WaitForDetectionConfig.ExecutionStepID == "drill_sim"` (matching that template's own `agent_task` step). This is the regression guard against ever shipping a 6th silently-dead template, the exact bug class Phase A1 fixed on the pre-existing two.
- **`TestBuiltinTemplates_PurpleTeamMetadataPopulated`**: for each of the 5 new templates, assert `Metadata.SuccessCriteria != ""` and `len(Metadata.ExpectedTechniques) > 0` — catches a template shipped with the execution skeleton but forgotten metadata.
- **`TestSeedBuiltinTemplates` (extend existing)**: assert `metadata_json` round-trips through a real Postgres write via `SeedBuiltinTemplates`/read via `GetTemplate`, not just Go-side construction — confirms the new column and (un)marshaling are wired correctly, not just compiling.
- **Backward compatibility**: the existing `internal/exercise` test suite (including Phase A0/A1's tests) must pass unmodified — this spec adds no changes to `Executor`, triggers, or the detection bridge; if any existing test breaks, that's a sign this spec accidentally touched engine code, which it must not.

## Category naming

`"purple-team"` is a new `Category` value (existing values: `"phishing"`, `"ransomware"`, `"credential-theft"`, `"soc-readiness"`). No enum/constant currently constrains `Category` — it's a bare string on `Template`, consistent with the existing 5 built-ins each using their own value freely. No validation code changes needed.
