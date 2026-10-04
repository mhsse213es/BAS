package exercise

// BuiltinTemplates is the library of built-in exercise templates that ships
// with the platform. These are seeded into exercise_templates on startup and
// marked built_in=true (not editable by operators).
//
// Each template uses ${VarName} references in step configs; operators fill
// these in when launching via the InstantiateTemplate API.
var BuiltinTemplates = []Template{

	// ── 1. Phishing Awareness ─────────────────────────────────────────────────
	// Simplest exercise: send a phishing email and measure click / report rate.
	{
		ID:          "builtin-phishing-awareness",
		Name:        "Phishing Awareness Exercise",
		Version:     1,
		Category:    "phishing",
		Description: "Send a phishing email to a target group and measure click rate, report rate, and time-to-report. Good for quarterly security awareness benchmarks.",
		Author:      "Audspect",
		BuiltIn:     true,
		Variables: []VarDef{
			{Name: "PhishingSubject", Type: VarTypeString, Required: true, Description: "Email subject line"},
			{Name: "PhishingBody", Type: VarTypeString, Required: true, Description: "Email body HTML (may reference ${TrackingURL})"},
			{Name: "SenderName", Type: VarTypeString, Required: true, Description: "Display name of the sender (e.g. 'IT Helpdesk')"},
			{Name: "WaitHours", Type: VarTypeDuration, Default: "24h", Description: "How long to wait before scoring"},
		},
		Steps: []PlanStep{
			{
				ID: "send", Type: StepTypeSendEmail, Label: "Send phishing email",
				Config: StepConfig{Email: &EmailConfig{
					Subject:     "${PhishingSubject}",
					BodyHTML:    "${PhishingBody}",
					TrackOpens:  true,
					TrackClicks: true,
					LandingPage: "safe",
				}},
			},
			{
				ID: "wait", Type: StepTypeWait, Label: "Wait for responses",
				DependsOn: []string{"send"},
				Config:    StepConfig{WaitDuration: "${WaitHours}"},
			},
			{
				ID: "score", Type: StepTypeNotify, Label: "Exercise complete — review results",
				DependsOn: []string{"wait"},
				Config:    StepConfig{NotifyMsg: "Phishing exercise complete. Review click/report rates in the evidence chain."},
			},
		},
	},

	// ── 2. Business Email Compromise ─────────────────────────────────────────
	// Impersonates a senior executive to target finance / AP staff.
	{
		ID:          "builtin-bec",
		Name:        "Business Email Compromise (BEC)",
		Version:     1,
		Category:    "phishing",
		Description: "Impersonates a senior executive targeting finance or accounts-payable staff. Measures susceptibility to wire-transfer or credential-theft lures.",
		Author:      "Audspect",
		BuiltIn:     true,
		Variables: []VarDef{
			{Name: "ExecName", Type: VarTypeString, Required: true, Description: "Name of the executive being impersonated (e.g. 'Rajesh Kumar, CFO')"},
			{Name: "PhishingSubject", Type: VarTypeString, Required: true, Description: "Email subject (e.g. 'Urgent wire transfer required')"},
			{Name: "PhishingBody", Type: VarTypeString, Required: true, Description: "Email body HTML"},
			{Name: "CredLanding", Type: VarTypeString, Default: "cred", Description: "Landing page type: 'safe' or 'cred'"},
			{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "2h", Description: "How long to wait for SOC detection before scoring"},
		},
		Steps: []PlanStep{
			{
				ID: "send_bec", Type: StepTypeSendEmail, Label: "Send BEC email",
				Config: StepConfig{Email: &EmailConfig{
					Subject:     "${PhishingSubject}",
					BodyHTML:    "${PhishingBody}",
					TrackOpens:  true,
					TrackClicks: true,
					LandingPage: "${CredLanding}",
				}},
			},
			{
				ID: "wait_detection", Type: StepTypeWaitForDetection, Label: "Wait for SOC/EDR detection",
				DependsOn:   []string{"send_bec"},
				TimeoutSecs: 7200,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes: []string{"edr_detected", "siem_alerted", "phishing_reported"},
				}},
			},
			{
				ID: "score_bec", Type: StepTypeNotify, Label: "BEC exercise complete",
				DependsOn: []string{"wait_detection"},
				Config:    StepConfig{NotifyMsg: "BEC exercise complete. Review credential submissions and detection latency."},
			},
		},
	},

	// ── 3. Ransomware Response ────────────────────────────────────────────────
	// Phishing → credential harvest → endpoint compromise → EDR detection.
	{
		ID:          "builtin-ransomware-response",
		Name:        "Ransomware Response Exercise",
		Version:     1,
		Category:    "ransomware",
		Description: "End-to-end ransomware scenario: phishing lure → credential harvest → BAS agent simulates ransomware precursor TTPs → waits for EDR/SIEM detection → approval gate for SOC sign-off.",
		Author:      "Audspect",
		BuiltIn:     true,
		Variables: []VarDef{
			{Name: "PhishingSubject", Type: VarTypeString, Required: true},
			{Name: "PhishingBody", Type: VarTypeString, Required: true},
			{Name: "SimAgentID", Type: VarTypeEndpoint, Required: true, Description: "BAS agent to run the simulation on"},
			{Name: "SimScenarioID", Type: VarTypeString, Required: true, Description: "Scenario to run (e.g. 'ransomware-precursors')"},
			{Name: "SOCEmail", Type: VarTypeEmailList, Description: "SOC team email for approval gate"},
			{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m"},
			{Name: "ApprovalTimeout", Type: VarTypeDuration, Default: "4h"},
		},
		Steps: []PlanStep{
			{
				ID: "phish", Type: StepTypeSendEmail, Label: "Send ransomware lure",
				Config: StepConfig{Email: &EmailConfig{
					Subject:     "${PhishingSubject}",
					BodyHTML:    "${PhishingBody}",
					TrackOpens:  true,
					TrackClicks: true,
					LandingPage: "cred",
				}},
			},
			{
				ID: "wait_click", Type: StepTypeWait, Label: "Wait for initial interaction",
				DependsOn: []string{"phish"},
				Config:    StepConfig{WaitDuration: "15m"},
			},
			{
				ID: "sim", Type: StepTypeAgentTask, Label: "Run ransomware precursor simulation",
				DependsOn: []string{"wait_click"},
				Config: StepConfig{AgentTask: &AgentTaskConfig{
					AgentID:    "${SimAgentID}",
					ScenarioID: "${SimScenarioID}",
				}},
			},
			{
				ID: "wait_sim", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
				DependsOn:   []string{"sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_edr", Type: StepTypeWaitForDetection, Label: "Wait for EDR/SIEM detection",
				DependsOn:   []string{"wait_sim"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"edr_detected", "siem_alerted"},
					ExecutionStepID: "sim",
				}},
			},
			{
				ID: "soc_approve", Type: StepTypeApproval, Label: "SOC sign-off — incident handled?",
				DependsOn:   []string{"wait_edr"},
				TimeoutSecs: 14400,
				Config: StepConfig{
					ApprovalPrompt: "Did the SOC follow the ransomware IR playbook and contain the incident?",
					ApproverRoles:  []string{"admin", "analyst"},
				},
			},
			{
				ID: "complete", Type: StepTypeNotify, Label: "Ransomware exercise complete",
				DependsOn: []string{"soc_approve"},
				Config:    StepConfig{NotifyMsg: "Ransomware response exercise complete. Review evidence chain and MTTD/MTTR scores."},
			},
		},
	},

	// ── 4. Credential Theft ───────────────────────────────────────────────────
	// Credential harvesting page → check if EDR blocked the POST.
	{
		ID:          "builtin-credential-theft",
		Name:        "Credential Theft Exercise",
		Version:     1,
		Category:    "credential-theft",
		Description: "Simulates a credential-harvesting campaign targeting internal users. Measures who submitted credentials, whether EDR/proxy blocked the page, and SOC response time.",
		Author:      "Audspect",
		BuiltIn:     true,
		Variables: []VarDef{
			{Name: "PhishingSubject", Type: VarTypeString, Required: true},
			{Name: "PhishingBody", Type: VarTypeString, Required: true, Description: "Body HTML — use ${TrackingURL} for the cred-harvest link"},
			{Name: "AgentID", Type: VarTypeEndpoint, Description: "Agent to run Mimikatz simulation (optional)"},
			{Name: "MimikatzScenario", Type: VarTypeString, Default: "credential-dumping", Description: "Scenario ID for credential-dumping simulation"},
			{Name: "WaitTimeout", Type: VarTypeDuration, Default: "1h"},
		},
		Steps: []PlanStep{
			{
				ID: "phish_cred", Type: StepTypeSendEmail, Label: "Send credential-harvest lure",
				Config: StepConfig{Email: &EmailConfig{
					Subject:     "${PhishingSubject}",
					BodyHTML:    "${PhishingBody}",
					TrackOpens:  true,
					TrackClicks: true,
					LandingPage: "cred",
				}},
			},
			{
				ID: "wait_interact", Type: StepTypeWait, Label: "Wait for interaction window",
				DependsOn: []string{"phish_cred"},
				Config:    StepConfig{WaitDuration: "${WaitTimeout}"},
			},
			{
				ID: "notify_cred", Type: StepTypeNotify, Label: "Credential theft exercise complete",
				DependsOn: []string{"wait_interact"},
				Condition: "step:phish_cred:clicked",
				Config:    StepConfig{NotifyMsg: "One or more users submitted credentials. Review credentials_submitted evidence."},
			},
			{
				ID: "notify_no_cred", Type: StepTypeNotify, Label: "No credentials submitted — good outcome",
				DependsOn: []string{"wait_interact"},
				Condition: "step:phish_cred:not_clicked",
				Config:    StepConfig{NotifyMsg: "No credentials submitted during the exercise window."},
			},
		},
	},

	// ── 5. SOC Drill (Detection Latency) ─────────────────────────────────────
	// Pure technical test: agent task → measure how fast SOC detects and responds.
	{
		ID:          "builtin-soc-drill",
		Name:        "SOC Detection Drill",
		Version:     1,
		Category:    "soc-readiness",
		Description: "Triggers a BAS simulation and measures SOC detection latency (MTTD) and response time (MTTR). No human-targeting component — purely technical.",
		Author:      "Audspect",
		BuiltIn:     true,
		Variables: []VarDef{
			{Name: "AgentID", Type: VarTypeEndpoint, Required: true, Description: "Target agent for the simulation"},
			{Name: "ScenarioID", Type: VarTypeString, Required: true, Description: "Scenario to execute (e.g. 'lateral-movement')"},
			{Name: "DetectionTimeout", Type: VarTypeDuration, Default: "30m", Description: "Max time to wait for detection before timing out"},
			{Name: "SOCNotifyEmail", Type: VarTypeEmailList, Description: "Email to notify when drill completes"},
		},
		Steps: []PlanStep{
			{
				ID: "drill_sim", Type: StepTypeAgentTask, Label: "Trigger BAS simulation",
				Config: StepConfig{AgentTask: &AgentTaskConfig{
					AgentID:    "${AgentID}",
					ScenarioID: "${ScenarioID}",
				}},
			},
			{
				ID: "wait_sim_done", Type: StepTypeWaitForAgent, Label: "Wait for simulation to complete",
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"edr_detected", "siem_alerted"},
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
				DependsOn:   []string{"wait_detect"},
				TimeoutSecs: 7200,
				Config: StepConfig{
					ApprovalPrompt: "Has the SOC completed triage, containment, and documented the incident?",
					ApproverRoles:  []string{"admin", "analyst"},
				},
			},
			{
				ID: "drill_complete", Type: StepTypeNotify, Label: "SOC drill complete — check MTTD/MTTR",
				DependsOn: []string{"approval_response"},
				Config:    StepConfig{NotifyMsg: "SOC drill complete. Review the technical score for MTTD and MTTR."},
			},
		},
	},

	// ── 6. APT29 Kill Chain Purple Team Drill ─────────────────────────────────
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
			ExpectedTechniques:      []string{"T1482", "T1059.001", "T1547.001", "T1053.005", "T1071.004"},
			ExpectedDetections:      []string{"Microsoft Defender", "Microsoft Sentinel"},
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
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"edr_detected", "siem_alerted", "security_control_detected"},
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
				DependsOn:   []string{"wait_detect"},
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

	// ── 7. Volt Typhoon LOTL Purple Team Drill ────────────────────────────────
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
			ExpectedTechniques:      []string{"T1082", "T1016", "T1090.001", "T1087.001", "T1003.002", "T1003.003", "T1105", "T1218.005", "T1053.005", "T1070.001"},
			ExpectedDetections:      []string{"Microsoft Defender", "Microsoft Sentinel", "Sigma-based SIEM rule"},
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
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"edr_detected", "siem_alerted", "security_control_detected"},
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
				DependsOn:   []string{"wait_detect"},
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

	// ── 8. Kerberoasting & AD Credential Theft Purple Team Drill ──────────────
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
			ExpectedTechniques:      []string{"T1558.003", "T1558.004", "T1087.002", "T1482", "T1069.002", "T1615", "T1552.006"},
			ExpectedDetections:      []string{"Microsoft Defender for Identity", "Microsoft Defender"},
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
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for identity-layer detection",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"security_control_detected"}, // identity-only, deliberately excludes edr_detected
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
				DependsOn:   []string{"wait_detect"},
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

	// ── 9. Collection to Exfiltration Purple Team Drill ────────────────────────
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
			ExpectedTechniques:      []string{"T1083", "T1074.001", "T1560.001", "T1048.001", "T1048.003", "T1567.002"},
			ExpectedDetections:      []string{"Microsoft Defender", "Microsoft Purview", "Microsoft Sentinel"},
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
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC/DLP detection",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"edr_detected", "siem_alerted", "security_control_detected"},
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
				DependsOn:   []string{"wait_detect"},
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

	// ── 10. DLP Exfiltration Purple Team Drill ─────────────────────────────────
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
			ExpectedTechniques:      []string{"T1052.001", "T1115", "T1052", "T1560.001", "T1074.001"},
			ExpectedDetections:      []string{"Trellix DLP"},
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
				DependsOn:   []string{"drill_sim"},
				Config:      StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for DLP block confirmation",
				DependsOn:   []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes:  []string{"security_control_detected"},
					MinCount:        5, // all 5 channels — one coherent claim, unlike the other templates' default MinCount:1
					ExecutionStepID: "drill_sim",
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC/Compliance: confirm DLP coverage reviewed",
				DependsOn:   []string{"wait_detect"},
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
}
