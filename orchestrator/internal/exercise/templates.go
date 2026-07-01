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
				DependsOn: []string{"send_bec"},
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
				DependsOn: []string{"sim"},
				Config:    StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_edr", Type: StepTypeWaitForDetection, Label: "Wait for EDR/SIEM detection",
				DependsOn: []string{"wait_sim"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes: []string{"edr_detected", "siem_alerted"},
				}},
			},
			{
				ID: "soc_approve", Type: StepTypeApproval, Label: "SOC sign-off — incident handled?",
				DependsOn: []string{"wait_edr"},
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
				DependsOn:  []string{"wait_interact"},
				Condition:  "step:phish_cred:clicked",
				Config:     StepConfig{NotifyMsg: "One or more users submitted credentials. Review credentials_submitted evidence."},
			},
			{
				ID: "notify_no_cred", Type: StepTypeNotify, Label: "No credentials submitted — good outcome",
				DependsOn:  []string{"wait_interact"},
				Condition:  "step:phish_cred:not_clicked",
				Config:     StepConfig{NotifyMsg: "No credentials submitted during the exercise window."},
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
				DependsOn: []string{"drill_sim"},
				Config:    StepConfig{WaitForAgent: &WaitForAgentConfig{AgentTaskStepID: "drill_sim"}},
				TimeoutSecs: 1800,
			},
			{
				ID: "wait_detect", Type: StepTypeWaitForDetection, Label: "Wait for SOC detection",
				DependsOn: []string{"wait_sim_done"},
				TimeoutSecs: 1800,
				Config: StepConfig{WaitForDetection: &WaitForDetectionConfig{
					DetectionTypes: []string{"edr_detected", "siem_alerted"},
				}},
			},
			{
				ID: "approval_response", Type: StepTypeApproval, Label: "SOC: confirm incident response completed",
				DependsOn: []string{"wait_detect"},
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
}
