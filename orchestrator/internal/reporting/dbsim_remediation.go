package reporting

// COPY THAT THE OWNER MUST REVIEW BEFORE RELEASE.
//
// Fixed remediation text per dbsim scenario id and dimension. It is shown only
// when that dimension is graded "fail" on a PASS/FAIL result. Every entry is
// worded conditionally ("If ..." / "Review ...") because the stored evidence
// does not name the exact grant or setting responsible. Nothing here is
// generated from evidence.
var dbsimRemediation = map[string]map[string]string{
	"dbsim-db01-auth-policy": {
		"prevention": "Review the target's authentication settings (password policy, TLS requirement, allowed methods) against your organisation's standard. If the observed settings are weaker than that standard, tighten them in the database or its identity provider.",
		"policy":     "Review the account's authentication configuration against your stated policy. If it deviates, align it with the policy.",
	},
	"dbsim-db02-excessive-grants": {
		"policy":     "Review the listed grant deviations against the privilege policy used for this run. If a grant is not required for the role's purpose, consider revoking it after confirming no application depends on it.",
		"prevention": "Review the privileges held by the BAS lab role. If it holds more than the policy allows, revoke the excess grants.",
	},
	"dbsim-db03-unauthorized-access": {
		"prevention": "Review the grants on the restricted table for the probe identity and any roles it inherits. If the identity can read a table it should not, remove that grant or the role membership.",
		"detection":  "Review whether database audit events for the denied or successful read reach your SIEM and whether a rule covers access to restricted tables. If they do not, enable forwarding and add a rule.",
	},
	"dbsim-db04-audit-coverage": {
		"audit":      "Review the target's audit configuration (for example pgaudit settings or MySQL audit/general log settings) and whether the probe's own marker appeared in the audit source. If coverage is partial or absent for the statement classes you need, enable or widen it.",
		"prevention": "Review why the read-only audit-check probes were refused for the BAS test account. If the account lacks the read access this check needs, grant only that minimal read access (audit settings and the audit source) in the lab or agreed target.",
	},
	"dbsim-db05-suspicious-read": {
		"detection":      "Review whether your SIEM receives database audit data and has a rule for reads of classified or high-volume tables. If no alert correlated to the run marker, add or tune such a rule.",
		"prevention":     "Review whether the lab account is intended to read the classified fixture. If reads of classified data should be blocked for this account, restrict its grants.",
		"classification": "Review the data-classification rules applied to the fixture table. If the classified columns were not recognised, update the rule set.",
	},
	"dbsim-db06-account-revocation": {
		"prevention": "Review whether other authentication paths (for example pooled sessions or cached credentials) still allow the revoked account to sign in, and how revocation is applied on this target.",
	},
	"dbsim-db07-sensitive-classification": {
		"classification": "Review the data-classification control's rules and the sources it monitors. If the synthetic sensitive patterns were not recognised by their expected rule, update or enable the matching rule.",
		"detection":      "Review whether the classification or DLP control forwards its findings to your SIEM. If no alert correlated to the run marker, enable forwarding.",
	},
	"dbsim-db08-audit-tamper-resistance": {
		"prevention": "Review which roles can change audit logging for a session (for example SET statements affecting logging). If an unprivileged account could switch audit off, restrict that setting to administrators, subject to your platform's supported controls.",
		"detection":  "Review whether attempts to disable audit logging raise an alert in your SIEM. If not, add a rule for such attempts.",
	},
	"dbsim-db09-bounded-bulk-read": {
		"detection":  "Review whether your SIEM has a rule for bulk reads (row-count or volume thresholds) on sensitive tables. If no alert correlated to the run marker, add or tune such a rule.",
		"prevention": "Review row-limit, statement-timeout and result-size controls for the account. If bulk reads are meant to be restricted, apply them.",
	},
	"dbsim-db10-write-delete-prevention": {
		"prevention": "Review the grants held by the SELECT-only test account and its inherited roles. If INSERT, UPDATE or DELETE succeeded, remove the write privileges from the account or role.",
		"detection":  "Review whether denied or successful write attempts reach your SIEM and are covered by a rule. If not, enable forwarding and add a rule.",
	},
	"dbsim-db11-backup-export-permissions": {
		"prevention": "Review which roles can run backup, export or file-write operations on the target. If the test account holds such privileges, revoke them unless a documented need exists.",
		"policy":     "Review the account's backup/export grants against your stated policy. If they deviate, align them with the policy.",
	},
}

// DBSimRemediation returns the fixed remediation text for a scenario id and
// dimension ("prevention", "detection", "audit", "policy", "classification"),
// or "" if there is none. The caller must show it only for a dimension graded
// fail.
func DBSimRemediation(scenarioID, dimension string) string {
	return dbsimRemediation[scenarioID][dimension]
}
