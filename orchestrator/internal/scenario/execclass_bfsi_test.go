package scenario

import "testing"

// Each Cobalt Group BFSI step resolves to an explicit class. An unknown pair fails closed to
// destructive, which vetoes the step on the agent unless a local grant exists, so an unlisted key
// silently blocks a scenario. These expectations are the agreed classification.
func TestBFSIStepsHaveExplicitClassification(t *testing.T) {
	cases := []struct {
		tid, action string
		want        ExecutionClass
	}{
		{"T1071.001", "c2_http_beaconing", ClassNonDestructive},
		{"T1573", "c2_encrypted_channel", ClassPotentiallyDestructive},
		{"T1105", "c2_ingress_tool_transfer", ClassPotentiallyDestructive},
		{"T1571", "c2_non_standard_port", ClassNonDestructive},
		{"T1005", "collection_local_data", ClassNonDestructive},
		{"T1039", "collection_network_share", ClassNonDestructive},
		{"T1114.001", "collection_email_presence", ClassNonDestructive},
		{"T1560.001", "collection_archive_data", ClassPotentiallyDestructive},
		{"T1041", "exfil_over_c2_simulation", ClassPotentiallyDestructive},
		{"T1048.003", "exfil_dns_simulation", ClassNonDestructive},
		{"T1003.001", "credential_lsass_simulation", ClassNonDestructive},
		{"T1003.002", "credential_sam_simulation", ClassNonDestructive},
		{"T1555.004", "credential_manager_discovery", ClassNonDestructive},
		{"T1555.003", "credential_browser_discovery", ClassNonDestructive},
		{"T1558.003", "credential_kerberoasting", ClassNonDestructive},
		{"T1558.004", "credential_asrep_roasting", ClassNonDestructive},
		{"T1110.003", "credential_password_spray", ClassDestructive},
		{"T1552.001", "credential_unsecured_discovery", ClassNonDestructive},
		{"T1518.001", "evasion_security_software_discovery", ClassNonDestructive},
		{"T1562.001", "evasion_security_tool_impairment_probe", ClassNonDestructive},
		{"T1027", "evasion_powershell_obfuscation", ClassNonDestructive},
		{"T1036", "evasion_masquerading_executable", ClassPotentiallyDestructive},
		{"T1112", "evasion_registry_modification", ClassPotentiallyDestructive},
		{"T1070.001", "evasion_event_log_clearing", ClassDestructive},
		{"T1055", "evasion_process_injection_readiness", ClassNonDestructive},
		{"T1046", "bfsi_banking_app_discovery", ClassNonDestructive},
		{"T1046", "bfsi_payment_gateway_discovery", ClassNonDestructive},
		{"T1046", "bfsi_atm_discovery", ClassNonDestructive},
		{"T1046", "bfsi_cardholder_data_discovery", ClassNonDestructive},
		{"T1565.001", "financial_transaction_manipulation", ClassPotentiallyDestructive},
		{"T1565.001", "financial_payment_instruction_manipulation", ClassPotentiallyDestructive},
		{"T1565.001", "financial_atm_dispense_manipulation", ClassPotentiallyDestructive},
		{"T1565.001", "financial_fraud_pattern_simulation", ClassPotentiallyDestructive},
		{"T1565.001", "financial_transaction_limit_bypass", ClassPotentiallyDestructive},
		{"T1565.001", "financial_reconciliation_manipulation", ClassPotentiallyDestructive},
		{"T1499", "financial_resilience_check", ClassNonDestructive},
		{"T1021.001", "lateral_rdp_connectivity", ClassNonDestructive},
		{"T1021.002", "lateral_smb_shares", ClassNonDestructive},
		{"T1021.006", "lateral_winrm_session", ClassPotentiallyDestructive},
		{"T1569.002", "lateral_remote_service", ClassDestructive},
		{"T1018", "lateral_system_discovery", ClassNonDestructive},
		{"T1547.001", "persistence_registry_run_key", ClassPotentiallyDestructive},
		{"T1546.003", "persistence_wmi_event_subscription", ClassDestructive},
		{"T1136.001", "persistence_local_account_creation", ClassDestructive},
		{"T1098", "persistence_account_manipulation", ClassDestructive},
		{"T1590.001", "recon_subdomain_enumeration", ClassNonDestructive},
		{"T1589.003", "recon_employee_discovery", ClassNonDestructive},
		{"T1078.002", "access_valid_account_logon", ClassDestructive},
		{"T1059.003", "exe_command_shell", ClassNonDestructive},
	}
	for _, c := range cases {
		got := ResolveExecutionClass(c.tid, c.action)
		if got.DestructiveAction == "unclassified" {
			t.Errorf("%s / %s: no catalog entry (fails closed to destructive)", c.tid, c.action)
			continue
		}
		if got.Class != c.want {
			t.Errorf("%s / %s: class %s, want %s", c.tid, c.action, got.Class, c.want)
		}
	}
}
