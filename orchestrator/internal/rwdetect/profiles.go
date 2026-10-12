package rwdetect

// RansomwareRelevantProfiles are the detection-profile names referenced by
// the 8 scenarios/drills internal/api.ransomwareScenarioIDs scopes
// rwevidence's integration to: akira-kill-chain.yaml, blackcat-kill-chain.yaml,
// clop-kill-chain.yaml, lockbit-kill-chain.yaml, play-kill-chain.yaml,
// ransomhub-kill-chain.yaml, ransomware-drill.yaml,
// endpoint-mastery/em-07-ransomware-readiness.yaml.
//
// This is a content inventory, not a capability model: a profile's
// presence here says nothing about whether it has real detection-provider
// wiring (see this package's deferred Track I work) or whether its MITRE
// technique is modeled by rwevidence (see internal/rwevidence/technique.go's
// own, smaller, independently-tracked set: T1490, T1486, T1567.002,
// T1560.001 today). Verified against the real scenario YAMLs by
// TestRansomwareRelevantProfiles_MatchesRealCorpus -- this list cannot
// silently drift from the content it describes.
var RansomwareRelevantProfiles = []string{
	"windows_ad_discovery",
	"windows_archive_staging",
	"windows_backup_service_stop",
	"windows_cloud_egress",
	"windows_defender_tampering",
	"windows_file_discovery",
	"windows_log_manipulation",
	"windows_malicious_service",
	"windows_network_share_discovery",
	"windows_ransomware_encryption",
	"windows_rdp_nla_posture",
	"windows_sam_theft",
	"windows_security_process_termination",
	"windows_security_software_discovery",
	"windows_smb_lateral_probe",
	"windows_vss_inhibition",
	"windows_vulnerable_driver_load",
	"linux_lvm_snapshot_inhibition",
	"linux_ransomware_encryption",
}
