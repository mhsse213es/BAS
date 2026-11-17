package scenario

// Execution-class catalog entries for the cloud VM packs (cloud-vm-*, cloud-vm-linux-*).
//
// Each entry is keyed by the (technique_id, action_key) that the pack's steps declare. Read-only probes are
// non_destructive. Steps that create cloud credentials or send data out of the VM are destructive: they run only
// behind their lab gates and undo themselves in-script, which the scenario YAML records as reversible.
//
// init merges these entries into the shared catalog and panics on a duplicate key, so a collision with the
// hand-authored or generated catalog cannot silently shadow an existing classification.
func init() {
	for technique, actions := range cloudVMClassifications {
		if executionClassifications[technique] == nil {
			executionClassifications[technique] = map[string]*ExecutionClassification{}
		}
		for key, c := range actions {
			if _, dup := executionClassifications[technique][key]; dup {
				panic("execclass: duplicate cloud VM catalog entry " + technique + "/" + key)
			}
			executionClassifications[technique][key] = c
		}
	}
}

var cloudVMClassifications = map[string]map[string]*ExecutionClassification{
	"T1552.005": {
		"cloud_imds_probe":  {Class: ClassNonDestructive, BlastRadius: "Read-only request to the instance metadata service."},
		"cloud_token_issue": {Class: ClassNonDestructive, BlastRadius: "Requests a managed-identity token into memory only; nothing is stored or changed."},
	},
	"T1528": {
		"cloud_token_use_read": {Class: ClassNonDestructive, BlastRadius: "One read-only call with a token acquired in the same step."},
	},
	"T1580": {
		"cloud_inventory_read": {Class: ClassNonDestructive, BlastRadius: "Read-only inventory listing (names and counts)."},
	},
	"T1526": {
		"cloud_inventory_read": {Class: ClassNonDestructive, BlastRadius: "Read-only inventory listing of database or extension resources."},
	},
	"T1619": {
		"cloud_inventory_read": {Class: ClassNonDestructive, BlastRadius: "Read-only listing of storage bucket names."},
	},
	"T1069.003": {
		"cloud_role_read": {Class: ClassNonDestructive, BlastRadius: "Read-only listing of role assignments or attached policies."},
	},
	"T1087.004": {
		"cloud_identity_read": {Class: ClassNonDestructive, BlastRadius: "Caller identity lookup, which every principal may perform."},
	},
	"T1555": {
		"cloud_secret_name_read":  {Class: ClassNonDestructive, BlastRadius: "Lists secret names only; no value is requested."},
		"cloud_secret_value_read": {Class: ClassPotentiallyDestructive, BlastRadius: "Requests one synthetic test secret value into memory; only its length is recorded and the value is discarded."},
	},
	"T1098": {
		"policy_simulation_read": {Class: ClassNonDestructive, BlastRadius: "IAM policy simulation only; no change is made."},
		"cloud_role_assume":      {Class: ClassPotentiallyDestructive, BlastRadius: "Asks the cloud to issue temporary credentials for one operator-named test role; returned credentials are discarded."},
	},
	"T1098.001": {
		"cloud_access_key_create": {Class: ClassDestructive, DestructiveAction: "create_then_delete_access_key", BlastRadius: "Creates one access key for an operator-named test user and deletes it; cleanup is verified in-script."},
		"cloud_client_secret_add": {Class: ClassDestructive, DestructiveAction: "add_then_remove_client_secret", BlastRadius: "Adds one client secret to an operator-named test application and removes it; cleanup is verified in-script."},
	},
	"T1552.001": {
		"local_credential_scan": {Class: ClassNonDestructive, BlastRadius: "Local read of credential-file presence and counts; values are never printed."},
	},
	"T1021": {
		"remote_mgmt_exposure_read": {Class: ClassNonDestructive, BlastRadius: "Read-only SSH or WinRM listener and firewall state check."},
	},
	"T1574": {
		"startup_location_read": {Class: ClassNonDestructive, BlastRadius: "Read-only permission check of startup script locations; nothing is written."},
	},
	"T1530": {
		"cloud_object_list_read": {Class: ClassNonDestructive, BlastRadius: "Lists container or bucket names on a synthetic test account."},
		"cloud_object_head_read": {Class: ClassNonDestructive, BlastRadius: "Metadata-only request for one synthetic object; the body is never read."},
	},
	"T1567.002": {
		"cloud_synthetic_upload": {Class: ClassDestructive, DestructiveAction: "synthetic_upload_then_delete", BlastRadius: "Uploads one 1 KB synthetic object to an operator-named test container and deletes it; cleanup is verified in-script. Tests egress to cloud storage."},
	},
}
