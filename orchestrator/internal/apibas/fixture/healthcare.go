package fixture

// HealthcareTwoPatient is the healthcare pack's fixture: two patients, each with a treating clinician, a patient record, a
// prescription, a laboratory result registered to a bedside device, and a medical image; plus one delegate who holds a
// summary-only consent for patient A. Every identity, diagnosis, insurance number and report reference is synthetic, and every
// protected value is tagged BAS-SIM.
//
// Ownership and relationships:
//   - Patient A owns REC-A-001, RX-A-001, LAB-A-001 and IMG-A-001. Clinician A is the treating clinician (assignee) of the
//     record, prescription and image. Device A is the registered device (assignee) of LAB-A-001.
//   - Patient B owns REC-B-001, RX-B-001, LAB-B-001 and IMG-B-001, with Clinician B and Device B.
//   - The delegate holds CONSENT-A-001 for REC-A-001. The consent scope is summary-only: the delegate may see the public
//     summary of the record and never the diagnosis or insurance number.
func HealthcareTwoPatient() Fixture {
	return Fixture{
		Name: "healthcare-two-patient",
		Identities: []Identity{
			{Name: "patient-a", CustomerID: "patient-a", TokenRef: "apibas/lab/patient-a", Role: "patient"},
			{Name: "patient-b", CustomerID: "patient-b", TokenRef: "apibas/lab/patient-b", Role: "patient"},
			{Name: "clinician-a", CustomerID: "clinician-a", TokenRef: "apibas/lab/clinician-a", Role: "clinician"},
			{Name: "clinician-b", CustomerID: "clinician-b", TokenRef: "apibas/lab/clinician-b", Role: "clinician"},
			{Name: "delegate-a", CustomerID: "delegate-a", TokenRef: "apibas/lab/delegate-a", Role: "delegate"},
			{Name: "bedside-device-a", CustomerID: "bedside-device-a", TokenRef: "apibas/lab/bedside-device-a", Role: "device"},
			{Name: "bedside-device-b", CustomerID: "bedside-device-b", TokenRef: "apibas/lab/bedside-device-b", Role: "device"},
		},
		Objects: []Object{
			{
				ID: "REC-A-001", OwnerID: "patient-a", Status: "active", Kind: "patient_record", Assignee: "clinician-a",
				Public:    map[string]string{"ward": "general", "initial": "A"},
				Protected: map[string]string{"diagnosis": "BAS-SIM-DX-A", "insurance_id": "BAS-SIM-INS-A"},
			},
			{
				ID: "REC-B-001", OwnerID: "patient-b", Status: "active", Kind: "patient_record", Assignee: "clinician-b",
				Public:    map[string]string{"ward": "cardiology", "initial": "B"},
				Protected: map[string]string{"diagnosis": "BAS-SIM-DX-B", "insurance_id": "BAS-SIM-INS-B"},
			},
			{
				ID: "RX-A-001", OwnerID: "patient-a", Status: "active", Kind: "prescription", Parent: "REC-A-001", Assignee: "clinician-a",
				Public: map[string]string{"drug": "drug-x", "amount": "10"},
			},
			{
				ID: "RX-B-001", OwnerID: "patient-b", Status: "active", Kind: "prescription", Parent: "REC-B-001", Assignee: "clinician-b",
				Public: map[string]string{"drug": "drug-y", "amount": "20"},
			},
			{
				ID: "LAB-A-001", OwnerID: "patient-a", Status: "preliminary", Kind: "lab_result", Parent: "REC-A-001", Assignee: "bedside-device-a",
				Public:    map[string]string{"test": "hba1c", "amount": "7.1"},
				Protected: map[string]string{"report_ref": "BAS-SIM-LABREF-A"},
			},
			{
				ID: "LAB-B-001", OwnerID: "patient-b", Status: "preliminary", Kind: "lab_result", Parent: "REC-B-001", Assignee: "bedside-device-b",
				Public:    map[string]string{"test": "hba1c", "amount": "6.0"},
				Protected: map[string]string{"report_ref": "BAS-SIM-LABREF-B"},
			},
			{
				ID: "IMG-A-001", OwnerID: "patient-a", Status: "available", Kind: "image", Parent: "REC-A-001", Assignee: "clinician-a",
				Public:    map[string]string{"modality": "xray"},
				Protected: map[string]string{"storage_ref": "BAS-SIM-IMG-A"},
			},
			{
				ID: "IMG-B-001", OwnerID: "patient-b", Status: "available", Kind: "image", Parent: "REC-B-001", Assignee: "clinician-b",
				Public:    map[string]string{"modality": "mri"},
				Protected: map[string]string{"storage_ref": "BAS-SIM-IMG-B"},
			},
			{
				ID: "CONSENT-A-001", OwnerID: "patient-a", Status: "active", Kind: "consent", Parent: "REC-A-001", Assignee: "delegate-a",
				Public: map[string]string{"scope": "summary-only"},
			},
		},
	}
}
