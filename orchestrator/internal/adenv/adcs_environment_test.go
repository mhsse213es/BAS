package adenv

import "testing"

// TestADCSEnvironment_IdentifiesVulnerableTemplateAmongPublishedOnes
// proves the "graph relationship" half of ADCS modeling: a CA's
// PublishedTemplates linked to the actual CertTemplate entries it names,
// walked together to find exactly the vulnerable one in a realistic
// multi-template environment -- not a predicate exercised against one
// isolated struct literal (sub-phase 2 already covers that case).
func TestADCSEnvironment_IdentifiesVulnerableTemplateAmongPublishedOnes(t *testing.T) {
	env := Environment{
		PKI: PKI{
			CAs: []CertificateAuthority{{
				Name:               "CORP-CA",
				PublishedTemplates: []string{"VulnerableWebAuth", "StandardUser"},
			}},
			Templates: []CertTemplate{
				{
					Name:                    "VulnerableWebAuth",
					EKUs:                    []string{"Client Authentication"},
					EnrolleeSuppliesSubject: true,
					ManagerApprovalRequired: false,
					PublishedToCA:           true,
				},
				{
					Name:                    "StandardUser",
					EKUs:                    []string{"Client Authentication"},
					EnrolleeSuppliesSubject: false, // the mitigating difference
					ManagerApprovalRequired: false,
					PublishedToCA:           true,
				},
				{
					// Exists in the environment but is NOT in any CA's
					// PublishedTemplates -- vulnerable in isolation, but
					// unreachable, so a "what can actually be requested"
					// query must exclude it.
					Name:                    "UnpublishedLegacyTemplate",
					EKUs:                    []string{"Client Authentication"},
					EnrolleeSuppliesSubject: true,
					ManagerApprovalRequired: false,
					PublishedToCA:           false,
				},
			},
		},
	}

	ca := env.PKI.CAs[0]
	templatesByName := map[string]CertTemplate{}
	for _, t := range env.PKI.Templates {
		templatesByName[t.Name] = t
	}

	var reachableVulnerable []string
	for _, name := range ca.PublishedTemplates {
		tmpl, ok := templatesByName[name]
		if !ok {
			continue
		}
		if IsESC1Vulnerable(tmpl) || IsESC2Vulnerable(tmpl) || IsESC3Vulnerable(tmpl) {
			reachableVulnerable = append(reachableVulnerable, name)
		}
	}

	if len(reachableVulnerable) != 1 || reachableVulnerable[0] != "VulnerableWebAuth" {
		t.Fatalf("expected exactly [VulnerableWebAuth] reachable-and-vulnerable, got %v", reachableVulnerable)
	}

	// IsESC1Vulnerable's own definition includes PublishedToCA (an
	// unpublished template cannot actually be requested at all, so it is
	// correctly excluded by the predicate itself, not merely by the
	// CA-linkage check above) -- two consistent signals, not a
	// predicate/reachability split.
	if IsESC1Vulnerable(templatesByName["UnpublishedLegacyTemplate"]) {
		t.Fatal("expected UnpublishedLegacyTemplate to be excluded by IsESC1Vulnerable itself (PublishedToCA is part of ESC1's own definition)")
	}
	for _, name := range reachableVulnerable {
		if name == "UnpublishedLegacyTemplate" {
			t.Fatal("UnpublishedLegacyTemplate must not appear in the CA-reachable vulnerable set -- it is not in any CA's PublishedTemplates")
		}
	}
}
