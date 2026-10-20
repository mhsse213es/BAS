package api

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

const testSessionPolicy = `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}`

func TestValidateCloudScenarioRunBody_SessionPolicy(t *testing.T) {
	role := validScenarioBody()
	role.Principal = "arn:aws:iam::111122223333:role/backup-operator"

	t.Run("role principal with valid session is accepted", func(t *testing.T) {
		b := role
		b.SessionPolicy = testSessionPolicy
		if err := validateCloudScenarioRunBody(b); err != nil {
			t.Errorf("valid role session refused: %v", err)
		}
	})

	t.Run("user principal is refused", func(t *testing.T) {
		b := validScenarioBody()
		b.SessionPolicy = testSessionPolicy
		err := validateCloudScenarioRunBody(b)
		if err == nil || !strings.Contains(err.Error(), "role ARN") {
			t.Errorf("err = %v, want refusal naming the role ARN requirement", err)
		}
	})

	t.Run("GCP scenario is refused", func(t *testing.T) {
		b := role
		b.ScenarioID = "backup-assurance-gcp"
		b.Account = cloudgraph.AccountScope{Provider: "gcp", AccountID: "proj-1"}
		b.SessionPolicy = testSessionPolicy
		if err := validateCloudScenarioRunBody(b); err == nil || !strings.Contains(err.Error(), "AWS scenarios only") {
			t.Errorf("err = %v, want refusal for a non-AWS scenario", err)
		}
	})

	t.Run("unreadable session policy is refused", func(t *testing.T) {
		b := role
		b.SessionPolicy = "not a policy"
		if err := validateCloudScenarioRunBody(b); err == nil {
			t.Error("unreadable session policy accepted")
		}
	})
}
