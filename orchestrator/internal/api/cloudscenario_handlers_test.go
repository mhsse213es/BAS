package api

import (
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

func validScenarioBody() cloudScenarioRunBody {
	return cloudScenarioRunBody{
		ScenarioID: "backup-assurance-aws",
		Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111122223333"},
		Principal:  "arn:aws:iam::111122223333:user/ops",
		Resource:   "arn:aws:backup:us-east-1:111122223333:backup-vault:prod",
	}
}

func TestValidateCloudScenarioRunBody(t *testing.T) {
	if err := validateCloudScenarioRunBody(validScenarioBody()); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}

	cases := map[string]struct {
		mutate func(*cloudScenarioRunBody)
		want   string
	}{
		"unknown scenario":  {func(b *cloudScenarioRunBody) { b.ScenarioID = "nope" }, "unknown scenarioId"},
		"provider mismatch": {func(b *cloudScenarioRunBody) { b.Account.Provider = "gcp" }, "targets aws"},
		"missing principal": {func(b *cloudScenarioRunBody) { b.Principal = "" }, "principal required"},
		"missing resource":  {func(b *cloudScenarioRunBody) { b.Resource = "" }, "resource required"},
		"missing account":   {func(b *cloudScenarioRunBody) { b.Account.AccountID = "" }, "accountId required"},
		"observe without time": {func(b *cloudScenarioRunBody) {
			b.Observe = &struct {
				ActionTime    time.Time `json:"actionTime"`
				WindowSeconds int       `json:"windowSeconds"`
			}{WindowSeconds: 60}
		}, "actionTime required"},
		"window too wide": {func(b *cloudScenarioRunBody) {
			b.Observe = &struct {
				ActionTime    time.Time `json:"actionTime"`
				WindowSeconds int       `json:"windowSeconds"`
			}{ActionTime: time.Now(), WindowSeconds: 7200}
		}, "windowSeconds must be between"},
	}
	for name, c := range cases {
		b := validScenarioBody()
		c.mutate(&b)
		err := validateCloudScenarioRunBody(b)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want containing %q", name, err, c.want)
		}
	}
}
