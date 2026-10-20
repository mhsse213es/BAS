package cloudgraph

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const (
	scnPrincipal = "arn:aws:iam::111122223333:user/ops"
	scnVault     = "arn:aws:backup:us-east-1:111122223333:backup-vault:prod"
)

// scnGraph returns a graph with the principal and vault present and the given
// permission edges. Every edge is an identity-policy edge with a policy
// document allowing exactly its own action.
func scnGraph(actions ...string) *DiscoveredGraph {
	id := &CloudIdentity{CanonicalID: scnPrincipal, Kind: "iam-user"}
	res := &CloudResource{CanonicalID: scnVault, Kind: "backup-vault"}
	g := &DiscoveredGraph{
		Identities:  []*CloudIdentity{id},
		Resources:   []*CloudResource{res},
		Evaluations: map[string]PathState{},
	}
	for _, a := range actions {
		g.Permissions = append(g.Permissions, &CloudPermission{
			Source: id, Target: res, Action: a, SourceType: "identity-policy",
			Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"` + a + `"}]}`},
		})
	}
	return g
}

func awsBackupScenario(t *testing.T) *CloudScenario {
	t.Helper()
	s := CloudScenarioByID("backup-assurance-aws")
	if s == nil {
		t.Fatal("backup-assurance-aws missing from builtins")
	}
	return s
}

func TestExecuteCloudScenario_MissingIdentityNotAttempted(t *testing.T) {
	g := scnGraph()
	g.Identities = nil
	res := ExecuteCloudScenario(awsBackupScenario(t), g, &AWSEvaluator{}, scnPrincipal, scnVault)
	if res.OverallVerdict != "not-attempted" || len(res.Steps) != 0 {
		t.Errorf("verdict = %s, steps = %d; want not-attempted with no steps", res.OverallVerdict, len(res.Steps))
	}
}

func TestExecuteCloudScenario_MissingVaultNotAttempted(t *testing.T) {
	g := scnGraph()
	g.Resources = nil
	res := ExecuteCloudScenario(awsBackupScenario(t), g, &AWSEvaluator{}, scnPrincipal, scnVault)
	if res.OverallVerdict != "not-attempted" {
		t.Errorf("verdict = %s, want not-attempted when the vault was not discovered", res.OverallVerdict)
	}
}

func TestExecuteCloudScenario_NoPermissionsFullyBlockedAtFirstStep(t *testing.T) {
	res := ExecuteCloudScenario(awsBackupScenario(t), scnGraph(), &AWSEvaluator{}, scnPrincipal, scnVault)
	if res.OverallVerdict != "fully-blocked" {
		t.Errorf("verdict = %s, want fully-blocked", res.OverallVerdict)
	}
	if len(res.Steps) != 1 || res.Steps[0].ExecutionOutcome != "Blocked" {
		t.Errorf("chain should stop at the first blocked step, got %d steps", len(res.Steps))
	}
}

func TestExecuteCloudScenario_PartialWhenEarlyStepsAllowed(t *testing.T) {
	g := scnGraph("backup:ListRecoveryPointsByBackupVault")
	res := ExecuteCloudScenario(awsBackupScenario(t), g, &AWSEvaluator{}, scnPrincipal, scnVault)
	if res.OverallVerdict != "partially-blocked" {
		t.Errorf("verdict = %s, want partially-blocked", res.OverallVerdict)
	}
	if len(res.Steps) != 2 || res.Steps[0].ExecutionOutcome != "Allowed" || res.Steps[1].ExecutionOutcome != "Blocked" {
		t.Errorf("steps = %+v", res.Steps)
	}
}

func TestExecuteCloudScenario_FullyOpenWhenEveryStepAllowed(t *testing.T) {
	s := awsBackupScenario(t)
	var actions []string
	for _, st := range s.Steps {
		actions = append(actions, st.Action)
	}
	res := ExecuteCloudScenario(s, scnGraph(actions...), &AWSEvaluator{}, scnPrincipal, scnVault)
	if res.OverallVerdict != "fully-open" {
		t.Errorf("verdict = %s, want fully-open", res.OverallVerdict)
	}
	if len(res.Steps) != len(s.Steps) {
		t.Errorf("steps = %d, want %d", len(res.Steps), len(s.Steps))
	}
}

func TestExecuteCloudScenario_GateRefusesUnknownEdgeAsInconclusive(t *testing.T) {
	g := scnGraph("backup:ListRecoveryPointsByBackupVault")
	g.Evaluations[scnPrincipal+"->backup:ListRecoveryPointsByBackupVault->"+scnVault] = Unknown
	res := ExecuteCloudScenario(awsBackupScenario(t), g, &AWSEvaluator{}, scnPrincipal, scnVault)
	if res.OverallVerdict != "inconclusive" {
		t.Errorf("verdict = %s, want inconclusive when the gate refuses an Unknown edge", res.OverallVerdict)
	}
	if len(res.Steps) != 1 || res.Steps[0].ExecutionOutcome != "Unknown" {
		t.Errorf("gate outcome should be Unknown and stop the chain, got %+v", res.Steps)
	}
}

func TestExecuteCloudScenario_WildcardResourceEdgeCoversVault(t *testing.T) {
	id := &CloudIdentity{CanonicalID: scnPrincipal, Kind: "iam-user"}
	g := &DiscoveredGraph{
		Identities: []*CloudIdentity{id},
		Resources:  []*CloudResource{{CanonicalID: scnVault, Kind: "backup-vault"}},
		Permissions: []*CloudPermission{{
			Source: id, Target: &CloudResource{CanonicalID: "*", Kind: "aws-resource-wildcard"},
			Action: "backup:ListRecoveryPointsByBackupVault", SourceType: "identity-policy",
			Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"backup:ListRecoveryPointsByBackupVault","Resource":"*"}]}`},
		}},
		Evaluations: map[string]PathState{},
	}
	res := ExecuteCloudScenario(awsBackupScenario(t), g, &AWSEvaluator{}, scnPrincipal, scnVault)
	if len(res.Steps) == 0 || res.Steps[0].ExecutionOutcome != "Allowed" {
		t.Errorf("wildcard-resource grant should cover the vault; steps = %+v", res.Steps)
	}
}

func TestBuiltinCloudScenarios_WellFormed(t *testing.T) {
	seen := map[string]bool{}
	providers := map[string]bool{"aws": true, "azure": true, "gcp": true}
	for _, s := range BuiltinCloudScenarios() {
		if seen[s.ID] {
			t.Errorf("duplicate scenario id %s", s.ID)
		}
		seen[s.ID] = true
		if !providers[s.Provider] {
			t.Errorf("%s: unknown provider %q", s.ID, s.Provider)
		}
		if len(s.Steps) == 0 {
			t.Errorf("%s has no steps", s.ID)
		}
		for _, st := range s.Steps {
			if st.Action == "" || st.TechniqueTag == "" {
				t.Errorf("%s/%s: action and technique are required", s.ID, st.Name)
			}
			if st.Kind != "control-plane" && st.Kind != "data-access" {
				t.Errorf("%s/%s: kind %q", s.ID, st.Name, st.Kind)
			}
		}
	}
}

func TestObserveCloudScenario_EvidenceDecidesOutcome(t *testing.T) {
	g := scnGraph("backup:ListRecoveryPointsByBackupVault", "backup:DeleteRecoveryPoint", "backup:DeleteBackupPlan", "backup:DeleteBackupVault")
	res := ExecuteCloudScenario(awsBackupScenario(t), g, &AWSEvaluator{}, scnPrincipal, scnVault)
	if res.OverallVerdict != "fully-open" {
		t.Fatalf("prediction verdict = %s, want fully-open", res.OverallVerdict)
	}

	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	corr := &SyntheticEventCorrelator{}
	// Evidence exists for the first step only. The rest have none, so they must
	// become Unknown rather than inherit the prediction.
	corr.addSyntheticEvent(&CloudEvent{
		Principal: scnPrincipal, Action: "backup:ListRecoveryPointsByBackupVault", Resource: scnVault,
		Timestamp: at, Result: "Success", Source: "cloudtrail",
	})
	ObserveCloudScenario(res, corr, scnPrincipal, scnVault, at, time.Minute)

	if res.Steps[0].ExecutionOutcome != "Allowed" || res.Steps[0].EventCorrelation != "perfect" {
		t.Errorf("first step should be observed Allowed with perfect correlation, got %+v", res.Steps[0])
	}
	if res.Steps[1].ExecutionOutcome != "Unknown" {
		t.Errorf("unobserved step must be Unknown, got %s", res.Steps[1].ExecutionOutcome)
	}
	if res.OverallVerdict != "inconclusive" {
		t.Errorf("verdict after observation = %s, want inconclusive", res.OverallVerdict)
	}
}

func TestObserveCloudScenario_FailureEvidenceReadsAsBlocked(t *testing.T) {
	g := scnGraph("backup:ListRecoveryPointsByBackupVault")
	res := ExecuteCloudScenario(awsBackupScenario(t), g, &AWSEvaluator{}, scnPrincipal, scnVault)
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	corr := &SyntheticEventCorrelator{}
	corr.addSyntheticEvent(&CloudEvent{
		Principal: scnPrincipal, Action: "backup:ListRecoveryPointsByBackupVault", Resource: scnVault,
		Timestamp: at, Result: "Failure", Source: "cloudtrail",
	})
	ObserveCloudScenario(res, corr, scnPrincipal, scnVault, at, time.Minute)
	if res.Steps[0].ExecutionOutcome != "Blocked" {
		t.Errorf("an AccessDenied event must observe as Blocked, got %s", res.Steps[0].ExecutionOutcome)
	}
}

// End to end: AWS discovery reads the vault from a fake Backup API, the
// identity's policy is read from fake IAM, and the scenario resolves both
// prerequisites from that discovered graph.
func TestAWSDiscoveryFeedsBackupScenario(t *testing.T) {
	policy := policyDoc(t, `{"Effect":"Allow","Action":"backup:ListRecoveryPointsByBackupVault","Resource":"`+scnVault+`"}`)
	snap := &iam.GetAccountAuthorizationDetailsOutput{
		UserDetailList: []types.UserDetail{{
			Arn:      aws.String(scnPrincipal),
			UserName: aws.String("ops"),
			UserPolicyList: []types.PolicyDetail{{
				PolicyName:     aws.String("list-recovery"),
				PolicyDocument: aws.String(policy),
			}},
		}},
	}
	client := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{snap}}).
		WithBackup(&fakeBackup{arns: []string{scnVault}})
	graph, stats, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if stats.BackupVaults != 1 {
		t.Fatalf("BackupVaults = %d, want 1", stats.BackupVaults)
	}
	res := ExecuteCloudScenario(awsBackupScenario(t), graph, &AWSEvaluator{}, scnPrincipal, scnVault)
	if res.OverallVerdict != "partially-blocked" {
		t.Errorf("verdict = %s, want partially-blocked from real discovery output", res.OverallVerdict)
	}
}

type fakeBackup struct{ arns []string }

func (f *fakeBackup) ListBackupVaults(_ context.Context, _ *backup.ListBackupVaultsInput, _ ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	out := &backup.ListBackupVaultsOutput{}
	for _, a := range f.arns {
		out.BackupVaultList = append(out.BackupVaultList, backuptypes.BackupVaultListMember{BackupVaultArn: aws.String(a)})
	}
	return out, nil
}

// A service-wildcard grant covers each step's concrete action; the evaluator
// must check the step's action, not the pattern's.
func TestExecuteCloudScenario_WildcardGrantCoversConcreteSteps(t *testing.T) {
	id := &CloudIdentity{CanonicalID: scnPrincipal, Kind: "iam-user"}
	res := &CloudResource{CanonicalID: scnVault, Kind: "backup-vault"}
	g := &DiscoveredGraph{
		Identities: []*CloudIdentity{id},
		Resources:  []*CloudResource{res},
		Permissions: []*CloudPermission{{
			Source: id, Target: res, Action: "backup:*", SourceType: "identity-policy",
			Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"backup:*","Resource":"*"}]}`},
		}},
		Evaluations: map[string]PathState{},
	}
	res2 := ExecuteCloudScenario(awsBackupScenario(t), g, &AWSEvaluator{}, scnPrincipal, scnVault)
	if res2.OverallVerdict != "fully-open" {
		t.Errorf("verdict = %s, want fully-open under backup:*", res2.OverallVerdict)
	}
}
