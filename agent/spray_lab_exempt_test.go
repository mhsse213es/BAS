package main

import (
	"testing"

	"audspect/agent/protocol"
)

func sprayStep(command string) protocol.ScenarioStep {
	return protocol.ScenarioStep{
		TechniqueID:    "T1110.003",
		ActionKey:      "credential_password_spray",
		ExecutionClass: "destructive",
		Command:        command,
	}
}

// The spray command body (no destructive text) must not trip the local backstop.
const sprayBenignCommand = `$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain', $dom)
$ok = $ctx.ValidateCredentials($sam, $guess)`

func TestSprayLabExempt_LiftsSignedVetoForBenignSprayCommand(t *testing.T) {
	step := sprayStep(sprayBenignCommand)
	if vetoed, src := evaluateB5GateExempt(false, step, "ad-password-spray-lab"); !vetoed || src != "catalog" {
		t.Fatalf("without exemption: want catalog veto, got vetoed=%v src=%q", vetoed, src)
	}
	if vetoed, src := evaluateB5GateExempt(true, step, "ad-password-spray-lab"); vetoed {
		t.Fatalf("with exemption: want no veto, got vetoed src=%q", src)
	}
}

func TestSprayLabExempt_LocalBackstopStillVetoesDestructiveCommand(t *testing.T) {
	step := sprayStep("vssadmin delete shadows /all /quiet")
	if vetoed, _ := evaluateB5GateExempt(true, step, "ad-password-spray-lab"); !vetoed {
		t.Fatal("exemption must not lift the local backstop for a destructive command")
	}
}

func TestSprayLabExempt_Predicate(t *testing.T) {
	on := &protocol.LivePolicy{LabException: true}
	off := &protocol.LivePolicy{LabException: false}
	cases := []struct {
		name   string
		policy *protocol.LivePolicy
		scen   string
		action string
		want   bool
	}{
		{"all three true", on, "ad-password-spray-lab", "credential_password_spray", true},
		{"nil policy", nil, "ad-password-spray-lab", "credential_password_spray", false},
		{"flag off", off, "ad-password-spray-lab", "credential_password_spray", false},
		{"other scenario", on, "some-other-scenario", "credential_password_spray", false},
		{"guessing scenario, guess key", on, "ad-password-guessing-lab", "credential_password_guess", true},
		{"guessing scenario, stuffing key", on, "ad-password-guessing-lab", "credential_stuffing", true},
		{"spray key on guessing scenario", on, "ad-password-guessing-lab", "credential_password_spray", false},
		{"guess key on spray scenario", on, "ad-password-spray-lab", "credential_password_guess", false},
		{"other action key", on, "ad-password-spray-lab", "enumerate", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sprayLabExempt(c.policy, c.scen, c.action); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
}
