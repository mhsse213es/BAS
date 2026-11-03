//go:build windows

package main

import (
	"errors"
	"strings"
	"testing"
)

type fakeSettingsMutateClient struct {
	testServerCalled bool
	setServerCalled  bool
	testOutcome      TestOutcome
	testDetail       string
	setOK            bool
	setDetail        string
}

func (f *fakeSettingsMutateClient) TestServer(host string) (TestOutcome, string, error) {
	f.testServerCalled = true
	return f.testOutcome, f.testDetail, nil
}

func (f *fakeSettingsMutateClient) SetServer(host string) (bool, string, error) {
	f.setServerCalled = true
	return f.setOK, f.setDetail, nil
}

func TestSettingsController_Test_InvalidHost_ShowsInvalidHostImmediately(t *testing.T) {
	fake := &fakeSettingsMutateClient{testOutcome: TestOutcomeConnected, testDetail: "should not reach here"}
	c := NewSettingsController(fake)

	outcome, _ := c.Test("https://host:9443/foo?x=1")
	if outcome != TestOutcomeInvalidHost {
		t.Fatalf("outcome = %q, want %q", outcome, TestOutcomeInvalidHost)
	}
	if fake.testServerCalled {
		t.Fatal("TestServer must not be called for an invalid host")
	}
}

func TestSettingsController_Save_WarnsBeforeCommitting(t *testing.T) {
	fake := &fakeSettingsMutateClient{setOK: true, setDetail: "Saved and reconnected"}
	c := NewSettingsController(fake)

	needsConfirm, warning := c.RequestSave("https://10.0.0.5:9443")
	if !needsConfirm {
		t.Fatal("expected RequestSave to require confirmation before committing")
	}
	if warning == "" {
		t.Fatal("expected a non-empty warning explaining the restart")
	}
	if fake.setServerCalled {
		t.Fatal("SetServer must not be called by RequestSave alone")
	}

	ok, _ := c.ConfirmSave("https://10.0.0.5:9443")
	if !ok {
		t.Fatal("expected ConfirmSave to succeed with the fake's setOK=true")
	}
	if !fake.setServerCalled {
		t.Fatal("expected ConfirmSave to call SetServer")
	}
}

// TestSettingsController_ConfirmSave_HostChangedSinceRequest_DoesNotCommitStaleValue
// pins Important finding #5/#10 from the review: if the user edits the
// host field after clicking Save (which only warns, per RequestSave) but
// before clicking it again to confirm, ConfirmSave must never commit the
// host that was displayed at RequestSave time -- it must re-check against
// what the caller says is on screen right now.
func TestSettingsController_ConfirmSave_HostChangedSinceRequest_DoesNotCommitStaleValue(t *testing.T) {
	fake := &fakeSettingsMutateClient{setOK: true, setDetail: "Saved and reconnected"}
	c := NewSettingsController(fake)

	c.RequestSave("https://10.0.0.5:9443")

	ok, detail := c.ConfirmSave("https://10.0.0.6:9443") // user edited the field after RequestSave
	if ok {
		t.Fatal("expected ConfirmSave to refuse committing when the field changed since RequestSave")
	}
	if fake.setServerCalled {
		t.Fatal("SetServer must not be called when the displayed host no longer matches what was confirmed")
	}
	if detail == "" {
		t.Fatal("expected a non-empty detail explaining why nothing was saved")
	}
}

// A local problem (the agent service not answering on its pipe) must not be presented as the server being unreachable.
type failingClient struct{ fakeSettingsMutateClient }

func (f *failingClient) TestServer(host string) (TestOutcome, string, error) {
	return "", "", errors.New("connect to agent: context deadline exceeded")
}

func TestSettingsTest_ALocalAgentFailureIsNotBlamedOnTheServer(t *testing.T) {
	c := NewSettingsController(&failingClient{})
	_, detail := c.Test("https://192.168.10.78:9443")
	if !strings.Contains(detail, "service on this computer") {
		t.Errorf("detail = %q, want it to say the agent service on this computer did not answer", detail)
	}
	if strings.Contains(detail, "server could not be reached") {
		t.Errorf("detail = %q must not claim the server was unreachable", detail)
	}
}

// The Save warning must describe what Save really does. It used to say "will restart the agent service"; Save
// hot-swaps the live configuration and reconnects, and restores the previous host if the new one cannot be reached.
func TestSettingsController_SaveWarning_DescribesWhatSaveActuallyDoes(t *testing.T) {
	c := NewSettingsController(&fakeSettingsMutateClient{})
	_, warning := c.RequestSave("https://10.0.0.5:9443")
	lower := strings.ToLower(warning)
	if strings.Contains(lower, "restart the agent service") {
		t.Errorf("the warning claims a service restart that does not happen: %q", warning)
	}
	for _, want := range []string{"reconnect", "previous"} {
		if !strings.Contains(lower, want) {
			t.Errorf("warning %q does not mention %q", warning, want)
		}
	}
}

// One Save click shows the warning; the next click with the same text commits. Editing the text in between starts
// over with a fresh warning for the NEW host, so the confirmation is never carried to a host the user did not confirm.
func TestSettingsController_NeedsConfirmation_FollowsTheTextOnScreen(t *testing.T) {
	c := NewSettingsController(&fakeSettingsMutateClient{setOK: true})

	if need, warning := c.NeedsConfirmation("https://a:9443"); !need || warning == "" {
		t.Fatal("first click must warn and wait")
	}
	if need, _ := c.NeedsConfirmation("https://a:9443"); need {
		t.Fatal("second click on the same text must go ahead")
	}
	// the user confirms and the save runs: the confirmation is spent
	c.ConfirmSave("https://a:9443")
	if need, _ := c.NeedsConfirmation("https://a:9443"); !need {
		t.Fatal("after a save the next click must warn again")
	}

	// edit after the warning: the old confirmation does not apply to the new text
	c.NeedsConfirmation("https://b:9443")
	if need, warning := c.NeedsConfirmation("https://c:9443"); !need || warning == "" {
		t.Fatal("editing the host after the warning must produce a fresh warning, not a save")
	}
	if need, _ := c.NeedsConfirmation("https://c:9443"); need {
		t.Fatal("confirming the edited text must then go ahead")
	}
}

func TestSettingsController_NeedsConfirmation_NeverConfirmsAnEmptyHost(t *testing.T) {
	c := NewSettingsController(&fakeSettingsMutateClient{})
	if need, _ := c.NeedsConfirmation(""); !need {
		t.Fatal("an empty host must not be treated as already confirmed")
	}
	if need, _ := c.NeedsConfirmation(""); !need {
		t.Fatal("an empty host must keep asking")
	}
}
