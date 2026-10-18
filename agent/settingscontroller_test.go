//go:build windows

package main

import "testing"

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

	ok, _ := c.ConfirmSave()
	if !ok {
		t.Fatal("expected ConfirmSave to succeed with the fake's setOK=true")
	}
	if !fake.setServerCalled {
		t.Fatal("expected ConfirmSave to call SetServer")
	}
}
