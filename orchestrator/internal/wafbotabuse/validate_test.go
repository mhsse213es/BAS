package wafbotabuse

import "testing"

func mustVector(t *testing.T, id string) BotAbuseVector {
	t.Helper()
	benign := validBenign()
	v, err := NewBotAbuseVector(id, 1, CategoryBoundedAutomation, "x", SeverityHigh, "x", validMalicious(), &benign, "", validStandards(), "x")
	if err != nil {
		t.Fatalf("NewBotAbuseVector(%q): %v", id, err)
	}
	return v
}

func TestValidateBotAbuseCatalog_UniqueIDs_Succeeds(t *testing.T) {
	err := ValidateBotAbuseCatalog([]BotAbuseVector{mustVector(t, "BOTABUSE-001"), mustVector(t, "BOTABUSE-002")})
	if err != nil {
		t.Fatalf("ValidateBotAbuseCatalog: %v", err)
	}
}

func TestValidateBotAbuseCatalog_DuplicateID_Rejected(t *testing.T) {
	err := ValidateBotAbuseCatalog([]BotAbuseVector{mustVector(t, "BOTABUSE-001"), mustVector(t, "BOTABUSE-001")})
	if err == nil {
		t.Fatal("want error for duplicate ID, got nil")
	}
}

func TestValidateBotAbuseCatalog_Empty_Succeeds(t *testing.T) {
	if err := ValidateBotAbuseCatalog(nil); err != nil {
		t.Fatalf("ValidateBotAbuseCatalog(nil): %v", err)
	}
}
