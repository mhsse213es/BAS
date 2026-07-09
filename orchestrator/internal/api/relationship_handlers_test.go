package api

import (
	"testing"

	"github.com/audspect/bas/internal/relationships"
)

func TestValidRelationshipType(t *testing.T) {
	for _, v := range []string{
		relationships.TypeDirectExploitation, relationships.TypeObservedInTheWild,
		relationships.TypeCommonlyAssociated, relationships.TypePostExploitation,
		relationships.TypePrivilegeEscalation, relationships.TypePersistence,
	} {
		if !validRelationshipType(v) {
			t.Errorf("validRelationshipType(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "Made Up Type", "direct exploitation"} {
		if validRelationshipType(v) {
			t.Errorf("validRelationshipType(%q) = true, want false", v)
		}
	}
}

func TestValidConfidence(t *testing.T) {
	for _, v := range []string{relationships.ConfidenceHigh, relationships.ConfidenceMedium, relationships.ConfidenceLow} {
		if !validConfidence(v) {
			t.Errorf("validConfidence(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "Critical", "high"} {
		if validConfidence(v) {
			t.Errorf("validConfidence(%q) = true, want false", v)
		}
	}
}

func TestValidStatus(t *testing.T) {
	for _, v := range []string{relationships.StatusActive, relationships.StatusDeprecated,
		relationships.StatusDisputed, relationships.StatusRetired} {
		if !validStatus(v) {
			t.Errorf("validStatus(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "active", "Gone"} {
		if validStatus(v) {
			t.Errorf("validStatus(%q) = true, want false", v)
		}
	}
}
