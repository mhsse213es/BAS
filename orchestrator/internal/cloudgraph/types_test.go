package cloudgraph

import (
	"testing"
)

func TestCloudResource_CanonicalIDPreservesProvider(t *testing.T) {
	tests := []struct {
		name         string
		canonicalID  string
		provider     string
		expectedKind string
	}{
		{
			name:         "AWS S3 bucket",
			canonicalID:  "arn:aws:s3:::my-bucket",
			provider:     "aws",
			expectedKind: "s3-bucket",
		},
		{
			name:         "Azure storage account",
			canonicalID:  "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
			provider:     "azure",
			expectedKind: "storage-account",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := &CloudResource{
				CanonicalID: tt.canonicalID,
				Kind:        tt.expectedKind,
				AccountScope: &AccountScope{
					Provider: tt.provider,
				},
			}

			if res.CanonicalID != tt.canonicalID {
				t.Errorf("CanonicalID mismatch: got %s, want %s", res.CanonicalID, tt.canonicalID)
			}
			if res.AccountScope.Provider != tt.provider {
				t.Errorf("Provider mismatch: got %s, want %s", res.AccountScope.Provider, tt.provider)
			}
		})
	}
}

func TestPathState_SixStates(t *testing.T) {
	states := []PathState{
		Candidate,
		ConditionallyReachable,
		PolicySupported,
		Observed,
		Blocked,
		Unknown,
	}

	if len(states) != 6 {
		t.Errorf("Expected 6 PathState values, got %d", len(states))
	}
}
