package tracker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// MintToken creates and stores a single-use tracking token.
func MintToken(ctx context.Context, store TokenStore, execID, stepExecID, targetID, tokenType string, payload map[string]any) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	return token, store.InsertTrackToken(ctx, token, execID, stepExecID, targetID, tokenType, payload)
}
