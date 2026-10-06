package tracker

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeTokenStore is an in-memory TokenStore for pure tracker tests.
type fakeTokenStore struct {
	inserted []insertedToken
	failOn   bool
}

type insertedToken struct {
	token, execID, stepExecID, targetID, tokenType string
	payload                                        map[string]any
}

func (f *fakeTokenStore) InsertTrackToken(_ context.Context, token, execID, stepExecID, targetID, tokenType string, payload map[string]any) error {
	if f.failOn {
		return errors.New("insert failed")
	}
	f.inserted = append(f.inserted, insertedToken{token, execID, stepExecID, targetID, tokenType, payload})
	return nil
}
func (f *fakeTokenStore) GetTrackToken(context.Context, string) (*TrackToken, error) { return nil, nil }
func (f *fakeTokenStore) RecordTokenUse(context.Context, string) error               { return nil }

func TestMintToken_ShapeAndStore(t *testing.T) {
	fs := &fakeTokenStore{}
	tok, err := MintToken(context.Background(), fs, "e1", "se1", "t1", "click", map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	if len(tok) != 32 {
		t.Fatalf("token length = %d, want 32 hex", len(tok))
	}
	if len(fs.inserted) != 1 {
		t.Fatalf("expected 1 stored token, got %d", len(fs.inserted))
	}
	got := fs.inserted[0]
	if got.token != tok || got.execID != "e1" || got.tokenType != "click" {
		t.Fatalf("stored token mismatch: %+v", got)
	}
}

func TestMintToken_StoreErrorPropagates(t *testing.T) {
	fs := &fakeTokenStore{failOn: true}
	if _, err := MintToken(context.Background(), fs, "e", "s", "t", "open", nil); err == nil {
		t.Fatal("expected store error to propagate")
	}
}

func TestGenerateLinks_EmptyBaseURLUnchanged(t *testing.T) {
	fs := &fakeTokenStore{}
	body := `<a href="https://evil.test">click</a>`
	out, err := GenerateLinks(context.Background(), fs, "e", "s", body, LinkConfig{TrackClicks: true})
	if err != nil {
		t.Fatalf("GenerateLinks: %v", err)
	}
	if out != body {
		t.Fatalf("empty BaseURL must return body unchanged, got %q", out)
	}
}

func TestGenerateLinks_RewritesAbsoluteHrefsOnly(t *testing.T) {
	fs := &fakeTokenStore{}
	body := `<a href="https://evil.test/page">x</a> <a href="/relative">y</a> <a href="mailto:a@b.c">z</a>`
	out, err := GenerateLinks(context.Background(), fs, "e", "s", body, LinkConfig{
		TrackClicks: true, BaseURL: "https://bas.internal/",
	})
	if err != nil {
		t.Fatalf("GenerateLinks: %v", err)
	}
	if !strings.Contains(out, "https://bas.internal/x/click/") {
		t.Fatalf("absolute href not rewritten to redirect: %q", out)
	}
	if !strings.Contains(out, `href="/relative"`) {
		t.Fatalf("relative href must be left alone: %q", out)
	}
	if !strings.Contains(out, `href="mailto:a@b.c"`) {
		t.Fatalf("mailto href must be left alone: %q", out)
	}
	// Trailing slash on BaseURL is trimmed (no double slash before /x/click).
	if strings.Contains(out, "internal//x/click") {
		t.Fatalf("BaseURL trailing slash not trimmed: %q", out)
	}
}

func TestGenerateLinks_InjectsPixelBeforeBody(t *testing.T) {
	fs := &fakeTokenStore{}
	withBody := `<html><body>hi</body></html>`
	out, err := GenerateLinks(context.Background(), fs, "e", "s", withBody, LinkConfig{
		TrackOpens: true, BaseURL: "https://bas.internal",
	})
	if err != nil {
		t.Fatalf("GenerateLinks: %v", err)
	}
	if !strings.Contains(out, "/x/open/") || !strings.Contains(out, `width="1"`) {
		t.Fatalf("open pixel not injected: %q", out)
	}
	if strings.Index(out, "/x/open/") > strings.Index(out, "</body>") {
		t.Fatalf("pixel must appear before </body>: %q", out)
	}
	// No </body> → pixel appended at end.
	noBody := `plain text`
	out2, _ := GenerateLinks(context.Background(), fs, "e", "s", noBody, LinkConfig{TrackOpens: true, BaseURL: "https://bas.internal"})
	if !strings.HasPrefix(out2, "plain text") || !strings.Contains(out2, "/x/open/") {
		t.Fatalf("pixel not appended when no </body>: %q", out2)
	}
}
