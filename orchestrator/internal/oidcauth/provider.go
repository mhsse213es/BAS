// Package oidcauth wraps OIDC discovery and the Authorization Code + PKCE
// flow for Phase 7's SSO slice. One Provider is built per login attempt
// (or per admin "test config" call) from a tenant's sso_configs row — see
// docs/superpowers/specs/2026-07-19-phase7-sso-oidc-design.md.
package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider wraps OIDC discovery and the OAuth2 config for one tenant's IdP.
type Provider struct {
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// NewProvider performs OIDC discovery against issuerURL and builds a
// Provider configured for the Authorization Code flow with the given client
// credentials and redirect URL.
func NewProvider(ctx context.Context, issuerURL, clientID, clientSecret, redirectURL string) (*Provider, error) {
	p, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	return &Provider{
		oauth2Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier: p.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

// GeneratePKCE returns a fresh code_verifier and its derived S256
// code_challenge for one login attempt.
func GeneratePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// AuthCodeURL builds the redirect URL to the IdP's authorization endpoint.
func (p *Provider) AuthCodeURL(state, codeChallenge string) string {
	return p.oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange completes the Authorization Code flow: exchanges code (with the
// PKCE verifier) for tokens, verifies the ID token, and returns its email
// claim.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier string) (email string, err error) {
	tok, err := p.oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("no id_token in token response")
	}
	idTok, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("id_token verification: %w", err)
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := idTok.Claims(&claims); err != nil {
		return "", fmt.Errorf("decode id_token claims: %w", err)
	}
	if claims.Email == "" {
		return "", fmt.Errorf("id_token has no email claim")
	}
	return claims.Email, nil
}
