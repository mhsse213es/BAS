package lab

import (
	"net/http"
	"strings"
)

// Identity basis values recorded on access events as identity_basis. A basis says how the recorded identity was
// established. It is empty when the request established no identity.
const (
	BasisSignedToken         = "signed_token"          // the identity a signed lab token proves
	BasisChainVerifiedCert   = "chain_verified_cert"   // the common name of a certificate that chains to the lab CA
	BasisUnsignedTokenClaim  = "unsigned_token_claim"  // the subject of an unsigned token (vulnerable build): a claim, not proof
	BasisHeaderClaim         = "header_claim"          // the X-Customer-Id header (vulnerable build): a claim, not proof
	BasisUnverifiedCertClaim = "unverified_cert_claim" // the common name of a certificate that does not chain: a claim, not proof
)

// authContext is what a request establishes about its caller. Identity is the value the access event records. It is the
// same value the access log has always recorded, so existing rules see no change. Basis says how Identity was established.
// Claimed is set only when the basis is a claim: a value the request asserted and no credential proved.
type authContext struct {
	Identity string
	Basis    string
	Claimed  string
}

// resolveAuth returns what the request establishes about its caller. It is the single source for the access event's
// identity, basis and claim. Access decisions do not use it: handlers still call identify, and the proof lookup is
// verifiedIdentity. The order of cases mirrors identify, so Identity cannot differ from the identity that served the request.
func (s *Server) resolveAuth(r *http.Request) authContext {
	caller, st := s.identify(r)
	switch st {
	case authOK:
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.cfg.Mode == ModeVulnerable {
			if sub, ok := unsignedSubject(tok); ok {
				return authContext{Identity: caller, Basis: BasisUnsignedTokenClaim, Claimed: sub}
			}
			if claimed := r.Header.Get("X-Customer-Id"); claimed != "" {
				return authContext{Identity: caller, Basis: BasisHeaderClaim, Claimed: claimed}
			}
		}
		return authContext{Identity: caller, Basis: BasisSignedToken}
	case authMissing:
		cn, ok := s.certClaim(r)
		if !ok {
			return authContext{Identity: "anonymous"}
		}
		if _, verified := s.certIdentity(r); verified {
			return authContext{Identity: cn, Basis: BasisChainVerifiedCert}
		}
		return authContext{Identity: cn, Basis: BasisUnverifiedCertClaim, Claimed: cn}
	default:
		// A revoked or invalid credential establishes no identity. The access log has always recorded "unknown" here.
		return authContext{Identity: "unknown"}
	}
}
