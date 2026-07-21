package ioc

import (
	"context"
	"fmt"
)

// Lookup dispatches to the right Provider method for indicatorType, sharing
// one switch between the HTTP lookup endpoint (LookupIOC) and the background
// enrichment pipeline (enrichRunIOCs).
func Lookup(ctx context.Context, p Provider, indicatorType, value string) (*Result, error) {
	switch indicatorType {
	case "ip":
		return p.LookupIP(ctx, value)
	case "domain":
		return p.LookupDomain(ctx, value)
	case "url":
		return p.LookupURL(ctx, value)
	case "hash":
		return p.LookupHash(ctx, value)
	case "cve":
		return p.LookupCVE(ctx, value)
	default:
		return nil, fmt.Errorf("ioc: unsupported indicator type %q", indicatorType)
	}
}
