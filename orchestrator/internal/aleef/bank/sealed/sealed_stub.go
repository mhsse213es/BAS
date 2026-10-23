//go:build !aleefsealed

// Package sealed resolves policy variants by id. This stub is compiled when
// the aleefsealed build tag is absent and knows no ids.
package sealed

import "github.com/audspect/bas/internal/aleef/bank"

// Policy returns the policy registered under id. The stub registers none and
// returns the fixed policy with ok=false.
func Policy(id string) (bank.Policy, bool) {
	return bank.FixedPolicy(), false
}
