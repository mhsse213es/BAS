//go:build !aleefsealed

package main

import "testing"

func TestVulnerableEvaluationRefusedInDefaultBuild(t *testing.T) {
	if _, err := vulnerablePolicy(synth); err == nil {
		t.Fatal("a build without the aleefsealed tag must refuse the vulnerable evaluation")
	}
}
