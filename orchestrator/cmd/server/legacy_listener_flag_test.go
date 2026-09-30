package main

import (
	"testing"

	"github.com/audspect/bas/config"
)

func TestLegacyListenerShouldStart_DefaultTrue(t *testing.T) {
	cfg := config.Config{LegacyListenerEnabled: true}
	if !legacyListenerShouldStart(cfg) {
		t.Error("expected the legacy listener to start when LegacyListenerEnabled is true")
	}
}

func TestLegacyListenerShouldStart_DisabledFalse(t *testing.T) {
	cfg := config.Config{LegacyListenerEnabled: false}
	if legacyListenerShouldStart(cfg) {
		t.Error("expected the legacy listener NOT to start when LegacyListenerEnabled is false")
	}
}
