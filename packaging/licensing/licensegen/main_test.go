package main

import (
	"reflect"
	"testing"
)

func TestBuildFeatures(t *testing.T) {
	got, err := buildFeatures("full", "")
	if err != nil || !reflect.DeepEqual(got, []string{"full"}) {
		t.Fatalf("no add-ons: %v %v", got, err)
	}
	got, err = buildFeatures("full", "aleef,aleef")
	if err != nil || !reflect.DeepEqual(got, []string{"full", "addon:aleef"}) {
		t.Fatalf("aleef: %v %v", got, err)
	}
	for _, bad := range []string{"Aleef", "aleef2", "other", " aleef", "addon:aleef"} {
		if _, err := buildFeatures("full", bad); err == nil {
			t.Fatalf("add-on %q accepted", bad)
		}
	}
}
