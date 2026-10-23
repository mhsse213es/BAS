package k8sscenario

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const synthProbeToken = "probe-token-for-synthetic-read"

// newOpenServer is newAPIServer without the engine-token check: the requests here carry the probe's token, and the
// handler decides what that token may do.
func newOpenServer(t *testing.T, rec *recorder, handle func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		handle(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestReadSecretAs_AllowedReturnsValueAndUsesTheProbeToken checks a 200 returns the value, and that the request carries the
// probe's token, not the engine's credential.
func TestReadSecretAs_AllowedReturnsValueAndUsesTheProbeToken(t *testing.T) {
	rec := &recorder{}
	srv := newOpenServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+synthProbeToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"value":"` + base64.StdEncoding.EncodeToString([]byte("v1")) + `"}}`))
	})
	c := newTestAPIClient(t, srv)
	v, allowed, err := c.ReadSecretAs(context.Background(), []byte(synthProbeToken), "bas-sandbox", synthSecret)
	if err != nil || !allowed || v != "v1" {
		t.Fatalf("read = (%q, %v, %v), want (v1, true, nil)", v, allowed, err)
	}
}

// TestReadSecretAs_ForbiddenIsDeniedNotAnError checks a 403 is a denial, a finding, not a failure.
func TestReadSecretAs_ForbiddenIsDeniedNotAnError(t *testing.T) {
	rec := &recorder{}
	srv := newOpenServer(t, rec, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	c := newTestAPIClient(t, srv)
	_, allowed, err := c.ReadSecretAs(context.Background(), []byte(synthProbeToken), "bas-sandbox", synthSecret)
	if err != nil || allowed {
		t.Fatalf("403 must be a denial with no error: allowed=%v err=%v", allowed, err)
	}
}

// TestReadSecretAs_OtherStatusIsInconclusiveAndNeverCarriesTheValue checks any other status is an error, and the error
// text does not echo the response body, which can contain the value.
func TestReadSecretAs_OtherStatusIsInconclusiveAndNeverCarriesTheValue(t *testing.T) {
	const leaked = "VALUE-IN-BODY"
	rec := &recorder{}
	srv := newOpenServer(t, rec, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"data":{"value":"` + leaked + `"}}`))
	})
	c := newTestAPIClient(t, srv)
	_, allowed, err := c.ReadSecretAs(context.Background(), []byte(synthProbeToken), "bas-sandbox", synthSecret)
	if err == nil || allowed {
		t.Fatalf("a 500 must be inconclusive: allowed=%v err=%v", allowed, err)
	}
	if strings.Contains(err.Error(), leaked) {
		t.Fatal("the error text carried the response body")
	}
}

// TestSyntheticClient_RefusesAnyOtherObjectWithoutSendingAnything checks the named guards: no request is made for any
// name other than the fixture, and no subject outside the binding's namespace is accepted.
func TestSyntheticClient_RefusesAnyOtherObjectWithoutSendingAnything(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	c := newTestAPIClient(t, srv)
	ctx := context.Background()
	if _, _, err := c.ReadSecretAs(ctx, []byte(synthProbeToken), "bas-sandbox", "db-password"); err == nil {
		t.Fatal("reading another secret must be refused")
	}
	if _, _, err := c.GetBinding(ctx, "bas-sandbox", "cluster-admin-binding"); err == nil {
		t.Fatal("reading another binding must be refused")
	}
	if err := c.SetBindingSubjects(ctx, "bas-sandbox", "cluster-admin-binding", nil); err == nil {
		t.Fatal("changing another binding must be refused")
	}
	if err := c.SetSecretValue(ctx, "bas-sandbox", "db-password", "x"); err == nil {
		t.Fatal("changing another secret must be refused")
	}
	if err := c.SetBindingSubjects(ctx, "bas-sandbox", synthBinding, []string{"ServiceAccount/kube-system/admin"}); err == nil {
		t.Fatal("a subject outside the binding's namespace must be refused")
	}
	if err := c.SetBindingSubjects(ctx, "bas-sandbox", synthBinding, []string{"User/bas-sandbox/alice"}); err == nil {
		t.Fatal("a non-ServiceAccount subject must be refused")
	}
	if rec.count() != 0 {
		t.Fatalf("refused operations sent %d requests", rec.count())
	}
}

// TestSyntheticSecretLabels_AsksForMetadataOnly checks the label read asks the API for metadata, so the secret's data
// is not returned.
func TestSyntheticSecretLabels_AsksForMetadataOnly(t *testing.T) {
	var accept string
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		_, _ = w.Write([]byte(`{"metadata":{"labels":{"` + SynthLabel + `":"true"}}}`))
	})
	c := newTestAPIClient(t, srv)
	labels, ok, err := c.SyntheticSecretLabels(context.Background(), "bas-sandbox", synthSecret)
	if err != nil || !ok || labels[SynthLabel] != "true" {
		t.Fatalf("labels = %v ok=%v err=%v", labels, ok, err)
	}
	if !strings.Contains(accept, "as=PartialObjectMetadata") {
		t.Fatalf("Accept = %q, want the metadata-only representation", accept)
	}
}
