package phishbridge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/phishval"
)

func TestPHCHN_SMS_EndToEnd_KnownGood_RealInjectorDelivers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	inj := exercise.NewSMSInjector(exercise.SMSGatewayConfig{URL: srv.URL, From: "BAS"})
	res, err := inj.Send(context.Background(), []string{"+15550001"}, "smishing-sim")

	obs := FromChannelInjectorResult("sms", res, err, time.Now())
	outcome := phishval.Evaluate("run-ph-chn-sms", "known-good", phishval.Expectation{
		ScenarioID: "PH-CHN-SMS-TEST", Delivery: deliveryPtr(phishval.DeliveryDelivered),
	}, obs)
	if outcome.Delivery.Verdict != phishval.VerdictPass {
		t.Errorf("Delivery.Verdict = %q (%s), want %q", outcome.Delivery.Verdict, outcome.Delivery.Reason, phishval.VerdictPass)
	}
}

func TestPHCHN_Teams_EndToEnd_KnownBad_UnconfiguredWebhookRejected(t *testing.T) {
	inj := exercise.NewTeamsInjector("") // unconfigured -- real injector returns an error
	res, err := inj.Send(context.Background(), "phishing-sim-message")

	obs := FromChannelInjectorResult("teams", res, err, time.Now())
	outcome := phishval.Evaluate("run-ph-chn-teams", "known-bad", phishval.Expectation{
		ScenarioID: "PH-CHN-TEAMS-TEST", Delivery: deliveryPtr(phishval.DeliveryDelivered),
	}, obs)
	if outcome.Delivery.Verdict != phishval.VerdictFail {
		t.Errorf("Delivery.Verdict = %q, want %q", outcome.Delivery.Verdict, phishval.VerdictFail)
	}
}

func deliveryPtr(v phishval.DeliveryOutcome) *phishval.DeliveryOutcome { return &v }
