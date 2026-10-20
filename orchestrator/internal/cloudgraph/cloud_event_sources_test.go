package cloudgraph

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"google.golang.org/api/option"
)

var evtTime = time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// CloudTrail
// ---------------------------------------------------------------------------

const ctAssumeRecord = `{
  "eventTime": "2026-10-20T10:00:05Z",
  "eventSource": "sts.amazonaws.com",
  "eventName": "AssumeRole",
  "sourceIPAddress": "203.0.113.9",
  "userAgent": "aws-cli/2.15",
  "userIdentity": {
    "arn": "arn:aws:iam::111122223333:user/alice",
    "sessionContext": {"attributes": {"mfaAuthenticated": "true"}}
  },
  "resources": [{"ARN": "arn:aws:iam::111122223333:role/backup-operator"}]
}`

func TestParseCloudTrailEvent_NormalizesRecord(t *testing.T) {
	events := parseCloudTrailEvent(cttypes.Event{
		EventId:         aws.String("evt-1"),
		CloudTrailEvent: aws.String(ctAssumeRecord),
	})
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	e := events[0]
	if e.Principal != "arn:aws:iam::111122223333:user/alice" || e.Action != "sts:AssumeRole" {
		t.Errorf("principal/action = %s / %s", e.Principal, e.Action)
	}
	if e.Resource != "arn:aws:iam::111122223333:role/backup-operator" {
		t.Errorf("resource = %s", e.Resource)
	}
	if e.Result != "Success" || e.Source != "cloudtrail" || e.SourceIP != "203.0.113.9" {
		t.Errorf("result/source/ip = %s / %s / %s", e.Result, e.Source, e.SourceIP)
	}
	if !e.Timestamp.Equal(time.Date(2026, 10, 20, 10, 0, 5, 0, time.UTC)) {
		t.Errorf("timestamp = %v", e.Timestamp)
	}
}

func TestParseCloudTrailEvent_ErrorCodeIsFailure(t *testing.T) {
	rec := strings.Replace(ctAssumeRecord, `"sourceIPAddress"`, `"errorCode": "AccessDenied", "sourceIPAddress"`, 1)
	events := parseCloudTrailEvent(cttypes.Event{CloudTrailEvent: aws.String(rec)})
	if events[0].Result != "Failure" {
		t.Errorf("result = %s, want Failure", events[0].Result)
	}
}

func TestParseCloudTrailEvent_OneEventPerResource(t *testing.T) {
	rec := strings.Replace(ctAssumeRecord,
		`"resources": [{"ARN": "arn:aws:iam::111122223333:role/backup-operator"}]`,
		`"resources": [{"ARN": "arn:aws:iam::111122223333:role/a"},{"ARN": "arn:aws:iam::111122223333:role/b"}]`, 1)
	events := parseCloudTrailEvent(cttypes.Event{CloudTrailEvent: aws.String(rec)})
	if len(events) != 2 {
		t.Fatalf("events = %d, want one per resource", len(events))
	}
}

func TestParseCloudTrailEvent_FallsBackToSummaryFields(t *testing.T) {
	events := parseCloudTrailEvent(cttypes.Event{
		EventName:   aws.String("GetObject"),
		EventSource: aws.String("s3.amazonaws.com"),
		Username:    aws.String("arn:aws:iam::111122223333:user/bob"),
		EventTime:   aws.Time(evtTime),
	})
	if events[0].Action != "s3:GetObject" || events[0].Principal != "arn:aws:iam::111122223333:user/bob" {
		t.Errorf("fallback = %s / %s", events[0].Action, events[0].Principal)
	}
}

func TestCloudTrailEventName(t *testing.T) {
	cases := map[string]string{
		"sts:AssumeRole": "AssumeRole",
		"s3:*":           "",
		"":               "",
		"noprefix":       "",
	}
	for in, want := range cases {
		if got := cloudTrailEventName(in); got != want {
			t.Errorf("cloudTrailEventName(%q) = %q, want %q", in, got, want)
		}
	}
}

type fakeCloudTrail struct {
	pages     []*cloudtrail.LookupEventsOutput
	err       error
	gotFilter atomic.Value
	calls     int
}

func (f *fakeCloudTrail) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if len(in.LookupAttributes) > 0 {
		f.gotFilter.Store(aws.ToString(in.LookupAttributes[0].AttributeValue))
	}
	idx := f.calls
	f.calls++
	return f.pages[idx], nil
}

func TestCloudTrailSource_FollowsNextTokenAndFiltersByEventName(t *testing.T) {
	page1 := &cloudtrail.LookupEventsOutput{
		Events:    []cttypes.Event{{CloudTrailEvent: aws.String(ctAssumeRecord)}},
		NextToken: aws.String("next"),
	}
	page2 := &cloudtrail.LookupEventsOutput{
		Events: []cttypes.Event{{CloudTrailEvent: aws.String(ctAssumeRecord)}},
	}
	fake := &fakeCloudTrail{pages: []*cloudtrail.LookupEventsOutput{page1, page2}}
	src := &CloudTrailSource{API: fake}

	events, truncated, err := src.Fetch(context.Background(), EventQuery{
		Action: "sts:AssumeRole", Start: evtTime.Add(-time.Minute), End: evtTime.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if truncated {
		t.Error("exhausted log must not be reported truncated")
	}
	if len(events) != 2 {
		t.Errorf("events = %d, want 2 across both pages", len(events))
	}
	if fake.gotFilter.Load() != "AssumeRole" {
		t.Errorf("EventName filter = %v, want AssumeRole", fake.gotFilter.Load())
	}
}

func TestCloudTrailSource_APIErrorSurfaces(t *testing.T) {
	src := &CloudTrailSource{API: &fakeCloudTrail{err: errors.New("AccessDeniedException")}}
	if _, _, err := src.Fetch(context.Background(), EventQuery{}); err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// LiveCorrelator
// ---------------------------------------------------------------------------

type fakeSource struct {
	name      string
	events    []*CloudEvent
	truncated bool
	err       error
}

func (f fakeSource) Name() string { return f.name }
func (f fakeSource) Fetch(context.Context, EventQuery) ([]*CloudEvent, bool, error) {
	return f.events, f.truncated, f.err
}

func TestLiveCorrelator_PerfectMatchScoresHigh(t *testing.T) {
	src := fakeSource{name: "cloudtrail", events: []*CloudEvent{{
		Principal: "p1", Action: "sts:AssumeRole", Resource: "r1", Timestamp: evtTime,
	}}}
	c := &LiveCorrelator{Source: src}
	res := c.FindEvents("p1", "sts:AssumeRole", "r1", evtTime, time.Minute)
	if res.SearchStatus != "success" || res.MatchQuality != "perfect" || res.Confidence != "high" {
		t.Errorf("result = %s / %s / %s", res.SearchStatus, res.MatchQuality, res.Confidence)
	}
	if res.EventsSearched != 1 {
		t.Errorf("EventsSearched = %d", res.EventsSearched)
	}
}

func TestLiveCorrelator_FetchErrorIsUnavailableNotZero(t *testing.T) {
	c := &LiveCorrelator{Source: fakeSource{name: "activity-log", err: errors.New("status 403")}}
	res := c.FindEvents("p1", "a", "r", evtTime, time.Minute)
	if res.SearchStatus != "unavailable" {
		t.Fatalf("status = %s, want unavailable", res.SearchStatus)
	}
	if len(res.MissingTelemetry) != 1 || res.MissingTelemetry[0] != "activity-log" {
		t.Errorf("missing telemetry = %v", res.MissingTelemetry)
	}
}

func TestLiveCorrelator_TruncatedSearchIsPartial(t *testing.T) {
	src := fakeSource{name: "gcp-audit-log", truncated: true, events: []*CloudEvent{{
		Principal: "p1", Action: "a", Resource: "r", Timestamp: evtTime,
	}}}
	res := (&LiveCorrelator{Source: src}).FindEvents("p1", "a", "r", evtTime, time.Minute)
	if res.SearchStatus != "partial" {
		t.Errorf("status = %s, want partial", res.SearchStatus)
	}
	if res.Confidence == "high" {
		t.Error("a truncated search must not claim high confidence")
	}
}

// ---------------------------------------------------------------------------
// Azure Activity Log
// ---------------------------------------------------------------------------

func TestActivityLogSource_NormalizesAndFollowsNextLink(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()
	var srvURL string
	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "skiptoken") {
			io.WriteString(w, `{"value":[{"caller":"alice@contoso.com","eventTimestamp":"2026-10-20T10:00:04Z","resourceId":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1","status":{"value":"Failed"},"authorization":{"action":"Microsoft.Storage/storageAccounts/listKeys/action"},"httpRequest":{"clientIpAddress":"198.51.100.7"}}]}`)
			return
		}
		io.WriteString(w, `{"value":[{"caller":"alice@contoso.com","eventTimestamp":"2026-10-20T10:00:01Z","resourceId":"/subscriptions/sub-1/resourceGroups/rg","operationName":{"value":"Microsoft.Authorization/roleAssignments/write"},"status":{"value":"Succeeded"}}],"nextLink":"`+srvURL+`/page2?skiptoken=x"}`)
	}))
	defer armSrv.Close()
	srvURL = armSrv.URL

	client := newTestAzureDiscoveryClient(t, tokenSrv.URL, armSrv.URL, armSrv.URL)
	src := NewActivityLogSource(client)
	events, truncated, err := src.Fetch(context.Background(), EventQuery{
		Principal: "alice@contoso.com", Start: evtTime.Add(-time.Minute), End: evtTime.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if truncated {
		t.Error("not truncated")
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2 (both pages)", len(events))
	}
	if events[0].Action != "Microsoft.Authorization/roleAssignments/write" || events[0].Result != "Success" {
		t.Errorf("first event = %s / %s", events[0].Action, events[0].Result)
	}
	if events[1].Action != "Microsoft.Storage/storageAccounts/listKeys/action" || events[1].Result != "Failure" {
		t.Errorf("RBAC action should be preferred and Failed mapped to Failure, got %s / %s", events[1].Action, events[1].Result)
	}
	if events[1].SourceIP != "198.51.100.7" || events[1].Source != "activity-log" {
		t.Errorf("ip/source = %s / %s", events[1].SourceIP, events[1].Source)
	}
}

func TestActivityLogSource_FilterCarriesTimeWindowAndCaller(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()
	var gotFilter atomic.Value
	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFilter.Store(r.URL.Query().Get("$filter"))
		io.WriteString(w, `{"value":[]}`)
	}))
	defer armSrv.Close()

	client := newTestAzureDiscoveryClient(t, tokenSrv.URL, armSrv.URL, armSrv.URL)
	_, _, err := NewActivityLogSource(client).Fetch(context.Background(), EventQuery{
		Principal: "o'brien@contoso.com", Start: evtTime.Add(-time.Minute), End: evtTime.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	f, _ := gotFilter.Load().(string)
	if !strings.Contains(f, "caller eq 'o''brien@contoso.com'") {
		t.Errorf("caller quote not escaped: %s", f)
	}
	if !strings.Contains(f, "eventTimestamp ge '2026-10-20T09:59:00Z'") {
		t.Errorf("window start missing: %s", f)
	}
}

func TestActivityLogSource_ForbiddenIsErrorNotEmpty(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()
	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer armSrv.Close()
	client := newTestAzureDiscoveryClient(t, tokenSrv.URL, armSrv.URL, armSrv.URL)
	if _, _, err := NewActivityLogSource(client).Fetch(context.Background(), EventQuery{}); err == nil {
		t.Fatal("a forbidden read must be an error, never an empty result")
	}
}

// ---------------------------------------------------------------------------
// GCP Audit Logs
// ---------------------------------------------------------------------------

const gcpAuditEntries = `{"entries":[
 {"logName":"projects/proj-1/logs/cloudaudit.googleapis.com%2Fdata_access","timestamp":"2026-10-20T10:00:02.5Z",
  "protoPayload":{"authenticationInfo":{"principalEmail":"alice@example.com"},"methodName":"storage.objects.get",
   "resourceName":"projects/_/buckets/corp-backups/objects/db.dump",
   "requestMetadata":{"callerIp":"192.0.2.44","callerSuppliedUserAgent":"gsutil"}}},
 {"logName":"projects/proj-1/logs/cloudaudit.googleapis.com%2Factivity","timestamp":"2026-10-20T10:00:03Z",
  "protoPayload":{"authenticationInfo":{"principalEmail":"backup@proj-1.iam.gserviceaccount.com"},"methodName":"storage.buckets.update",
   "resourceName":"projects/_/buckets/corp-backups","status":{"code":7}}}
]}`

func TestGCPAuditLogSource_NormalizesEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "entries:list") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, gcpAuditEntries)
	}))
	defer srv.Close()

	src, err := NewGCPAuditLogSource(context.Background(), "proj-1",
		option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("NewGCPAuditLogSource: %v", err)
	}
	events, truncated, err := src.Fetch(context.Background(), EventQuery{
		Principal: "gcp:user:alice@example.com", Start: evtTime.Add(-time.Minute), End: evtTime.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if truncated {
		t.Error("not truncated")
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	read := events[0]
	if read.Principal != "gcp:user:alice@example.com" || read.Action != "storage.objects.get" {
		t.Errorf("read = %s / %s", read.Principal, read.Action)
	}
	if read.Resource != "projects/proj-1/buckets/corp-backups" {
		t.Errorf("resource not rewritten to scope canonical: %s", read.Resource)
	}
	if read.Result != "Success" || read.SourceIP != "192.0.2.44" || read.UserAgent != "gsutil" {
		t.Errorf("read result/ip/ua = %s / %s / %s", read.Result, read.SourceIP, read.UserAgent)
	}
	update := events[1]
	if update.Principal != "gcp:serviceAccount:backup@proj-1.iam.gserviceaccount.com" {
		t.Errorf("service account principal = %s", update.Principal)
	}
	if update.Result != "Failure" {
		t.Errorf("status code 7 should be Failure, got %s", update.Result)
	}
}

func TestGCPCanonicalResource(t *testing.T) {
	cases := map[string]string{
		"projects/_/buckets/corp/objects/x": "projects/proj-1/buckets/corp",
		"projects/_/buckets/corp":           "projects/proj-1/buckets/corp",
		"projects/other/instances/vm1":      "projects/other/instances/vm1",
	}
	for in, want := range cases {
		if got := gcpCanonicalResource(in, "proj-1"); got != want {
			t.Errorf("gcpCanonicalResource(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGCPEmailFromCanonical(t *testing.T) {
	if got := gcpEmailFromCanonical("gcp:serviceAccount:x@p.iam.gserviceaccount.com"); got != "x@p.iam.gserviceaccount.com" {
		t.Errorf("got %q", got)
	}
	if got := gcpEmailFromCanonical("arn:aws:iam::1:user/x"); got != "" {
		t.Errorf("non-GCP id must yield empty, got %q", got)
	}
}
