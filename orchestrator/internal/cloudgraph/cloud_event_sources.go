package cloudgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	logging "google.golang.org/api/logging/v2"
	"google.golang.org/api/option"
)

// EventQuery is one audit search: a principal, action and resource within a
// time window. Empty Action or Resource widens the search.
type EventQuery struct {
	Principal string
	Action    string
	Resource  string
	Start     time.Time
	End       time.Time
}

// EventSource fetches raw audit events from one provider's log service and
// normalizes them to CloudEvent. Fetch reports truncated=true when the page
// cap stopped the search before the log was exhausted; such results are
// partial, never presented as a complete absence of events.
type EventSource interface {
	Name() string
	Fetch(ctx context.Context, q EventQuery) (events []*CloudEvent, truncated bool, err error)
}

// maxEventPages bounds one audit search. A window that needs more pages is
// reported as partial rather than walked without limit.
const maxEventPages = 20

// defaultEventTimeout bounds one FindEvents call against a live log service.
const defaultEventTimeout = 30 * time.Second

// LiveCorrelator implements EventCorrelator over a live log service. The
// matching rules are exactly those of SyntheticEventCorrelator, so a live
// result and a fixture result score the same way for the same events. A
// failed fetch is reported as SearchStatus "unavailable" with the error
// redacted, never as zero events.
type LiveCorrelator struct {
	Source  EventSource
	Timeout time.Duration
}

// FindEvents satisfies EventCorrelator. It bounds the fetch with Timeout and
// scores the fetched events against the requested principal/action/resource.
func (c *LiveCorrelator) FindEvents(principal, action, resource string, actionTime time.Time, window time.Duration) *EventSearchResult {
	start := actionTime.Add(-window)
	end := actionTime.Add(window)
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultEventTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	events, truncated, err := c.Source.Fetch(ctx, EventQuery{
		Principal: principal, Action: action, Resource: resource, Start: start, End: end,
	})
	if err != nil {
		return &EventSearchResult{
			EventsFound:      []*CloudEvent{},
			SearchStatus:     "unavailable",
			SearchError:      err.Error(),
			WindowStart:      start,
			WindowEnd:        end,
			MatchQuality:     "none",
			Confidence:       "low",
			MissingTelemetry: []string{c.Source.Name()},
		}
	}

	scorer := &SyntheticEventCorrelator{}
	for _, e := range events {
		scorer.addSyntheticEvent(e)
	}
	result := scorer.FindEvents(principal, action, resource, actionTime, window)
	result.EventsSearched = len(events)
	result.SearchStatus = "success"
	result.MissingTelemetry = []string{}
	if truncated {
		result.SearchStatus = "partial"
		result.MissingTelemetry = append(result.MissingTelemetry, "search-truncated")
		if result.Confidence == "high" {
			result.Confidence = "medium"
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// AWS CloudTrail
// ---------------------------------------------------------------------------

// CloudTrailAPI is the LookupEvents surface. *cloudtrail.Client satisfies it.
type CloudTrailAPI interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// CloudTrailSource reads management events through LookupEvents. LookupEvents
// accepts one attribute filter, so the action's event name is used as the
// filter and principal and resource are matched after retrieval.
type CloudTrailSource struct {
	API CloudTrailAPI
}

func (s *CloudTrailSource) Name() string { return "cloudtrail" }

// Fetch pages through LookupEvents within the window.
func (s *CloudTrailSource) Fetch(ctx context.Context, q EventQuery) ([]*CloudEvent, bool, error) {
	input := &cloudtrail.LookupEventsInput{
		StartTime:  aws.Time(q.Start),
		EndTime:    aws.Time(q.End),
		MaxResults: aws.Int32(50),
	}
	if name := cloudTrailEventName(q.Action); name != "" {
		input.LookupAttributes = []cttypes.LookupAttribute{{
			AttributeKey:   cttypes.LookupAttributeKeyEventName,
			AttributeValue: aws.String(name),
		}}
	}

	var events []*CloudEvent
	for pages := 0; ; pages++ {
		if pages >= maxEventPages {
			return events, true, nil
		}
		out, err := s.API.LookupEvents(ctx, input)
		if err != nil {
			return nil, false, fmt.Errorf("cloudtrail lookup: %w", err)
		}
		for _, raw := range out.Events {
			events = append(events, parseCloudTrailEvent(raw)...)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return events, false, nil
		}
		input.NextToken = out.NextToken
	}
}

// cloudTrailEventName turns an IAM action ("sts:AssumeRole") into the
// CloudTrail event name ("AssumeRole"). Wildcards cannot be expressed as an
// attribute filter, so they return "" and widen the search.
func cloudTrailEventName(action string) string {
	_, name, ok := strings.Cut(action, ":")
	if !ok || name == "" || strings.Contains(name, "*") {
		return ""
	}
	return name
}

// cloudTrailRecord is the subset of a CloudTrail event record this package reads.
type cloudTrailRecord struct {
	EventTime       time.Time `json:"eventTime"`
	EventSource     string    `json:"eventSource"`
	EventName       string    `json:"eventName"`
	SourceIPAddress string    `json:"sourceIPAddress"`
	UserAgent       string    `json:"userAgent"`
	ErrorCode       string    `json:"errorCode"`
	UserIdentity    struct {
		ARN            string `json:"arn"`
		SessionContext struct {
			Attributes struct {
				MFAAuthenticated string `json:"mfaAuthenticated"`
			} `json:"attributes"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	Resources []struct {
		ARN string `json:"ARN"`
	} `json:"resources"`
}

// parseCloudTrailEvent normalizes one LookupEvents entry. The authoritative
// record is the embedded CloudTrailEvent JSON; the summary fields are used
// only when that record is missing. One CloudEvent is emitted per resource
// ARN so a resource-scoped search matches on any of them.
func parseCloudTrailEvent(raw cttypes.Event) []*CloudEvent {
	var rec cloudTrailRecord
	if raw.CloudTrailEvent != nil {
		if err := json.Unmarshal([]byte(*raw.CloudTrailEvent), &rec); err != nil {
			rec = cloudTrailRecord{}
		}
	}
	if rec.EventName == "" {
		rec.EventName = aws.ToString(raw.EventName)
	}
	if rec.EventSource == "" {
		rec.EventSource = aws.ToString(raw.EventSource)
	}
	if rec.UserIdentity.ARN == "" {
		rec.UserIdentity.ARN = aws.ToString(raw.Username)
	}
	if rec.EventTime.IsZero() && raw.EventTime != nil {
		rec.EventTime = *raw.EventTime
	}

	service := strings.TrimSuffix(rec.EventSource, ".amazonaws.com")
	action := service + ":" + rec.EventName
	result := "Success"
	if rec.ErrorCode != "" {
		result = "Failure"
	}

	base := CloudEvent{
		Principal:    rec.UserIdentity.ARN,
		Action:       action,
		Timestamp:    rec.EventTime,
		Result:       result,
		Source:       "cloudtrail",
		SessionToken: aws.ToString(raw.EventId),
		SourceIP:     rec.SourceIPAddress,
		UserAgent:    rec.UserAgent,
	}

	var out []*CloudEvent
	for _, r := range rec.Resources {
		e := base
		e.Resource = r.ARN
		out = append(out, &e)
	}
	if len(out) == 0 {
		e := base
		out = append(out, &e)
	}
	return out
}

// ---------------------------------------------------------------------------
// Azure Activity Log
// ---------------------------------------------------------------------------

// ActivityLogSource reads the subscription's Activity Log through the Azure
// Resource Manager eventtypes endpoint. It shares the discovery client's token
// source, throttling and retry, so a log read and an inventory read cannot
// bypass each other's limits.
type ActivityLogSource struct {
	client *AzureDiscoveryClient
}

// NewActivityLogSource returns an Activity Log source for the client's subscription.
func NewActivityLogSource(client *AzureDiscoveryClient) *ActivityLogSource {
	return &ActivityLogSource{client: client}
}

func (s *ActivityLogSource) Name() string { return "activity-log" }

type activityLogPage struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"nextLink"`
}

type activityLogEntry struct {
	Caller         string `json:"caller"`
	EventTimestamp string `json:"eventTimestamp"`
	ResourceID     string `json:"resourceId"`
	Status         struct {
		Value string `json:"value"`
	} `json:"status"`
	OperationName struct {
		Value string `json:"value"`
	} `json:"operationName"`
	Authorization struct {
		Action string `json:"action"`
	} `json:"authorization"`
	HTTPRequest struct {
		ClientIPAddress string `json:"clientIpAddress"`
	} `json:"httpRequest"`
	CorrelationID string `json:"correlationId"`
}

// Fetch lists Activity Log entries for the caller and window, following nextLink.
func (s *ActivityLogSource) Fetch(ctx context.Context, q EventQuery) ([]*CloudEvent, bool, error) {
	filter := fmt.Sprintf("eventTimestamp ge '%s' and eventTimestamp le '%s'",
		q.Start.UTC().Format(time.RFC3339), q.End.UTC().Format(time.RFC3339))
	if q.Principal != "" {
		filter += fmt.Sprintf(" and caller eq '%s'", strings.ReplaceAll(q.Principal, "'", "''"))
	}
	next := fmt.Sprintf("%s/subscriptions/%s/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&$filter=%s",
		s.client.ARMBaseURL, s.client.subscriptionID, url.QueryEscape(filter))

	var events []*CloudEvent
	for pages := 0; next != ""; pages++ {
		if pages >= maxEventPages {
			return events, true, nil
		}
		resp, err := s.client.get(ctx, next, s.client.armTokens)
		if err != nil {
			return nil, false, fmt.Errorf("activity log: %w", err)
		}
		var page activityLogPage
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		status := resp.StatusCode
		resp.Body.Close()
		if status != http.StatusOK {
			return nil, false, fmt.Errorf("activity log: status %d", status)
		}
		if decodeErr != nil {
			return nil, false, fmt.Errorf("activity log: decoding page: %w", decodeErr)
		}
		for _, raw := range page.Value {
			var entry activityLogEntry
			if err := json.Unmarshal(raw, &entry); err != nil {
				return nil, false, fmt.Errorf("activity log: parsing entry: %w", err)
			}
			events = append(events, normalizeActivityLogEntry(entry))
		}
		if page.NextLink == next {
			return nil, false, fmt.Errorf("activity log: pagination did not advance")
		}
		next = page.NextLink
	}
	return events, false, nil
}

// normalizeActivityLogEntry maps one Activity Log record to a CloudEvent. The
// RBAC action is preferred over the operation name, since it is the value
// the Azure evaluator's role_actions list is written in.
func normalizeActivityLogEntry(e activityLogEntry) *CloudEvent {
	action := e.Authorization.Action
	if action == "" {
		action = e.OperationName.Value
	}
	result := "Success"
	if strings.EqualFold(e.Status.Value, "Failed") {
		result = "Failure"
	}
	ts, _ := time.Parse(time.RFC3339, e.EventTimestamp)
	return &CloudEvent{
		Principal:    e.Caller,
		Action:       action,
		Resource:     e.ResourceID,
		Timestamp:    ts,
		Result:       result,
		Source:       "activity-log",
		SessionToken: e.CorrelationID,
		SourceIP:     e.HTTPRequest.ClientIPAddress,
	}
}

// ---------------------------------------------------------------------------
// GCP Audit Logs
// ---------------------------------------------------------------------------

// gcpAuditPayload is the subset of an AuditLog protoPayload this package reads.
type gcpAuditPayload struct {
	AuthenticationInfo struct {
		PrincipalEmail string `json:"principalEmail"`
	} `json:"authenticationInfo"`
	MethodName   string `json:"methodName"`
	ResourceName string `json:"resourceName"`
	Status       struct {
		Code int `json:"code"`
	} `json:"status"`
	RequestMetadata struct {
		CallerIP        string `json:"callerIp"`
		CallerUserAgent string `json:"callerSuppliedUserAgent"`
	} `json:"requestMetadata"`
}

// GCPAuditLogSource reads Cloud Audit Logs through the Logging entries.list API.
type GCPAuditLogSource struct {
	projectID string
	service   *logging.Service
	maxPages  int
}

// NewGCPAuditLogSource builds the Logging client for projectID. Auth comes from
// Application Default Credentials unless opts overrides it.
func NewGCPAuditLogSource(ctx context.Context, projectID string, opts ...option.ClientOption) (*GCPAuditLogSource, error) {
	if projectID == "" {
		return nil, fmt.Errorf("gcp audit log: project ID is required")
	}
	svc, err := logging.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcp audit log: building logging client: %w", err)
	}
	return &GCPAuditLogSource{projectID: projectID, service: svc, maxPages: maxEventPages}, nil
}

func (s *GCPAuditLogSource) Name() string { return "gcp-audit-log" }

// Fetch runs entries.list for the project's Cloud Audit Log entries in the window.
func (s *GCPAuditLogSource) Fetch(ctx context.Context, q EventQuery) ([]*CloudEvent, bool, error) {
	filterParts := []string{
		`logName:"cloudaudit.googleapis.com"`,
		fmt.Sprintf(`timestamp>=%q`, q.Start.UTC().Format(time.RFC3339)),
		fmt.Sprintf(`timestamp<=%q`, q.End.UTC().Format(time.RFC3339)),
	}
	if email := gcpEmailFromCanonical(q.Principal); email != "" {
		filterParts = append(filterParts, fmt.Sprintf(`protoPayload.authenticationInfo.principalEmail=%q`, email))
	}
	if method := q.Action; method != "" && !strings.Contains(method, "*") {
		filterParts = append(filterParts, fmt.Sprintf(`protoPayload.methodName=%q`, method))
	}
	req := &logging.ListLogEntriesRequest{
		ResourceNames: []string{"projects/" + s.projectID},
		Filter:        strings.Join(filterParts, " AND "),
		OrderBy:       "timestamp desc",
		PageSize:      500,
	}

	var events []*CloudEvent
	for pages := 0; ; pages++ {
		if pages >= s.maxPages {
			return events, true, nil
		}
		resp, err := s.service.Entries.List(req).Context(ctx).Do()
		if err != nil {
			return nil, false, fmt.Errorf("gcp audit log: %w", err)
		}
		for _, entry := range resp.Entries {
			if e := normalizeGCPAuditEntry(entry, s.projectID); e != nil {
				events = append(events, e)
			}
		}
		if resp.NextPageToken == "" {
			return events, false, nil
		}
		req.PageToken = resp.NextPageToken
	}
}

// gcpEmailFromCanonical strips the "gcp:user:" / "gcp:serviceAccount:" prefix
// from a canonical GCP identity, returning the email the audit log records.
func gcpEmailFromCanonical(canonical string) string {
	for _, prefix := range []string{"gcp:user:", "gcp:serviceAccount:", "gcp:group:"} {
		if strings.HasPrefix(canonical, prefix) {
			return strings.TrimPrefix(canonical, prefix)
		}
	}
	return ""
}

// normalizeGCPAuditEntry maps one audit log entry to a CloudEvent. The
// principal is given the canonical form the discovery pass uses, so a
// discovered identity and its audit trail compare equal. Bucket resource names
// (projects/_/buckets/NAME/...) are rewritten to the project-qualified scope
// canonical form.
func normalizeGCPAuditEntry(entry *logging.LogEntry, projectID string) *CloudEvent {
	if entry == nil || len(entry.ProtoPayload) == 0 {
		return nil
	}
	var p gcpAuditPayload
	if err := json.Unmarshal(entry.ProtoPayload, &p); err != nil {
		return nil
	}
	email := p.AuthenticationInfo.PrincipalEmail
	principal := ""
	if email != "" {
		kind := "user"
		if strings.HasSuffix(email, ".gserviceaccount.com") {
			kind = "serviceAccount"
		}
		principal = "gcp:" + kind + ":" + email
	}
	result := "Success"
	if p.Status.Code != 0 {
		result = "Failure"
	}
	ts, _ := time.Parse(time.RFC3339Nano, entry.Timestamp)
	return &CloudEvent{
		Principal: principal,
		Action:    p.MethodName,
		Resource:  gcpCanonicalResource(p.ResourceName, projectID),
		Timestamp: ts,
		Result:    result,
		Source:    "gcp-audit-log",
		SourceIP:  p.RequestMetadata.CallerIP,
		UserAgent: p.RequestMetadata.CallerUserAgent,
	}
}

// gcpCanonicalResource rewrites a Cloud Audit resource name into the scope
// canonical used by discovery: projects/_/buckets/NAME[/objects/...] becomes
// projects/PROJECT/buckets/NAME. Other names pass through unchanged.
func gcpCanonicalResource(name, projectID string) string {
	const prefix = "projects/_/buckets/"
	if !strings.HasPrefix(name, prefix) {
		return name
	}
	bucket, _, _ := strings.Cut(strings.TrimPrefix(name, prefix), "/")
	return "projects/" + projectID + "/buckets/" + bucket
}
