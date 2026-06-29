package ticketing

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// snowConnector implements Connector for the ServiceNow Table API.
// Authentication: HTTP Basic (username + password).
// Credentials are stored in Config.Settings["username"] and ["password"].
type snowConnector struct {
	instanceURL string
	username    string
	password    string
	category    string // incident category (default "security")
	assignGroup string // optional assignment_group value
	httpClient  *http.Client
}

func newServiceNow(settings map[string]string) *snowConnector {
	client := &http.Client{Timeout: 15 * time.Second}
	if settings["insecure_tls"] == "yes" {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	instanceURL := strings.TrimRight(settings["instance_url"], "/")
	if instanceURL != "" && !strings.HasPrefix(instanceURL, "http://") && !strings.HasPrefix(instanceURL, "https://") {
		instanceURL = "https://" + instanceURL
	}
	return &snowConnector{
		instanceURL: instanceURL,
		username:    settings["username"],
		password:    settings["password"],
		category:    orDefault(settings["category"], "security"),
		assignGroup: settings["assignment_group"],
		httpClient:  client,
	}
}

// tableForRecord maps our RecordType to the ServiceNow table name.
func tableForRecord(rt RecordType) string {
	switch rt {
	case RecordProblem:
		return "problem"
	case RecordRisk:
		return "sn_risk_risk"
	case RecordChangeRequest:
		return "change_request"
	case RecordTask:
		return "task"
	default:
		return "incident"
	}
}

func (s *snowConnector) CreateTicket(ctx context.Context, f TicketFinding, rt RecordType) (TicketRef, error) {
	table := tableForRecord(rt)
	body := s.buildCreateBody(f, rt)
	resp, err := s.doRequest(ctx, "POST", "/api/now/table/"+table, body)
	if err != nil {
		return TicketRef{}, err
	}
	var result struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp, &result); err != nil || result.Result.SysID == "" {
		return TicketRef{}, fmt.Errorf("servicenow: unexpected create response: %s", resp)
	}
	// Encode table/sys_id so CloseTicket/AddComment know which endpoint to call.
	ticketID := table + "/" + result.Result.SysID
	ticketURL := s.instanceURL + "/nav_to.do?uri=" + table + ".do?sys_id=" + result.Result.SysID
	if result.Result.Number != "" {
		ticketURL = s.instanceURL + "/nav_to.do?uri=" + table + ".do?number=" + result.Result.Number
	}
	return TicketRef{TicketID: ticketID, TicketURL: ticketURL}, nil
}

func (s *snowConnector) buildCreateBody(f TicketFinding, rt RecordType) map[string]any {
	pri := SevPriority(f.Severity)
	shortDesc := fmt.Sprintf("[BAS] %s — %s on %s", f.TechniqueID, f.TechniqueName, f.AgentHostname)
	if len(shortDesc) > 160 {
		shortDesc = shortDesc[:160]
	}
	body := map[string]any{
		"short_description": shortDesc,
		"description":       buildSnowDescription(f),
		"category":          s.category,
		"urgency":           pri,
		"impact":            pri,
	}
	if s.assignGroup != "" {
		body["assignment_group"] = s.assignGroup
	}
	if rt == RecordRisk {
		body["name"] = shortDesc
		body["risk_category"] = "security"
		delete(body, "short_description")
		delete(body, "urgency")
		delete(body, "impact")
	}
	return body
}

func buildSnowDescription(f TicketFinding) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "== BAS Finding: %s ==\n\n", f.TechniqueID)
	fmt.Fprintf(&sb, "Technique:     %s (%s)\n", f.TechniqueName, f.TechniqueID)
	fmt.Fprintf(&sb, "Tactic:        %s\n", f.Tactic)
	fmt.Fprintf(&sb, "Severity:      %s\n", f.Severity)
	fmt.Fprintf(&sb, "Exposure:      %s\n", f.ExposureState)
	fmt.Fprintf(&sb, "Control Class: %s\n", f.ControlClass)
	fmt.Fprintf(&sb, "Agent:         %s (%s)\n", f.AgentHostname, f.AgentID)
	fmt.Fprintf(&sb, "First Seen:    %s\n", f.FirstSeen.Format("2006-01-02"))
	fmt.Fprintf(&sb, "Days Exposed:  %d days\n", f.DaysExposed)
	fmt.Fprintf(&sb, "Occurrences:   %d BAS runs\n\n", f.OccurrenceCount)
	fmt.Fprintf(&sb, "ATT&CK Ref:    https://attack.mitre.org/techniques/%s\n\n", f.TechniqueID)
	if len(f.Mitigations) > 0 {
		sb.WriteString("== Recommended Mitigations ==\n")
		for _, m := range f.Mitigations {
			fmt.Fprintf(&sb, "- %s: %s\n", m.Name, m.Description)
		}
		sb.WriteString("\n")
	}
	if len(f.ComplianceMappings) > 0 {
		sb.WriteString("== Compliance Impact ==\n")
		for _, c := range f.ComplianceMappings {
			fmt.Fprintf(&sb, "- %s %s — %s\n", c.Framework, c.ControlID, c.ControlName)
		}
		sb.WriteString("\n")
	}
	fmt.Fprintf(&sb, "BAS Run: %s", f.LastRunID)
	return sb.String()
}

func (s *snowConnector) AddComment(ctx context.Context, ticketID, body string) error {
	table, sysID, err := splitSnowID(ticketID)
	if err != nil {
		return err
	}
	_, err = s.doRequest(ctx, "PATCH", "/api/now/table/"+table+"/"+sysID, map[string]any{"work_notes": body})
	return err
}

func (s *snowConnector) CloseTicket(ctx context.Context, ticketID string) error {
	table, sysID, err := splitSnowID(ticketID)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"state":       "6",
		"close_code":  "Solved (Permanently)",
		"close_notes": "BAS revalidation confirmed this technique is now prevented. Auto-resolved by BAS.",
	}
	if table == "problem" {
		payload["state"] = "107"
		delete(payload, "close_code")
		delete(payload, "close_notes")
		payload["cause_notes"] = "Remediated — BAS revalidation confirmed prevention."
		payload["fix_notes"] = "BAS revalidation confirmed this technique is now prevented."
	}
	_, err = s.doRequest(ctx, "PATCH", "/api/now/table/"+table+"/"+sysID, payload)
	return err
}

func (s *snowConnector) ReopenTicket(ctx context.Context, ticketID string) error {
	table, sysID, err := splitSnowID(ticketID)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"state":      "2",
		"work_notes": "BAS re-validation failed — this technique is still not prevented. Ticket reopened automatically.",
	}
	_, err = s.doRequest(ctx, "PATCH", "/api/now/table/"+table+"/"+sysID, payload)
	return err
}

func (s *snowConnector) GetStatus(ctx context.Context, ticketID string) (string, error) {
	table, sysID, err := splitSnowID(ticketID)
	if err != nil {
		return "", err
	}
	resp, err := s.doRequest(ctx, "GET", "/api/now/table/"+table+"/"+sysID+"?sysparm_fields=state", nil)
	if err != nil {
		return "", err
	}
	var result struct {
		Result struct {
			State string `json:"state"`
		} `json:"result"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", err
	}
	return snowStateLabel(result.Result.State), nil
}

func snowStateLabel(state string) string {
	switch state {
	case "1":
		return "open"
	case "2", "3":
		return "in_progress"
	case "4", "5", "6", "7":
		return "resolved"
	default:
		return "unknown"
	}
}

func (s *snowConnector) TestConnection(ctx context.Context) error {
	_, err := s.doRequest(ctx, "GET", "/api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id", nil)
	return err
}

func (s *snowConnector) doRequest(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.instanceURL+path, reqBody)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(s.username, s.password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("servicenow %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("servicenow %s %s: HTTP %d: %s", method, path, resp.StatusCode, data)
	}
	return data, nil
}

func splitSnowID(ticketID string) (table, sysID string, err error) {
	parts := strings.SplitN(ticketID, "/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", fmt.Errorf("servicenow: invalid ticketID %q (expected table/sys_id)", ticketID)
	}
	return parts[0], parts[1], nil
}
