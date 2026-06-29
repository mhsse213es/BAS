package ticketing

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// jiraConnector implements Connector for the Jira REST API v2.
// Works with Jira Server, Jira Data Center, and Jira Cloud.
// Authentication: HTTP Basic with base64(username:api_token).
type jiraConnector struct {
	baseURL    string // https://jira.example.com
	username   string
	apiToken   string
	projectKey string // e.g. "SEC"
	httpClient *http.Client
}

func newJira(settings map[string]string) *jiraConnector {
	client := &http.Client{Timeout: 15 * time.Second}
	if settings["insecure_tls"] == "yes" {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	baseURL := strings.TrimRight(settings["base_url"], "/")
	if baseURL != "" && !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}
	return &jiraConnector{
		baseURL:    baseURL,
		username:   settings["username"],
		apiToken:   settings["api_token"],
		projectKey: settings["project_key"],
		httpClient: client,
	}
}

// issueTypeForRecord maps our RecordType to a Jira issue type name.
// Falls back to "Bug" if the project doesn't have the specific type — Jira
// will return a 400 which CreateTicket handles by retrying with "Bug".
func issueTypeForRecord(rt RecordType) string {
	switch rt {
	case RecordProblem, RecordRisk:
		return "Story"
	case RecordTask:
		return "Task"
	case RecordSecurityFinding:
		return "Security Finding"
	default:
		return "Bug"
	}
}

func jiraPriorityName(sev string) string {
	switch sev {
	case "Critical":
		return "Highest"
	case "High":
		return "High"
	case "Medium":
		return "Medium"
	default:
		return "Low"
	}
}

func (j *jiraConnector) CreateTicket(ctx context.Context, f TicketFinding, rt RecordType) (TicketRef, error) {
	summary := fmt.Sprintf("[BAS] %s — %s on %s", f.TechniqueID, f.TechniqueName, f.AgentHostname)
	if len(summary) > 255 {
		summary = summary[:255]
	}
	payload := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": j.projectKey},
			"summary":     summary,
			"description": buildJiraDescription(f),
			"issuetype":   map[string]string{"name": issueTypeForRecord(rt)},
			"priority":    map[string]string{"name": jiraPriorityName(f.Severity)},
			"labels":      []string{"BAS", "ATT&CK", f.TechniqueID},
		},
	}
	resp, err := j.doRequest(ctx, "POST", "/rest/api/2/issue", payload)
	if err != nil {
		// Issue type not found in project — retry with "Bug" (always present).
		if strings.Contains(strings.ToLower(err.Error()), "issuetype") ||
			strings.Contains(strings.ToLower(err.Error()), "issue type") {
			payload["fields"].(map[string]any)["issuetype"] = map[string]string{"name": "Bug"}
			resp, err = j.doRequest(ctx, "POST", "/rest/api/2/issue", payload)
		}
		if err != nil {
			return TicketRef{}, err
		}
	}
	var result struct {
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := json.Unmarshal(resp, &result); err != nil || result.Key == "" {
		return TicketRef{}, fmt.Errorf("jira: unexpected create response: %s", resp)
	}
	return TicketRef{
		TicketID:  result.Key,
		TicketURL: j.baseURL + "/browse/" + result.Key,
	}, nil
}

func buildJiraDescription(f TicketFinding) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "h2. BAS Finding: %s\n\n", f.TechniqueID)
	sb.WriteString("||Field||Value||\n")
	fmt.Fprintf(&sb, "|Technique|[%s|https://attack.mitre.org/techniques/%s]|\n", f.TechniqueName, f.TechniqueID)
	fmt.Fprintf(&sb, "|Tactic|%s|\n", f.Tactic)
	fmt.Fprintf(&sb, "|Severity|*%s*|\n", f.Severity)
	fmt.Fprintf(&sb, "|Exposure|%s|\n", f.ExposureState)
	fmt.Fprintf(&sb, "|Control Class|%s|\n", f.ControlClass)
	fmt.Fprintf(&sb, "|Agent|%s (%s)|\n", f.AgentHostname, f.AgentID)
	fmt.Fprintf(&sb, "|First Seen|%s|\n", f.FirstSeen.Format("2006-01-02"))
	fmt.Fprintf(&sb, "|Days Exposed|%d days|\n", f.DaysExposed)
	fmt.Fprintf(&sb, "|Occurrences|%d BAS runs|\n\n", f.OccurrenceCount)
	if len(f.Mitigations) > 0 {
		sb.WriteString("h3. Recommended Mitigations\n\n")
		for _, m := range f.Mitigations {
			fmt.Fprintf(&sb, "* *%s*: %s\n", m.Name, m.Description)
		}
		sb.WriteString("\n")
	}
	if len(f.ComplianceMappings) > 0 {
		sb.WriteString("h3. Compliance Impact\n\n")
		for _, c := range f.ComplianceMappings {
			fmt.Fprintf(&sb, "* %s %s — %s\n", c.Framework, c.ControlID, c.ControlName)
		}
		sb.WriteString("\n")
	}
	fmt.Fprintf(&sb, "BAS Run ID: {{%s}}", f.LastRunID)
	return sb.String()
}

func (j *jiraConnector) AddComment(ctx context.Context, ticketID, body string) error {
	_, err := j.doRequest(ctx, "POST", "/rest/api/2/issue/"+ticketID+"/comment",
		map[string]any{"body": body})
	return err
}

func (j *jiraConnector) CloseTicket(ctx context.Context, ticketID string) error {
	transID, err := j.findTransition(ctx, ticketID,
		"Done", "Resolved", "Closed", "Close Issue", "Resolve Issue")
	if err != nil {
		return err
	}
	_, err = j.doRequest(ctx, "POST", "/rest/api/2/issue/"+ticketID+"/transitions",
		map[string]any{
			"transition": map[string]string{"id": transID},
			"update": map[string]any{
				"comment": []map[string]any{
					{"add": map[string]string{
						"body": "BAS revalidation confirmed this technique is now prevented. Closing automatically.",
					}},
				},
			},
		})
	return err
}

func (j *jiraConnector) ReopenTicket(ctx context.Context, ticketID string) error {
	transID, err := j.findTransition(ctx, ticketID,
		"Reopen", "Reopen Issue", "Reopened", "Open", "To Do", "In Progress", "New")
	if err != nil {
		return err
	}
	_, err = j.doRequest(ctx, "POST", "/rest/api/2/issue/"+ticketID+"/transitions",
		map[string]any{
			"transition": map[string]string{"id": transID},
			"update": map[string]any{
				"comment": []map[string]any{
					{"add": map[string]string{
						"body": "BAS re-validation failed — this technique is still not prevented. Reopening.",
					}},
				},
			},
		})
	return err
}

// findTransition fetches the available transitions and returns the ID of the
// first name match (case-insensitive). Falls back to any "done/close/resolv" transition.
func (j *jiraConnector) findTransition(ctx context.Context, ticketID string, names ...string) (string, error) {
	resp, err := j.doRequest(ctx, "GET", "/rest/api/2/issue/"+ticketID+"/transitions", nil)
	if err != nil {
		return "", err
	}
	var result struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"transitions"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", err
	}
	for _, want := range names {
		for _, t := range result.Transitions {
			if strings.EqualFold(t.Name, want) {
				return t.ID, nil
			}
		}
	}
	for _, t := range result.Transitions {
		lower := strings.ToLower(t.Name)
		if strings.Contains(lower, "done") || strings.Contains(lower, "clos") || strings.Contains(lower, "resolv") {
			return t.ID, nil
		}
	}
	if len(result.Transitions) > 0 {
		return result.Transitions[len(result.Transitions)-1].ID, nil
	}
	return "", fmt.Errorf("jira: no transitions available for %s", ticketID)
}

func (j *jiraConnector) GetStatus(ctx context.Context, ticketID string) (string, error) {
	resp, err := j.doRequest(ctx, "GET", "/rest/api/2/issue/"+ticketID+"?fields=status", nil)
	if err != nil {
		return "", err
	}
	var result struct {
		Fields struct {
			Status struct {
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return "", err
	}
	switch result.Fields.Status.StatusCategory.Key {
	case "done":
		return "resolved", nil
	case "new", "undefined":
		return "open", nil
	default:
		return "in_progress", nil
	}
}

func (j *jiraConnector) TestConnection(ctx context.Context) error {
	_, err := j.doRequest(ctx, "GET", "/rest/api/2/project/"+j.projectKey, nil)
	return err
}

// ListProjects returns all projects visible to the authenticated user.
func (j *jiraConnector) ListProjects(ctx context.Context) ([]map[string]string, error) {
	resp, err := j.doRequest(ctx, "GET", "/rest/api/2/project?expand=&maxResults=200", nil)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(resp, &raw); err != nil {
		return nil, fmt.Errorf("jira: parse projects: %w", err)
	}
	out := make([]map[string]string, len(raw))
	for i, p := range raw {
		out[i] = map[string]string{"key": p.Key, "name": p.Name}
	}
	return out, nil
}

func (j *jiraConnector) doRequest(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, j.baseURL+path, reqBody)
	if err != nil {
		return nil, err
	}
	creds := base64.StdEncoding.EncodeToString([]byte(j.username + ":" + j.apiToken))
	req.Header.Set("Authorization", "Basic "+creds)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := j.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jira %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("jira %s %s: HTTP %d: %s", method, path, resp.StatusCode, data)
	}
	return data, nil
}
