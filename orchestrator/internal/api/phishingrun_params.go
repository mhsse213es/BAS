package api

// ParamSpec describes one run parameter a phishing scenario reads. The library
// renders its form from these specs, and the server never trusts the form: each
// executor still validates its own parameters.
type ParamSpec struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Kind     string `json:"kind"` // "text" | "number" | "email"
	Required bool   `json:"required"`
}

var emailGWRunParam = ParamSpec{Name: "emailGwRunId", Label: "Email gateway run ID", Kind: "text", Required: true}

// phishingRunParams is the parameter schema for every scenario the registry can
// run. A scenario with no parameters still has an entry (an empty slice), so a
// missing entry means the schema is incomplete. Keep this in step with the
// executors: TestPhishingRunParams_EveryExecutableHasSchema enforces it.
var phishingRunParams = map[string][]ParamSpec{
	"PH-DET-002": {
		{Name: "executionId", Label: "Execution ID", Kind: "text", Required: true},
		{Name: "targetId", Label: "Target ID", Kind: "text", Required: true},
	},
	"PH-ID-001": {{Name: "executionId", Label: "Execution ID", Kind: "text", Required: true}},
	"PH-ID-002": {
		{Name: "runId", Label: "Action run ID", Kind: "text", Required: true},
		{Name: "clientIds", Label: "Application (client) IDs, comma-separated", Kind: "text", Required: true},
	},
	"PH-IR-003": {{Name: "runId", Label: "Action run ID", Kind: "text", Required: true}},
	"PH-ID-003": {
		{Name: "userIds", Label: "User principal names or object IDs, comma-separated", Kind: "text", Required: true},
	},
	"PH-ID-004": {
		{Name: "userId", Label: "User ID", Kind: "text", Required: true},
		{Name: "threshold", Label: "Denial threshold", Kind: "number", Required: true},
		{Name: "windowSeconds", Label: "Window (seconds)", Kind: "number", Required: true},
	},
	"PH-ID-005": {
		{Name: "userId", Label: "User ID", Kind: "text", Required: true},
		{Name: "windowSeconds", Label: "Window (seconds)", Kind: "number", Required: true},
	},
	"PH-EVA-002": {
		{Name: "emailGwRunId", Label: "Direct-path email gateway run ID", Kind: "text", Required: true},
		{Name: "relayEmailGwRunId", Label: "Relay-path email gateway run ID", Kind: "text", Required: true},
	},
	"PH-CHN-004": {
		{Name: "organizerUserId", Label: "Organizer mailbox", Kind: "text", Required: true},
		{Name: "attendeeEmail", Label: "Attendee address", Kind: "email", Required: true},
	},
	"PH-AUTH-002": {emailGWRunParam},
	"PH-AUTH-003": {emailGWRunParam},
	"PH-AUTH-004": {emailGWRunParam},
	"PH-AUTH-007": {emailGWRunParam},
	"PH-AUTH-008": {emailGWRunParam},
	"PH-BEC-001":  {emailGWRunParam},
	"PH-BEC-006":  {emailGWRunParam},
	"PH-URL-001":  {emailGWRunParam},
	"PH-ATT-001":  {emailGWRunParam},
	"PH-ATT-002":  {emailGWRunParam},
	"PH-ATT-003":  {emailGWRunParam},
	"PH-ATT-010":  {emailGWRunParam},
	"PH-CHN-005":  {emailGWRunParam},
}
