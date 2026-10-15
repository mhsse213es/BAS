package wafbotabuse

import "fmt"

// AudspectWAFBotAbuseCatalog returns Audspect's real, current seed
// bot/abuse/rate-limit vector catalog: exactly one vector per
// BotAbuseCategory, validated before being returned.
func AudspectWAFBotAbuseCatalog() ([]BotAbuseVector, error) {
	type seed struct {
		id, name, preconditions, provenance string
		category                            BotAbuseCategory
		severity                            Severity
		malicious, benign                   RequestTemplate
		standards                           StandardsMapping
	}
	seeds := []seed{
		{
			id: "BOTABUSE-001", category: CategoryBoundedAutomation, name: "Non-Human-Paced Automation Burst", severity: SeverityHigh,
			preconditions: "search endpoint accepts unauthenticated GET requests with no declared per-client pacing requirement",
			malicious: RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "header+timing", Payload: "50 requests in 2 seconds (25/sec), each missing a browser-issued JS-challenge cookie and User-Agent header",
				Description: "a rapid, non-human-paced burst of otherwise-valid search requests lacking standard browser automation signals (JS-challenge cookie, User-Agent), consistent with a headless scripted client rather than a human browsing session"},
			benign: RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "header+timing", Payload: "a single human-paced request carrying a valid JS-challenge cookie and a standard browser User-Agent header",
				Description: "a single search request sent at human timing with normal browser signals present"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-799"}}, provenance: "manually authored from waf.txt Phase 6's named bounded-automation category",
		},
		{
			id: "BOTABUSE-002", category: CategoryRateLimit, name: "Order-Creation Rate-Limit Overrun", severity: SeverityHigh,
			preconditions: "order-creation API declares a 500 requests/60s rate limit per API key",
			malicious: RequestTemplate{Method: "POST", Path: "/api/orders", PayloadLocation: "header:X-API-Key+timing", Payload: "the 501st order-creation request within a 60-second window from the same API key, following 500 prior requests already sent in that window",
				Description: "exceeds the order-creation API's declared rate limit (500 requests/60s per API key) by continuing past the threshold"},
			benign: RequestTemplate{Method: "POST", Path: "/api/orders", PayloadLocation: "header:X-API-Key+timing", Payload: "a single order-creation request from an API key that has sent 10 requests in the current 60-second window, well within the 500/60s limit",
				Description: "a request well within the declared rate limit"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-770"}}, provenance: "manually authored from waf.txt Phase 6's named rate-limits category",
		},
		{
			id: "BOTABUSE-003", category: CategoryCredentialAbuse, name: "Failed-Login Lockout Bypass", severity: SeverityCritical,
			preconditions: "login endpoint declares a 20 failed-attempts/5-minute lockout threshold per username",
			malicious: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username+timing", Payload: "the 21st failed login attempt within 5 minutes against the same username, following 20 prior failed attempts, with no CAPTCHA/lockout triggered yet",
				Description: "continues brute-force login attempts past the declared failed-attempt threshold (20 failures/5 min) without the account entering a lockout or CAPTCHA-challenge state"},
			benign: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username", Payload: "a single login attempt against a username with zero prior failed attempts in the current window",
				Description: "a single legitimate login attempt with no preceding failure history"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-307"}}, provenance: "manually authored from waf.txt Phase 6's named credential-abuse-controls category",
		},
		{
			id: "BOTABUSE-004", category: CategoryDistributedEnforcement, name: "Cross-Node Lockout-State Bypass", severity: SeverityCritical,
			preconditions: "login endpoint's 20 failed-attempts/5-minute lockout is declared to be enforced globally across the deployment's backend nodes",
			malicious: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username+routing", Payload: "20 failed login attempts against the same username, deliberately distributed 5-at-a-time across 4 different backend nodes via round-robin, so no single node locally observes more than 5 failures, while the username's true aggregate failure count across the deployment is 20",
				Description: "splits a brute-force attempt across multiple backend nodes to stay under each node's local failure threshold, testing whether the control's lockout state is shared/global across the distributed deployment or only locally enforced per node"},
			benign: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username+routing", Payload: "20 login attempts, all correctly evaluated against the deployment's single shared/global failure-count state for that username",
				Description: "the same volume of attempts evaluated against genuinely shared distributed state, which should trigger the lockout identically to a single-node deployment"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-799"}}, provenance: "manually authored from waf.txt Phase 6's named distributed-enforcement category",
		},
	}

	var out []BotAbuseVector
	for _, sd := range seeds {
		benign := sd.benign
		v, err := NewBotAbuseVector(sd.id, 1, sd.category, sd.name, sd.severity, sd.preconditions, sd.malicious, &benign, "", sd.standards, sd.provenance)
		if err != nil {
			return nil, fmt.Errorf("loading seed bot-abuse catalog: %w", err)
		}
		out = append(out, v)
	}

	if err := ValidateBotAbuseCatalog(out); err != nil {
		return nil, fmt.Errorf("seed bot-abuse catalog failed validation: %w", err)
	}
	return out, nil
}
