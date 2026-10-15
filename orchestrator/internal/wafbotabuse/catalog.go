package wafbotabuse

import "fmt"

// AudspectWAFBotAbuseCatalog returns Audspect's real, current seed
// bot/abuse/rate-limit vector catalog: exactly one vector per
// BotAbuseCategory, validated before being returned.
func AudspectWAFBotAbuseCatalog() ([]BotAbuseVector, error) {
	type seed struct {
		id, name, preconditions, provenance, noBenignReason string
		category                                            BotAbuseCategory
		severity                                            Severity
		malicious, benign                                   RequestTemplate
		standards                                           StandardsMapping
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
			id: "BOTABUSE-003", category: CategoryCredentialAbuse, name: "Post-Lockout CAPTCHA-Gate Bypass", severity: SeverityCritical,
			preconditions: "login endpoint issues a CAPTCHA/step-up challenge after 20 failed attempts within 5 minutes against one username, and is declared to require a valid CAPTCHA solution on every subsequent attempt until the account's failure count resets",
			malicious: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username+captchaToken", Payload: "a login attempt submitted after the account has already been issued a CAPTCHA challenge (following 20 prior failures), with no valid CAPTCHA-solution token attached",
				Description: "bypasses an already-issued CAPTCHA challenge by submitting the login request without a valid CAPTCHA-solution token, testing whether the challenge gate is actually enforced on subsequent requests or merely displayed to the client without being checked server-side -- distinct from a raw-volume brute-force burst, which this control is assumed to already detect"},
			benign: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username+captchaToken", Payload: "the same post-challenge login attempt submitted with a valid CAPTCHA-solution token attached",
				Description: "a login attempt correctly carrying a valid CAPTCHA solution after the challenge gate was issued, which should be allowed through to normal authentication processing"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-307"}}, provenance: "manually authored from waf.txt Phase 6's named credential-abuse-controls category; revised during final review to model challenge-gate enforcement rather than restating wafcatalog's AUTH-001 raw-burst-detection shape",
		},
		{
			id: "BOTABUSE-004", category: CategoryDistributedEnforcement, name: "Cross-Node Lockout-State Bypass", severity: SeverityCritical,
			preconditions: "login endpoint's 20 failed-attempts/5-minute lockout is declared to be enforced globally across the deployment's backend nodes",
			malicious: RequestTemplate{Method: "POST", Path: "/api/auth/login", PayloadLocation: "body:username+routing", Payload: "20 failed login attempts against the same username, deliberately distributed 5-at-a-time across 4 different backend nodes via round-robin, so no single node locally observes more than 5 failures, while the username's true aggregate failure count across the deployment is 20",
				Description: "splits a brute-force attempt across multiple backend nodes to stay under each node's local failure threshold, testing whether the control's lockout state is shared/global across the distributed deployment or only locally enforced per node"},
			standards: StandardsMapping{CWEIDs: []string{"CWE-799"}}, provenance: "manually authored from waf.txt Phase 6's named distributed-enforcement category",
			noBenignReason: "both legs are deliberate attack probes that differ only in distribution strategy across backend nodes, not in malicious intent -- there is no legitimate single-request lookalike distinct from the credential-abuse benign leg already modeled by BOTABUSE-003; revised during final review after the original BenignCounterpart leg's own narrative ('should trigger the lockout') was found to contradict the ClaimFalsePositive semantics it would be evaluated against",
		},
	}

	var out []BotAbuseVector
	for _, sd := range seeds {
		var benignPtr *RequestTemplate
		if sd.noBenignReason == "" {
			benign := sd.benign
			benignPtr = &benign
		}
		v, err := NewBotAbuseVector(sd.id, 1, sd.category, sd.name, sd.severity, sd.preconditions, sd.malicious, benignPtr, sd.noBenignReason, sd.standards, sd.provenance)
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
