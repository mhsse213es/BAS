package observability

import (
	"fmt"
	"sync"
	"time"
)

// AlertRule defines a threshold-based alert.
type AlertRule struct {
	// Name is the alert identifier (e.g., "high_failure_rate")
	Name string

	// Description explains what triggered the alert.
	Description string

	// Condition is the threshold check function.
	// Returns true if the alert should fire.
	Condition func() bool

	// Severity is one of: info, warning, critical.
	Severity string

	// NotificationWebhook is the URL to POST alert events (optional).
	NotificationWebhook string
}

// Alert is a fired alert event.
type Alert struct {
	RuleName        string
	Description     string
	Severity        string
	FiredAt         time.Time
	NotificationURL string
	Message         string
}

// AlertEngine evaluates rules periodically and notifies on changes.
type AlertEngine struct {
	mu      sync.RWMutex
	rules   []*AlertRule
	fired   map[string]bool // ruleNa me → is currently firing
	history []Alert

	ticker *time.Ticker
	done   chan struct{}
}

// NewAlertEngine creates a new alert engine with a polling interval.
func NewAlertEngine(checkInterval time.Duration) *AlertEngine {
	engine := &AlertEngine{
		fired:   make(map[string]bool),
		history: []Alert{},
		ticker:  time.NewTicker(checkInterval),
		done:    make(chan struct{}),
	}

	// Start polling in the background
	go engine.run()

	return engine
}

// AddRule registers a new alert rule.
func (e *AlertEngine) AddRule(rule *AlertRule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	if rule.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}
	if rule.Condition == nil {
		return fmt.Errorf("rule condition cannot be nil")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = append(e.rules, rule)
	e.fired[rule.Name] = false
	return nil
}

// run periodically evaluates rules and fires alerts.
func (e *AlertEngine) run() {
	for {
		select {
		case <-e.done:
			e.ticker.Stop()
			return
		case <-e.ticker.C:
			e.evaluate()
		}
	}
}

// evaluate checks all rules and fires alerts on state changes.
func (e *AlertEngine) evaluate() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, rule := range e.rules {
		wasFiring := e.fired[rule.Name]
		isFiring := rule.Condition()

		// Fire alert on state change (false → true or true → false)
		if isFiring && !wasFiring {
			e.fireAlert(rule, true)
		} else if !isFiring && wasFiring {
			e.fireAlert(rule, false)
		}

		e.fired[rule.Name] = isFiring
	}
}

// fireAlert logs and notifies on alert state change.
func (e *AlertEngine) fireAlert(rule *AlertRule, firing bool) {
	state := "FIRING"
	if !firing {
		state = "RESOLVED"
	}

	alert := Alert{
		RuleName:        rule.Name,
		Description:     rule.Description,
		Severity:        rule.Severity,
		FiredAt:         time.Now(),
		NotificationURL: rule.NotificationWebhook,
		Message:         fmt.Sprintf("%s: %s (%s)", state, rule.Description, rule.Severity),
	}

	e.history = append(e.history, alert)

	// TODO: POST to NotificationWebhook if configured (Task 7 future work)
	// For now, alerts are logged to history only
}

// Stop shuts down the alert engine.
func (e *AlertEngine) Stop() {
	close(e.done)
}

// GetHistory returns all fired alerts.
func (e *AlertEngine) GetHistory() []Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return append([]Alert{}, e.history...)
}

// GetFiredAlerts returns currently firing alerts.
func (e *AlertEngine) GetFiredAlerts() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var fired []string
	for name, isFiring := range e.fired {
		if isFiring {
			fired = append(fired, name)
		}
	}
	return fired
}

// PrebuiltRules returns common alert rules (P0 example rules).
func PrebuiltRules(metrics *MetricsRegistry) []*AlertRule {
	return []*AlertRule{
		{
			Name:        "high_active_tasks",
			Description: "Executor has > 50 active tasks (possible queue buildup)",
			Severity:    "warning",
			Condition: func() bool {
				// TODO: Read from metrics registry when integrated
				return false
			},
		},
		{
			Name:        "execution_errors_spike",
			Description: "Execution errors increase > 10% in last 60s",
			Severity:    "critical",
			Condition: func() bool {
				// TODO: Compare histograms from metrics registry
				return false
			},
		},
		{
			Name:        "scheduler_stalled",
			Description: "Scheduler ticks dropped below 0.5/sec",
			Severity:    "critical",
			Condition: func() bool {
				// TODO: Monitor scheduler tick frequency
				return false
			},
		},
	}
}
