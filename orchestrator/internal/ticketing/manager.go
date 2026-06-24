package ticketing

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/findings"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// Manager loads connector configs from the database, dispatches ticket
// operations on finding state transitions, and runs a background sync loop
// that polls open tickets for status changes every 15 minutes.
type Manager struct {
	db   *pgxpool.Pool
	mu   sync.RWMutex
	cfgs map[string]*Config
	cons map[string]Connector
}

// NewManager creates a Manager. Call Start after the DB schema is ready.
func NewManager(db *pgxpool.Pool) *Manager {
	return &Manager{
		db:   db,
		cfgs: map[string]*Config{},
		cons: map[string]Connector{},
	}
}

// Start loads active connectors and begins the background sync loop.
func (m *Manager) Start(ctx context.Context) {
	if err := m.reload(ctx); err != nil {
		log.Printf("[ticketing] initial config load: %v", err)
	}
	go m.syncLoop(ctx)
}

// Reload re-reads all connector configs from the database.
// Call after any CRUD on ticketing_configs.
func (m *Manager) Reload(ctx context.Context) error {
	return m.reload(ctx)
}

func (m *Manager) reload(ctx context.Context) error {
	rows, err := m.db.Query(ctx,
		`SELECT id, name, provider, enabled, auto_create, auto_update, auto_close, settings
		   FROM ticketing_configs ORDER BY created_at`)
	if err != nil {
		return err
	}
	defer rows.Close()

	cfgs := map[string]*Config{}
	cons := map[string]Connector{}
	for rows.Next() {
		var c Config
		var settingsRaw []byte
		if err := rows.Scan(&c.ID, &c.Name, &c.Provider, &c.Enabled,
			&c.AutoCreate, &c.AutoUpdate, &c.AutoClose, &settingsRaw); err != nil {
			continue
		}
		if c.Settings == nil {
			c.Settings = map[string]string{}
		}
		_ = json.Unmarshal(settingsRaw, &c.Settings)
		cfgs[c.ID] = &c
		if c.Enabled {
			if con := buildConnector(&c); con != nil {
				cons[c.ID] = con
			}
		}
	}
	m.mu.Lock()
	m.cfgs = cfgs
	m.cons = cons
	m.mu.Unlock()
	return nil
}

func buildConnector(c *Config) Connector {
	switch c.Provider {
	case "servicenow":
		return newServiceNow(c.Settings)
	case "jira":
		return newJira(c.Settings)
	case "webhook":
		return newWebhook(c.Settings)
	}
	return nil
}

// Dispatch fires ticket operations asynchronously after a finding state
// transition. Never blocks the BAS result-ingest pipeline.
func (m *Manager) Dispatch(findingID string, transition findings.Transition) {
	m.mu.RLock()
	if len(m.cons) == 0 {
		m.mu.RUnlock()
		return
	}
	cfgs := make(map[string]*Config, len(m.cfgs))
	cons := make(map[string]Connector, len(m.cons))
	for k, v := range m.cfgs {
		cfgs[k] = v
	}
	for k, v := range m.cons {
		cons[k] = v
	}
	m.mu.RUnlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		f, err := m.enrichFinding(ctx, findingID)
		if err != nil {
			log.Printf("[ticketing] enrich %s: %v", findingID, err)
			return
		}
		for configID, con := range cons {
			m.dispatchOne(ctx, cfgs[configID], con, findingID, transition, f)
		}
	}()
}

func (m *Manager) dispatchOne(ctx context.Context, cfg *Config, con Connector,
	findingID string, transition findings.Transition, f TicketFinding) {

	switch transition {
	case findings.Created:
		if !m.shouldAutoCreate(cfg, f.Severity) {
			return
		}
		_, _ = m.createTicketRecord(ctx, cfg, con, findingID, f, RecordIncident)

	case findings.Recurred, findings.Refined:
		if !cfg.AutoUpdate {
			return
		}
		ticketID := m.existingOpenTicket(ctx, findingID, cfg.ID)
		if ticketID == "" {
			return
		}
		comment := fmt.Sprintf(
			"BAS re-observation (%s): technique still %s.\nOccurrences: %d | Days exposed: %d | Run: %s",
			time.Now().Format("2006-01-02"), f.ExposureState, f.OccurrenceCount, f.DaysExposed, f.LastRunID)
		if err := con.AddComment(ctx, ticketID, comment); err != nil {
			log.Printf("[ticketing] add comment %s/%s: %v", cfg.Provider, ticketID, err)
		}

	case findings.Healed:
		if !cfg.AutoClose {
			return
		}
		ticketID := m.existingOpenTicket(ctx, findingID, cfg.ID)
		if ticketID == "" {
			return
		}
		if err := con.CloseTicket(ctx, ticketID); err != nil {
			log.Printf("[ticketing] close %s/%s: %v", cfg.Provider, ticketID, err)
			return
		}
		m.setTicketStatus(ctx, findingID, cfg.ID, "resolved")

	case findings.Reopened:
		ticketID := m.existingOpenTicket(ctx, findingID, cfg.ID)
		if ticketID == "" {
			return
		}
		if err := con.ReopenTicket(ctx, ticketID); err != nil {
			log.Printf("[ticketing] reopen %s/%s: %v", cfg.Provider, ticketID, err)
			return
		}
		m.setTicketStatus(ctx, findingID, cfg.ID, "open")
	}
}

func (m *Manager) shouldAutoCreate(cfg *Config, sev string) bool {
	switch cfg.AutoCreate {
	case "all":
		return true
	case "critical_high":
		return sev == "Critical" || sev == "High"
	case "critical":
		return sev == "Critical"
	default:
		return false
	}
}

// PushFinding manually creates a ticket for a finding in the given connector.
// If a ticket already exists, returns the existing ref without creating a duplicate.
func (m *Manager) PushFinding(ctx context.Context, configID, findingID string, rt RecordType) (TicketRef, error) {
	m.mu.RLock()
	con, conOK := m.cons[configID]
	cfg, cfgOK := m.cfgs[configID]
	m.mu.RUnlock()
	if !conOK || !cfgOK {
		return TicketRef{}, fmt.Errorf("ticketing: connector %q not found or disabled", configID)
	}

	// Deduplication: return the existing ticket if one is open.
	existingID := m.existingOpenTicket(ctx, findingID, configID)
	if existingID != "" {
		var url string
		_ = m.db.QueryRow(ctx,
			`SELECT ticket_url FROM finding_tickets WHERE finding_id=$1 AND config_id=$2`,
			findingID, configID).Scan(&url)
		return TicketRef{TicketID: existingID, TicketURL: url}, nil
	}

	f, err := m.enrichFinding(ctx, findingID)
	if err != nil {
		return TicketRef{}, fmt.Errorf("ticketing: enrich finding: %w", err)
	}
	return m.createTicketRecord(ctx, cfg, con, findingID, f, rt)
}

func (m *Manager) createTicketRecord(ctx context.Context, cfg *Config, con Connector,
	findingID string, f TicketFinding, rt RecordType) (TicketRef, error) {
	ref, err := con.CreateTicket(ctx, f, rt)
	if err != nil {
		return TicketRef{}, fmt.Errorf("%s create: %w", cfg.Provider, err)
	}
	_, _ = m.db.Exec(ctx,
		`INSERT INTO finding_tickets (finding_id, config_id, ticket_id, ticket_url, status)
		 VALUES ($1,$2,$3,$4,'open')
		 ON CONFLICT (finding_id, config_id) DO UPDATE
		   SET ticket_id=$3, ticket_url=$4, status='open', last_synced_at=NOW()`,
		findingID, cfg.ID, ref.TicketID, ref.TicketURL)
	return ref, nil
}

// TestConnector verifies connection for the given config ID.
func (m *Manager) TestConnector(ctx context.Context, configID string) error {
	m.mu.RLock()
	con, ok := m.cons[configID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("connector not loaded — check that it is enabled and credentials are set")
	}
	return con.TestConnection(ctx)
}

// ListTicketsForFinding returns all ticket references for a finding.
func (m *Manager) ListTicketsForFinding(ctx context.Context, findingID string) ([]map[string]any, error) {
	rows, err := m.db.Query(ctx,
		`SELECT ft.id, ft.config_id, tc.name, tc.provider,
		        ft.ticket_id, ft.ticket_url, ft.status,
		        ft.revalidation_required, ft.created_at
		   FROM finding_tickets ft
		   JOIN ticketing_configs tc ON tc.id = ft.config_id
		  WHERE ft.finding_id = $1 ORDER BY ft.created_at`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, configID, name, provider, ticketID, ticketURL, status string
		var revalRequired bool
		var createdAt time.Time
		if rows.Scan(&id, &configID, &name, &provider, &ticketID, &ticketURL,
			&status, &revalRequired, &createdAt) != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "configId": configID, "connectorName": name, "provider": provider,
			"ticketId": ticketID, "ticketUrl": ticketURL, "status": status,
			"revalidationRequired": revalRequired, "createdAt": createdAt,
		})
	}
	return out, nil
}

// Candidates returns open/triaged findings that have no active open ticket.
// These are displayed in the "Ticket Candidates" panel for analyst review.
func (m *Manager) Candidates(ctx context.Context) ([]map[string]any, error) {
	rows, err := m.db.Query(ctx,
		`SELECT f.id, f.technique_id, f.technique_name, f.tactic, f.severity,
		        f.exposure_state, f.control_class, f.agent_id, f.occurrence_count,
		        f.first_seen, f.last_seen, f.status,
		        EXTRACT(DAY FROM NOW() - f.first_seen)::int AS days_exposed
		   FROM findings f
		  WHERE f.status IN ('open','triaged')
		    AND NOT EXISTS (
		        SELECT 1 FROM finding_tickets ft
		         WHERE ft.finding_id = f.id AND ft.status = 'open'
		    )
		  ORDER BY CASE f.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1
		                           WHEN 'Medium' THEN 2 ELSE 3 END,
		           f.last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, techID, name, tactic, sev, exposure, control, agentID, status string
		var occ, days int
		var firstSeen, lastSeen time.Time
		if rows.Scan(&id, &techID, &name, &tactic, &sev, &exposure, &control,
			&agentID, &occ, &firstSeen, &lastSeen, &status, &days) != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "techniqueId": techID, "techniqueName": name, "tactic": tactic,
			"severity": sev, "exposureState": exposure, "controlClass": control,
			"agentId": agentID, "occurrenceCount": occ,
			"firstSeen": firstSeen, "lastSeen": lastSeen, "status": status,
			"daysExposed": days,
		})
	}
	return out, nil
}

// syncLoop polls all open tickets for status changes every 15 minutes.
func (m *Manager) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.syncAll(ctx)
		}
	}
}

// SyncNow triggers an immediate sync cycle (admin manual trigger).
func (m *Manager) SyncNow(ctx context.Context) {
	go m.syncAll(ctx)
}

func (m *Manager) syncAll(ctx context.Context) {
	rows, err := m.db.Query(ctx,
		`SELECT ft.id, ft.finding_id, ft.config_id, ft.ticket_id
		   FROM finding_tickets ft
		  WHERE ft.status = 'open'
		    AND (ft.last_synced_at IS NULL OR ft.last_synced_at < NOW() - INTERVAL '14 minutes')
		  LIMIT 200`)
	if err != nil {
		return
	}
	type pending struct{ id, findingID, configID, ticketID string }
	var todos []pending
	for rows.Next() {
		var p pending
		if rows.Scan(&p.id, &p.findingID, &p.configID, &p.ticketID) == nil {
			todos = append(todos, p)
		}
	}
	rows.Close()

	m.mu.RLock()
	cons := make(map[string]Connector, len(m.cons))
	for k, v := range m.cons {
		cons[k] = v
	}
	m.mu.RUnlock()

	for _, p := range todos {
		con, ok := cons[p.configID]
		if !ok {
			continue
		}
		syncCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		status, err := con.GetStatus(syncCtx, p.ticketID)
		cancel()
		if err != nil {
			log.Printf("[ticketing] sync %s: %v", p.ticketID, err)
			continue
		}
		reval := status == "resolved"
		_, _ = m.db.Exec(ctx,
			`UPDATE finding_tickets
			    SET status=$1, revalidation_required=$2, last_synced_at=NOW()
			  WHERE id=$3`, status, reval, p.id)
	}
}

// enrichFinding loads a finding from DB and attaches agent hostname + ATT&CK
// mitigations. Called in the async dispatch goroutine.
func (m *Manager) enrichFinding(ctx context.Context, findingID string) (TicketFinding, error) {
	var f TicketFinding
	var days int
	err := m.db.QueryRow(ctx,
		`SELECT f.technique_id, f.technique_name, f.tactic, f.severity,
		        f.exposure_state, f.control_class, f.agent_id,
		        f.occurrence_count, f.first_seen, f.last_seen,
		        COALESCE(f.last_run_id,''),
		        COALESCE(a.hostname, f.agent_id),
		        EXTRACT(DAY FROM NOW() - f.first_seen)::int
		   FROM findings f
		   LEFT JOIN agents a ON a.agent_id = f.agent_id
		  WHERE f.id = $1`, findingID).
		Scan(&f.TechniqueID, &f.TechniqueName, &f.Tactic, &f.Severity,
			&f.ExposureState, &f.ControlClass, &f.AgentID,
			&f.OccurrenceCount, &f.FirstSeen, &f.LastSeen, &f.LastRunID,
			&f.AgentHostname, &days)
	if err != nil {
		return TicketFinding{}, fmt.Errorf("finding %s: %w", findingID, err)
	}
	f.FindingID = findingID
	f.DaysExposed = days
	if e := attackdata.Lookup(f.TechniqueID); e != nil {
		for _, mit := range e.Mitigations {
			f.Mitigations = append(f.Mitigations, MitigationRef{
				Name:        mit.Name,
				Description: mit.Description,
			})
		}
	}
	return f, nil
}

func (m *Manager) existingOpenTicket(ctx context.Context, findingID, configID string) string {
	var ticketID string
	_ = m.db.QueryRow(ctx,
		`SELECT ticket_id FROM finding_tickets
		  WHERE finding_id=$1 AND config_id=$2 AND status='open'`,
		findingID, configID).Scan(&ticketID)
	return ticketID
}

func (m *Manager) setTicketStatus(ctx context.Context, findingID, configID, status string) {
	_, _ = m.db.Exec(ctx,
		`UPDATE finding_tickets SET status=$1, last_synced_at=NOW()
		  WHERE finding_id=$2 AND config_id=$3`, status, findingID, configID)
}

// ActiveConfigs returns all configs (masked) for API responses.
func (m *Manager) ActiveConfigs() []Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Config, 0, len(m.cfgs))
	for _, c := range m.cfgs {
		out = append(out, c.MaskedConfig())
	}
	return out
}
