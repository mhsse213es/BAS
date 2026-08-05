package notifications

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Insert(ctx context.Context, evt Event) error {
	metaJSON, err := json.Marshal(evt.Metadata)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`INSERT INTO notifications (type, job_id, target_id, agent_id, severity, message, metadata)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		string(evt.Type), evt.JobID, evt.TargetID, evt.AgentID, string(evt.Severity), evt.Message, metaJSON)
	return err
}

// ListFilter narrows GetNotifications results. Zero-value fields are
// unfiltered. Limit <= 0 is treated as the caller's responsibility --
// internal/api's handler is what clamps to a sane default/max.
type ListFilter struct {
	JobID    string
	Severity string
	Type     string
	Limit    int
	Offset   int
}

func (s *Store) List(ctx context.Context, f ListFilter) ([]Event, error) {
	where := "WHERE 1=1"
	args := []any{}
	argc := 1
	if f.JobID != "" {
		where += " AND job_id = $" + strconv.Itoa(argc)
		args = append(args, f.JobID)
		argc++
	}
	if f.Severity != "" {
		where += " AND severity = $" + strconv.Itoa(argc)
		args = append(args, f.Severity)
		argc++
	}
	if f.Type != "" {
		where += " AND type = $" + strconv.Itoa(argc)
		args = append(args, f.Type)
		argc++
	}
	args = append(args, f.Limit, f.Offset)

	rows, err := s.pool.Query(ctx,
		`SELECT id, type, job_id, target_id, agent_id, severity, message, metadata, created_at
		 FROM notifications `+where+`
		 ORDER BY created_at DESC
		 LIMIT $`+strconv.Itoa(argc)+` OFFSET $`+strconv.Itoa(argc+1),
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var typ, sev string
		var metaJSON []byte
		if err := rows.Scan(&e.ID, &typ, &e.JobID, &e.TargetID, &e.AgentID, &sev, &e.Message, &metaJSON, &e.Timestamp); err != nil {
			return nil, err
		}
		e.Type = EventType(typ)
		e.Severity = Severity(sev)
		_ = json.Unmarshal(metaJSON, &e.Metadata)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Webhook is one configured outbound notification target.
type Webhook struct {
	ID          string
	Name        string
	URL         string
	Secret      string
	MinSeverity string
	Enabled     bool
	CreatedAt   time.Time
}

func (s *Store) CreateWebhook(ctx context.Context, w Webhook) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx,
		`INSERT INTO notification_webhooks (name, url, secret, min_severity, enabled)
		 VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		w.Name, w.URL, w.Secret, w.MinSeverity, w.Enabled).Scan(&id)
	return id, err
}

func (s *Store) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	return s.queryWebhooks(ctx, `SELECT id, name, url, secret, min_severity, enabled, created_at FROM notification_webhooks ORDER BY created_at DESC`)
}

func (s *Store) ListEnabledWebhooks(ctx context.Context) ([]Webhook, error) {
	return s.queryWebhooks(ctx, `SELECT id, name, url, secret, min_severity, enabled, created_at FROM notification_webhooks WHERE enabled = true`)
}

func (s *Store) queryWebhooks(ctx context.Context, sql string) ([]Webhook, error) {
	rows, err := s.pool.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		var w Webhook
		if err := rows.Scan(&w.ID, &w.Name, &w.URL, &w.Secret, &w.MinSeverity, &w.Enabled, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) DeleteWebhook(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM notification_webhooks WHERE id = $1`, id)
	return err
}
