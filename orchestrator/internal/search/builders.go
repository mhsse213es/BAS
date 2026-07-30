package search

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/intelligence"
	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/scenario"
)

// scenariosFrom maps every loaded scenario into a Document. Scenarios are
// file-backed (scenario.Engine), not a Postgres table -- no query needed,
// engine.List() is already in memory.
func scenariosFrom(engine *scenario.Engine) []Document {
	list := engine.List()
	out := make([]Document, 0, len(list))
	for _, s := range list {
		tags := make([]string, 0, len(s.Tags)+len(s.MITREPhases)+len(s.ARTTechniques))
		tags = append(tags, s.Tags...)
		tags = append(tags, s.MITREPhases...)
		tags = append(tags, s.ARTTechniques...)
		out = append(out, Document{
			DocType: "scenario", SourceID: s.ID, Title: s.Name,
			Description: s.Description, Tags: tags,
		})
	}
	return out
}

// runsFrom maps every scenario_runs row into a Document. Title falls back
// to scenario_id when name is empty, matching the existing UI convention
// (e.g. cmd/server/wwwroot/index.html's `r.name || r.scenarioId`).
func runsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT id, scenario_id, name, status FROM scenario_runs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, scenarioID, name, status string
		if err := rows.Scan(&id, &scenarioID, &name, &status); err != nil {
			return nil, err
		}
		title := name
		if title == "" {
			title = scenarioID
		}
		out = append(out, Document{
			DocType: "run", SourceID: id, Title: title,
			Description: status, Tags: []string{status},
		})
	}
	return out, rows.Err()
}

// findingsFrom maps every findings row into a Document. Title falls back
// to technique_id when technique_name is empty.
func findingsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, technique_id, technique_name, control_class, severity, exposure_state, status FROM findings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, techID, techName, controlClass, severity, exposureState, status string
		if err := rows.Scan(&id, &techID, &techName, &controlClass, &severity, &exposureState, &status); err != nil {
			return nil, err
		}
		title := techName
		if title == "" {
			title = techID
		}
		out = append(out, Document{
			DocType: "finding", SourceID: id, Title: title,
			Description: severity + " " + exposureState,
			Tags:        []string{controlClass, severity, status},
		})
	}
	return out, rows.Err()
}

// actorsFrom maps every threat_actor_profiles row into a Document.
func actorsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT name, aliases, sectors, regions FROM threat_actor_profiles`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var name string
		var aliases, sectors, regions []string
		if err := rows.Scan(&name, &aliases, &sectors, &regions); err != nil {
			return nil, err
		}
		tags := make([]string, 0, len(aliases)+len(sectors)+len(regions))
		tags = append(tags, aliases...)
		tags = append(tags, sectors...)
		tags = append(tags, regions...)
		out = append(out, Document{DocType: "actor", SourceID: name, Title: name, Tags: tags})
	}
	return out, rows.Err()
}

// campaignsFrom reuses internal/intelligence.ListCampaigns rather than
// re-deriving its query logic.
func campaignsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	campaigns, err := intelligence.ListCampaigns(ctx, pool)
	if err != nil {
		return nil, err
	}
	out := make([]Document, 0, len(campaigns))
	for _, c := range campaigns {
		out = append(out, Document{
			DocType: "campaign", SourceID: c.ID, Title: c.Name,
			Description: c.Description, Tags: c.Aliases,
		})
	}
	return out, nil
}

// malwareFrom reuses internal/intelligence.ListMalware.
func malwareFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	malware, err := intelligence.ListMalware(ctx, pool)
	if err != nil {
		return nil, err
	}
	out := make([]Document, 0, len(malware))
	for _, m := range malware {
		tags := make([]string, 0, len(m.Aliases)+len(m.MalwareTypes))
		tags = append(tags, m.Aliases...)
		tags = append(tags, m.MalwareTypes...)
		out = append(out, Document{DocType: "malware", SourceID: m.ID, Title: m.Name, Tags: tags})
	}
	return out, nil
}

// toolsFrom reuses internal/intelligence.ListTools.
func toolsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	tools, err := intelligence.ListTools(ctx, pool)
	if err != nil {
		return nil, err
	}
	out := make([]Document, 0, len(tools))
	for _, t := range tools {
		out = append(out, Document{DocType: "tool", SourceID: t.ID, Title: t.Name, Tags: t.Aliases})
	}
	return out, nil
}

// techniquesFrom maps every techniques row into a Document. Title includes
// both the ID and the name (e.g. "T1059.001 PowerShell") so either
// independently matches a search query.
func techniquesFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT technique_id, name, tactic, description FROM techniques`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, name, tactic, description string
		if err := rows.Scan(&id, &name, &tactic, &description); err != nil {
			return nil, err
		}
		title := id
		if name != "" {
			title = id + " " + name
		}
		out = append(out, Document{
			DocType: "technique", SourceID: id, Title: title,
			Description: description, Tags: []string{tactic},
		})
	}
	return out, rows.Err()
}

// rulesFrom maps every embedded Sigma rule into a Document. engine may be
// nil if the caller never attached a rule library (mirrors h.rules'
// nil-when-unloaded convention in internal/api.Handler) -- returns no
// documents rather than panicking.
func rulesFrom(engine *rulelib.Engine) []Document {
	if engine == nil {
		return nil
	}
	rules := engine.Search(rulelib.SearchFilter{}) // empty filter = every rule, same call ListRules already makes
	out := make([]Document, 0, len(rules))
	for _, r := range rules {
		out = append(out, Document{
			DocType: "rule", SourceID: r.ID, Title: r.Title,
			Description: r.Description,
			Tags:        append([]string{r.Severity, r.Status}, r.TechniqueIDs...),
		})
	}
	return out
}

// complianceControlsFrom maps every control across every loaded compliance
// framework into a Document. mapper may be nil (WithCompliance was never
// called, or compliance.NewMapper() failed at startup) -- returns no
// documents rather than erroring, matching how h.complianceMapper == nil is
// already handled throughout internal/api's compliance handlers.
func complianceControlsFrom(mapper *compliance.Mapper) []Document {
	if mapper == nil {
		return nil
	}
	out := []Document{}
	for _, cwf := range mapper.AllControls() {
		tags := append([]string{cwf.FrameworkID, cwf.Control.Domain, cwf.Control.Category}, cwf.Control.Techniques...)
		out = append(out, Document{
			DocType:     "compliance_control",
			SourceID:    cwf.FrameworkID + ":" + cwf.Control.ID, // namespaced -- the same control ID can recur across frameworks
			Title:       cwf.Control.Name,
			Description: cwf.Control.Domain + " · " + cwf.Control.Category,
			Tags:        tags,
		})
	}
	return out
}

// detectionConnectorsFrom maps every detection_connectors row into a
// Document. Selects only id/name/provider -- never client_secret/api_token/
// tenant_id/base_url/workspace_id, matching the same restraint
// ListDetectionConnectors's own SELECT already exercises.
func detectionConnectorsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT id, name, provider FROM detection_connectors`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, name, provider string
		if err := rows.Scan(&id, &name, &provider); err != nil {
			return nil, err
		}
		out = append(out, Document{
			DocType: "detection_connector", SourceID: id, Title: name,
			Description: "provider: " + provider, Tags: []string{provider},
		})
	}
	return out, rows.Err()
}

// actionConnectorsFrom mirrors detectionConnectorsFrom for action_connectors
// (EPP response-action connectors) -- deliberately a separate function
// since the two tables are gated by different RBAC permissions at the
// Search handler layer (CanListResponseConnectors vs
// CanListDetectionConnectors) and may diverge in columns later.
func actionConnectorsFrom(ctx context.Context, pool *pgxpool.Pool) ([]Document, error) {
	rows, err := pool.Query(ctx, `SELECT id, name, provider FROM action_connectors`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Document
	for rows.Next() {
		var id, name, provider string
		if err := rows.Scan(&id, &name, &provider); err != nil {
			return nil, err
		}
		out = append(out, Document{
			DocType: "action_connector", SourceID: id, Title: name,
			Description: "provider: " + provider, Tags: []string{provider},
		})
	}
	return out, rows.Err()
}
