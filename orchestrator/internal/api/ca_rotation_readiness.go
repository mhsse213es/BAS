package api

import (
	"context"
	"path/filepath"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/pki"
)

// RotationQuerier is the slice of a database pool the readiness check needs.
type RotationQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// RotationReadiness says how far the fleet is through the current CA rotation step.
type RotationReadiness struct {
	// Step is what the readiness is for: "promote" while a rotation is prepared, "retire" once it is promoted.
	Step    string
	Total   int
	Done    int
	Pending []string
	// Ready is true only when every agent that can still connect is done. Zero agents is not ready.
	Ready bool
	// Marker is the new root fingerprint (promote) or the new CA's key id (retire).
	Marker string
}

// CARotationReadiness reports, for a prepared or promoted rotation, how many agents are done: for promote, trust
// the new root; for retire, present a certificate the new CA signed. An agent whose issuer is unknown counts as
// pending, never as safe. Revoked and uninstalling agents are not counted. For any other state it returns
// ok=false: there is nothing to be ready for.
func CARotationReadiness(ctx context.Context, q RotationQuerier, pkiDir string, state pki.RotationState) (RotationReadiness, bool, error) {
	var out RotationReadiness
	var marker, query string
	switch state {
	case pki.RotationPrepared:
		fp, err := pemFingerprint(filepath.Join(pkiDir, "next-ca-cert.pem"))
		if err != nil {
			return out, false, err
		}
		out.Step, marker = "promote", fp
		query = `SELECT agent_id, COALESCE(trusted_root_fps, '[]'::jsonb) ? $1
		           FROM agents
		          WHERE COALESCE(state,'active') NOT IN ('revoked','uninstalling','uninstalled')
		          ORDER BY agent_id`
	case pki.RotationPromoted:
		id, err := caKeyID(filepath.Join(pkiDir, "ca-cert.pem"))
		if err != nil {
			return out, false, err
		}
		out.Step, marker = "retire", id
		query = `SELECT agent_id, COALESCE(cert_issuer_key_id,'') = $1
		           FROM agents
		          WHERE COALESCE(state,'active') NOT IN ('revoked','uninstalling','uninstalled')
		          ORDER BY agent_id`
	default:
		return out, false, nil
	}
	rows, err := q.Query(ctx, query, marker)
	if err != nil {
		return out, false, err
	}
	defer rows.Close()
	out.Marker, out.Pending = marker, []string{}
	for rows.Next() {
		var id string
		var done bool
		if rows.Scan(&id, &done) != nil {
			continue
		}
		out.Total++
		if done {
			out.Done++
		} else {
			out.Pending = append(out.Pending, id)
		}
	}
	if err := rows.Err(); err != nil {
		return out, false, err
	}
	out.Ready = out.Total > 0 && out.Done == out.Total
	return out, true, nil
}
