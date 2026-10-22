package postgres

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/jackc/pgx/v5"

	"audspect/agent/dbprobe"
)

// Fixed SQL. Nothing from a scenario or the server is ever spliced into these
// strings; values are bind parameters and identifiers go through quoteTable.
const (
	sqlClock     = "SELECT clock_timestamp()"
	sqlIdentity  = "SELECT system_identifier::text FROM pg_control_system()"
	sqlRoles     = "SELECT rolname::text, rolcanlogin, rolsuper FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' ORDER BY rolname"
	sqlAllGrants = "SELECT grantee::text, table_schema::text || '.' || table_name::text, privilege_type::text " +
		"FROM information_schema.role_table_grants " +
		"WHERE table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY 1, 2, 3"
	sqlRoleGrants = "SELECT grantee::text, table_schema::text || '.' || table_name::text, privilege_type::text " +
		"FROM information_schema.role_table_grants " +
		"WHERE table_schema NOT IN ('pg_catalog', 'information_schema') AND grantee::text = $1 ORDER BY 1, 2, 3"
	sqlAuthCheck = "SELECT current_user::text, session_user::text"
)

var (
	identPart = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	rolePat   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
	fixtureID = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
)

// validRole checks a role name used as a bind value.
func validRole(s string) error {
	if !rolePat.MatchString(s) {
		return fmt.Errorf("dbprobe/postgres: invalid role name")
	}
	return nil
}

// quoteTable validates "table" or "schema.table" against a strict pattern and
// returns it quoted via pgx.Identifier.
func quoteTable(s string) (string, error) {
	parts := splitDot(s)
	if len(parts) < 1 || len(parts) > 2 {
		return "", fmt.Errorf("dbprobe/postgres: invalid table identifier")
	}
	for _, p := range parts {
		if !identPart.MatchString(p) {
			return "", fmt.Errorf("dbprobe/postgres: invalid table identifier")
		}
	}
	return pgx.Identifier(parts).Sanitize(), nil
}

func splitDot(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

// checkParams enforces required params, declared names and ParamKind for def.
// ValidateSpec only checks names; this is the adapter-side enforcement.
func checkParams(def dbprobe.ProbeDef, params map[string]string) error {
	for k := range params {
		if _, ok := def.ParamSchema[k]; !ok {
			return fmt.Errorf("dbprobe/postgres: param %q not declared for probe %q", k, def.ID)
		}
	}
	for k, kind := range def.ParamSchema {
		v, ok := params[k]
		if !ok || v == "" {
			return fmt.Errorf("dbprobe/postgres: probe %q requires param %q", def.ID, k)
		}
		switch kind {
		case dbprobe.ParamInt:
			if _, err := strconv.Atoi(v); err != nil {
				return fmt.Errorf("dbprobe/postgres: param %q must be an integer", k)
			}
		case dbprobe.ParamBool:
			if _, err := strconv.ParseBool(v); err != nil {
				return fmt.Errorf("dbprobe/postgres: param %q must be a boolean", k)
			}
		case dbprobe.ParamString:
		default:
			return fmt.Errorf("dbprobe/postgres: param %q has unknown kind %q", k, kind)
		}
	}
	return nil
}

// probeSQL returns the fixed statement and bind args for a named probe.
func probeSQL(probeID string, params map[string]string, maxRows int) (string, []any, error) {
	switch probeID {
	case "read_roles":
		return sqlRoles, nil, nil
	case "read_grants":
		if err := validRole(params["role"]); err != nil {
			return "", nil, err
		}
		return sqlRoleGrants, []any{params["role"]}, nil
	case "auth_check":
		return sqlAuthCheck, nil, nil
	case "read_restricted_table":
		q, err := quoteTable(params["table"])
		if err != nil {
			return "", nil, err
		}
		return "SELECT 1 FROM " + q + " LIMIT $1", []any{maxRows + 1}, nil
	}
	return "", nil, fmt.Errorf("dbprobe/postgres: unsupported probe %q", probeID)
}
