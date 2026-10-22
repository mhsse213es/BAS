package mysql

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"audspect/agent/dbprobe"
)

// Fixed SQL. Nothing from a scenario or the server is ever spliced into these
// strings; values are bind parameters and identifiers go through quoteTable.
// The marker comment is prefixed by the adapter, never stored here.
const (
	sqlClock    = "SELECT UTC_TIMESTAMP(6)"
	sqlIdentity = "SELECT @@server_uuid"
	// mysql.user is readable only with the matching privilege; if it is not,
	// the probe reports the denial instead of guessing.
	sqlRoles = "SELECT `User`, `Host`, (`account_locked` = 'N'), (`Super_priv` = 'Y') " +
		"FROM mysql.user WHERE `User` NOT LIKE 'mysql.%' ORDER BY `User`, `Host`"
	sqlAllGrants = "SELECT GRANTEE, CONCAT(TABLE_SCHEMA, '.', TABLE_NAME), PRIVILEGE_TYPE " +
		"FROM information_schema.TABLE_PRIVILEGES " +
		"WHERE TABLE_SCHEMA NOT IN ('mysql', 'sys', 'information_schema', 'performance_schema') ORDER BY 1, 2, 3"
	sqlRoleGrants = "SELECT GRANTEE, CONCAT(TABLE_SCHEMA, '.', TABLE_NAME), PRIVILEGE_TYPE " +
		"FROM information_schema.TABLE_PRIVILEGES " +
		"WHERE TABLE_SCHEMA NOT IN ('mysql', 'sys', 'information_schema', 'performance_schema') " +
		"AND SUBSTRING_INDEX(GRANTEE, '@', 1) = CONCAT('''', ?, '''') ORDER BY 1, 2, 3"
	sqlAuthCheck = "SELECT CURRENT_USER(), USER()"

	sqlSchemaExists = "SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?"
	sqlUserExists   = "SELECT 1 FROM mysql.user WHERE `User` = ?"
)

var (
	// identPart is one MySQL identifier part (max 64). Letters, digits, '_'.
	// Backticks, quotes, whitespace, control characters and '.' never match.
	identPart = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	rolePat   = regexp.MustCompile(`^[A-Za-z0-9_]{1,32}$`)
	// fixtureID is lower-case after normalisation. "dbsim_" + id + "_ro" must
	// fit MySQL's 32 character user name limit, hence at most 20.
	fixtureID = regexp.MustCompile(`^[a-z0-9_]{1,20}$`)
)

// validRole checks a user name used as a bind value.
func validRole(s string) error {
	if !rolePat.MatchString(s) {
		return fmt.Errorf("dbprobe/mysql: invalid role name")
	}
	return nil
}

// quoteIdent validates one identifier part and wraps it in backticks. It is
// the only way an identifier reaches SQL text.
func quoteIdent(s string) (string, error) {
	if !identPart.MatchString(s) || strings.ContainsAny(s, "`\x00") {
		return "", fmt.Errorf("dbprobe/mysql: invalid identifier")
	}
	return "`" + s + "`", nil
}

// quoteTable validates "table" or "schema.table" and returns it quoted.
func quoteTable(s string) (string, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 2 {
		return "", fmt.Errorf("dbprobe/mysql: invalid table identifier")
	}
	q := make([]string, 0, 2)
	for _, p := range parts {
		qi, err := quoteIdent(p)
		if err != nil {
			return "", fmt.Errorf("dbprobe/mysql: invalid table identifier")
		}
		q = append(q, qi)
	}
	return strings.Join(q, "."), nil
}

// parseGrantee turns 'user'@'host' into "user" (host '%') or "user@host".
func parseGrantee(g string) string {
	if len(g) >= 5 && g[0] == '\'' {
		if i := strings.Index(g, "'@'"); i > 0 && strings.HasSuffix(g, "'") {
			user, host := g[1:i], g[i+3:len(g)-1]
			if host == "%" {
				return user
			}
			return user + "@" + host
		}
	}
	return g
}

// checkParams enforces required params, declared names and ParamKind for def.
// ValidateSpec only checks names; this is the adapter-side enforcement.
func checkParams(def dbprobe.ProbeDef, params map[string]string) error {
	for k := range params {
		if _, ok := def.ParamSchema[k]; !ok {
			return fmt.Errorf("dbprobe/mysql: param %q not declared for probe %q", k, def.ID)
		}
	}
	for k, kind := range def.ParamSchema {
		v, ok := params[k]
		if !ok || v == "" {
			return fmt.Errorf("dbprobe/mysql: probe %q requires param %q", def.ID, k)
		}
		switch kind {
		case dbprobe.ParamInt:
			if _, err := strconv.Atoi(v); err != nil {
				return fmt.Errorf("dbprobe/mysql: param %q must be an integer", k)
			}
		case dbprobe.ParamBool:
			if _, err := strconv.ParseBool(v); err != nil {
				return fmt.Errorf("dbprobe/mysql: param %q must be a boolean", k)
			}
		case dbprobe.ParamString:
		default:
			return fmt.Errorf("dbprobe/mysql: param %q has unknown kind %q", k, kind)
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
		return "SELECT 1 FROM " + q + " LIMIT ?", []any{maxRows + 1}, nil
	}
	return "", nil, fmt.Errorf("dbprobe/mysql: unsupported probe %q", probeID)
}
