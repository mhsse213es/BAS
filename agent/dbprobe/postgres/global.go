package postgres

import (
	"fmt"

	"audspect/agent/dbprobe"
)

// Read-only catalog reads for DB-02-05 (global privileges) and DB-02-06 (memberships).
// Fixed SQL, no parameters, no writes. Built-in pg_ roles are excluded so the lab's
// own roles are what the policy is compared against.
const (
	sqlGlobalPrivileges = "SELECT rolname::text, 'cluster'::text, 'SUPERUSER'::text FROM pg_roles WHERE rolsuper AND rolname NOT LIKE 'pg\\_%' " +
		"UNION ALL SELECT rolname::text, 'cluster'::text, 'CREATEDB'::text FROM pg_roles WHERE rolcreatedb AND rolname NOT LIKE 'pg\\_%' " +
		"UNION ALL SELECT rolname::text, 'cluster'::text, 'CREATEROLE'::text FROM pg_roles WHERE rolcreaterole AND rolname NOT LIKE 'pg\\_%' " +
		"UNION ALL SELECT rolname::text, 'cluster'::text, 'BYPASSRLS'::text FROM pg_roles WHERE rolbypassrls AND rolname NOT LIKE 'pg\\_%' " +
		"UNION ALL SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END::text, " +
		"'database:' || current_database()::text, a.privilege_type::text " +
		"FROM pg_database d CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a " +
		"WHERE d.datname = current_database() ORDER BY 1, 2, 3"
	sqlMemberships = "SELECT pg_get_userbyid(roleid)::text, pg_get_userbyid(member)::text, inherit_option " +
		"FROM pg_auth_members WHERE pg_get_userbyid(roleid) NOT LIKE 'pg\\_%' ORDER BY 1, 2"
)

// strictGlobalGrants converts read_global_privileges rows (role, scope, privilege).
// A malformed row fails the probe rather than being dropped.
func strictGlobalGrants(rows [][]any) ([]dbprobe.DBProbeGlobalGrant, error) {
	out := make([]dbprobe.DBProbeGlobalGrant, 0, len(rows))
	for i, r := range rows {
		if len(r) != 3 {
			return nil, fmt.Errorf("row %d has %d columns, want 3", i, len(r))
		}
		role, ok1 := r[0].(string)
		scope, ok2 := r[1].(string)
		priv, ok3 := r[2].(string)
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("row %d is not three text values", i)
		}
		out = append(out, dbprobe.DBProbeGlobalGrant{Role: role, Scope: scope, Privilege: priv})
	}
	return out, nil
}

// strictMemberships converts read_memberships rows (role, member, inherit).
func strictMemberships(rows [][]any) ([]dbprobe.DBProbeMembership, error) {
	out := make([]dbprobe.DBProbeMembership, 0, len(rows))
	for i, r := range rows {
		if len(r) != 3 {
			return nil, fmt.Errorf("row %d has %d columns, want 3", i, len(r))
		}
		role, ok1 := r[0].(string)
		member, ok2 := r[1].(string)
		inherit, ok3 := r[2].(bool)
		if !ok1 || !ok2 || !ok3 {
			return nil, fmt.Errorf("row %d is not two text values and a boolean", i)
		}
		out = append(out, dbprobe.DBProbeMembership{Role: role, Member: member, Inherit: inherit})
	}
	return out, nil
}
