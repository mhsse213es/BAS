// Package schemacheck fingerprints a PostgreSQL schema from the catalog so two
// schemas can be compared regardless of column order or schema qualifiers
// (H1 spec 4.2). Used by migrate adoption and the baseline equivalence test.
package schemacheck

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Object is one schema object; Detail is its normalized definition.
type Object struct{ Kind, Name, Detail string }

// Fingerprint maps Kind + "/" + Name to its Object.
type Fingerprint map[string]Object

// Querier is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

var queries = []struct{ kind, sql string }{
	{"table", `SELECT c.relname, c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind IN ('r','p')`},
	{"column", `SELECT c.relname || '.' || a.attname,
		format_type(a.atttypid, a.atttypmod) || ' notnull=' || a.attnotnull || ' default=' || coalesce(pg_get_expr(d.adbin, d.adrelid), '') ||
		' identity=' || a.attidentity::text || ' generated=' || a.attgenerated::text
		FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE n.nspname = $1 AND c.relkind IN ('r','p') AND a.attnum > 0 AND NOT a.attisdropped`},
	{"constraint", `SELECT c.relname || '.' || con.conname, con.contype::text || ' ' || pg_get_constraintdef(con.oid)
		FROM pg_constraint con JOIN pg_class c ON c.oid = con.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1`},
	{"index", `SELECT i.relname, pg_get_indexdef(i.oid)
		FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_namespace n ON n.oid = i.relnamespace
		WHERE n.nspname = $1 AND NOT EXISTS (SELECT 1 FROM pg_constraint con WHERE con.conindid = i.oid)`},
	{"sequence", `SELECT c.relname, format_type(s.seqtypid, NULL) || ' ' || s.seqstart || ' ' || s.seqincrement || ' ' || s.seqmin || ' ' || s.seqmax || ' ' || s.seqcache || ' ' || s.seqcycle
		FROM pg_sequence s JOIN pg_class c ON c.oid = s.seqrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1`},
	{"function", `SELECT p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')', pg_get_functiondef(p.oid)
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = $1 AND p.prokind IN ('f','p')
		AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')`},
	{"trigger", `SELECT c.relname || '.' || t.tgname, pg_get_triggerdef(t.oid)
		FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND NOT t.tgisinternal`},
	// Extensions are database-wide; $1 is only bound to keep one call shape.
	{"extension", `SELECT extname, extversion FROM pg_extension WHERE $1::text IS NOT NULL`},
}

// Take fingerprints schema. Schema qualifiers ("schema". / schema. / public.)
// are removed from every definition, so the same object compares equal across
// schemas; column order is never part of the fingerprint.
func Take(ctx context.Context, q Querier, schema string) (Fingerprint, error) {
	s := regexp.QuoteMeta(schema)
	strip := regexp.MustCompile(`(?:"(?:` + s + `|public)"|\b(?:` + s + `|public))\.`)
	fp := Fingerprint{}
	for _, qq := range queries {
		rows, err := q.Query(ctx, qq.sql, schema)
		if err != nil {
			return nil, fmt.Errorf("schemacheck %s: %w", qq.kind, err)
		}
		for rows.Next() {
			var name, detail string
			if err := rows.Scan(&name, &detail); err != nil {
				rows.Close()
				return nil, fmt.Errorf("schemacheck %s: %w", qq.kind, err)
			}
			detail = strings.Join(strings.Fields(strip.ReplaceAllString(detail, "")), " ")
			fp[qq.kind+"/"+name] = Object{Kind: qq.kind, Name: name, Detail: detail}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("schemacheck %s: %w", qq.kind, err)
		}
	}
	return fp, nil
}

// Diff compares got against want. missing: in want only; different: in both
// with another definition; extra: in got only. Each slice is sorted by key.
func Diff(want, got Fingerprint) (missing, different, extra []Object) {
	for k, w := range want {
		g, ok := got[k]
		switch {
		case !ok:
			missing = append(missing, w)
		case g.Detail != w.Detail:
			different = append(different, Object{Kind: w.Kind, Name: w.Name, Detail: "want: " + w.Detail + " | got: " + g.Detail})
		}
	}
	for k, g := range got {
		if _, ok := want[k]; !ok {
			extra = append(extra, g)
		}
	}
	for _, s := range [][]Object{missing, different, extra} {
		sort.Slice(s, func(i, j int) bool { return s[i].Kind+"/"+s[i].Name < s[j].Kind+"/"+s[j].Name })
	}
	return missing, different, extra
}
