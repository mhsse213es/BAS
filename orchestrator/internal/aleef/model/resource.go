package model

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Resource types.
//
// A resource type is a short lower-case noun naming the kind of object an
// identifier refers to ("order", "invoice"). It is derived, deterministically,
// from the OpenAPI document alone:
//
//   - a path parameter named like <stem>Id, <stem>_id (also Ref/_ref) takes
//     the type <stem> (snake case, lower case);
//   - any other path parameter (a bare "id", "cid", ...) takes the singular
//     stem of the literal path segment right before it;
//   - a collection operation (path ending in a literal segment) creates
//     objects of the singular stem of that segment.
//
// Singularisation is a fixed, small rule set: "ies" -> "y", "sses" -> "ss",
// a trailing single "s" is dropped, anything else is unchanged.

// ResourceStem returns the lower-case singular stem of a literal path segment.
func ResourceStem(seg string) string {
	s := strings.ToLower(strings.TrimSpace(seg))
	s = nonAlnumRun.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	switch {
	case len(s) > 3 && strings.HasSuffix(s, "ies"):
		return s[:len(s)-3] + "y"
	case len(s) > 4 && strings.HasSuffix(s, "sses"):
		return s[:len(s)-2]
	case len(s) > 1 && strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss"):
		return s[:len(s)-1]
	}
	return s
}

var (
	nonAlnumRun = regexp.MustCompile(`[^a-z0-9]+`)
	idSuffix    = regexp.MustCompile(`^(.+?)(?:_id|_ref|Id|Ref)$`)
)

// NameStem returns the resource type an identifier-like name refers to
// ("accountId" -> "account", "account_id" -> "account"), or "" for a bare
// "id" or a name without an id suffix.
func NameStem(name string) string {
	m := idSuffix.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return snake(m[1])
}

func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
			continue
		}
		b.WriteRune(r)
	}
	out := nonAlnumRun.ReplaceAllString(b.String(), "_")
	return strings.Trim(out, "_")
}

// paramResourceType derives the resource type of path parameter name whose
// preceding literal segment is prev ("" when there is none).
func paramResourceType(name, prev string) string {
	if s := NameStem(name); s != "" {
		return s
	}
	if prev == "" {
		return ""
	}
	return ResourceStem(prev)
}

// PrimaryType is the resource type of the object the operation acts on: the
// type of its last identifier path parameter, "" when it has none.
func (o Operation) PrimaryType() string {
	t := ""
	for _, p := range o.PathParams {
		if p.IsObjectID && p.ResourceType != "" {
			t = p.ResourceType
		}
	}
	return t
}

// CreatedType is the resource type an operation creates: the singular stem of
// its last path segment when that is a literal ("" otherwise).
func (o Operation) CreatedType() string {
	segs := strings.Split(strings.Trim(o.Path, "/"), "/")
	if len(segs) == 0 {
		return ""
	}
	last := segs[len(segs)-1]
	if last == "" || strings.HasPrefix(last, "{") {
		return ""
	}
	return ResourceStem(last)
}

// ResourceTypes lists every resource type the model mentions, sorted.
func (m Model) ResourceTypes() []string {
	set := map[string]bool{}
	for _, o := range m.Operations {
		for _, p := range o.PathParams {
			if p.ResourceType != "" {
				set[p.ResourceType] = true
			}
		}
		if o.Method == "POST" {
			if t := o.CreatedType(); t != "" {
				set[t] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// HasResourceType reports whether the model mentions the type.
func (m Model) HasResourceType(t string) bool {
	for _, x := range m.ResourceTypes() {
		if x == t {
			return true
		}
	}
	return false
}
