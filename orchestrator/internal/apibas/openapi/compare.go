package openapi

import "sort"

// AuthChange is an operation whose effective authentication differs between two inventories.
type AuthChange struct {
	Key  string   `json:"key"`
	From AuthMode `json:"from"`
	To   AuthMode `json:"to"`
}

// Changes is what differs between an earlier inventory and a later one of the same API.
type Changes struct {
	Added       []string     `json:"added"`
	Removed     []string     `json:"removed"`
	AuthChanged []AuthChange `json:"auth_changed"`
}

// Empty reports whether nothing changed.
func (c Changes) Empty() bool {
	return len(c.Added) == 0 && len(c.Removed) == 0 && len(c.AuthChanged) == 0
}

// Compare reports operations added, removed or re-secured between old and next. A nil old means there is no earlier inventory,
// and every operation counts as added. Only the operation identity (method and path) and its effective authentication are
// compared; a change to a field list or a class is not a change here.
func Compare(old, next *Inventory) Changes {
	c := Changes{Added: []string{}, Removed: []string{}, AuthChanged: []AuthChange{}}
	prev := map[string]Operation{}
	if old != nil {
		for _, o := range old.Operations {
			prev[o.Key()] = o
		}
	}
	seen := map[string]bool{}
	for _, o := range next.Operations {
		k := o.Key()
		seen[k] = true
		p, existed := prev[k]
		switch {
		case !existed:
			c.Added = append(c.Added, k)
		case p.Auth != o.Auth:
			c.AuthChanged = append(c.AuthChanged, AuthChange{Key: k, From: p.Auth, To: o.Auth})
		}
	}
	for k := range prev {
		if !seen[k] {
			c.Removed = append(c.Removed, k)
		}
	}
	sort.Strings(c.Added)
	sort.Strings(c.Removed)
	sort.Slice(c.AuthChanged, func(i, j int) bool { return c.AuthChanged[i].Key < c.AuthChanged[j].Key })
	return c
}
