package threatidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// ResolverVersion is recorded in every resolver context, so a stored
// decision says which rules produced it.
const ResolverVersion = "threatidentity/resolver/v1"

// SourceKey is one identity a source assigns to a record: its stable
// external id, or "name:<normalized name>" for sources without one.
type SourceKey struct{ Source, ID string }

// Incoming is one merged actor record from a sync.
type Incoming struct {
	Name             string
	Aliases          []string
	CanonicalGroupID string
	Sources          []SourceKey
}

// KnownActor is an existing actor as the resolver sees it.
type KnownActor struct {
	ID               string
	Name             string
	Aliases          []string
	CanonicalGroupID string
}

// Snapshot is everything the resolver may consult.
type Snapshot struct {
	Actors           []KnownActor
	SourceIdentities map[SourceKey]string
	// AdminOverrides maps a source key to the actor an admin decided it
	// belongs to; the latest decision per key wins. Outranks every other rule.
	AdminOverrides map[SourceKey]string
}

type Outcome string

const (
	OutcomeExisting  Outcome = "existing"
	OutcomeNew       Outcome = "new"
	OutcomeAmbiguous Outcome = "ambiguous"
)

type Decision struct {
	Outcome      Outcome
	ActorID      string
	Rule         string // source_identity | attack_group | alias | none
	Reason       string
	CandidateIDs []string
	Context      []byte // canonical JSON of what the resolver saw (spec §3.4)
	ContextHash  string
}

// NormalizeName is connector.actorKey's rule (lowercase, no spaces or
// hyphens) plus trimming; kept identical so resolution and the existing
// merge agree on what "the same name" means.
func NormalizeName(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(s), " ", ""), "-", ""))
}

// KeysFor returns the identity keys one raw source record contributes: its
// stable external id when it has one, and its per-source normalized name.
func KeysFor(source, sourceID, name string) []SourceKey {
	var out []SourceKey
	if sourceID != "" {
		out = append(out, SourceKey{source, sourceID})
	}
	if n := NormalizeName(name); n != "" {
		out = append(out, SourceKey{source, "name:" + n})
	}
	return out
}

// Resolve applies the spec §3.3 hierarchy. It never merges on similarity and
// never guesses between candidates: more than one possible actor, or strong
// signals that disagree, is OutcomeAmbiguous.
func Resolve(in Incoming, snap Snapshot) Decision {
	byID := map[string]KnownActor{}
	for _, a := range snap.Actors {
		byID[a.ID] = a
	}

	byOverride := set{}
	for _, k := range in.Sources {
		if id, ok := snap.AdminOverrides[k]; ok {
			byOverride.add(id)
		}
	}
	bySource := set{}
	for _, k := range in.Sources {
		if id, ok := snap.SourceIdentities[k]; ok {
			bySource.add(id)
		}
	}
	byGroup := set{}
	if in.CanonicalGroupID != "" {
		for _, a := range snap.Actors {
			if a.CanonicalGroupID == in.CanonicalGroupID {
				byGroup.add(a.ID)
			}
		}
	}
	tokens := set{}
	for _, s := range append([]string{in.Name}, in.Aliases...) {
		if n := NormalizeName(s); n != "" {
			tokens.add(n)
		}
	}
	byAlias := set{}
	for _, a := range snap.Actors {
		for _, s := range append([]string{a.Name}, a.Aliases...) {
			if n := NormalizeName(s); n != "" && tokens[n] {
				byAlias.add(a.ID)
				break
			}
		}
	}

	var d Decision
	switch {
	case len(byOverride) > 1:
		d = Decision{Outcome: OutcomeAmbiguous, Rule: "admin_decision", Reason: "admin decisions map to different actors",
			CandidateIDs: byOverride.sorted()}
	case len(byOverride) == 1:
		d = Decision{Outcome: OutcomeExisting, ActorID: byOverride.only(), Rule: "admin_decision"}
	case len(bySource) > 1:
		d = Decision{Outcome: OutcomeAmbiguous, Rule: "source_identity", Reason: "source identities map to different actors",
			CandidateIDs: bySource.sorted()}
	case len(bySource) == 1 && len(byGroup) == 1 && bySource.only() != byGroup.only():
		d = Decision{Outcome: OutcomeAmbiguous, Rule: "source_identity", Reason: "source identity and ATT&CK group disagree",
			CandidateIDs: union(bySource, byGroup).sorted()}
	case len(bySource) == 1:
		d = Decision{Outcome: OutcomeExisting, ActorID: bySource.only(), Rule: "source_identity"}
	case len(byGroup) > 1:
		d = Decision{Outcome: OutcomeAmbiguous, Rule: "attack_group", Reason: "several actors carry this ATT&CK group",
			CandidateIDs: byGroup.sorted()}
	case len(byGroup) == 1:
		d = Decision{Outcome: OutcomeExisting, ActorID: byGroup.only(), Rule: "attack_group"}
	case len(byAlias) > 1:
		d = Decision{Outcome: OutcomeAmbiguous, Rule: "alias", Reason: "name or alias matches several actors",
			CandidateIDs: byAlias.sorted()}
	case len(byAlias) == 1:
		a := byID[byAlias.only()]
		if in.CanonicalGroupID != "" && a.CanonicalGroupID != "" && a.CanonicalGroupID != in.CanonicalGroupID {
			d = Decision{Outcome: OutcomeAmbiguous, Rule: "alias", Reason: "alias match carries a different ATT&CK group",
				CandidateIDs: []string{a.ID}}
		} else {
			d = Decision{Outcome: OutcomeExisting, ActorID: a.ID, Rule: "alias"}
		}
	default:
		d = Decision{Outcome: OutcomeNew, Rule: "none"}
	}
	d.Context, d.ContextHash = resolverContext(in, d, byID)
	return d
}

type resolverContextDoc struct {
	ResolverVersion string              `json:"resolver_version"`
	Incoming        incomingDoc         `json:"incoming"`
	Outcome         Outcome             `json:"outcome"`
	Rule            string              `json:"rule"`
	Reason          string              `json:"reason"`
	Candidates      []candidateActorDoc `json:"candidates"`
}

type incomingDoc struct {
	Name             string      `json:"name"`
	Aliases          []string    `json:"aliases"`
	CanonicalGroupID string      `json:"canonical_group_id"`
	Sources          []SourceKey `json:"sources"`
}

type candidateActorDoc struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Aliases          []string `json:"aliases"`
	CanonicalGroupID string   `json:"canonical_group_id"`
}

// resolverContext is the immutable snapshot behind resolver_context_hash:
// the incoming record and every candidate actor exactly as the resolver
// saw them, with all slices sorted so input order cannot change the hash.
func resolverContext(in Incoming, d Decision, byID map[string]KnownActor) ([]byte, string) {
	doc := resolverContextDoc{ResolverVersion: ResolverVersion, Outcome: d.Outcome, Rule: d.Rule, Reason: d.Reason,
		Incoming: incomingDoc{Name: in.Name, Aliases: sortedCopy(in.Aliases), CanonicalGroupID: in.CanonicalGroupID,
			Sources: sortedKeys(in.Sources)}, Candidates: []candidateActorDoc{}}
	ids := d.CandidateIDs
	if d.ActorID != "" {
		ids = []string{d.ActorID}
	}
	for _, id := range ids {
		a := byID[id]
		doc.Candidates = append(doc.Candidates, candidateActorDoc{ID: a.ID, Name: a.Name, Aliases: sortedCopy(a.Aliases),
			CanonicalGroupID: a.CanonicalGroupID})
	}
	b, _ := json.Marshal(doc)
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:])
}

type set map[string]bool

func (s set) add(v string) { s[v] = true }

func (s set) only() string {
	for v := range s {
		return v
	}
	return ""
}

func (s set) sorted() []string {
	out := make([]string, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func union(a, b set) set {
	out := set{}
	for v := range a {
		out.add(v)
	}
	for v := range b {
		out.add(v)
	}
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func sortedKeys(in []SourceKey) []SourceKey {
	out := append([]SourceKey{}, in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].ID < out[j].ID
	})
	return out
}
