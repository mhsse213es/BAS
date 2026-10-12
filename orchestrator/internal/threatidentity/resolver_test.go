package threatidentity

import "testing"

func snap(actors ...KnownActor) Snapshot {
	return Snapshot{Actors: actors, SourceIdentities: map[SourceKey]string{}}
}

func TestResolve_SourceIdentityWins(t *testing.T) {
	s := snap(KnownActor{ID: "act-a", Name: "APT29"}, KnownActor{ID: "act-b", Name: "Cozy Bear"})
	s.SourceIdentities[SourceKey{"opencti", "oc-1"}] = "act-a"
	d := Resolve(Incoming{Name: "Cozy Bear", Sources: []SourceKey{{"opencti", "oc-1"}}}, s)
	if d.Outcome != OutcomeExisting || d.ActorID != "act-a" || d.Rule != "source_identity" {
		t.Fatalf("%+v", d)
	}
}

func TestResolve_SourceIdentitiesDisagreeIsAmbiguous(t *testing.T) {
	s := snap(KnownActor{ID: "act-a", Name: "A"}, KnownActor{ID: "act-b", Name: "B"})
	s.SourceIdentities[SourceKey{"misp", "e1"}] = "act-a"
	s.SourceIdentities[SourceKey{"opencti", "o1"}] = "act-b"
	d := Resolve(Incoming{Name: "A", Sources: []SourceKey{{"misp", "e1"}, {"opencti", "o1"}}}, s)
	if d.Outcome != OutcomeAmbiguous || len(d.CandidateIDs) != 2 {
		t.Fatalf("%+v", d)
	}
}

func TestResolve_AttackGroupMatch(t *testing.T) { // acceptance 1: rename keeps id
	s := snap(KnownActor{ID: "act-a", Name: "APT29", CanonicalGroupID: "G0016"})
	d := Resolve(Incoming{Name: "Midnight Blizzard", CanonicalGroupID: "G0016"}, s)
	if d.Outcome != OutcomeExisting || d.ActorID != "act-a" || d.Rule != "attack_group" {
		t.Fatalf("%+v", d)
	}
}

func TestResolve_SourceIdentityContradictsAttackGroup(t *testing.T) {
	s := snap(KnownActor{ID: "act-a", Name: "A", CanonicalGroupID: "G0001"},
		KnownActor{ID: "act-b", Name: "B", CanonicalGroupID: "G0002"})
	s.SourceIdentities[SourceKey{"misp", "e1"}] = "act-a"
	d := Resolve(Incoming{Name: "A", CanonicalGroupID: "G0002", Sources: []SourceKey{{"misp", "e1"}}}, s)
	if d.Outcome != OutcomeAmbiguous {
		t.Fatalf("%+v", d)
	}
}

func TestResolve_NewAliasSameActor(t *testing.T) { // acceptance 2
	s := snap(KnownActor{ID: "act-a", Name: "Volt Typhoon", Aliases: []string{"Vanguard Panda"}})
	d := Resolve(Incoming{Name: "Bronze Silhouette", Aliases: []string{"vanguard-panda"}}, s)
	if d.Outcome != OutcomeExisting || d.ActorID != "act-a" || d.Rule != "alias" {
		t.Fatalf("%+v", d)
	}
}

func TestResolve_AmbiguousAlias(t *testing.T) { // acceptance 3
	s := snap(KnownActor{ID: "act-a", Name: "A", Aliases: []string{"Panda Group"}},
		KnownActor{ID: "act-b", Name: "B", Aliases: []string{"Panda Group"}})
	d := Resolve(Incoming{Name: "Panda Group"}, s)
	if d.Outcome != OutcomeAmbiguous || d.Reason == "" || d.ContextHash == "" || len(d.Context) == 0 {
		t.Fatalf("%+v", d)
	}
}

func TestResolve_AliasPointsAtActorWithDifferentGroup(t *testing.T) {
	s := snap(KnownActor{ID: "act-a", Name: "Panda", CanonicalGroupID: "G0001"})
	d := Resolve(Incoming{Name: "Panda", CanonicalGroupID: "G0099"}, s)
	if d.Outcome != OutcomeAmbiguous {
		t.Fatalf("%+v", d)
	}
}

func TestResolve_NoMatchIsNew(t *testing.T) { // acceptance 5 (resolver half)
	d := Resolve(Incoming{Name: "Brand New"}, snap(KnownActor{ID: "act-a", Name: "Other"}))
	if d.Outcome != OutcomeNew || d.ActorID != "" {
		t.Fatalf("%+v", d)
	}
}

func TestResolve_EmptyTokensNeverMatch(t *testing.T) { // Review Focus 4
	s := snap(KnownActor{ID: "act-a", Name: "A", Aliases: []string{"", "  "}})
	d := Resolve(Incoming{Name: "Z", Aliases: []string{" ", "-", ""}}, s)
	if d.Outcome != OutcomeNew {
		t.Fatalf("%+v", d)
	}
}

func TestResolve_ContextHashStableAcrossInputOrder(t *testing.T) {
	a := KnownActor{ID: "act-a", Name: "A", Aliases: []string{"P"}}
	b := KnownActor{ID: "act-b", Name: "B", Aliases: []string{"P"}}
	d1 := Resolve(Incoming{Name: "P", Aliases: []string{"x", "y"}}, snap(a, b))
	d2 := Resolve(Incoming{Name: "P", Aliases: []string{"y", "x"}}, snap(b, a))
	if d1.ContextHash != d2.ContextHash {
		t.Fatal("context hash depends on input order")
	}
}

func TestKeysFor(t *testing.T) {
	k := KeysFor("misp", "evt-1", "Cozy Bear")
	if len(k) != 2 || k[0] != (SourceKey{"misp", "evt-1"}) || k[1] != (SourceKey{"misp", "name:cozybear"}) {
		t.Fatalf("%v", k)
	}
	if k := KeysFor("bundle", "", " "); len(k) != 0 {
		t.Fatalf("%v", k)
	}
}
