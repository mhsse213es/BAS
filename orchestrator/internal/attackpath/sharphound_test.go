package attackpath

import (
	"archive/zip"
	"bytes"
	"testing"
)

// BloodHound v4 fixture files (trimmed to the fields the parser reads).
const shComputers = `{"meta":{"type":"computers","count":2},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-1001","Properties":{"name":"DC01.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},
   "Sessions":{"Results":[{"UserSID":"S-1-5-21-1-1-1-1107","ComputerSID":"S-1-5-21-1-1-1-1001"}]}},
  {"ObjectIdentifier":"S-1-5-21-1-1-1-1002","Properties":{"name":"FILESRV01.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[{"ObjectIdentifier":"S-1-5-21-1-1-1-1107","ObjectType":"User"}]},
   "Sessions":{"Results":[]}}
]}`

const shUsers = `{"meta":{"type":"users","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-1107","Properties":{"name":"HELPDESK@CORP.LOCAL","domain":"CORP.LOCAL"}}
]}`

const shGroups = `{"meta":{"type":"groups","count":2},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-512","Properties":{"name":"DOMAIN ADMINS@CORP.LOCAL"},
   "Members":[{"ObjectIdentifier":"S-1-5-21-1-1-1-1107","ObjectType":"User"}]},
  {"ObjectIdentifier":"S-1-5-21-1-1-1-516","Properties":{"name":"DOMAIN CONTROLLERS@CORP.LOCAL"},
   "Members":[{"ObjectIdentifier":"S-1-5-21-1-1-1-1001","ObjectType":"Computer"}]}
]}`

func TestParseSharpHoundFiles(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputers), []byte(shUsers), []byte(shGroups)})

	g := BuildGraph(c)

	// DC01 must be classified as a domain controller via the DC group membership.
	dc, ok := g.Node("S-1-5-21-1-1-1-1001")
	if !ok || dc.Role != RoleDC {
		t.Fatalf("DC01 should be role=domain-controller, got %+v (ok=%v)", dc, ok)
	}
	// FILESRV01 should be a server by name heuristic.
	srv, _ := g.Node("S-1-5-21-1-1-1-1002")
	if srv.Role != RoleServer {
		t.Fatalf("FILESRV01 should be role=server, got %q", srv.Role)
	}
	// Domain Admins must be flagged high-value via the -512 RID.
	da, _ := g.Node("S-1-5-21-1-1-1-512")
	if !da.HighValue {
		t.Fatal("Domain Admins (-512) must be high-value")
	}

	// The helpdesk user is local admin on FILESRV01 and a member of Domain Admins,
	// and has a session on DC01 — so from FILESRV01 an attacker reaches Domain Admin.
	s := g.Analyze()
	if !s.DomainCompromise {
		t.Fatalf("expected domain compromise from SharpHound graph: %+v", s)
	}
	// FILESRV01 → helpdesk (admin-to is principal→host, so traverse via session on
	// DC01 path instead): verify a path from DC01 to Domain Admins exists.
	if p := g.ShortestPathToDomainAdmin("S-1-5-21-1-1-1-1001"); p == nil {
		t.Fatal("DC01 should reach Domain Admins (session → helpdesk → member-of DA)")
	}
}

func TestParseSharpHoundZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"20260619_computers.json": shComputers,
		"20260619_users.json":     shUsers,
		"20260619_groups.json":    shGroups,
		"README.txt":              "ignored",
	} {
		f, _ := zw.Create(name)
		f.Write([]byte(body))
	}
	zw.Close()

	c, err := ParseSharpHoundZip("agent-1", "DC01", buf.Bytes())
	if err != nil {
		t.Fatalf("ParseSharpHoundZip: %v", err)
	}
	if c.Source != "sharphound" || c.AgentID != "agent-1" {
		t.Fatalf("collection metadata wrong: %+v", c)
	}
	if len(c.Nodes) == 0 || len(c.Edges) == 0 {
		t.Fatalf("zip parse produced empty graph: %d nodes, %d edges", len(c.Nodes), len(c.Edges))
	}
}

// BloodHound v4 fixture: a computer with one ACE per modeled RightName.
const shComputersWithAces = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-2001","Properties":{"name":"FILESRV02.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "Aces":[
     {"PrincipalSID":"S-1-5-21-1-1-1-3001","RightName":"GenericAll","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3002","RightName":"GenericWrite","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3003","RightName":"WriteOwner","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3004","RightName":"WriteDacl","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3005","RightName":"Owns","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3006","RightName":"AllExtendedRights","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3007","RightName":"ForceChangePassword","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3008","RightName":"AddMember","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3009","RightName":"AddSelf","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3010","RightName":"AddKeyCredentialLink","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-3011","RightName":"ReadLAPSPassword","IsInherited":false}
   ]}
]}`

func TestParseSharpHoundFiles_AceRights_ProduceCorrectEdgeKinds(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersWithAces)})
	g := BuildGraph(c)

	cases := []struct {
		principal string
		want      EdgeKind
	}{
		{"S-1-5-21-1-1-1-3001", EdgeGenericAll},
		{"S-1-5-21-1-1-1-3002", EdgeGenericWrite},
		{"S-1-5-21-1-1-1-3003", EdgeWriteOwner},
		{"S-1-5-21-1-1-1-3004", EdgeWriteDacl},
		{"S-1-5-21-1-1-1-3005", EdgeOwns},
		{"S-1-5-21-1-1-1-3006", EdgeAllExtendedRights},
		{"S-1-5-21-1-1-1-3007", EdgeForceChangePassword},
		{"S-1-5-21-1-1-1-3008", EdgeAddMember},
		{"S-1-5-21-1-1-1-3009", EdgeAddSelf},
		{"S-1-5-21-1-1-1-3010", EdgeAddKeyCredentialLink},
		{"S-1-5-21-1-1-1-3011", EdgeReadLAPSPassword},
	}
	for _, tc := range cases {
		found := false
		for _, e := range g.Edges() {
			if e.From == tc.principal && e.To == "S-1-5-21-1-1-1-2001" && e.Kind == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected edge {From: %s, To: FILESRV02, Kind: %s} not found", tc.principal, tc.want)
		}
	}
}

const shComputersAclPathToDomainAdmin = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-4001","Properties":{"name":"SVCHOST01.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "Aces":[{"PrincipalSID":"S-1-5-21-1-1-1-4100","RightName":"GenericWrite","IsInherited":false}]}
]}`

const shUsersAclPathToDomainAdmin = `{"meta":{"type":"users","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-4100","Properties":{"name":"LOWPRIV@CORP.LOCAL","domain":"CORP.LOCAL"}}
]}`

const shGroupsAclPathToDomainAdmin = `{"meta":{"type":"groups","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-512","Properties":{"name":"DOMAIN ADMINS@CORP.LOCAL"},
   "Members":[{"ObjectIdentifier":"S-1-5-21-1-1-1-4001","ObjectType":"Computer"}]}
]}`

func TestParseSharpHoundFiles_AclEdge_IsDiscoverableByExistingPathFinding(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{
		[]byte(shComputersAclPathToDomainAdmin),
		[]byte(shUsersAclPathToDomainAdmin),
		[]byte(shGroupsAclPathToDomainAdmin),
	})
	g := BuildGraph(c)

	// LOWPRIV has GenericWrite on SVCHOST01, and SVCHOST01 is a member of
	// Domain Admins. The ONLY path from LOWPRIV to Domain Admins is through
	// the new generic-write edge -- proving ShortestPathToDomainAdmin needs
	// no changes to find an ACL-abuse path.
	path := g.ShortestPathToDomainAdmin("S-1-5-21-1-1-1-4100")
	if path == nil {
		t.Fatal("expected a path from LOWPRIV to Domain Admins via the new generic-write edge, got nil")
	}
	if path[0].Kind != EdgeGenericWrite {
		t.Fatalf("expected the first edge to be generic-write, got %s", path[0].Kind)
	}
	if !g.CanReachDomainAdmin() {
		t.Fatal("CanReachDomainAdmin() should be true once an ACL edge exists in the path")
	}
}

const shComputersMalformedAces = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-5001","Properties":{"name":"SRV99.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "Aces":[
     {"PrincipalSID":"","RightName":"GenericAll","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-5100","RightName":"SomeFutureRightWeDontModel","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-5001","RightName":"GenericAll","IsInherited":false},
     {"PrincipalSID":"S-1-5-21-1-1-1-5200","RightName":"genericwrite","IsInherited":true},
     {"PrincipalSID":"S-1-5-21-1-1-1-5200","RightName":"GenericWrite","IsInherited":true}
   ]}
]}`

func TestParseSharpHoundFiles_Aces_SkipsEmptyPrincipalAndUnrecognizedRight(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersMalformedAces)})
	g := BuildGraph(c)

	for _, e := range g.Edges() {
		if e.From == "" {
			t.Fatal("an edge with an empty PrincipalSID must never be created")
		}
		if e.From == "S-1-5-21-1-1-1-5100" {
			t.Fatal("an unrecognized RightName must never produce an edge")
		}
	}
}

func TestParseSharpHoundFiles_Aces_SelfReferentialAceDoesNotHangPathFinding(t *testing.T) {
	// SRV99 has GenericAll on itself (S-1-5-21-1-1-1-5001 -> S-1-5-21-1-1-1-5001).
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersMalformedAces)})
	g := BuildGraph(c)

	// ShortestPath must return promptly (no infinite loop) and correctly
	// report "no path" for an unrelated target.
	if p := g.ShortestPath("S-1-5-21-1-1-1-5001", "nonexistent-target"); p != nil {
		t.Fatalf("expected nil for an unreachable target, got %+v", p)
	}
}

func TestParseSharpHoundFiles_Aces_CaseInsensitiveRightNameMatching(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersMalformedAces)})
	g := BuildGraph(c)

	found := false
	for _, e := range g.Edges() {
		if e.From == "S-1-5-21-1-1-1-5200" && e.Kind == EdgeGenericWrite {
			found = true
		}
	}
	if !found {
		t.Fatal("lowercase RightName \"genericwrite\" must still match EdgeGenericWrite")
	}
}

func TestParseSharpHoundFiles_Aces_DuplicateAceDoesNotDuplicateEdgeAfterBuildGraph(t *testing.T) {
	// shComputersMalformedAces has two identical {5200 -> 5001, GenericWrite}
	// ACEs (the IsInherited:true one and the un-inherited duplicate below it).
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersMalformedAces)})
	g := BuildGraph(c)

	count := 0
	for _, e := range g.Edges() {
		if e.From == "S-1-5-21-1-1-1-5200" && e.To == "S-1-5-21-1-1-1-5001" && e.Kind == EdgeGenericWrite {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 deduplicated generic-write edge from a duplicate ACE pair, got %d", count)
	}
}

const shComputersDelegation = `{"meta":{"type":"computers","count":2},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-6001","Properties":{"name":"WEBSVC01.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "AllowedToDelegate":["S-1-5-21-1-1-1-6002"]},
  {"ObjectIdentifier":"S-1-5-21-1-1-1-6002","Properties":{"name":"TARGET01.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "AllowedToAct":[{"ObjectIdentifier":"S-1-5-21-1-1-1-6001","ObjectType":"Computer"}]}
]}`

func TestParseSharpHoundFiles_Delegation_ProducesCorrectlyDirectedEdges(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersDelegation)})
	g := BuildGraph(c)

	// AllowedToDelegate: WEBSVC01 (the computer carrying the property) is
	// From; TARGET01 (the listed target) is To -- control WEBSVC01, gain the
	// ability to authenticate to TARGET01 as an arbitrary user.
	foundDelegate := false
	for _, e := range g.Edges() {
		if e.From == "S-1-5-21-1-1-1-6001" && e.To == "S-1-5-21-1-1-1-6002" && e.Kind == EdgeAllowedToDelegate {
			foundDelegate = true
		}
	}
	if !foundDelegate {
		t.Fatal("expected {From: WEBSVC01, To: TARGET01, Kind: allowed-to-delegate}")
	}

	// AllowedToAct: WEBSVC01 (the listed principal) is From; TARGET01 (the
	// computer carrying the property) is To -- control WEBSVC01, gain the
	// ability to impersonate arbitrary users to TARGET01 via RBCD. Note the
	// direction is the OPPOSITE of AllowedToDelegate relative to "the
	// computer carrying the JSON property" -- this is exactly the mistake
	// the spec's direction table exists to prevent.
	foundAct := false
	for _, e := range g.Edges() {
		if e.From == "S-1-5-21-1-1-1-6001" && e.To == "S-1-5-21-1-1-1-6002" && e.Kind == EdgeAllowedToAct {
			foundAct = true
		}
	}
	if !foundAct {
		t.Fatal("expected {From: WEBSVC01, To: TARGET01, Kind: allowed-to-act}")
	}
}

const shComputersDelegationMissingFields = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-7001","Properties":{"name":"SRV77.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]}}
]}`

func TestParseSharpHoundFiles_Delegation_MissingFieldsDoNotCrash(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersDelegationMissingFields)})
	g := BuildGraph(c)

	for _, e := range g.Edges() {
		if e.Kind == EdgeAllowedToDelegate || e.Kind == EdgeAllowedToAct {
			t.Fatalf("expected no delegation edges for an object with neither field present, got %+v", e)
		}
	}
}

const shComputersSelfDelegation = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-8001","Properties":{"name":"SRV88.CORP.LOCAL","domain":"CORP.LOCAL"},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]},
   "AllowedToDelegate":["S-1-5-21-1-1-1-8001"]}
]}`

func TestParseSharpHoundFiles_Delegation_SelfReferentialDoesNotHangPathFinding(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersSelfDelegation)})
	g := BuildGraph(c)

	if p := g.ShortestPath("S-1-5-21-1-1-1-8001", "nonexistent-target"); p != nil {
		t.Fatalf("expected nil for an unreachable target, got %+v", p)
	}
}

const shComputersUnconstrainedDelegation = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-9001","Properties":{"name":"LEGACY01.CORP.LOCAL","domain":"CORP.LOCAL","unconstraineddelegation":true},
   "LocalAdmins":{"Results":[]},"Sessions":{"Results":[]}}
]}`

const shUsersUnconstrainedDelegation = `{"meta":{"type":"users","count":1},"data":[
  {"ObjectIdentifier":"S-1-5-21-1-1-1-9100","Properties":{"name":"SVCACCT@CORP.LOCAL","domain":"CORP.LOCAL","unconstraineddelegation":true}}
]}`

func TestParseSharpHoundFiles_UnconstrainedDelegation_SetsFlagNotEdge(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{
		[]byte(shComputersUnconstrainedDelegation),
		[]byte(shUsersUnconstrainedDelegation),
	})
	before := len(c.Edges)
	g := BuildGraph(c)

	host, ok := g.Node("S-1-5-21-1-1-1-9001")
	if !ok || !host.UnconstrainedDelegation {
		t.Fatalf("expected LEGACY01.UnconstrainedDelegation == true, got %+v (ok=%v)", host, ok)
	}
	user, ok := g.Node("S-1-5-21-1-1-1-9100")
	if !ok || !user.UnconstrainedDelegation {
		t.Fatalf("expected SVCACCT.UnconstrainedDelegation == true, got %+v (ok=%v)", user, ok)
	}
	// The property must never create an edge -- it's a capability flag, not
	// a relationship to a fixed target (see the spec).
	if len(c.Edges) != before {
		t.Fatalf("unconstrained delegation must not add any edges, got %d edges (started with %d)", len(c.Edges), before)
	}
}

func TestParseSharpHoundFiles_UnconstrainedDelegation_IndependentOfAcesAndDelegationFields(t *testing.T) {
	// shComputersWithAces (Task 1) has Aces but no AllowedToDelegate/unconstraineddelegation.
	c := parseSharpHoundFiles([][]byte{[]byte(shComputersWithAces)})
	g := BuildGraph(c)

	n, ok := g.Node("S-1-5-21-1-1-1-2001")
	if !ok {
		t.Fatal("FILESRV02 node should exist")
	}
	if n.UnconstrainedDelegation {
		t.Fatal("a computer with only Aces present must not have UnconstrainedDelegation set")
	}
}

const shUsersKerberoastAndASREP = `{"meta":{"type":"users","count":2},"data":[
  {"ObjectIdentifier":"SVCACCT2","Properties":{"name":"svc_sql2@CORP.LOCAL","domain":"CORP.LOCAL","hasspn":true,"dontreqpreauth":false}},
  {"ObjectIdentifier":"NORMALUSER","Properties":{"name":"NORMALUSER@CORP.LOCAL","domain":"CORP.LOCAL","hasspn":false,"dontreqpreauth":true}}
]}`

const shComputersSPNPropertyIgnored = `{"meta":{"type":"computers","count":1},"data":[
  {"ObjectIdentifier":"LEGACY02","Properties":{"name":"LEGACY02.CORP.LOCAL","domain":"CORP.LOCAL","hasspn":true}}
]}`

func TestParseSharpHoundFiles_KerberoastAndASREP_SetFlagsOnUsersOnly(t *testing.T) {
	c := parseSharpHoundFiles([][]byte{
		[]byte(shUsersKerberoastAndASREP),
		[]byte(shComputersSPNPropertyIgnored),
	})
	g := BuildGraph(c)

	svc, ok := g.Node("SVCACCT2")
	if !ok || !svc.HasSPN || svc.DontRequirePreauth {
		t.Fatalf("expected SVCACCT2 HasSPN=true DontRequirePreauth=false, got %+v (ok=%v)", svc, ok)
	}

	normal, ok := g.Node("NORMALUSER")
	if !ok || normal.HasSPN || !normal.DontRequirePreauth {
		t.Fatalf("expected NORMALUSER HasSPN=false DontRequirePreauth=true, got %+v (ok=%v)", normal, ok)
	}

	// SharpHound reports hasspn for computers too (every computer has a
	// default machine-account SPN), but it is not a meaningful attack
	// signal there -- must not be copied onto the host node.
	host, ok := g.Node("LEGACY02")
	if !ok || host.HasSPN {
		t.Fatalf("expected LEGACY02 (a computer) to NOT have HasSPN set even though SharpHound reported hasspn:true, got %+v (ok=%v)", host, ok)
	}
}
