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
