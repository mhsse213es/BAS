package attackpath

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"
)

// This file parses SharpHound collector output (BloodHound legacy / v4 JSON) into
// a normalized Collection. The agent runs SharpHound and uploads the RAW zip —
// it never parses or reasons about the data; all interpretation happens here on
// the server (intelligence-on-server). Parsing is deliberately defensive: an
// unrecognized or malformed file is skipped, never fatal, because SharpHound's
// schema varies across versions and we must not drop a whole collection over one
// odd record.

// Well-known RID suffixes (the tail of a SID) for tier-0 / high-value groups.
// Matching by RID is locale- and rename-proof, unlike matching display names.
var highValueRIDs = []string{
	"-512", // Domain Admins
	"-519", // Enterprise Admins
	"-518", // Schema Admins
	"-544", // BUILTIN\Administrators
}

const domainControllersRID = "-516" // Domain Controllers group

// bhProps is the subset of BloodHound node Properties we use.
type bhProps struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

// bhMember is a group member / local-admin principal reference.
type bhMember struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

// bhAce is one Access Control Entry: a principal's right over the object
// whose Aces array this entry appears in.
type bhAce struct {
	PrincipalSID string `json:"PrincipalSID"`
	RightName    string `json:"RightName"`
	IsInherited  bool   `json:"IsInherited"` // parsed, not yet used by any logic
}

// aceRightEdgeKinds maps a BloodHound ACE RightName (case-insensitively) to
// the EdgeKind it represents. An unrecognized RightName is intentionally
// absent and must be skipped by the caller, never fatal.
var aceRightEdgeKinds = map[string]EdgeKind{
	"genericall":           EdgeGenericAll,
	"genericwrite":         EdgeGenericWrite,
	"writeowner":           EdgeWriteOwner,
	"writedacl":            EdgeWriteDacl,
	"owns":                 EdgeOwns,
	"allextendedrights":    EdgeAllExtendedRights,
	"forcechangepassword":  EdgeForceChangePassword,
	"addmember":            EdgeAddMember,
	"addself":              EdgeAddSelf,
	"addkeycredentiallink": EdgeAddKeyCredentialLink,
	"readlapspassword":     EdgeReadLAPSPassword,
}

// addAceEdges appends one edge per recognized, well-formed ACE in aces,
// where objectID is the object the Aces array is attached to (the ACL
// target). Unrecognized RightName values and ACEs with no PrincipalSID are
// skipped, never fatal — consistent with this file's defensive-parsing
// principle.
func addAceEdges(edges *[]Edge, objectID string, aces []bhAce) {
	for _, ace := range aces {
		if ace.PrincipalSID == "" {
			continue
		}
		kind, ok := aceRightEdgeKinds[strings.ToLower(ace.RightName)]
		if !ok {
			continue
		}
		*edges = append(*edges, Edge{From: ace.PrincipalSID, To: objectID, Kind: kind})
	}
}

type bhComputer struct {
	ObjectIdentifier string  `json:"ObjectIdentifier"`
	Properties       bhProps `json:"Properties"`
	LocalAdmins      struct {
		Results []bhMember `json:"Results"`
	} `json:"LocalAdmins"`
	Sessions struct {
		Results []struct {
			UserSID     string `json:"UserSID"`
			ComputerSID string `json:"ComputerSID"`
		} `json:"Results"`
	} `json:"Sessions"`
	Aces              []bhAce    `json:"Aces"`
	AllowedToDelegate []string   `json:"AllowedToDelegate"`
	AllowedToAct      []bhMember `json:"AllowedToAct"`
}

type bhUser struct {
	ObjectIdentifier string  `json:"ObjectIdentifier"`
	Properties       bhProps `json:"Properties"`
	Aces             []bhAce `json:"Aces"`
}

type bhGroup struct {
	ObjectIdentifier string     `json:"ObjectIdentifier"`
	Properties       bhProps    `json:"Properties"`
	Members          []bhMember `json:"Members"`
	Aces             []bhAce    `json:"Aces"`
}

// bhFile is the envelope every BloodHound JSON file shares.
type bhFile struct {
	Data json.RawMessage `json:"data"`
	Meta struct {
		Type string `json:"type"`
	} `json:"meta"`
}

// ParseSharpHoundZip reads a SharpHound collection zip and returns a normalized
// Collection. Non-JSON entries and unparseable files are skipped.
func ParseSharpHoundZip(agentID, hostname string, data []byte) (Collection, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Collection{}, err
	}
	var files [][]byte
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, readErr := io.ReadAll(rc)
		rc.Close()
		if readErr == nil {
			files = append(files, b)
		}
	}
	c := parseSharpHoundFiles(files)
	c.AgentID = agentID
	c.Hostname = hostname
	c.Source = "sharphound"
	c.CollectedAt = time.Now().UTC()
	return c, nil
}

// parseSharpHoundFiles buckets the BloodHound files by type, then builds nodes
// and edges. Groups are resolved first so Domain Controllers can be identified
// before computers are classified.
func parseSharpHoundFiles(files [][]byte) Collection {
	var computers []bhComputer
	var users []bhUser
	var groups []bhGroup

	for _, raw := range files {
		var env bhFile
		if json.Unmarshal(raw, &env) != nil || len(env.Data) == 0 {
			continue
		}
		switch strings.ToLower(env.Meta.Type) {
		case "computers":
			var d []bhComputer
			if json.Unmarshal(env.Data, &d) == nil {
				computers = append(computers, d...)
			}
		case "users":
			var d []bhUser
			if json.Unmarshal(env.Data, &d) == nil {
				users = append(users, d...)
			}
		case "groups":
			var d []bhGroup
			if json.Unmarshal(env.Data, &d) == nil {
				groups = append(groups, d...)
			}
		}
	}
	return buildSharpHoundCollection(computers, users, groups)
}

func buildSharpHoundCollection(computers []bhComputer, users []bhUser, groups []bhGroup) Collection {
	var c Collection

	// Identify Domain Controllers from the Domain Controllers group membership.
	dcSIDs := map[string]bool{}
	for _, g := range groups {
		if strings.HasSuffix(g.ObjectIdentifier, domainControllersRID) {
			for _, m := range g.Members {
				if strings.EqualFold(m.ObjectType, "Computer") {
					dcSIDs[m.ObjectIdentifier] = true
				}
			}
		}
	}

	for _, u := range users {
		if u.ObjectIdentifier == "" {
			continue
		}
		c.Nodes = append(c.Nodes, Node{
			ID: u.ObjectIdentifier, Kind: KindUser, Label: labelOf(u.Properties, u.ObjectIdentifier),
		})
		addAceEdges(&c.Edges, u.ObjectIdentifier, u.Aces)
	}

	for _, g := range groups {
		if g.ObjectIdentifier == "" {
			continue
		}
		c.Nodes = append(c.Nodes, Node{
			ID: g.ObjectIdentifier, Kind: KindGroup,
			Label: labelOf(g.Properties, g.ObjectIdentifier), HighValue: isHighValue(g.ObjectIdentifier),
		})
		for _, m := range g.Members {
			if m.ObjectIdentifier == "" {
				continue
			}
			c.Edges = append(c.Edges, Edge{From: m.ObjectIdentifier, To: g.ObjectIdentifier, Kind: EdgeMemberOf})
		}
		addAceEdges(&c.Edges, g.ObjectIdentifier, g.Aces)
	}

	for _, cm := range computers {
		if cm.ObjectIdentifier == "" {
			continue
		}
		role := RoleEndpoint
		if dcSIDs[cm.ObjectIdentifier] {
			role = RoleDC
		} else if isServerName(cm.Properties.Name) {
			role = RoleServer
		}
		c.Nodes = append(c.Nodes, Node{
			ID: cm.ObjectIdentifier, Kind: KindHost,
			Label: labelOf(cm.Properties, cm.ObjectIdentifier), Role: role,
		})
		// Local admins → principal is admin-to this computer.
		for _, a := range cm.LocalAdmins.Results {
			if a.ObjectIdentifier == "" {
				continue
			}
			c.Edges = append(c.Edges, Edge{From: a.ObjectIdentifier, To: cm.ObjectIdentifier, Kind: EdgeAdminTo})
		}
		// Sessions → this computer has a harvestable session for the user.
		for _, s := range cm.Sessions.Results {
			if s.UserSID == "" {
				continue
			}
			c.Edges = append(c.Edges, Edge{From: cm.ObjectIdentifier, To: s.UserSID, Kind: EdgeHasSession})
		}
		addAceEdges(&c.Edges, cm.ObjectIdentifier, cm.Aces)
		// AllowedToDelegate: cm (the computer with this property) is From; each
		// listed target is To.
		for _, target := range cm.AllowedToDelegate {
			if target == "" {
				continue
			}
			c.Edges = append(c.Edges, Edge{From: cm.ObjectIdentifier, To: target, Kind: EdgeAllowedToDelegate})
		}
		// AllowedToAct: each listed principal is From; cm (the computer with this
		// property) is To. Direction is the OPPOSITE of AllowedToDelegate above.
		for _, p := range cm.AllowedToAct {
			if p.ObjectIdentifier == "" {
				continue
			}
			c.Edges = append(c.Edges, Edge{From: p.ObjectIdentifier, To: cm.ObjectIdentifier, Kind: EdgeAllowedToAct})
		}
	}
	return c
}

func labelOf(p bhProps, sid string) string {
	if p.Name != "" {
		return p.Name
	}
	return sid
}

func isHighValue(sid string) bool {
	for _, rid := range highValueRIDs {
		if strings.HasSuffix(sid, rid) {
			return true
		}
	}
	return false
}

// isServerName is a best-effort role heuristic from the hostname. SharpHound
// does not classify endpoints vs. servers, so we infer from common naming.
func isServerName(name string) bool {
	n := strings.ToUpper(name)
	for _, tok := range []string{"SRV", "SQL", "FILE", "APP", "EXCH", "WEB", "DB", "BACKUP", "VCENTER", "ESX"} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}
