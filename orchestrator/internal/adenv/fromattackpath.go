package adenv

import "github.com/audspect/bas/internal/attackpath"

// aclEdgeKinds maps each attackpath.EdgeKind that represents an ACL grant
// (as opposed to reachability, group membership, or delegation) to its
// ACLRight. This is an explicit table, not a string cast: only the 4
// constants added by the AD-M03 fix (Owns, AllExtendedRights,
// AddKeyCredentialLink, ReadLAPSPassword) happen to share EdgeKind's
// kebab-case value -- the original 7 from AD-M01 use PascalCase
// ("GenericWrite") while attackpath uses kebab-case ("generic-write"), so
// casting one to the other would silently produce an ACLRight value that
// matches no defined constant.
var aclEdgeKinds = map[attackpath.EdgeKind]ACLRight{
	attackpath.EdgeGenericAll:           ACLGenericAll,
	attackpath.EdgeGenericWrite:         ACLGenericWrite,
	attackpath.EdgeWriteOwner:           ACLWriteOwner,
	attackpath.EdgeWriteDacl:            ACLWriteDACL,
	attackpath.EdgeOwns:                 ACLOwns,
	attackpath.EdgeAllExtendedRights:    ACLAllExtendedRights,
	attackpath.EdgeForceChangePassword:  ACLForceChangePassword,
	attackpath.EdgeAddMember:            ACLAddMember,
	attackpath.EdgeAddSelf:              ACLAddSelf,
	attackpath.EdgeAddKeyCredentialLink: ACLAddKeyCredentialLink,
	attackpath.EdgeReadLAPSPassword:     ACLReadLAPSPassword,
}

// FromGraph maps an attackpath.Graph (SharpHound-derived Node/Edge data,
// AD-M03) into an Environment (AD-M01's richer ontology) -- a mapping of
// EXISTING data, never a redesign of attackpath's own SharpHound parsing.
//
// Several Environment categories have NO corresponding data anywhere in
// attackpath today and are left at their Go zero-value here on purpose,
// not approximated:
//   - Forest (Domains/Trusts/ForestRelationships): attackpath has no
//     domain or trust data at all.
//   - Authentication (Kerberos/NTLM/LDAP/SMB/RDP/WinRM config flags):
//     attackpath's SMB/WinRM/RDP edges are host-to-host REACHABILITY
//     relationships, not "is this protocol's signing/hardening enabled"
//     environment config -- a different concept entirely.
//   - Policy (GPOs/RestrictedGroups/SecurityPolicies) and PKI (CAs/
//     Templates): zero source data; SharpHound's gpos.json/domains.json
//     files are not parsed by attackpath at all yet.
//   - Identity.ServiceAccounts / Identity.ComputerAccounts: attackpath
//     does not distinguish a service account from a regular user, and a
//     computer account is already reported as a Machine, not separately
//     as an Identity -- mapping it to both would duplicate the same
//     object under two different shapes.
//   - Machines.AdminWorkstations: attackpath has no PAW (privileged
//     access workstation) classification distinct from a regular
//     workstation.
//
// Within the categories this DOES map, two fields also stay at zero-value
// for the same "no source data" reason, not because they were forgotten:
//   - User.Enabled: attackpath never tracks enabled/disabled state. This
//     field is always false here, and that MUST be read as "unknown",
//     never as "this account is disabled".
//   - User.SPNs: attackpath only tracks whether a user HAS an SPN
//     (Node.HasSPN, a bool), never the actual SPN string values. This
//     field stays nil rather than holding a fabricated placeholder.
//   - ConstrainedDelegation.ProtocolTransition: attackpath's
//     EdgeAllowedToDelegate carries no S4U2Self flag; always false here.
func FromGraph(g *attackpath.Graph) Environment {
	var env Environment

	groupMembers := map[string][]string{}
	constrained := map[string]*ConstrainedDelegation{}
	var constrainedOrder []string
	rbcd := map[string]*RBCDEntry{}
	var rbcdOrder []string

	for _, e := range g.Edges() {
		if right, ok := aclEdgeKinds[e.Kind]; ok {
			env.Authorization.ACLs = append(env.Authorization.ACLs, ACLEntry{
				Principal: e.From, Target: e.To, Right: right,
			})
			continue
		}
		switch e.Kind {
		case attackpath.EdgeMemberOf:
			groupMembers[e.To] = append(groupMembers[e.To], e.From)
		case attackpath.EdgeAllowedToDelegate:
			// From = the delegating computer (Principal), To = the target
			// SPN's service/computer (collected into Targets).
			cd, ok := constrained[e.From]
			if !ok {
				cd = &ConstrainedDelegation{Principal: e.From}
				constrained[e.From] = cd
				constrainedOrder = append(constrainedOrder, e.From)
			}
			cd.Targets = append(cd.Targets, e.To)
		case attackpath.EdgeAllowedToAct:
			// From = the principal allowed to act, To = the resource
			// computer accepting delegation (Target). OPPOSITE grantee
			// position from EdgeAllowedToDelegate above.
			r, ok := rbcd[e.To]
			if !ok {
				r = &RBCDEntry{Target: e.To}
				rbcd[e.To] = r
				rbcdOrder = append(rbcdOrder, e.To)
			}
			r.AllowedPrincipals = append(r.AllowedPrincipals, e.From)
		}
	}
	for _, principal := range constrainedOrder {
		env.Delegation.Constrained = append(env.Delegation.Constrained, *constrained[principal])
	}
	for _, target := range rbcdOrder {
		env.Delegation.RBCD = append(env.Delegation.RBCD, *rbcd[target])
	}

	for _, n := range g.Nodes() {
		switch n.Kind {
		case attackpath.KindUser:
			env.Identity.Users = append(env.Identity.Users, User{Name: n.Label, SID: n.ID})
			if n.HighValue {
				env.Identity.PrivilegedAccounts = append(env.Identity.PrivilegedAccounts, n.ID)
			}
			if n.UnconstrainedDelegation {
				env.Delegation.Unconstrained = append(env.Delegation.Unconstrained, n.ID)
			}
		case attackpath.KindGroup:
			env.Identity.Groups = append(env.Identity.Groups, Group{
				Name: n.Label, SID: n.ID, Members: groupMembers[n.ID],
			})
			if n.HighValue {
				env.Identity.PrivilegedAccounts = append(env.Identity.PrivilegedAccounts, n.ID)
			}
		case attackpath.KindHost:
			m := Machine{Hostname: n.Label, SID: n.ID}
			switch n.Role {
			case attackpath.RoleDC:
				env.Machines.DomainControllers = append(env.Machines.DomainControllers, m)
			case attackpath.RoleServer:
				env.Machines.Servers = append(env.Machines.Servers, m)
			default:
				env.Machines.Workstations = append(env.Machines.Workstations, m)
			}
			if n.UnconstrainedDelegation {
				env.Delegation.Unconstrained = append(env.Delegation.Unconstrained, n.ID)
			}
		}
	}

	return env
}
