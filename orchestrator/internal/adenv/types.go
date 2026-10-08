// Package adenv is the AD environment knowledge model (AD-M01): a typed
// representation of an Active Directory environment's structure, mirroring
// the ontology in AD.txt's own diagram (Forest, Identity, Machines,
// Authentication, Delegation, Authorization, Policy, PKI).
//
// This package holds pure data types only — no discovery/collection logic
// (AD-M02 will populate an Environment from SharpHound/BloodHound output)
// and no graph projection (AD-M03's internal/attackpath graph is built FROM
// an Environment, not the other way around). Keeping this package free of
// behavior keeps it the stable, shared vocabulary every later AD-M phase
// reads and writes, instead of each phase inventing its own shape.
package adenv

// Environment is the full AD environment knowledge model: one forest's
// worth of structure, as reconstructed from discovery data.
type Environment struct {
	Forest         Forest         `json:"forest"`
	Identity       Identity       `json:"identity"`
	Machines       Machines       `json:"machines"`
	Authentication Authentication `json:"authentication"`
	Delegation     Delegation     `json:"delegation"`
	Authorization  Authorization  `json:"authorization"`
	Policy         Policy         `json:"policy"`
	PKI            PKI            `json:"pki"`
}

// Forest is the forest/domain/trust layer.
type Forest struct {
	Domains             []Domain `json:"domains,omitempty"`
	Trusts              []Trust  `json:"trusts,omitempty"`
	ForestRelationships []string `json:"forestRelationships,omitempty"` // e.g. "child-domain", "cross-forest"
}

// Domain is one domain within the forest.
type Domain struct {
	Name    string `json:"name"` // DNS name, e.g. "corp.example.com"
	SID     string `json:"sid"`  // domain SID
	NetBIOS string `json:"netbios,omitempty"`
}

// TrustDirection is the direction of trust flow between two domains/forests.
type TrustDirection string

const (
	TrustInbound       TrustDirection = "inbound"
	TrustOutbound      TrustDirection = "outbound"
	TrustBidirectional TrustDirection = "bidirectional"
)

// TrustType names the kind of trust relationship.
type TrustType string

const (
	TrustTypeParentChild TrustType = "parent-child"
	TrustTypeCrossLink   TrustType = "cross-link"
	TrustTypeExternal    TrustType = "external"
	TrustTypeForest      TrustType = "forest"
	TrustTypeRealm       TrustType = "realm"
)

// Trust is one trust relationship between two domains.
type Trust struct {
	SourceDomain string         `json:"sourceDomain"`
	TargetDomain string         `json:"targetDomain"`
	Direction    TrustDirection `json:"direction"`
	Type         TrustType      `json:"type"`
	Transitive   bool           `json:"transitive"`
}

// Identity is the user/group/account layer.
type Identity struct {
	Users              []User   `json:"users,omitempty"`
	Groups             []Group  `json:"groups,omitempty"`
	ServiceAccounts    []User   `json:"serviceAccounts,omitempty"`
	ComputerAccounts   []User   `json:"computerAccounts,omitempty"`
	PrivilegedAccounts []string `json:"privilegedAccounts,omitempty"` // SIDs/names flagged privileged
}

// User is one user, service, or computer account.
type User struct {
	Name    string   `json:"name"`
	SID     string   `json:"sid"`
	Enabled bool     `json:"enabled"`
	SPNs    []string `json:"spns,omitempty"` // service principal names (Kerberoastable if non-empty)
}

// Group is one AD group.
type Group struct {
	Name    string   `json:"name"`
	SID     string   `json:"sid"`
	Members []string `json:"members,omitempty"` // member SIDs/names
}

// Machines is the host inventory layer.
type Machines struct {
	DomainControllers []Machine `json:"domainControllers,omitempty"`
	Servers           []Machine `json:"servers,omitempty"`
	Workstations      []Machine `json:"workstations,omitempty"`
	AdminWorkstations []Machine `json:"adminWorkstations,omitempty"`
}

// Machine is one computer in the environment.
type Machine struct {
	Hostname string `json:"hostname"`
	SID      string `json:"sid"`
	OS       string `json:"os,omitempty"`
}

// Authentication is per-environment protocol configuration — not live
// session state, just which protocols/config are present.
type Authentication struct {
	Kerberos KerberosConfig `json:"kerberos"`
	NTLM     bool           `json:"ntlm"`
	LDAP     LDAPConfig     `json:"ldap"`
	SMB      SMBConfig      `json:"smb"`
	RDP      bool           `json:"rdp"`
	WinRM    bool           `json:"winrm"`
}

// KerberosConfig is the environment's Kerberos-relevant configuration.
type KerberosConfig struct {
	Enabled bool `json:"enabled"`
	// PreAuthRequired false on an account makes it AS-REP-roastable; this
	// field is the environment-level default an AD-M02 mapper observes,
	// not a per-user override (per-user exceptions live on User later if
	// a future phase needs them).
	PreAuthRequired bool `json:"preAuthRequired"`
}

// LDAPConfig is the environment's LDAP hardening configuration.
type LDAPConfig struct {
	SigningRequired        bool `json:"signingRequired"`
	ChannelBindingRequired bool `json:"channelBindingRequired"`
}

// SMBConfig is the environment's SMB hardening configuration.
type SMBConfig struct {
	SigningRequired bool `json:"signingRequired"`
}

// Delegation is the Kerberos delegation layer.
type Delegation struct {
	Unconstrained []string                `json:"unconstrained,omitempty"` // principal names/SIDs with unconstrained delegation
	Constrained   []ConstrainedDelegation `json:"constrained,omitempty"`
	RBCD          []RBCDEntry             `json:"rbcd,omitempty"`
}

// ConstrainedDelegation is one principal's constrained-delegation grant.
type ConstrainedDelegation struct {
	Principal          string   `json:"principal"`
	Targets            []string `json:"targets"`            // SPNs this principal can delegate to
	ProtocolTransition bool     `json:"protocolTransition"` // true = S4U2Self allowed
}

// RBCDEntry is one resource-based constrained delegation grant.
type RBCDEntry struct {
	Target            string   `json:"target"` // the resource/computer accepting delegation
	AllowedPrincipals []string `json:"allowedPrincipals"`
}

// Authorization is the ACL layer.
type Authorization struct {
	ACLs []ACLEntry `json:"acls,omitempty"`
}

// ACLRight names one of AD.txt's closed set of abuse-relevant ACL rights.
type ACLRight string

const (
	ACLGenericAll          ACLRight = "GenericAll"
	ACLGenericWrite        ACLRight = "GenericWrite"
	ACLWriteDACL           ACLRight = "WriteDACL"
	ACLWriteOwner          ACLRight = "WriteOwner"
	ACLForceChangePassword ACLRight = "ForceChangePassword"
	ACLAddMember           ACLRight = "AddMember"
	ACLAddSelf             ACLRight = "AddSelf"

	// The 4 below match attackpath.EdgeKind values already shipped in
	// AD-M03's graph (orchestrator/internal/attackpath/graph.go) --
	// added here so adenv's enum doesn't lag what the graph already
	// models.
	ACLOwns                 ACLRight = "owns"
	ACLAllExtendedRights    ACLRight = "all-extended-rights"
	ACLAddKeyCredentialLink ACLRight = "add-key-credential-link"
	ACLReadLAPSPassword     ACLRight = "read-laps-password"
)

// ACLEntry is one ACL grant from a principal onto a target object.
type ACLEntry struct {
	Principal string   `json:"principal"` // the SID/name holding the right
	Target    string   `json:"target"`    // the SID/name the right applies to
	Right     ACLRight `json:"right"`
}

// Policy is the GPO/security-policy layer.
type Policy struct {
	GPOs             []GPO    `json:"gpos,omitempty"`
	RestrictedGroups []string `json:"restrictedGroups,omitempty"`
	LAPSEnabled      bool     `json:"lapsEnabled"`
	SecurityPolicies []string `json:"securityPolicies,omitempty"` // free-form policy names/IDs
}

// GPO is one Group Policy Object.
type GPO struct {
	Name      string   `json:"name"`
	LinkedOUs []string `json:"linkedOUs,omitempty"`
}

// PKI is the ADCS layer.
type PKI struct {
	CAs       []CertificateAuthority `json:"cas,omitempty"`
	Templates []CertTemplate         `json:"templates,omitempty"`
}

// CertificateAuthority is one enterprise/standalone CA.
type CertificateAuthority struct {
	Name string `json:"name"`

	// PublishedTemplates are the certificate templates this CA will
	// issue certificates against. A template not listed here cannot be
	// requested through this CA regardless of its own properties.
	PublishedTemplates []string `json:"publishedTemplates,omitempty"`

	// EnrollmentRights are principals who hold enrollment permission on
	// the CA object itself -- a separate permission layer from any given
	// template's own EnrollmentRights below; both must be held to
	// successfully request a certificate.
	EnrollmentRights []string `json:"enrollmentRights,omitempty"`
}

// CertTemplate is one certificate template's configuration: the
// properties a certificate-services configuration review inspects.
type CertTemplate struct {
	Name string `json:"name"`

	// EKUs are the Extended Key Usages this template's issued
	// certificates may be used for (e.g. "Client Authentication",
	// "Any Purpose", "Certificate Request Agent", "Smart Card Logon"). A
	// template may carry more than one.
	EKUs []string `json:"ekus,omitempty"`

	EnrollmentRights []string `json:"enrollmentRights,omitempty"` // principals who hold Enroll/AutoEnroll on this template
	WriteRights      []string `json:"writeRights,omitempty"`      // principals who hold GenericWrite/WriteOwner/WriteDacl on the TEMPLATE object itself

	ManagerApprovalRequired bool `json:"managerApprovalRequired"`
	EnrolleeSuppliesSubject bool `json:"enrolleeSuppliesSubject"` // the template's CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag

	// PublishedToCA mirrors CertificateAuthority.PublishedTemplates from
	// the template's own side -- nothing in this schema enforces the two
	// stay consistent with each other; that is a future validation
	// concern, not this type's job.
	PublishedToCA bool `json:"publishedToCA"`
}
