// Package scim implements the wire schema and translation layer for
// Audspect's SCIM 2.0 provisioning endpoints — practical RFC 7644
// compliance for Okta/Azure AD, Users-only, no Groups. See
// docs/superpowers/specs/2026-07-19-phase7-scim-provisioning-design.md.
package scim

import "encoding/json"

const (
	SchemaUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatchOp               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema                = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// Meta is the standard SCIM resource metadata block.
type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

// Email is one entry of a SCIM User's multi-valued emails attribute.
type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

// User is the outgoing wire shape for a SCIM User resource — Active is
// always serialized (never omitted), since Audspect's users.is_active is
// always a concrete boolean.
type User struct {
	Schemas  []string `json:"schemas"`
	ID       string   `json:"id,omitempty"`
	UserName string   `json:"userName"`
	Active   bool     `json:"active"`
	Emails   []Email  `json:"emails,omitempty"`
	Meta     *Meta    `json:"meta,omitempty"`
}

// IncomingUser is the wire shape Audspect accepts for POST/PUT request
// bodies. Active is a pointer so ActiveOrDefault can distinguish "omitted"
// (defaults to true, SCIM's convention for a newly created/replaced
// resource) from "explicitly false".
type IncomingUser struct {
	Schemas  []string `json:"schemas"`
	UserName string   `json:"userName"`
	Active   *bool    `json:"active"`
	Emails   []Email  `json:"emails,omitempty"`
}

// ActiveOrDefault returns the incoming active flag, defaulting to true
// when omitted.
func (u IncomingUser) ActiveOrDefault() bool {
	if u.Active == nil {
		return true
	}
	return *u.Active
}

// ListResponse is the wire shape for GET /Users.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []User   `json:"Resources"`
}

// Error is the wire shape for every SCIM error response.
type Error struct {
	Schemas []string `json:"schemas"`
	Status  string   `json:"status"`
	Detail  string   `json:"detail,omitempty"`
}

// PatchOp is the wire shape for PATCH /Users/{id} request bodies.
type PatchOp struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one entry of a PatchOp's Operations array. Path is
// optional — some IdPs (Azure AD) send path-less operations with the
// changed attributes nested inside Value instead.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ServiceProviderConfig is the wire shape for GET /ServiceProviderConfig —
// IdPs fetch this during SCIM app setup and refuse to proceed without it.
type ServiceProviderConfig struct {
	Schemas        []string        `json:"schemas"`
	Patch          Supported       `json:"patch"`
	Bulk           BulkSupported   `json:"bulk"`
	Filter         FilterSupported `json:"filter"`
	ChangePassword Supported       `json:"changePassword"`
	Sort           Supported       `json:"sort"`
	ETag           Supported       `json:"etag"`
}

type Supported struct {
	Supported bool `json:"supported"`
}

type BulkSupported struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

type FilterSupported struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// ResourceType is the wire shape for one entry of GET /ResourceTypes.
type ResourceType struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Endpoint    string   `json:"endpoint"`
	Description string   `json:"description"`
	Schema      string   `json:"schema"`
}

// Schema is the wire shape for one entry of GET /Schemas.
type Schema struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Attributes  []SchemaAttribute `json:"attributes"`
}

// SchemaAttribute describes one attribute of a Schema.
type SchemaAttribute struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	MultiValued bool   `json:"multiValued"`
	Required    bool   `json:"required"`
	CaseExact   bool   `json:"caseExact"`
	Mutability  string `json:"mutability"`
	Returned    string `json:"returned"`
	Uniqueness  string `json:"uniqueness"`
}
