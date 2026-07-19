package scim

import "testing"

func TestFromUserRow_MapsFieldsAndSchema(t *testing.T) {
	u := FromUserRow(UserRow{
		ID: "u1", Username: "person@example.com", Active: true,
		CreatedAt: "2026-07-19T00:00:00Z", UpdatedAt: "2026-07-19T00:00:00Z",
	})
	if u.ID != "u1" || u.UserName != "person@example.com" || !u.Active {
		t.Errorf("got %+v", u)
	}
	if len(u.Schemas) != 1 || u.Schemas[0] != SchemaUser {
		t.Errorf("Schemas = %v, want [%s]", u.Schemas, SchemaUser)
	}
	if len(u.Emails) != 1 || u.Emails[0].Value != "person@example.com" || !u.Emails[0].Primary {
		t.Errorf("Emails = %+v", u.Emails)
	}
	if u.Meta == nil || u.Meta.ResourceType != "User" {
		t.Errorf("Meta = %+v", u.Meta)
	}
}

func TestIncomingUser_ActiveOrDefault(t *testing.T) {
	trueVal := true
	falseVal := false
	cases := []struct {
		name string
		in   IncomingUser
		want bool
	}{
		{"omitted defaults true", IncomingUser{UserName: "a"}, true},
		{"explicit true", IncomingUser{UserName: "a", Active: &trueVal}, true},
		{"explicit false", IncomingUser{UserName: "a", Active: &falseVal}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.ActiveOrDefault(); got != c.want {
				t.Errorf("ActiveOrDefault() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseUserNameFilter_SupportedShape(t *testing.T) {
	v, err := ParseUserNameFilter(`userName eq "person@example.com"`)
	if err != nil {
		t.Fatalf("ParseUserNameFilter: %v", err)
	}
	if v != "person@example.com" {
		t.Errorf("value = %q, want person@example.com", v)
	}
}

func TestParseUserNameFilter_Empty(t *testing.T) {
	v, err := ParseUserNameFilter("")
	if err != nil {
		t.Fatalf("ParseUserNameFilter: %v", err)
	}
	if v != "" {
		t.Errorf("value = %q, want empty", v)
	}
}

func TestParseUserNameFilter_UnsupportedShapeRejected(t *testing.T) {
	if _, err := ParseUserNameFilter(`userName co "person"`); err == nil {
		t.Fatal("expected an error for an unsupported filter expression, got nil")
	}
	if _, err := ParseUserNameFilter(`active eq true`); err == nil {
		t.Fatal("expected an error for a non-userName filter, got nil")
	}
}

func TestParsePatchActive_PathShape(t *testing.T) {
	body := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)
	active, found, err := ParsePatchActive(body)
	if err != nil {
		t.Fatalf("ParsePatchActive: %v", err)
	}
	if !found || active {
		t.Errorf("active=%v found=%v, want false/true", active, found)
	}
}

func TestParsePatchActive_ValueObjectShape(t *testing.T) {
	body := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`)
	active, found, err := ParsePatchActive(body)
	if err != nil {
		t.Fatalf("ParsePatchActive: %v", err)
	}
	if !found || active {
		t.Errorf("active=%v found=%v, want false/true", active, found)
	}
}

func TestParsePatchActive_NoActiveOperation(t *testing.T) {
	body := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"userName","value":"new@example.com"}]}`)
	_, found, err := ParsePatchActive(body)
	if err != nil {
		t.Fatalf("ParsePatchActive: %v", err)
	}
	if found {
		t.Error("found = true, want false — no active operation in this body")
	}
}
