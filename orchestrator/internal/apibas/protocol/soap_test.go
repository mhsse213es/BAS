package protocol

import "testing"

func TestParseSOAPReadsOrder(t *testing.T) {
	env, err := ParseSOAP(`<?xml version="1.0"?><request><order>ORD-2001</order></request>`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if env.Root != "request" || env.Order != "ORD-2001" {
		t.Fatalf("envelope = %+v, want root request and order ORD-2001", env)
	}
	if len(env.External) != 0 {
		t.Fatalf("no entity declared, but External = %v", env.External)
	}
}

func TestParseSOAPSeesLoopbackExternalEntity(t *testing.T) {
	body := `<?xml version="1.0"?><!DOCTYPE request [<!ENTITY x SYSTEM "http://127.0.0.1:8099/internal/orders/ORD-2001">]><request><order>&x;</order></request>`
	env, err := ParseSOAP(body)
	if err != nil {
		t.Fatalf("loopback entity refused: %v", err)
	}
	if env.Order != "{{entity:x}}" {
		t.Fatalf("order = %q, want the entity reference {{entity:x}}", env.Order)
	}
	if env.External["x"] != "http://127.0.0.1:8099/internal/orders/ORD-2001" {
		t.Fatalf("external[x] = %q", env.External["x"])
	}
}

// The adapter must refuse an external entity that reaches anywhere except the lab.
func TestParseSOAPRefusesNonLoopbackEntity(t *testing.T) {
	cases := map[string]string{
		"remote host": `<!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/">]><r>&x;</r>`,
		"file scheme": `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
		"ftp scheme":  `<!DOCTYPE r [<!ENTITY x SYSTEM "ftp://127.0.0.1/a">]><r>&x;</r>`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSOAP(doc); err == nil {
				t.Fatalf("external entity %s accepted, want refusal", name)
			}
		})
	}
}

func TestParseSOAPRefusesMalformedAndUndeclared(t *testing.T) {
	cases := map[string]string{
		"not xml":           `this is not xml`,
		"unclosed root":     `<request><order>ORD-2001</order>`,
		"undeclared entity": `<request><order>&nope;</order></request>`,
		"empty":             ``,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSOAP(doc); err == nil {
				t.Fatalf("%s accepted, want an error", name)
			}
		})
	}
}

func TestSOAPIsRegistered(t *testing.T) {
	if !Supported("soap") {
		t.Fatal("soap has an adapter but Supported reports false")
	}
	if err := (SOAP{}).Validate(`<request><order>ORD-2001</order></request>`); err != nil {
		t.Fatalf("valid body refused by adapter: %v", err)
	}
}
