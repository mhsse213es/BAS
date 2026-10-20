package protocol

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

// SOAP is the SOAP adapter. A SOAP request is an XML document POSTed with a text/xml body. The
// adapter parses it strictly, and validates every external entity the document declares. An
// external entity may point only at a loopback lab host, so a scenario cannot send a request
// that reaches anywhere else (the INJ-005 prerequisite).
type SOAP struct{}

func init() { Register(SOAP{}) }

// Name is the protocol name.
func (SOAP) Name() string { return "soap" }

// Validate checks that the body parses as XML and that every external entity targets a loopback
// lab host.
func (SOAP) Validate(body string) error {
	_, err := ParseSOAP(body)
	return err
}

// SOAPEnvelope is a parsed SOAP request.
type SOAPEnvelope struct {
	// Root is the local name of the document's root element.
	Root string
	// Order is the text of the first <order> element. An entity reference in it appears as
	// {{entity:NAME}}, so the caller sees where the document refers to an external entity.
	Order string
	// External maps each external entity the DOCTYPE declares to its SYSTEM identifier.
	External map[string]string
}

// entityDecl matches one external entity declaration in a DOCTYPE.
var entityDecl = regexp.MustCompile(`<!ENTITY\s+([A-Za-z_][\w.-]*)\s+SYSTEM\s+"([^"]+)"\s*>`)

// ParseSOAP parses a SOAP request. The entity declarations are read first, and each external
// target is checked against the loopback lab hosts before the document is decoded.
func ParseSOAP(body string) (SOAPEnvelope, error) {
	env := SOAPEnvelope{External: map[string]string{}}
	entities := map[string]string{}
	for _, m := range entityDecl.FindAllStringSubmatch(body, -1) {
		name, sys := m[1], m[2]
		if err := loopbackOnly(sys); err != nil {
			return SOAPEnvelope{}, fmt.Errorf("soap entity %s: %w", name, err)
		}
		env.External[name] = sys
		entities[name] = "{{entity:" + name + "}}"
	}

	dec := xml.NewDecoder(strings.NewReader(body))
	dec.Strict = true
	dec.Entity = entities
	inOrder := false
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return SOAPEnvelope{}, fmt.Errorf("soap body is not well-formed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if env.Root == "" {
				env.Root = t.Name.Local
			}
			if t.Name.Local == "order" && env.Order == "" {
				inOrder = true
			}
		case xml.EndElement:
			if t.Name.Local == "order" {
				inOrder = false
			}
		case xml.CharData:
			if inOrder {
				env.Order += string(t)
			}
		}
	}
	if env.Root == "" {
		return SOAPEnvelope{}, fmt.Errorf("soap body has no root element")
	}
	return env, nil
}

// loopbackOnly refuses any external entity identifier that does not name a loopback lab host.
func loopbackOnly(sys string) error {
	u, err := url.Parse(sys)
	if err != nil {
		return fmt.Errorf("identifier is not a URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q is not allowed", u.Scheme)
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost":
		return nil
	}
	return fmt.Errorf("host %q is not a loopback lab host", u.Hostname())
}
