package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Async is the asynchronous-messaging adapter, in its publish form: an event is POSTed to
// /broker/topics/{topic}/publish as a JSON object with an "event" string. A signed event carries
// X-Event-Signature as "sha256=" followed by 64 hex digits. The runner sends only paths and headers
// that pass these checks. Delivery and consumer behaviour are the lab's, not the adapter's.
type Async struct{}

func init() { Register(Async{}) }

// Name is the protocol name.
func (Async) Name() string { return "async" }

// Validate checks that the body is a JSON object with an "event" string.
func (Async) Validate(body string) error {
	var ev struct {
		Event string `json:"event"`
	}
	if err := json.Unmarshal([]byte(body), &ev); err != nil {
		return fmt.Errorf("async body must be a JSON object: %w", err)
	}
	if strings.TrimSpace(ev.Event) == "" {
		return errors.New("async event needs a non-empty event name")
	}
	return nil
}

// publishPath matches a topic publish: /broker/topics/{topic}/publish.
var publishPath = regexp.MustCompile(`^/broker/topics/[A-Za-z][\w.-]*/publish$`)

// ValidatePublishPath reports whether a path is a topic publish.
func ValidatePublishPath(path string) error {
	if !publishPath.MatchString(path) {
		return fmt.Errorf("async path %q is not /broker/topics/{topic}/publish", path)
	}
	return nil
}

// signatureFormat matches the signature header value: sha256= and 64 hex digits.
var signatureFormat = regexp.MustCompile(`^sha256=[0-9a-f]{64}$`)

// ValidateSignatureHeader reports whether a signature header value has the sha256 form. The value
// is checked against the body by the consumer; this checks only its shape.
func ValidateSignatureHeader(value string) error {
	if !signatureFormat.MatchString(value) {
		return errors.New("X-Event-Signature must be sha256= followed by 64 lowercase hex digits")
	}
	return nil
}
