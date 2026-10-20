package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// GRPC is the gRPC adapter, in its JSON transcoding form: a gRPC method is sent as an HTTP POST to
// /{package.Service}/{Method} with a JSON object body, and a gRPC status is returned as its HTTP
// equivalent (PERMISSION_DENIED as 403). This is not native gRPC framing over HTTP/2. The runner's
// client speaks HTTP/1.1, so the adapter covers the transcoded surface only, and the QA log says so.
type GRPC struct{}

func init() { Register(GRPC{}) }

// Name is the protocol name.
func (GRPC) Name() string { return "grpc" }

// Validate checks that the body is a JSON object, which is what a transcoded request carries.
func (GRPC) Validate(body string) error {
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return fmt.Errorf("grpc body must be a JSON object: %w", err)
	}
	if obj == nil {
		return errors.New("grpc body must be a JSON object, not null")
	}
	return nil
}

// methodPath matches a gRPC method: /package.Service/Method, where the package may be empty.
var methodPath = regexp.MustCompile(`^/([A-Za-z_]\w*\.)*[A-Za-z_]\w*/[A-Za-z_]\w*$`)

// ValidateMethodPath reports whether a path names a fully qualified gRPC method. The runner sends
// only paths that pass this check, so a scenario cannot address anything but a gRPC method.
func ValidateMethodPath(path string) error {
	if !methodPath.MatchString(path) {
		return fmt.Errorf("grpc path %q is not /package.Service/Method", path)
	}
	return nil
}
