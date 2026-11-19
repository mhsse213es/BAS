package carbanakledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Identity is a synthetic lab operator. Token is a synthetic credential, never a
// real one. Roles are "operator", "approver", and "privileged". Limit is the
// per-transfer limit in minor units.
type Identity struct {
	ID    string   `json:"id"`
	Token string   `json:"token"`
	Roles []string `json:"roles"`
	Limit int64    `json:"limit"`
}

// WindowConfig is the operating window as configured. Weekdays use Go numbering
// (0 = Sunday ... 6 = Saturday).
type WindowConfig struct {
	Timezone  string `json:"timezone"`
	StartHour int    `json:"start_hour"`
	EndHour   int    `json:"end_hour"`
	Weekdays  []int  `json:"weekdays"`
}

type Config struct {
	ListenAddr        string       `json:"listen_addr"`
	LabHostname       string       `json:"lab_hostname"`
	AuditPath         string       `json:"audit_path"`
	SessionTTLSeconds int          `json:"session_ttl_seconds"`
	Identities        []Identity   `json:"identities"`
	Window            WindowConfig `json:"window"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse config: %w", err)
	}
	return c, nil
}

func (w WindowConfig) Build() (Window, error) {
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		return Window{}, fmt.Errorf("timezone %q: %w", w.Timezone, err)
	}
	days := make([]time.Weekday, 0, len(w.Weekdays))
	for _, d := range w.Weekdays {
		if d < 0 || d > 6 {
			return Window{}, fmt.Errorf("weekday %d out of range 0-6", d)
		}
		days = append(days, time.Weekday(d))
	}
	return Window{Location: loc, StartHour: w.StartHour, EndHour: w.EndHour, Weekdays: days}, nil
}

// CheckListenAddr enforces the loopback-only rule. Non-loopback needs the
// explicit override and a lab hostname ending .test, .invalid, or .lab.
func CheckListenAddr(addr, labHostname string, allowNonLocal bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if !allowNonLocal {
		return errors.New("refusing non-loopback listen address: set BAS_CARBANAK_ALLOW_NONLOCAL=1 for a lab host")
	}
	for _, suffix := range []string{".test", ".invalid", ".lab"} {
		if strings.HasSuffix(labHostname, suffix) {
			return nil
		}
	}
	return fmt.Errorf("refusing non-loopback listen: lab_hostname %q must end .test, .invalid, or .lab", labHostname)
}

// Listen wraps net.Listen so that a port already in use is reported plainly.
func Listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: port in use or unavailable: %w", addr, err)
	}
	return ln, nil
}
