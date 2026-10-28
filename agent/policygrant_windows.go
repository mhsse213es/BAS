//go:build windows

// Windows side of the B5 Local Policy Grant Mechanism
// (docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md):
// the grant store's HMAC key is protected at rest via the existing DPAPI
// helpers in tamper.go (EncryptSecret/DecryptSecret, machine-scope --
// checked for and reused per the spec's own instruction, rather than
// building a new secure-storage primitive).
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"audspect/agent/policygrant"
)

var (
	flagPolicyGrant      *bool
	flagPolicyScope      *string
	flagPolicyScenarioID *string
	flagPolicyReason     *string
	flagPolicyExpires    *string
)

func registerPolicyGrantFlags() {
	flagPolicyGrant = flag.Bool("policy-grant", false, "Issue a local policy grant authorizing one destructive-classified action on this agent (requires an elevated/Administrator process)")
	flagPolicyScope = flag.String("scope", "", "The action to authorize, shaped \"technique_id:action_key\" (e.g. T1003.006:default)")
	flagPolicyScenarioID = flag.String("scenario-id", "", "Optional: narrow the grant to this scenario only (omit to cover the action regardless of which scenario invokes it)")
	flagPolicyReason = flag.String("reason", "", "Required: why this grant is being issued, recorded in the audit trail")
	flagPolicyExpires = flag.String("expires", "", "Required: how long the grant is valid, as a Go duration (e.g. 30m, 2h). No permanent grants are supported")
}

func init() {
	checkDestructiveGrant = windowsCheckDestructiveGrant
}

func policyDir() string {
	return filepath.Join(os.Getenv("ProgramData"), "Audspect", "policy")
}

func grantStorePaths() (dataPath, macPath, keyPath string) {
	dir := policyDir()
	return filepath.Join(dir, "grants.json"), filepath.Join(dir, "grants.hmac"), filepath.Join(dir, "grant-hmac.key.dpapi")
}

// loadOrCreateGrantHMACKey returns the DPAPI-protected HMAC key that signs
// the grant store, generating and persisting a fresh random one the first
// time this is called on a given machine.
func loadOrCreateGrantHMACKey() ([]byte, error) {
	_, _, keyPath := grantStorePaths()
	if b, err := os.ReadFile(keyPath); err == nil {
		plain, derr := DecryptSecret(b)
		if derr != nil {
			return nil, fmt.Errorf("decrypt grant HMAC key: %w", derr)
		}
		return []byte(plain), nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	blob, err := EncryptSecret(string(key))
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(policyDir(), 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, blob, 0600); err != nil {
		return nil, err
	}
	return key, nil
}

func loadGrantStore() (policygrant.Store, error) {
	key, err := loadOrCreateGrantHMACKey()
	if err != nil {
		return policygrant.Store{}, err
	}
	dataPath, macPath, _ := grantStorePaths()
	data, derr := os.ReadFile(dataPath)
	if derr != nil && !os.IsNotExist(derr) {
		return policygrant.Store{}, derr
	}
	mac, merr := os.ReadFile(macPath)
	if merr != nil && !os.IsNotExist(merr) {
		return policygrant.Store{}, merr
	}
	return policygrant.UnmarshalSigned(data, mac, key)
}

func saveGrantStore(s policygrant.Store) error {
	key, err := loadOrCreateGrantHMACKey()
	if err != nil {
		return err
	}
	data, mac, err := policygrant.MarshalSigned(s, key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(policyDir(), 0700); err != nil {
		return err
	}
	dataPath, macPath, _ := grantStorePaths()
	if err := os.WriteFile(dataPath, data, 0600); err != nil {
		return err
	}
	return os.WriteFile(macPath, mac, 0600)
}

// auditGrantEvent records a grant lifecycle event. The audit log is
// evidence, not enforcement -- the grant store alone decides ALLOW/VETO.
func auditGrantEvent(event, action, scenarioID, reason, detail string) {
	line := fmt.Sprintf("%s event=%s action=%q scenario=%q reason=%q detail=%q\n",
		time.Now().UTC().Format(time.RFC3339), event, action, scenarioID, reason, detail)
	if err := os.MkdirAll(policyDir(), 0700); err != nil {
		log.Printf("[policygrant] audit log: %v", err)
		return
	}
	f, err := os.OpenFile(filepath.Join(policyDir(), "grants.audit.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("[policygrant] audit log: %v", err)
		return
	}
	defer f.Close()
	f.WriteString(line)
}

// windowsCheckDestructiveGrant is the real B5 grant check, wired in by this
// file's init(). A store load failure fails closed (treated as no grant).
func windowsCheckDestructiveGrant(action, scenarioID string) (ok bool, status string) {
	s, err := loadGrantStore()
	if err != nil {
		log.Printf("[policygrant] load grant store: %v", err)
		return false, "invalid"
	}
	agentID := collectIdentity().AgentID
	ok, status = s.CheckGrant(agentID, action, scenarioID, time.Now())
	if ok {
		auditGrantEvent("grant_used", action, scenarioID, "", "")
	} else {
		auditGrantEvent("grant_rejected", action, scenarioID, "", status)
	}
	return ok, status
}

// runPolicyGrantCLI is the "bas-agent policy grant" entry point. Root of
// trust is the host OS's own administrative privilege boundary -- never the
// orchestrator -- so this refuses to run at all without isElevated().
func runPolicyGrantCLI(action, scenarioID, reason, expiresStr string) int {
	if !isElevated() {
		fmt.Fprintln(os.Stderr, "[!] policy grant requires an elevated (Administrator) process")
		return 1
	}
	ttl, err := time.ParseDuration(expiresStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] invalid --expires %q: %v\n", expiresStr, err)
		return 1
	}
	agentID := collectIdentity().AgentID
	g, err := policygrant.NewGrant(agentID, policygrant.Request{Action: action, ScenarioID: scenarioID, Reason: reason, TTL: ttl}, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %v\n", err)
		auditGrantEvent("grant_rejected", action, scenarioID, reason, err.Error())
		return 1
	}
	store, err := loadGrantStore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] load grant store: %v\n", err)
		return 1
	}
	store.Grants = append(store.Grants, g)
	if err := saveGrantStore(store); err != nil {
		fmt.Fprintf(os.Stderr, "[!] save grant store: %v\n", err)
		return 1
	}
	auditGrantEvent("grant_created", action, scenarioID, reason, "")
	scenarioDesc := scenarioID
	if scenarioDesc == "" {
		scenarioDesc = "(any)"
	}
	fmt.Printf("[+] grant issued: action=%s scenario=%s expires=%s\n", action, scenarioDesc, g.ExpiresAt.Format(time.RFC3339))
	return 0
}
