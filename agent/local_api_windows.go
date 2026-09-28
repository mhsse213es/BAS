//go:build windows

package main

import (
	"bufio"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

const localAPIAddr = "127.0.0.1:9001"

// dashboardHTML is the self-contained status console served at GET /.
// The page itself is unauthenticated markup; the data endpoints it calls
// (/status, /activity, …) still require the bearer token, which the tray
// passes to the page via the ?t=<token> query parameter.
//
//go:embed ui_dashboard.html
var dashboardHTML []byte

// startLocalAPI starts the loopback-only status HTTP server.
// The auth token is persisted at %ProgramData%\BASAgent\api.token so the
// unprivileged tray application can read it without requiring elevation.
func (a *Agent) startLocalAPI() {
	token, err := ensureAPIToken()
	if err != nil {
		log.Printf("[!] local API: token setup failed: %v", err)
		return
	}

	mux := http.NewServeMux()
	bearer := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(dashboardHTML)
	})
	// Reuses the same embedded wordmark logo_windows.go decodes for the
	// native status window's own header, so the browser dashboard shows the
	// identical Audspect logo rather than a separate hand-drawn icon.
	mux.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "max-age=86400")
		w.Write(logoNamePNG)
	})
	mux.HandleFunc("/status",   bearer(a.handleLocalStatus))
	mux.HandleFunc("/activity", bearer(a.handleLocalActivity))
	mux.HandleFunc("/evidence", bearer(a.handleLocalEvidence))
	mux.HandleFunc("/controls", bearer(a.handleLocalControls))
	mux.HandleFunc("/logs",     bearer(a.handleLocalLogs))

	srv := &http.Server{
		Addr:         localAPIAddr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Printf("[*] local status API on %s", localAPIAddr)
	if err := srv.ListenAndServe(); err != nil {
		log.Printf("[!] local API: %v", err)
	}
}

func ensureAPIToken() (string, error) {
	dir := filepath.Join(os.Getenv("ProgramData"), "BASAgent")
	_ = os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, "api.token")
	if data, err := os.ReadFile(path); err == nil && len(data) > 8 {
		return strings.TrimSpace(string(data)), nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := base64.URLEncoding.EncodeToString(b)
	return tok, os.WriteFile(path, []byte(tok), 0644)
}

func localJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ── Endpoint handlers ─────────────────────────────────────────────────────────

func (a *Agent) handleLocalStatus(w http.ResponseWriter, _ *http.Request) {
	a.localSt.mu.RLock()
	connected := a.localSt.serverConnected
	lastHB := a.localSt.lastHeartbeat
	lastUpOK := a.localSt.lastUploadOK
	lastUpTime := a.localSt.lastUploadTime
	start := a.localSt.startTime
	a.localSt.mu.RUnlock()

	a.mu.Lock()
	state, status := a.state, a.status
	a.mu.Unlock()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	// Emit null (not a zero year-0001 time) when no heartbeat has yet succeeded,
	// so the dashboard renders "—" rather than a bogus old timestamp.
	var lastHBField interface{}
	if !lastHB.IsZero() {
		lastHBField = lastHB
	}

	// A running simulation with a lost link is "Paused": it keeps executing locally,
	// but the agent will finalize it as Partial once the outage passes the grace
	// period. Surface how long the link has been down so the console can count down.
	disconnectedSec := int(a.disconnectedFor().Seconds())
	paused := !connected && status != "" && status != "idle"

	localJSON(w, map[string]interface{}{
		"agentVersion":    version,
		"agentId":         a.id.AgentID,
		"hostname":        a.id.Hostname,
		"state":           state,
		"status":          status,
		"serverUrl":       a.cfg().ServerURL,
		"serverConnected": connected,
		"lastHeartbeat":   lastHBField,
		"serviceRunning":  true,
		"lastUploadOk":    lastUpOK,
		"lastUploadTime":  lastUpTime,
		"uptimeSec":       int(time.Since(start).Seconds()),
		"ramMB":           ms.Sys / (1024 * 1024),
		"paused":          paused,
		"disconnectedSec": disconnectedSec,
		"graceSec":        int(disconnectGracePeriod.Seconds()),
	})
}

func (a *Agent) handleLocalActivity(w http.ResponseWriter, _ *http.Request) {
	a.localSt.mu.RLock()
	cur := a.localSt.currentOp
	last := a.localSt.lastOp
	acts := make([]LocalActivity, len(a.localSt.activity))
	copy(acts, a.localSt.activity)
	a.localSt.mu.RUnlock()

	// most-recent-first
	for i, j := 0, len(acts)-1; i < j; i, j = i+1, j-1 {
		acts[i], acts[j] = acts[j], acts[i]
	}
	localJSON(w, map[string]interface{}{
		"currentOperation": cur,
		"lastOperation":    last,
		"recentActivity":   acts,
	})
}

func (a *Agent) handleLocalEvidence(w http.ResponseWriter, _ *http.Request) {
	a.localSt.mu.RLock()
	ev := a.localSt.evidence
	a.localSt.mu.RUnlock()
	localJSON(w, ev)
}

// ── Security controls (cached 60 s) ──────────────────────────────────────────

var (
	ctrlMu    sync.Mutex
	ctrlCache *SecurityControls
	ctrlExp   time.Time
)

func (a *Agent) handleLocalControls(w http.ResponseWriter, _ *http.Request) {
	ctrlMu.Lock()
	if ctrlCache == nil || time.Now().After(ctrlExp) {
		ctrlCache = querySecurityControls()
		ctrlExp = time.Now().Add(60 * time.Second)
	}
	c := ctrlCache
	ctrlMu.Unlock()
	localJSON(w, c)
}

func (a *Agent) handleLocalLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if s := r.URL.Query().Get("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	localJSON(w, map[string]interface{}{"lines": readRecentLogLines(limit)})
}

// ── Security controls types + query ──────────────────────────────────────────

type SecurityControls struct {
	Defender  DefenderCtrl  `json:"defender"`
	Sysmon    SysmonCtrl    `json:"sysmon"`
	Firewall  FirewallCtrl  `json:"firewall"`
	AppLocker AppLockerCtrl `json:"appLocker"`
	WDAC      WDACCtrl      `json:"wdac"`
	AMSI      AMSICtrl      `json:"amsi"`
	CheckedAt time.Time     `json:"checkedAt"`
}

type DefenderCtrl struct {
	Present         bool `json:"present"`
	RTPEnabled      bool `json:"rtpEnabled"`
	TamperProtected bool `json:"tamperProtected"`
}
type SysmonCtrl    struct { Present bool   `json:"present"`;  ServiceName string `json:"serviceName,omitempty"` }
type FirewallCtrl  struct { Enabled bool   `json:"enabled"` }
type AppLockerCtrl struct { Enabled bool   `json:"enabled"` }
type WDACCtrl      struct { Enabled bool   `json:"enabled"` }
type AMSICtrl      struct { Enabled bool   `json:"enabled"` }

func querySecurityControls() *SecurityControls {
	sc := &SecurityControls{CheckedAt: time.Now()}

	// ── Defender ────────────────────────────────────────────────────────────
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows Defender`, registry.QUERY_VALUE); err == nil {
		k.Close()
		sc.Defender.Present = true
		// RTP — DisableRealtimeMonitoring absent or 0 → enabled
		if rk, err2 := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`,
			registry.QUERY_VALUE); err2 == nil {
			v, _, _ := rk.GetIntegerValue("DisableRealtimeMonitoring")
			sc.Defender.RTPEnabled = v == 0
			rk.Close()
		} else {
			sc.Defender.RTPEnabled = true // key absent = not disabled
		}
		// Tamper protection — value 5 = on
		if fk, err3 := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows Defender\Features`,
			registry.QUERY_VALUE); err3 == nil {
			tv, _, _ := fk.GetIntegerValue("TamperProtection")
			sc.Defender.TamperProtected = tv == 5
			fk.Close()
		}
	}

	// ── Sysmon ──────────────────────────────────────────────────────────────
	if m, err := mgr.Connect(); err == nil {
		for _, name := range []string{"Sysmon64", "Sysmon"} {
			if svc, err2 := m.OpenService(name); err2 == nil {
				sc.Sysmon.Present = true
				sc.Sysmon.ServiceName = name
				svc.Close()
				break
			}
		}
		m.Disconnect()
	}

	// ── Windows Firewall ────────────────────────────────────────────────────
	for _, profile := range []string{"DomainProfile", "StandardProfile", "PublicProfile"} {
		key := `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\` + profile
		if fk, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE); err == nil {
			v, _, _ := fk.GetIntegerValue("EnableFirewall")
			fk.Close()
			if v == 1 {
				sc.Firewall.Enabled = true
				break
			}
		}
	}

	// ── AppLocker ────────────────────────────────────────────────────────────
	if ak, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\SrpV2`,
		registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := ak.ReadSubKeyNames(-1)
		sc.AppLocker.Enabled = len(names) > 0
		ak.Close()
	}

	// ── WDAC (Code Integrity) ────────────────────────────────────────────────
	if ck, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\CI\Config`,
		registry.QUERY_VALUE); err == nil {
		v, _, _ := ck.GetIntegerValue("Enabled")
		sc.WDAC.Enabled = v == 1
		ck.Close()
	}

	// ── AMSI — present on Win10+, disabled only via explicit registry entry ──
	sc.AMSI.Enabled = true
	if ak, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\AMSI\Providers`,
		registry.ENUMERATE_SUB_KEYS); err == nil {
		names, _ := ak.ReadSubKeyNames(-1)
		sc.AMSI.Enabled = len(names) > 0
		ak.Close()
	}

	return sc
}

// ── Log reader ────────────────────────────────────────────────────────────────

func readRecentLogLines(n int) []string {
	dir := logDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	// find the latest op_log file
	latest := ""
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "op_log-") && strings.HasSuffix(e.Name(), ".log") {
			if e.Name() > latest {
				latest = e.Name()
			}
		}
	}
	if latest == "" {
		return nil
	}
	f, err := os.Open(filepath.Join(dir, latest))
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}
