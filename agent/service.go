//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcName        = "Audspect Agent"
	svcDisplayName = "Audspect - BAS Platform Agent"
	svcDescription = "Next-Gen Breach & Attack Simulation endpoint agent. Runs security posture checks and reports results to the BAS orchestrator."

	// svcNameLegacy is the service name used before the Audspect rebrand.
	// Windows has no in-place service rename (Name is immutable after
	// CreateService; only DisplayName can be updated), so an endpoint
	// enrolled under the old name still has a "BASAgent" service
	// registered. migrateLegacyServiceName (below) detects and replaces
	// it on the next --update. Never reuse this for anything else.
	svcNameLegacy = "BASAgent"
)

// unquoteServicePath strips a single matching pair of surrounding double
// quotes from a service's registry BinaryPathName, if present.
// mgr.CreateService (golang.org/x/sys/windows/svc/mgr, via
// syscall.EscapeArg) wraps any exe path containing a space -- every
// default "Program Files" install qualifies -- in literal quote characters
// before storing it as the service's ImagePath. cfg.BinaryPathName read
// back from an existing service therefore is not a clean filesystem path
// on its own: every call site that passes it straight to a raw
// path-consuming API breaks on the embedded quote characters. Confirmed
// live -- MoveFileEx(..., MOVEFILE_DELAY_UNTIL_REBOOT) against a real
// installed service's unmodified BinaryPathName fails with
// ERROR_INVALID_NAME, leaving the old binary on disk forever after
// uninstall; os.WriteFile fails outright since '"' is not a legal
// character in a Windows filename. Only strips a genuinely matched
// leading+trailing pair -- a lone stray quote (which should never happen,
// but must never be silently mangled) is left untouched.
func unquoteServicePath(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// stopRequested signals agentSvc.Execute()'s own select loop from the
// WS-command goroutine (agent.go's stopSelf), so a remote stop while
// running as a Windows service goes through the same clean SERVICE_STOPPED
// handshake as a normal svc.Stop — calling os.Exit() directly from a
// different goroutine would skip that handshake and could look like a
// crash to SCM, triggering ApplyServiceRecovery's auto-restart. stopSelf
// already ran finalize/heartbeat/disable before signaling, so no payload
// is needed here — an empty struct is enough.
var stopRequested = make(chan struct{}, 1)

// ── Service Handler ───────────────────────────────────────────────────────────

type agentSvc struct{}

func (s *agentSvc) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	enablePrivileges()

	// Startup integrity check — compare running binary against hash stored at install.
	if err := VerifyOwnIntegrity(); err != nil {
		log.Printf("[!] INTEGRITY: %v — continuing; server will quarantine on hash mismatch", err)
	}

	cfg := loadConfig()
	id := collectIdentity()
	agent := newAgent(cfg, id)
	agent.enrollWithServer()

	go agent.connectWS()
	go agent.startLocalAPI()
	go agent.runSpoolDrainer()
	go agent.runDisconnectWatchdog()
	agent.sendHeartbeat("idle")

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange,
	}

	// Covers a session that was already active before the service started (or
	// restarted, e.g. via svcUpdate) — SessionChange notifications only fire for
	// transitions that happen after we start accepting them, not retroactively.
	launchTrayForActiveSession()

	for {
		select {
		case <-ticker.C:
			agent.sendHeartbeat(agent.getStatus())
		case <-stopRequested:
			// stopSelf (agent.go) already ran finalize/heartbeat/disable before
			// signaling here — this just performs the clean SCM handshake.
			status <- svc.Status{State: svc.StopPending, WaitHint: uint32((shutdownGrace + 5*time.Second) / time.Millisecond)}
			return false, 0
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				// Tell the SCM how long we may take so it doesn't kill us before an
				// in-flight run finalizes its Partial to the spool.
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32((shutdownGrace + 5*time.Second) / time.Millisecond)}
				agent.shutdownFinalize(shutdownGrace)
				agent.sendHeartbeat("offline")
				RestoreSystemDialogs()
				return false, 0
			case svc.SessionChange:
				// WTS_SESSION_LOGON (5): a user has just logged on to a session.
				// WTS_CONSOLE_CONNECT (1): a session was connected to the console
				// (covers fast user switching / RDP reconnect to console).
				if c.EventType == windows.WTS_SESSION_LOGON || c.EventType == windows.WTS_CONSOLE_CONNECT {
					launchTrayForActiveSession()
				}
			case svc.Interrogate:
				status <- c.CurrentStatus
			}
		}
	}
}

// ── Service Control ───────────────────────────────────────────────────────────

func svcInstall(serverURL, envLabel, secret string) error {
	exePath, err := filepath.Abs(os.Args[0])
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already installed — run --uninstall first", svcName)
	}

	s, err := m.CreateService(svcName, exePath,
		mgr.Config{
			DisplayName:      svcDisplayName,
			Description:      svcDescription,
			StartType:        mgr.StartAutomatic,
			ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
			ServiceStartName: "LocalSystem",
			DelayedAutoStart: true,
		},
	)
	if err != nil {
		return fmt.Errorf("CreateService: %w", err)
	}
	defer s.Close()

	// Write URL + env label to registry (plaintext — these are not secrets).
	if err := writeServiceParams(serverURL, envLabel); err != nil {
		log.Printf("[svc] warning: could not write service params: %v", err)
	}

	// DPAPI-encrypt the agent secret and store the blob in registry.
	// Plain-text secret is never persisted to disk.
	if secret != "" {
		if err := StoreEncryptedSecret(secret); err != nil {
			log.Printf("[svc] warning: could not store encrypted secret: %v", err)
		} else {
			fmt.Printf("[+] Agent secret encrypted (DPAPI, machine-scope) and stored\n")
		}
	}

	// Store the binary hash so startup integrity checks can detect replacement.
	if hash, err := SelfHash(); err == nil {
		if err := StoreBinaryHash(hash); err != nil {
			log.Printf("[svc] warning: could not store binary hash: %v", err)
		} else {
			fmt.Printf("[+] Binary hash stored: %s...\n", hash[:16])
		}
	}

	_ = eventlog.InstallAsEventCreate(svcName, eventlog.Error|eventlog.Warning|eventlog.Info)
	fmt.Printf("[+] Service %q installed (LocalSystem, auto-start)\n", svcName)

	// Apply tamper protections — failures are non-fatal (logged, service still starts).
	if err := ApplyServiceRecovery(); err != nil {
		log.Printf("[svc] warning: recovery policy: %v", err)
	}
	if err := ApplyServiceDACL(); err != nil {
		log.Printf("[svc] warning: service DACL: %v", err)
	}
	installDir := filepath.Dir(exePath)
	if err := ApplyFileACL(installDir); err != nil {
		log.Printf("[svc] warning: file ACL: %v", err)
	}
	if err := ApplyRegistryACL(); err != nil {
		log.Printf("[svc] warning: registry ACL: %v", err)
	}
	if err := ApplyDefenderExclusion(exePath); err != nil {
		log.Printf("[svc] warning: Defender exclusion: %v", err)
	} else {
		fmt.Printf("[+] Windows Defender exclusion added for %s\n", exePath)
	}

	fmt.Printf("    Run: sc start %s\n", svcName)
	return nil
}

// migrateLegacyServiceName replaces an endpoint's old "BASAgent" service
// registration with a fresh one under svcName ("Audspect Agent"), for
// endpoints enrolled before the rename. Windows cannot rename a service's
// Name in place (CreateService's Name is immutable; only DisplayName is
// mutable via UpdateConfig), so this recreates the service under the new
// name -- capturing everything Delete() would otherwise destroy (the
// binary path, server URL/env label, DPAPI-encrypted secret, and stored
// binary hash, all of which live in the legacy service's own Parameters
// registry subkey) and restoring it under the new registration. No-op
// (returns nil immediately) when svcName already exists (already migrated,
// or a fresh install) or when svcNameLegacy does not exist (nothing to
// migrate). Called at the start of svcUpdate so migration happens
// transparently on an endpoint's next agent update.
func migrateLegacyServiceName() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		return nil
	}

	legacy, err := m.OpenService(svcNameLegacy)
	if err != nil {
		return nil // no legacy service either -- fresh install, nothing to migrate
	}
	defer legacy.Close()

	cfg, err := legacy.Config()
	if err != nil {
		return fmt.Errorf("query legacy service config: %w", err)
	}
	binaryPath := unquoteServicePath(cfg.BinaryPathName)

	legacyParamKey := paramKeyFor(svcNameLegacy)
	serverURL, envLabel := readServiceParamsFrom(svcNameLegacy)
	secret := readEncryptedSecretFrom(legacyParamKey)
	binaryHash := readBinaryHashFrom(legacyParamKey)

	fmt.Printf("[*] Migrating service registration %q -> %q...\n", svcNameLegacy, svcName)
	if err := stopServiceAndWait(legacy, 15*time.Second, 500*time.Millisecond, terminateProcessByPID); err != nil {
		return fmt.Errorf("stop legacy service: %w", err)
	}
	if err := legacy.Delete(); err != nil {
		return fmt.Errorf("delete legacy service: %w", err)
	}
	_ = eventlog.Remove(svcNameLegacy)

	newSvc, err := m.CreateService(svcName, binaryPath, mgr.Config{
		DisplayName:      svcDisplayName,
		Description:      svcDescription,
		StartType:        mgr.StartAutomatic,
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		ServiceStartName: "LocalSystem",
		DelayedAutoStart: true,
	})
	if err != nil {
		return fmt.Errorf("create migrated service: %w", err)
	}
	defer newSvc.Close()

	if err := writeServiceParams(serverURL, envLabel); err != nil {
		log.Printf("[svc] warning: could not restore service params after migration: %v", err)
	}
	if secret != "" {
		if err := StoreEncryptedSecret(secret); err != nil {
			log.Printf("[svc] warning: could not restore encrypted secret after migration: %v", err)
		}
	}
	if binaryHash != "" {
		if err := StoreBinaryHash(binaryHash); err != nil {
			log.Printf("[svc] warning: could not restore binary hash after migration: %v", err)
		}
	}

	_ = eventlog.InstallAsEventCreate(svcName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err := ApplyServiceRecovery(); err != nil {
		log.Printf("[svc] warning: recovery policy: %v", err)
	}
	if err := ApplyServiceDACL(); err != nil {
		log.Printf("[svc] warning: service DACL: %v", err)
	}

	fmt.Printf("[+] Service migrated to %q\n", svcName)
	return nil
}

// svcUpdate stops the service, replaces the binary with the currently
// running exe, and restarts it — no uninstall/reinstall needed.
func svcUpdate() error {
	if err := migrateLegacyServiceName(); err != nil {
		return fmt.Errorf("migrate legacy service: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q not installed", svcName)
	}
	defer s.Close()

	// Get the path the service is configured to run from
	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("query service config: %w", err)
	}
	installedPath := unquoteServicePath(cfg.BinaryPathName)

	// Stop the service
	fmt.Printf("[*] Stopping %s...\n", svcName)
	_, _ = s.Control(svc.Stop)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := s.Query()
		if st.State == svc.Stopped {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Copy current exe over the installed path (in-place update)
	newExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current exe: %w", err)
	}
	newExe, _ = filepath.Abs(newExe)

	if !strings.EqualFold(newExe, installedPath) {
		fmt.Printf("[*] Replacing %s\n    with %s\n", installedPath, newExe)
		src, err := os.ReadFile(newExe)
		if err != nil {
			return fmt.Errorf("read new binary: %w", err)
		}
		if err := os.WriteFile(installedPath, src, 0755); err != nil {
			return fmt.Errorf("write binary to %s: %w", installedPath, err)
		}
		// Copy manifest alongside
		mfSrc := newExe + ".manifest" // e.g. bas_agent.exe.manifest
		mfDst := installedPath + ".manifest"
		if data, err := os.ReadFile(mfSrc); err == nil {
			_ = os.WriteFile(mfDst, data, 0644)
		}
	}

	// Re-apply the Defender exclusion on every update, not just fresh
	// installs -- covers an exclusion an operator removed by hand, and
	// costs nothing when it's already present (Add-MpPreference is
	// idempotent). Best-effort, same as at install time.
	if err := ApplyDefenderExclusion(installedPath); err != nil {
		log.Printf("[svc] warning: Defender exclusion: %v", err)
	} else {
		fmt.Printf("[+] Windows Defender exclusion confirmed for %s\n", installedPath)
	}

	// Restart
	fmt.Printf("[*] Starting %s...\n", svcName)
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Printf("[+] %s updated and restarted\n", svcName)
	return nil
}

// svcUninstall removes every service registration this binary has ever
// shipped under -- both the current svcName ("Audspect Agent") and the
// pre-rename svcNameLegacy ("BASAgent") -- not just whichever one happens
// to currently be running. Without this, an endpoint that was enrolled
// before the service rename (and never went through migrateLegacyServiceName,
// which only runs as part of an --update, not automatically) could still
// have a live, Automatic-start "BASAgent" registration sitting untouched
// after an operator ran --uninstall against "Audspect Agent": the uninstall
// would look completely successful (service stopped, tray gone) while the
// legacy registration silently started itself again on the endpoint's next
// boot, looking exactly like the "uninstall didn't take" resurrection this
// was written to fix. See [[project_agent_uninstall_legacy_name_gap]].
func svcUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	removedAny := false
	var lastErr error
	for _, name := range []string{svcName, svcNameLegacy} {
		removed, err := uninstallServiceRegistration(m, name)
		if err != nil {
			lastErr = err
			continue
		}
		if removed {
			removedAny = true
		}
	}
	if !removedAny {
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("service %q not found", svcName)
	}

	// Everything below is best-effort cleanup: the tray autostart entry/
	// window/shortcut are all independently idempotent -- a missing key,
	// window, or file is already the desired end state -- and are not tied
	// to whichever specific service registration(s) were removed above.
	if err := removeTrayRunKey(); err != nil {
		fmt.Printf("[~] Could not remove tray autostart entry: %v\n", err)
	}
	closeTrayWindow()
	terminateOtherAgentProcesses()
	if err := removeTrayShortcut(); err != nil {
		fmt.Printf("[~] Could not remove tray shortcut: %v\n", err)
	}

	fmt.Printf("[+] Uninstall complete\n")
	return nil
}

// uninstallServiceRegistration stops and deletes the named service
// registration if it exists: notifies the server of decommissioning and
// schedules its binary for delayed deletion on next reboot. Returns
// (false, nil) -- not an error -- when the named service simply doesn't
// exist, since svcUninstall calls this once per known service name and
// typically only one is actually present on a given endpoint.
func uninstallServiceRegistration(m *mgr.Mgr, name string) (removed bool, err error) {
	s, err := m.OpenService(name)
	if err != nil {
		return false, nil
	}
	defer s.Close()

	// serverURL/secret must be read while the service (and its registry
	// Parameters) still exist -- capture them now, but notify only after
	// the stop/delete below actually succeeds, so the server never learns
	// "uninstalled" before it's true (a partial failure below used to leave
	// the server thinking the endpoint was gone while the service was still
	// registered).
	serverURL, _ := readServiceParamsFrom(name)
	secret := readEncryptedSecretFrom(paramKeyFor(name))
	agentID := collectIdentity().AgentID

	// Capture the installed binary path before Delete() removes the service
	// registration -- needed below to schedule the exe for delayed deletion.
	var binaryPath string
	if cfg, cfgErr := s.Config(); cfgErr == nil {
		binaryPath = unquoteServicePath(cfg.BinaryPathName)
	}

	// Stop, confirming via poll like svcUpdate does; if the service is still
	// wedged after the poll window, terminate its process directly so
	// uninstall never hangs.
	fmt.Printf("[*] Stopping %s...\n", name)
	if err := stopServiceAndWait(s, 15*time.Second, 500*time.Millisecond, terminateProcessByPID); err != nil {
		return false, fmt.Errorf("stop service %q: %w", name, err)
	}

	if err := s.Delete(); err != nil {
		return false, fmt.Errorf("delete service %q: %w", name, err)
	}
	_ = eventlog.Remove(name)

	// Best-effort: tell the server this endpoint is being decommissioned so
	// it's hidden from the live Agents list instead of just showing
	// "offline" -- now sent only after Delete above actually succeeded.
	if err := notifyServerUnenroll(serverURL, secret, agentID); err != nil {
		fmt.Printf("[~] Could not notify server of uninstall (%s): %v\n", name, err)
	}

	if binaryPath != "" {
		if err := scheduleBinaryDeleteOnReboot(binaryPath); err != nil {
			fmt.Printf("[~] Could not schedule binary for delayed deletion: %v\n", err)
		}
	}

	fmt.Printf("[+] Service %q uninstalled\n", name)
	return true, nil
}

func svcRun() error {
	return svc.Run(svcName, &agentSvc{})
}

func isWindowsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

// readServiceParams reads BAS_SERVER_URL and BAS_ENV_LABEL from
// HKLM\SYSTEM\CurrentControlSet\Services\<svcName>\Parameters.
func readServiceParams() (serverURL, envLabel string) {
	return readServiceParamsFrom(svcName)
}

// readServiceParamsFrom is readServiceParams generalized to an explicit
// service name -- migrateLegacyServiceName uses this to read from
// svcNameLegacy's Parameters key before that service is deleted.
func readServiceParamsFrom(name string) (serverURL, envLabel string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+name+`\Parameters`,
		registry.QUERY_VALUE)
	if err != nil {
		return "", ""
	}
	defer k.Close()
	serverURL, _, _ = k.GetStringValue("BAS_SERVER_URL")
	envLabel, _, _ = k.GetStringValue("BAS_ENV_LABEL")
	return
}

// writeServiceParams stores BAS_SERVER_URL and BAS_ENV_LABEL under
// HKLM\SYSTEM\CurrentControlSet\Services\BASAgent\Parameters
// so the service reads them without depending on user env vars.
func writeServiceParams(serverURL, envLabel string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+svcName+`\Parameters`,
		registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("BAS_SERVER_URL", serverURL); err != nil {
		return err
	}
	return k.SetStringValue("BAS_ENV_LABEL", envLabel)
}

// platformDisableAutoStart sets the service's start type to Disabled so it
// does not start at the endpoint's next boot. Safe to call on a running
// service — only affects future start attempts, not this one.
func platformDisableAutoStart() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return fmt.Errorf("query service config: %w", err)
	}
	cfg.StartType = mgr.StartDisabled
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("update service config: %w", err)
	}
	log.Printf("[svc] service start type set to Disabled — will not start at next boot")
	return nil
}

// platformSelfUninstall performs the parts of an uninstall that are safe to
// run from within the live, running service process itself: cleaning up
// tray/registry artifacts, scheduling the binary for delete-on-reboot, and
// marking the service registration for deletion via Delete() -- a legal,
// non-blocking call while running. Windows completes the actual removal
// once the service later reaches the Stopped state, which
// platformDisableAutoStartFn/platformExitAfterStopFn (called by
// uninstallSelf right after this returns) already bring about via the same
// stopRequested-channel signaling used by Stop Agent. This deliberately
// does NOT call Control(svc.Stop) or wait for Stopped itself -- doing so
// from within the very process being stopped would race this function's
// own return and the HTTP result report that follows it.
func platformSelfUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect SCM: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	var binaryPath string
	if cfg, cfgErr := s.Config(); cfgErr == nil {
		binaryPath = unquoteServicePath(cfg.BinaryPathName)
	}

	if err := s.Delete(); err != nil {
		return fmt.Errorf("mark service for deletion: %w", err)
	}
	_ = eventlog.Remove(svcName)

	// Everything below is best-effort cleanup, matching svcUninstall's own
	// philosophy: a missing key/window/file is already the desired end
	// state, not an error worth failing the whole uninstall over.
	if binaryPath != "" {
		if err := scheduleBinaryDeleteOnReboot(binaryPath); err != nil {
			log.Printf("[~] Could not schedule binary for delayed deletion: %v", err)
		}
	}
	if err := removeTrayRunKey(); err != nil {
		log.Printf("[~] Could not remove tray autostart entry: %v", err)
	}
	closeTrayWindow()
	terminateOtherAgentProcesses()
	if err := removeTrayShortcut(); err != nil {
		log.Printf("[~] Could not remove tray shortcut: %v", err)
	}
	return nil
}

// platformExitAfterStop ends this process. When running as a Windows
// service, it hands off to agentSvc.Execute()'s own select loop (via
// stopRequested) instead of exiting directly, so SCM sees a clean stop
// rather than a crash. In console mode there is no SCM handshake to honor,
// so it exits directly.
func platformExitAfterStop() {
	if isWindowsService() {
		select {
		case stopRequested <- struct{}{}:
		default:
		}
		return
	}
	os.Exit(0)
}
