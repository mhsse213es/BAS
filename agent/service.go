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
	svcName        = "BASAgent"
	svcDisplayName = "BAS Platform Agent (Audspect)"
	svcDescription = "Next-Gen Breach & Attack Simulation endpoint agent. Runs security posture checks and reports results to the BAS orchestrator."
)

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

	fmt.Printf("    Run: sc start %s\n", svcName)
	return nil
}

// svcUpdate stops the service, replaces the binary with the currently
// running exe, and restarts it — no uninstall/reinstall needed.
func svcUpdate() error {
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
	installedPath := cfg.BinaryPathName

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

	// Restart
	fmt.Printf("[*] Starting %s...\n", svcName)
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service: %w", err)
	}
	fmt.Printf("[+] %s updated and restarted\n", svcName)
	return nil
}

func svcUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("service %q not found", svcName)
	}
	defer s.Close()

	// Stop before deleting
	_, _ = s.Control(svc.Stop)
	time.Sleep(2 * time.Second)

	if err := s.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(svcName)
	fmt.Printf("[+] Service %q uninstalled\n", svcName)
	return nil
}

func svcRun() error {
	return svc.Run(svcName, &agentSvc{})
}

func isWindowsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

// readServiceParams reads BAS_SERVER_URL and BAS_ENV_LABEL from
// HKLM\SYSTEM\CurrentControlSet\Services\BASAgent\Parameters.
func readServiceParams() (serverURL, envLabel string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+svcName+`\Parameters`,
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
