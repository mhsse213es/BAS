//go:build windows

package main

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "BASLegacyAgent"

type legacySvc struct{}

func (s *legacySvc) Execute(_ []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	cfg := loadConfig()
	id := buildIdentity()
	client := NewClient(cfg)
	client.Enroll(id)

	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for range ticker.C {
			client.SendHeartbeat(id, "idle")
		}
	}()
	go connectWS(cfg, id)

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		req := <-r
		switch req.Cmd {
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		case svc.Interrogate:
			status <- req.CurrentStatus
		}
	}
}

func isWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	return err == nil && isSvc
}

func svcRun() error {
	elog, err := eventlog.Open(serviceName)
	if err == nil {
		defer elog.Close()
	}
	return svc.Run(serviceName, &legacySvc{})
}

func svcInstall(serverURL, envLabel, secret string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("service %q already installed -- run --uninstall first", serviceName)
	}

	os.Setenv("BAS_SERVER_URL", serverURL)
	os.Setenv("BAS_ENV_LABEL", envLabel)
	os.Setenv("BAS_AGENT_SECRET", secret)

	s, err := m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName:      "Audspect Legacy Windows Agent",
		Description:      "Audspect BAS legacy Windows compatibility agent (Windows 7 SP1/8/8.1/Server 2008 R2-2012 R2)",
		StartType:        mgr.StartAutomatic,
		ServiceType:      windows.SERVICE_WIN32_OWN_PROCESS,
		ServiceStartName: "LocalSystem",
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)

	return s.Start()
}

func svcUninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()
	s.Control(svc.Stop)
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	_ = eventlog.Remove(serviceName)
	return nil
}
