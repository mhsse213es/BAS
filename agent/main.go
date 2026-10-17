//go:generate rsrc -manifest bas_agent.exe.manifest -ico logo.ico -arch amd64 -o rsrc.syso

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"os/signal"
	"syscall"
	"time"

	"audspect/agent/preflight"
)

// version is the release version, stamped at link time (-X main.version=...) by the
// build scripts. An unstamped build reports "dev", never a release number.
var version = "dev"

const heartbeatInterval = 30 * time.Second

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	if p := initFileLogging(); p != "" {
		log.Printf("[*] agent log file: %s", p)
	}

	flagInstall := flag.Bool("install", false, "Install agent as a system service (requires root/admin)")
	flagUninstall := flag.Bool("uninstall", false, "Uninstall agent system service")
	flagServer := flag.String("server", "", "Override BAS_SERVER_URL")
	flagEnv := flag.String("env", "Production", "Override BAS_ENV_LABEL")
	flagSecret := flag.String("secret", "", "Agent shared secret (encrypted at rest via DPAPI on Windows)")
	flagSecretStdin := flag.Bool("secret-stdin", false, "Read the agent secret from stdin (one line) instead of --secret, so it never appears in process arguments")
	flagTokenFile := flag.String("enrollment-token-file", "", "Path to a file holding a single-use enrolment token (one line); the file is deleted once read. The token is never accepted as a command-line value")
	flagTokenStdin := flag.Bool("enrollment-token-stdin", false, "Read a single-use enrolment token from stdin (one line); cannot be combined with --secret-stdin")
	flagPreflight := flag.Bool("preflight", false, "Check connectivity, CA trust and the agent secret without installing anything; the secret is read from stdin (--secret-stdin). Exit codes: 0 ok, 20 invalid input, 21 unreachable, 22 secret rejected, 23 trust failure, 24 invalid CA")
	flagCARoot := flag.String("ca-root", "", "Path to the deployment CA root PEM (required for mTLS enrollment; fetch via GET /api/config/connection)")
	flagEnrollPort := flag.String("enroll-port", "", "Host port of the orchestrator enrollment listener, if the published port was remapped from the 9444 default (persisted as BAS_ENROLL_PORT)")

	flagConfig := flag.String("config", "", "Path to the signed deployment.json; replaces --server, --enroll-port and --ca-root. Requires --config-fingerprint")
	flagConfigFingerprint := flag.String("config-fingerprint", "", "SHA-256 fingerprint of the deployment signing certificate, obtained from the dashboard (not from the downloaded files)")
	flagIdentityStatus := flag.Bool("identity-status", false, "Report, without changing anything, whether the installed agent identity belongs to the CA in --config; exit 29 if it is stale. Installers use it to decide to re-enrol")
	flagResetIdentity := flag.Bool("reset-identity", false, "Re-enrol an installed agent whose identity belongs to a different CA than --config: moves the old identity aside, stores the new CA and spends the enrolment token. Leaves the service and files alone; exit 0 if nothing needed doing")
	flagVerifyConfig := flag.Bool("verify-config", false, "Verify --config against --config-fingerprint and print the verified target; exit 25 if rejected")

	registerPlatformFlags()
	flag.Parse()

	if *flagVerifyConfig {
		os.Exit(runVerifyConfigCLI(deployFlags{ConfigPath: *flagConfig, Fingerprint: *flagConfigFingerprint}, time.Now(), os.Stdout))
	}

	if *flagIdentityStatus {
		os.Exit(runIdentityStatusCLI(deployFlags{ConfigPath: *flagConfig, Fingerprint: *flagConfigFingerprint}, time.Now(), os.Stdout))
	}

	if *flagResetIdentity {
		os.Exit(runResetIdentityCLI(deployFlags{ConfigPath: *flagConfig, Fingerprint: *flagConfigFingerprint},
			*flagSecret, *flagSecretStdin, *flagTokenFile, *flagTokenStdin, *flagEnv))
	}

	if *flagPreflight {
		os.Exit(runPreflightCLI(preflightCLIArgs{
			Server: *flagServer, EnrollPort: *flagEnrollPort, CARootPath: *flagCARoot,
			SecretArg: *flagSecret, SecretStdin: *flagSecretStdin,
			ConfigPath: *flagConfig, ConfigFingerprint: *flagConfigFingerprint,
		}, os.Stdin, os.Stdout))
	}

	if platformHandleFlags() {
		return
	}

	if *flagInstall {
		dep, depErr := resolveDeployment(deployFlags{
			ConfigPath: *flagConfig, Fingerprint: *flagConfigFingerprint,
			Server: *flagServer, EnrollPort: *flagEnrollPort, CARootPath: *flagCARoot,
		}, time.Now())
		if depErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", depErr)
			var ce *caFileError
			if errors.As(depErr, &ce) {
				os.Exit(1)
			}
			os.Exit(preflight.CodeConfigRejected)
		}
		serverURL := dep.Server
		if serverURL == "" {
			serverURL = os.Getenv("BAS_SERVER_URL")
		}
		if serverURL == "" {
			fmt.Fprintln(os.Stderr, "error: provide --server <url> or set BAS_SERVER_URL")
			os.Exit(1)
		}
		secret, secretFromStdin, secretErr := secretFromFlags(*flagSecret, *flagSecretStdin, os.Stdin)
		if secretErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", secretErr)
			os.Exit(1)
		}
		if secret == "" && !secretFromStdin {
			secret = os.Getenv("BAS_AGENT_SECRET")
		}
		if secret == "" {
			if !stdinIsTerminal() {
				fmt.Fprintln(os.Stderr, "error: provide --secret <secret> or set BAS_AGENT_SECRET")
				os.Exit(1)
			}
			s, err := promptHidden("Agent Secret: ", os.Stdin, os.Stdout)
			if err == nil && s == "" {
				err = errors.New("agent secret must not be empty")
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			secret = s
		}
		if len(dep.CARootPEM) > 0 {
			pemBytes := dep.CARootPEM
			// A stale identity (issued by another CA) can never enroll; move it aside first.
			if moved, err := clearStaleIdentity(pemBytes); err != nil {
				fmt.Fprintf(os.Stderr, "error: reset old agent identity: %v\n", err)
				os.Exit(1)
			} else if moved {
				fmt.Println("[*] old agent identity was issued by a different CA; moved aside so the agent can enroll again")
			}
			// saveDeploymentCARoot validates that pemBytes parses as an
			// X.509 certificate before writing anything.
			if err := saveDeploymentCARoot(pemBytes); err != nil {
				fmt.Fprintf(os.Stderr, "error: deployment CA root: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("[+] deployment CA root installed")
		} else {
			// No --ca-root supplied: fetch the public deployment CA root from
			// the server automatically so a bare `--install --server ...
			// --secret ...` is self-sufficient -- no hand curl, no manual
			// file. The agent cannot complete mTLS enrollment without this
			// trust anchor on disk (bootstrapHTTPClient aborts if it is
			// absent), which is the single most common "agent stuck on legacy
			// transport / unknown authority / never shows in console" cause.
			// A fetch failure is a warning, not fatal: the operator can still
			// place the file and the agent retries bootstrap on every start.
			if pemBytes, err := fetchDeploymentCARoot(serverURL); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not auto-fetch deployment CA root (%v)\n", err)
				fmt.Fprintln(os.Stderr, "         the agent will start on legacy transport and retry; re-run with --ca-root <file> to place it explicitly.")
			} else if err := saveDeploymentCARoot(pemBytes); err != nil {
				fmt.Fprintf(os.Stderr, "warning: fetched deployment CA root but could not store it: %v\n", err)
			} else {
				fmt.Println("[+] deployment CA root fetched from server and installed")
			}
		}
		// A single-use enrolment token (BAS_ENROLLMENT_TOKEN, installer environment only) is spent right
		// here, so it never has to be stored: the service then starts already enrolled.
		tok, tokErr := resolveEnrollmentToken(*flagTokenFile, *flagTokenStdin, secretFromStdin, os.Stdin)
		if tokErr != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", tokErr)
			os.Exit(1)
		}
		if tok == "" && stdinIsTerminal() {
			// Optional: servers that issue per-host tokens need one; servers using only the shared secret do not.
			t, perr := promptHidden("Enrollment token (press Enter to skip if this server uses the shared secret only): ", os.Stdin, os.Stdout)
			if perr != nil {
				fmt.Fprintln(os.Stderr, "error: could not read the enrollment token")
				os.Exit(1)
			}
			tok = strings.TrimSpace(t)
		}
		if tok != "" {
			icfg := Config{ServerURL: serverURL, AgentSecret: secret, EnrollmentToken: tok}
			if err := enrollAtInstall(context.Background(), icfg, dep.EnrollPort, collectIdentity().AgentID); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(installExitCode(err))
			}
			fmt.Println("[+] agent enrolled with the supplied token")
		}
		if err := svcInstall(serverURL, *flagEnv, secret, dep.EnrollPort); err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *flagUninstall {
		if err := svcUninstall(); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	platformPreStart()

	if *flagServer != "" {
		os.Setenv("BAS_SERVER_URL", *flagServer)
	}
	if *flagEnv != "Production" {
		os.Setenv("BAS_ENV_LABEL", *flagEnv)
	}

	cfg := loadConfig()
	id := collectIdentity()

	fmt.Printf("\n")
	fmt.Printf("  BAS Agent v%s\n", version)
	fmt.Printf("  Hostname  : %s\n", id.Hostname)
	fmt.Printf("  AgentID   : %s\n", id.AgentID)
	fmt.Printf("  IP        : %s\n", id.IPAddress)
	fmt.Printf("  OS        : %s\n", id.OSVersion)
	fmt.Printf("  Server    : %s\n", cfg.ServerURL)
	fmt.Printf("  Env       : %s\n", cfg.EnvLabel)
	platformPrintBannerExtras(id)
	fmt.Printf("\n")

	// Certificate bootstrap/renewal runs BEFORE newAgent: newAgent builds
	// the long-lived HTTP client, log shipper and (via a.cfg()) the WS
	// dialer from cfg, so cfg must already carry the resolved mTLS
	// ServerURL and MTLS flag -- building them first is what left a
	// freshly bootstrapped agent with a non-mTLS client until restart.
	cfg, outcome, _ := resolveOperationalConfig(context.Background(), cfg, id.AgentID)
	if outcome == outcomeBlocked {
		// An already-enrolled identity whose mTLS path is currently
		// unusable NEVER operates over legacy transport -- block here,
		// retrying with backoff, before newAgent (and therefore any
		// network communication at all) ever starts. If an operator
		// resets the enrollment marker to force a genuine re-bootstrap,
		// the next retry picks that up automatically via isEnrolled().
		attempt := 0
		for outcome == outcomeBlocked {
			delay := bootstrapRetryBackoff(attempt)
			log.Printf("[!] blocked pending mTLS recovery -- retrying in %s (attempt %d)", delay.Round(time.Second), attempt+1)
			time.Sleep(delay)
			attempt++
			cfg, outcome, _ = resolveOperationalConfig(context.Background(), cfg, id.AgentID)
		}
	}
	agent := newAgent(cfg, id)
	agent.enrollWithServer()

	if outcome == outcomeLegacyPending {
		// Never-enrolled, initial bootstrap failed: operate on legacy
		// transport now (cfg as built above) while retrying bootstrap in
		// the background. retryBootstrapUntilEnrolled upgrades the running
		// agent's transport permanently the moment it succeeds.
		go agent.retryBootstrapUntilEnrolled(context.Background())
	}

	go agent.connectWS()
	go agent.startLocalAPI()
	go agent.runSpoolDrainer()
	go agent.runDisconnectWatchdog()
	go agent.runPressureLoop()
	go agent.runCertRenewal(context.Background())
	agent.sendHeartbeat("idle")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			agent.sendHeartbeat(agent.getStatus())
		case <-quit:
			log.Println("[*] Shutting down — finalizing active scenario if any...")
			agent.shutdownFinalize(shutdownGrace)
			agent.sendHeartbeat("offline")
			platformRestoreOnShutdown()
			return
		}
	}
}
