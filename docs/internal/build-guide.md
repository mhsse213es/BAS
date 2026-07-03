# Audspect BAS — Build Guide

**Classification:** Internal — Audspect Engineering / Confidential  
**Platform Version:** v1.7.3

---

## Overview

The Audspect BAS build pipeline runs on Windows (build host) and produces:
- A garble-obfuscated Go orchestrator binary
- A Docker image containing the orchestrator and all bundled content
- A Docker Compose deployment package
- Signed scenario YAML files with RSA-4096 detached signatures
- BINARIES.sha256 manifest with signatures

The build host is the Windows machine where `windows-build.ps1` lives. The final Docker images are pushed to the delivery registry and packaged as tarballs in the delivery ZIP.

---

## Prerequisites

### Windows Build Host

| Tool | Version | Install |
|---|---|---|
| Go | 1.22+ | https://go.dev/dl/ |
| Garble | latest | `go install mvdan.cc/garble@latest` |
| Docker Desktop | latest | https://www.docker.com/products/docker-desktop |
| PowerShell | 5.1+ | Built into Windows |
| GnuPG (GPG) | 2.x | Winget: `winget install GnuPG.Gpg4win` |

### GPG Key

The signing key must be available in the Windows GPG keyring before running the build. See [Signing Infrastructure](signing-infrastructure.md) for key management.

The key is identified by its fingerprint in `windows-build.ps1`. Do not hardcode the passphrase in the script — the build prompts for it or reads from `$env:GPG_PASSPHRASE`.

---

## Running the Build

```powershell
cd C:\path\to\Audspect_Cloud
.\windows-build.ps1
```

The script runs in numbered steps:

### Step 0a — Content Preparation

Ensures required content directories exist and are populated:
- `art-atomics/` — ART YAML library
- `art-payloads/` — Operator-supplied ART payload binaries
- `content/cisa-kev.json` — CISA KEV catalog

If these directories are missing, the build fails with an error.

### Step 0b — Scenario Signing

Signs all scenario YAML files in `scenarios/` with the RSA-4096 GPG key:

```powershell
foreach ($yamlFile in Get-ChildItem scenarios/*.yaml) {
    gpg --detach-sign --armor --output "$($yamlFile.FullName).sig" $yamlFile.FullName
}
```

Produces `.yaml.sig` files alongside each YAML. The orchestrator loads and verifies these at startup.

After signing scenarios, updates `BINARIES.sha256`:
- Computes SHA-256 of the Windows agent binary (`agent/agent.exe`) and Linux agent binary (`agent/bas-agent`)
- Writes hashes to `orchestrator/agents/BINARIES.sha256`
- Signs the manifest: `gpg --detach-sign --armor --output BINARIES.sha256.sig BINARIES.sha256`

### Step 1 — Go Dependency Check

```powershell
cd orchestrator
go mod tidy
go mod verify
```

Ensures all Go module dependencies are correct and the module cache is clean.

### Step 2 — Garble Build (Orchestrator)

```powershell
garble -literals -tiny build -o cmd/server/bas-server ./cmd/server/...
```

Garble applies:
- `-literals` — obfuscates string literals (symbol names, package names, const strings)
- `-tiny` — strips debug info and reduces binary size

**Important:** Garble breaks Go's `html/template` field-name reflection. The orchestrator uses JSON-tag-based map rendering for all report templates. Do not use structs with field names in templates.

The output binary `cmd/server/bas-server` is placed in the server root. The Docker image COPY step picks it up from there.

### Step 3 — Docker Image Build

```powershell
docker build -t audspect-orchestrator:1.7.3 -f orchestrator/Dockerfile orchestrator/
docker build -t audspect-caldera:1.7.3 -f caldera/Dockerfile caldera/
```

The orchestrator Dockerfile:
1. Uses `golang:1.22` for the build stage (garble runs inside Docker for Linux binary)
2. Copies the binary and static assets into a `gcr.io/distroless/static:nonroot` final image
3. Copies `scenarios/` and `content/` into the image

### Step 4 — Image Export

```powershell
docker save audspect-orchestrator:1.7.3 | gzip > release/images/orchestrator.tar.gz
docker save audspect-caldera:1.7.3 | gzip > release/images/caldera.tar.gz
docker save postgres:16 | gzip > release/images/postgres.tar.gz
docker save chromium:latest | gzip > release/images/chromium.tar.gz
```

### Step 5 — Agent Binary Build

Agent binaries are built for each target platform:

```powershell
# Windows AMD64
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -o agent/bas-agent.exe ./agent/...

# Linux AMD64
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -o agent/bas-agent-linux-amd64 ./agent/...

# Linux ARM64
$env:GOOS="linux"; $env:GOARCH="arm64"
go build -o agent/bas-agent-linux-arm64 ./agent/...

# macOS AMD64
$env:GOOS="darwin"; $env:GOARCH="amd64"
go build -o agent/bas-agent-darwin-amd64 ./agent/...
```

After building all binaries, BINARIES.sha256 is updated and re-signed (see Step 0b).

### Step 6 — Delivery ZIP Assembly

```powershell
$zipPath = "release/audspect-bas-v1.7.3.zip"
Compress-Archive -Path @(
    "release/images",
    "docker-compose.yml",
    "setup.sh",
    "config.template.env",
    "scenarios",    # includes .yaml.sig files
    "orchestrator/agents/BINARIES.sha256",
    "orchestrator/agents/BINARIES.sha256.sig"
) -DestinationPath $zipPath
```

---

## Versioning

The platform version string is set in:
- `orchestrator/cmd/server/version.go`: `const Version = "1.7.3"`
- `docker-compose.yml`: image tags
- `windows-build.ps1`: `$Version = "1.7.3"`

Update all three when cutting a new release.

---

## Build Artifacts

After a successful build:

| File | Description |
|---|---|
| `orchestrator/cmd/server/bas-server` | Garble-obfuscated orchestrator binary (Linux) |
| `agent/bas-agent.exe` | Windows agent binary |
| `agent/bas-agent-linux-amd64` | Linux AMD64 agent binary |
| `agent/bas-agent-linux-arm64` | Linux ARM64 agent binary |
| `agent/bas-agent-darwin-amd64` | macOS AMD64 agent binary |
| `orchestrator/agents/BINARIES.sha256` | Agent binary trust manifest |
| `orchestrator/agents/BINARIES.sha256.sig` | GPG signature of the manifest |
| `scenarios/*.yaml.sig` | Scenario RSA-4096 signatures |
| `release/images/*.tar.gz` | Docker image tarballs |
| `release/audspect-bas-v1.7.3.zip` | Final delivery ZIP |

---

## Common Build Failures

| Error | Cause | Fix |
|---|---|---|
| `garble: command not found` | Garble not in PATH | `go install mvdan.cc/garble@latest`; ensure `$GOPATH/bin` is in PATH |
| `gpg: no suitable key found` | Signing key not imported | Import key: `gpg --import audspect-signing-key.asc` |
| `html/template: field not found` | Struct used in template after garble | Use JSON-tag map rendering; never template struct fields |
| `docker: no space left on device` | Old images filling disk | `docker image prune -f` |
| `go: module mismatch` | Stale go.sum | `go mod tidy && go mod download` |

---

## Running Tests

```powershell
cd orchestrator
go test ./...
```

Tests do not require a running database. Database-dependent tests use a test PostgreSQL instance or mock.

---

*© Audspect Engineering — Internal / Confidential*
