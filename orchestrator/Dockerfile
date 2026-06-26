# ── ART Atomics (sparse clone — YAML only, ~10 MB, no binaries) ──────────────
FROM alpine AS art-fetcher
RUN apk add --no-cache git curl && \
    git init /art-repo && \
    cd /art-repo && \
    git remote add origin https://github.com/redcanaryco/atomic-red-team.git && \
    git sparse-checkout init --no-cone && \
    printf 'atomics/T[0-9]*/T[0-9]*.yaml\n' > .git/info/sparse-checkout && \
    git -c protocol.version=2 fetch --depth=1 --filter=blob:none origin master && \
    git checkout FETCH_HEAD && \
    mkdir /art-atomics /art-payloads && \
    find atomics -name 'T[0-9]*.yaml' -exec cp {} /art-atomics/ \;

# CISA Known Exploited Vulnerabilities catalog — fetched at build, baked into the
# image so it travels inside the air-gap bundle. &&-chained with a size check so
# the build fails loudly if CISA is unreachable (never ships an empty catalog).
RUN mkdir -p /content && \
    curl -fsSL --retry 3 \
      https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
      -o /content/cisa-kev.json && \
    test -s /content/cisa-kev.json

# ── Agent + Installer Builder ────────────────────────────────────────────────
# Plain stripped build: golang.org/x/sys assembly is incompatible with garble.
FROM golang:1.26-alpine AS agent-builder
RUN apk add --no-cache git
WORKDIR /agent
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ .
# All platform binaries
RUN CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-linux-amd64   . && \
    CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-linux-arm64   . && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-windows-amd64.exe . && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-darwin-amd64  . && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-darwin-arm64  .
# Generate BINARIES.sha256 from the binaries just compiled so the orchestrator
# can verify connecting agents at runtime. Must be generated here - from the
# same build - so hashes match what endpoints actually download and run.
RUN cd /agents && sha256sum bas-agent-linux-amd64 bas-agent-linux-arm64 \
        bas-agent-windows-amd64.exe bas-agent-darwin-amd64 bas-agent-darwin-arm64 \
    > /agents/BINARIES.sha256
# Windows GUI installer — embeds the single Windows agent binary built above.
# The agent contains the tray + status-window UI (run via --tray / --status-window),
# so there is no separate tray executable to build.
WORKDIR /installer
COPY installer/go.mod installer/go.sum ./
RUN go mod download
COPY installer/ .
# Bundle the WebView2 runtime into the installer when the Evergreen Standalone
# Installer is present at installer/webview2/ (auto-installed on clients lacking
# the runtime so the status console opens natively). Absent -> browser fallback.
RUN cp /agents/bas-agent-windows-amd64.exe ./bas_agent.exe && \
    TAGS=""; if [ -f webview2/MicrosoftEdgeWebView2RuntimeInstaller.exe ]; then TAGS="webview2bundled"; fi && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -tags "$TAGS" -ldflags="-s -w -H windowsgui" \
    -o /agents/bas-agent-windows-amd64-setup.exe .

# ── Package Builder (.deb, .rpm) ─────────────────────────────────────────────
FROM debian:bookworm-slim AS packager
ARG BAS_VERSION=1.6.0
ENV BAS_VERSION=${BAS_VERSION}
RUN apt-get update && apt-get install -y --no-install-recommends \
    dpkg alien rpm && \
    rm -rf /var/lib/apt/lists/*
COPY --from=agent-builder /agents /binaries
COPY packaging/build-agent-packages.sh /build-packages.sh
RUN bash /build-packages.sh

# ── Go Orchestrator ───────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder
# BAS_WWWROOT_HASH: SHA-256 of wwwroot/index.html, computed by windows-build.ps1
# and injected here so StaticHandler() halts on mismatch at startup. Empty in
# dev/manual builds — hash check is silently disabled when the value is "".
ARG BAS_WWWROOT_HASH=""
RUN apk add --no-cache git && \
    go install mvdan.cc/garble@latest
WORKDIR /src
COPY orchestrator/go.mod orchestrator/go.sum ./
RUN go mod download
COPY orchestrator/ .
# GOGARBLE scopes obfuscation to our own module only. Obfuscating third-party
# deps (esp. github.com/go-pdf/fpdf) renames their reflection-driven struct
# fields and breaks PDF font loading ("font has not been set") — and protects no
# IP, since those libs are public OSS.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOGARBLE='github.com/audspect/*' \
    garble -literals build \
    -ldflags="-s -w -X main.expectedWWWRootHash=${BAS_WWWROOT_HASH}" \
    -o /bin/orchestrator ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=builder /bin/orchestrator /orchestrator
COPY --from=agent-builder /agents /agents
COPY --from=packager /packages/ /agents/
COPY orchestrator/wwwroot /wwwroot
COPY scenarios /scenarios
COPY --from=art-fetcher /art-atomics /art-atomics
# Empty by default — mount a volume here (or bake binaries in) to enable ART
# atomics that need external payloads (gsecdump, etc.). Absent payloads → the
# atomic is skipped cleanly, never run with a broken path.
COPY --from=art-fetcher /art-payloads /art-payloads
# CISA KEV catalog (seeds the cves knowledge-graph table at boot).
COPY --from=art-fetcher /content /content
ENV ART_DIR=/art-atomics
ENV ART_PAYLOAD_DIR=/art-payloads
ENV KEV_FILE=/content/cisa-kev.json
USER nonroot
EXPOSE 9000
ENTRYPOINT ["/orchestrator"]
