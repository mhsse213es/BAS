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
FROM golang:1.26-alpine AS agent-builder
# Pinned to the same v0.17.0 used by the orchestrator's own builder stage
# below -- v0.18.0 requires go >= 1.27, which this image's go1.26.7 cannot
# satisfy under GOTOOLCHAIN=local (see that stage's comment for the full
# rationale). Each Dockerfile stage is independent, so this stage needs
# its own install -- it cannot reuse the builder stage's.
RUN apk add --no-cache git && \
    go install mvdan.cc/garble@v0.17.0
WORKDIR /agent
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ .
# GOGARBLE scopes obfuscation to our own module only -- golang.org/x/sys,
# windigo, sspi, and gorilla/websocket stay un-obfuscated, same reasoning
# as the orchestrator's own GOGARBLE scoping below (a third-party
# dependency's reflection/assembly code is never garble's business to
# rewrite). All platform binaries.
RUN CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /agents/bas-agent-linux-amd64   . && \
    CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /agents/bas-agent-linux-arm64   . && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /agents/bas-agent-windows-amd64.exe . && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /agents/bas-agent-darwin-amd64  . && \
    CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 GOGARBLE='audspect/*' garble -literals build -ldflags="-s -w" -o /agents/bas-agent-darwin-arm64  .
# BINARIES.sha256 is generated later, in the binaries-manifest stage, once
# both this stage's and agent-legacy-builder's binaries exist to hash together.
# Windows GUI installer — embeds the single Windows agent binary built above
# (already garbled; the installer's own source is out of D2's scope, since
# it has no Audspect detection/scenario logic, only unpacking and
# service-install plumbing). The agent contains the tray + status-window UI
# (run via --tray / --status-window), so there is no separate tray
# executable to build.
WORKDIR /installer
COPY installer/go.mod installer/go.sum ./
RUN go mod download
COPY installer/ .
RUN apk add --no-cache zip && \
    cp /agents/bas-agent-windows-amd64.exe ./bas_agent.exe && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -H windowsgui" \
    -o /agents/Audspect_Agent.exe . && \
    EXE_MB=$(( $(stat -c%s /agents/Audspect_Agent.exe) / 1024 / 1024 )) && \
    if [ "$EXE_MB" -gt 25 ]; then echo "Audspect_Agent.exe is ${EXE_MB}MB, expected ~14MB - something is being embedded that shouldn't be" >&2; exit 1; fi && \
    cd /agents && zip -q bas-agent-windows-amd64-setup.zip Audspect_Agent.exe && rm Audspect_Agent.exe

# ── Legacy Windows Agent Builder ─────────────────────────────────────────────
# go1.20.14 is the last Go release supporting Windows 7 SP1/8/8.1/Server
# 2008 R2-2012 R2. See
# docs/superpowers/specs/2026-08-18-legacy-windows-agent-phase1-design.md.
# Uses golang:1.20.14-alpine directly rather than GOTOOLCHAIN=go1.20.14 on
# top of a newer base image: the latter downloads go1.20.14 as a *module*
# toolchain under GOMODCACHE, and garble v0.10.1 (the newest version that
# still installs under a go1.20 toolchain -- it predates Go's
# module-toolchain feature entirely) panics parsing `go list -json`
# output because of the "toolchain ... invoked to provide ..." banner
# that mechanism prints. A native GOROOT install has no such banner.
# See D2's design doc, Gap 2.
FROM golang:1.20.14-alpine AS agent-legacy-builder
RUN apk add --no-cache git zip && \
    go install mvdan.cc/garble@v0.10.1
WORKDIR /agent-legacy
COPY agent-legacy/go.mod agent-legacy/go.sum ./
RUN go mod download
COPY agent-legacy/ .
# Hard assertion: fail the image build outright if the resolved toolchain
# isn't exactly go1.20.14 -- now asserting the base image itself (a
# stronger guarantee than the previous GOTOOLCHAIN-driven assertion,
# which could not distinguish a correct native install from a
# garble-incompatible module-downloaded one carrying the same version
# string).
RUN GOVERSION=$(go version) && \
    echo "Resolved toolchain: $GOVERSION" && \
    case "$GOVERSION" in \
      *go1.20.14*) ;; \
      *) echo "FATAL: expected go1.20.14, got: $GOVERSION" >&2; exit 1 ;; \
    esac
# GOGARBLE scopes obfuscation to our own module only -- golang.org/x/sys
# (an older version than the modern agent's, v0.15.0) stays un-obfuscated,
# same reasoning as agent-builder above.
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOGARBLE='audspect/*' \
    garble -literals build -ldflags="-s -w" -o /agents-legacy/bas-agent-windows-legacy-amd64.exe .
RUN cd /agents-legacy && zip -q bas-agent-windows-legacy-amd64-setup.zip bas-agent-windows-legacy-amd64.exe

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

# ── Combined Binary Manifest ─────────────────────────────────────────────────
# Must run after agent-builder, agent-legacy-builder, AND packager so the
# manifest covers every artifact an endpoint can download -- generated from
# a single COPY of each stage's real output, not duplicated/recomputed
# elsewhere, so the hashes always match what's actually shipped. Must be
# textually defined after packager: BuildKit resolves a `COPY --from=`
# reference only against stages already declared earlier in the file,
# regardless of the dependency graph it then builds in.
FROM alpine AS binaries-manifest
RUN mkdir /agents
COPY --from=agent-builder /agents/bas-agent-linux-amd64 /agents/bas-agent-linux-arm64 \
     /agents/bas-agent-windows-amd64.exe /agents/bas-agent-darwin-amd64 /agents/bas-agent-darwin-arm64 \
     /agents/bas-agent-windows-amd64-setup.zip \
     /agents/
COPY --from=agent-legacy-builder /agents-legacy/bas-agent-windows-legacy-amd64.exe \
     /agents-legacy/bas-agent-windows-legacy-amd64-setup.zip \
     /agents/
COPY --from=packager /packages/bas-agent-linux-amd64.deb /packages/bas-agent-linux-arm64.deb \
     /packages/bas-agent-linux-amd64.rpm \
     /agents/
RUN cd /agents && sha256sum \
      bas-agent-linux-amd64 bas-agent-linux-arm64 bas-agent-windows-amd64.exe \
      bas-agent-darwin-amd64 bas-agent-darwin-arm64 bas-agent-windows-legacy-amd64.exe \
      bas-agent-windows-amd64-setup.zip bas-agent-windows-legacy-amd64-setup.zip \
      bas-agent-linux-amd64.deb bas-agent-linux-arm64.deb bas-agent-linux-amd64.rpm \
    > /agents/BINARIES.sha256

# ── Go Orchestrator ───────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder
# BAS_WWWROOT_HASH: SHA-256 of wwwroot/index.html, computed by windows-build.ps1
# and injected here so StaticHandler() halts on mismatch at startup. Empty in
# dev/manual builds — hash check is silently disabled when the value is "".
ARG BAS_WWWROOT_HASH=""
# Pinned, not @latest: garble v0.18.0 (2026-09-19) bumped its go.mod
# requirement to go >= 1.27, which this golang:1.26-alpine base image
# (go 1.26.7) can't satisfy under GOTOOLCHAIN=local, breaking the build
# outright. v0.17.0 is the newest release whose own go.mod still only
# requires go 1.26.2. Bump this pin (and the base image, if needed) as a
# deliberate choice, not a side effect of @latest silently moving forward.
RUN apk add --no-cache git && \
    go install mvdan.cc/garble@v0.17.0
# Seed the CA directory with correct nonroot ownership here, in a stage that
# still has a shell -- gcr.io/distroless/static-debian12 (the final stage)
# has none, so a RUN mkdir/chown there is impossible. This directory is
# COPY --chown'd into the final stage below. Production deployments mount
# a HOST bind-mount at this path (packaging/compose/docker-compose.yml's
# ./pki:/etc/audspect/pki), which does NOT inherit ownership from the
# image -- install.sh/uninstall.sh's own chown 65532:65532 on the host
# directory is what makes that writable by nonroot. This seed step matters
# for a standalone `docker run` with no bind-mount, and gives install.sh a
# verified-correct UID:GID to chown the host directory to.
# 65532:65532 is gcr.io/distroless/static-debian12:nonroot's real nonroot
# UID:GID -- verified directly against the image's /etc/passwd, not assumed.
RUN mkdir -p /pki-seed && chown 65532:65532 /pki-seed
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
COPY --from=binaries-manifest /agents/BINARIES.sha256 /agents/BINARIES.sha256
COPY --from=agent-builder /agents /agents
COPY --from=agent-legacy-builder /agents-legacy/bas-agent-windows-legacy-amd64.exe /agents/bas-agent-windows-legacy-amd64.exe
COPY --from=agent-legacy-builder /agents-legacy/bas-agent-windows-legacy-amd64-setup.zip /agents/bas-agent-windows-legacy-amd64-setup.zip
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
COPY --from=builder --chown=65532:65532 /pki-seed /etc/audspect/pki
ENV ART_DIR=/art-atomics
ENV ART_PAYLOAD_DIR=/art-payloads
ENV KEV_FILE=/content/cisa-kev.json
USER nonroot
EXPOSE 9000 9443 9444 9543
ENTRYPOINT ["/orchestrator"]
