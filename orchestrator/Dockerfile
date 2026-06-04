# ── ART Atomics (sparse clone — YAML only, ~10 MB, no binaries) ──────────────
FROM alpine AS art-fetcher
RUN apk add --no-cache git && \
    git init /art-repo && \
    cd /art-repo && \
    git remote add origin https://github.com/redcanaryco/atomic-red-team.git && \
    git sparse-checkout init --no-cone && \
    printf 'atomics/T[0-9]*/T[0-9]*.yaml\n' > .git/info/sparse-checkout && \
    git -c protocol.version=2 fetch --depth=1 --filter=blob:none origin master && \
    git checkout FETCH_HEAD && \
    mkdir /art-atomics && \
    find atomics -name 'T[0-9]*.yaml' -exec cp {} /art-atomics/ \;

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
# Windows GUI installer — embeds the single Windows agent binary built above.
# The agent contains the tray + status-window UI (run via --tray / --status-window),
# so there is no separate tray executable to build.
WORKDIR /installer
COPY installer/go.mod installer/go.sum ./
RUN go mod download
COPY installer/ .
RUN cp /agents/bas-agent-windows-amd64.exe ./bas_agent.exe && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -H windowsgui" \
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
RUN apk add --no-cache git && \
    go install mvdan.cc/garble@latest
WORKDIR /src
COPY orchestrator/go.mod orchestrator/go.sum ./
RUN go mod download
COPY orchestrator/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    garble -literals -tiny build \
    -ldflags="-s -w" \
    -o /bin/orchestrator ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=builder /bin/orchestrator /orchestrator
COPY --from=agent-builder /agents /agents
COPY --from=packager /packages/ /agents/
COPY orchestrator/wwwroot /wwwroot
COPY scenarios /scenarios
COPY --from=art-fetcher /art-atomics /art-atomics
ENV ART_DIR=/art-atomics
USER nonroot
EXPOSE 9000
ENTRYPOINT ["/orchestrator"]
