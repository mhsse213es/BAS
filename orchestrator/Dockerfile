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

# ── Agent Builder (linux/amd64 and linux/arm64) ───────────────────────────────
FROM golang:1.25-alpine AS agent-builder
WORKDIR /src
COPY agent/go.mod agent/go.sum ./
RUN go mod download
COPY agent/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-linux-amd64 . && \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
    go build -trimpath -ldflags="-s -w" -o /agents/bas-agent-linux-arm64 .

# ── Go Orchestrator (garble-obfuscated) ──────────────────────────────────────
# IMPORTANT: must stay on golang:1.23-alpine — garble v0.12.x cannot obfuscate
# Go 1.25 runtime internals (ABI selector error). GOTOOLCHAIN=local lets Go 1.23
# build the module even though go.mod declares go 1.25.0.
# Do NOT upgrade to golang:1.25-alpine here until garble adds Go 1.25 support.
FROM golang:1.23-alpine AS builder
ENV GOTOOLCHAIN=local
RUN apk add --no-cache git
WORKDIR /src
COPY orchestrator/go.mod orchestrator/go.sum ./
RUN go mod download
RUN go install mvdan.cc/garble@v0.12.1
COPY orchestrator/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    garble -tiny -seed=random build -ldflags="-s -w" -o /bin/orchestrator ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=builder /bin/orchestrator /orchestrator
COPY --from=agent-builder /agents /agents
COPY orchestrator/wwwroot /wwwroot
COPY scenarios /scenarios
COPY --from=art-fetcher /art-atomics /art-atomics
ENV ART_DIR=/art-atomics
USER nonroot
EXPOSE 9000
ENTRYPOINT ["/orchestrator"]
