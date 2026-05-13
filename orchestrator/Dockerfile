FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /bin/orchestrator ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=builder /bin/orchestrator /orchestrator
COPY --chown=nonroot:nonroot wwwroot /wwwroot
COPY --chown=nonroot:nonroot scenarios /scenarios
USER nonroot
EXPOSE 9000
ENTRYPOINT ["/orchestrator", "/etc/bas/config.json"]
