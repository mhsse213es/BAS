FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY orchestrator/go.mod orchestrator/go.sum ./
RUN go mod download
COPY orchestrator/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /bin/orchestrator ./cmd/server

FROM gcr.io/distroless/static-debian12
COPY --from=builder /bin/orchestrator /orchestrator
COPY orchestrator/wwwroot /wwwroot
COPY scenarios /scenarios
USER nonroot
EXPOSE 9000
ENTRYPOINT ["/orchestrator"]
