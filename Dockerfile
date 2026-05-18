FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY orchestrator/go.mod orchestrator/go.sum ./
RUN go mod download

COPY orchestrator/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o orchestrator ./cmd/server

FROM gcr.io/distroless/static-debian12

WORKDIR /app

COPY --from=builder /src/orchestrator .

EXPOSE 9000

CMD ["./orchestrator"]