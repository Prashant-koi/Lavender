FROM golang:1.25-bookworm AS builder

WORKDIR /app/services/ingest
COPY services/ingest/go.mod services/ingest/go.sum ./
RUN go mod download

COPY services/ingest ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/ingest .

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/ingest /app/ingest

CMD ["/app/ingest"]
