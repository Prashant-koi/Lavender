FROM golang:1.25-bookworm AS builder

WORKDIR /app/services/telemetry-writer
COPY services/telemetry-writer/go.mod services/telemetry-writer/go.sum ./
RUN go mod download

COPY services/telemetry-writer ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/telemetry-writer .

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/telemetry-writer /app/telemetry-writer

CMD [ "/app/telemetry-writer" ]