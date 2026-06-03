FROM golang:1.25-bookworm AS builder

WORKDIR /app/services/detection
COPY services/detection/go.mod services/detection/go.sum ./
RUN go mod download

COPY services/detection ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/detection .

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/detection /app/detection

CMD ["/app/detection"]
