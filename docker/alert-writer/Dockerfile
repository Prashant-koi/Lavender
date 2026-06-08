FROM golang:1.25-bookworm AS builder

WORKDIR /app/services/alert-writer
COPY services/alert-writer/go.mod services/alert-writer/go.sum ./
RUN go mod download

COPY services/alert-writer ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/alert-writer .

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/alert-writer /app/alert-writer

CMD [ "/app/alert-writer" ]
