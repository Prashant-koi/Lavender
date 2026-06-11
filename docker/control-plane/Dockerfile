FROM golang:1.25-bookworm AS builder

WORKDIR /app/services/control-plane
COPY services/control-plane/go.mod services/control-plane/go.sum ./
RUN go mod download

COPY services/control-plane ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/control-plane .

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/control-plane /app/control-plane

CMD [ "/app/control-plane" ]