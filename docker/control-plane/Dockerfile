# --- build the dashboard ---
FROM node:24-bookworm-slim AS web

WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# --- build the control-plane binary ---
FROM golang:1.25-bookworm AS builder

WORKDIR /app/services/control-plane
COPY services/control-plane/go.mod services/control-plane/go.sum ./
RUN go mod download

COPY services/control-plane ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/control-plane .

# --- runtime: serves the API + the dashboard same-origin ---
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/control-plane /app/control-plane
COPY --from=web /web/dist /app/web
ENV WEB_DIR=/app/web

CMD [ "/app/control-plane" ]
