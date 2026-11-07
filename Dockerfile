# Unified finops image: ONE image ships ALL service binaries. Which process a
# container runs is decided by the compose service's entrypoint (or a
# --entrypoint override), not by the build:
#   api              -> entrypoint: ["/app/finops-api"]        (auto-migrates, serves UI+API)
#   sync-worker      -> entrypoint: ["/app/sync-worker"]       (asynq task consumer)
#   gitstatus-worker -> entrypoint: ["/app/gitstatus-worker"]  (standalone PR poller,
#                       scale-out only; the api process already embeds one poller)
# Sharing one image keeps every container version-atomic and lets them share
# all image layers.
#
# Build: docker build -t finops .
# Standalone run defaults to the API server.

# Stage 1: frontend build (dist is embedded into the api binary)
FROM node:22-alpine AS frontend-builder

WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# Stage 2: Go build (both binaries; api embeds the freshly built dist)
FROM golang:1.26-alpine AS go-builder

# Module proxy is overridable: --build-arg GOPROXY=https://proxy.golang.org,direct
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Overwrite the checked-in dist placeholder with the freshly built assets.
COPY --from=frontend-builder /web/dist ./frontend/dist

# Version stamped into the API binary and exposed on GET /version. Pass it at
# build time so audit records can name the platform version:
#   docker build --build-arg VERSION=v1.0.9 -t finops .
ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=${VERSION}" -o /finops-api ./cmd/api \
 && CGO_ENABLED=0 GOOS=linux go build -o /sync-worker ./cmd/sync-worker \
 && CGO_ENABLED=0 GOOS=linux go build -o /gitstatus-worker ./cmd/gitstatus-worker \
 && CGO_ENABLED=0 GOOS=linux go build -o /platform-token ./cmd/platform-token

# Stage 3: runtime
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=go-builder /finops-api ./finops-api
COPY --from=go-builder /sync-worker ./sync-worker
COPY --from=go-builder /gitstatus-worker ./gitstatus-worker
# Ops CLI: re-sign an admin token when the bootstrap file was lost but the
# admin user already exists (bootstrap skips in that case). Run via:
#   docker exec finops-api /app/platform-token -user-id admin -expires-in 720h
COPY --from=go-builder /platform-token ./platform-token

EXPOSE 8080

# Non-loopback binds (required for Docker port publishing) are guarded by
# API_ALLOW_NON_LOOPBACK=true in docker-compose.yml.
ENTRYPOINT ["./finops-api"]
