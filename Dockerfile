# syntax=docker/dockerfile:1.7
ARG NODE_VERSION=22

# Runs on BUILDPLATFORM: the frontend build is platform-independent, so
# this stage never pays for emulation on a non-native target.
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-bookworm-slim AS web
WORKDIR /src/web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ .
RUN pnpm run build

# Cross-compiles without emulation: CGO is off, so the build platform's Go
# toolchain produces a binary for TARGETARCH directly.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
ARG TARGETARCH
# The release workflow sets this to the pushed tag; a local build stays
# "dev", the zero value internal/jobs.ToolVersion already has.
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist/app ./web/dist/app
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X github.com/MorganKryze/sealift/internal/jobs.ToolVersion=$VERSION" -o /out/sealift ./cmd/sealift

# Runs on TARGETPLATFORM, under emulation for a non-native target: setcap
# needs to run on the binary it marks, and the capabilities it sets survive
# both the emulation and the COPY into the final stage.
FROM node:${NODE_VERSION}-bookworm-slim AS caps
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/sealift /sealift
# cap_setuid and cap_setgid start pnpm and Trivy as tools; cap_kill lets the
# server, running as app, kill a process group owned by tools when a job is
# cancelled.
RUN setcap cap_setuid,cap_setgid,cap_kill=ep /sealift

FROM node:${NODE_VERSION}-bookworm-slim AS final
# Node bundles its own root CA store, but the Go binary trusts the OS one,
# which this base image does not carry; without it every HTTPS call sealift
# makes to the npm registry or the GitHub API fails to verify its
# certificate, failing an analysis at "prepare-tools" with no visible error.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 2000 data \
    && useradd --uid 10000 --gid data --home-dir /data/home --no-create-home app \
    && useradd --uid 10001 --gid data --home-dir /data/home --no-create-home tools \
    && mkdir -p /data && chown app:data /data && chmod 0770 /data
# Read by cmd/sealift's toolsCredential so pnpm and Trivy run as tools
# instead of app, the account that owns /data/private/settings.json.
ENV SEALIFT_TOOLS_UID=10001
ENV SEALIFT_TOOLS_GID=2000

COPY --from=caps /sealift /usr/local/bin/sealift
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

VOLUME /data
USER app
ENV HOME=/data/home
EXPOSE 8080
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["sealift"]
