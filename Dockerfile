# syntax=docker/dockerfile:1.7
ARG NODE_VERSION=22

# Cross-compiles without emulation: CGO is off, so the build platform's Go
# toolchain produces a binary for TARGETARCH directly.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/sealift ./cmd/sealift

# Runs on TARGETPLATFORM, under emulation for a non-native target: setcap
# needs to run on the binary it marks, and the risk check of 2026-09-18
# found this survives emulation and the COPY into the final stage.
FROM node:${NODE_VERSION}-bookworm-slim AS caps
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/sealift /sealift
# cap_setuid and cap_setgid start pnpm and Trivy as tools; cap_kill lets the
# server, running as app, kill a process group owned by tools when a job is
# cancelled (decisions.md, "phase 2 part A review, what part B must carry").
RUN setcap cap_setuid,cap_setgid,cap_kill=ep /sealift

FROM node:${NODE_VERSION}-bookworm-slim AS final
# Node bundles its own root CA store, but the Go binary trusts the OS one,
# which this base image does not carry; without it every HTTPS call sealift
# makes to the npm registry or the GitHub API fails to verify its
# certificate (found running the end-to-end test against a real server,
# task "e2e-1": every analysis failed at "prepare-tools" with no visible
# error until this was added).
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 2000 data \
    && useradd --uid 10000 --gid data --home-dir /data/home --no-create-home app \
    && useradd --uid 10001 --gid data --home-dir /data/home --no-create-home tools \
    && mkdir -p /data && chown app:data /data && chmod 0770 /data

COPY --from=caps /sealift /usr/local/bin/sealift
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

VOLUME /data
USER app
ENV HOME=/data/home
EXPOSE 8080
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["sealift"]
