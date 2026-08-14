# TableX — multi-stage build producing a tiny, CGo-free, distroless image.
# All web assets are embedded via go:embed, so the runtime image is just the
# static binary (no PHP, no Node, no external files).

# golang:1.26.6 — pinned by digest for reproducible builds; bump tag + digest together.
# --platform=$BUILDPLATFORM: the build stage always runs natively on the build
# host and CROSS-COMPILES via TARGETOS/TARGETARCH. Pure Go makes that free, and
# it means a multi-arch `buildx build` needs no QEMU/binfmt emulation at all.
FROM --platform=$BUILDPLATFORM golang@sha256:640a234f4bea3e399c056b7b8f9c667c4939befae8db2f14e9785e16eccd4205 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
# CGO disabled keeps the binary pure-Go and statically linked. TARGETOS/TARGETARCH
# are empty under a plain single-platform `docker build`, which Go reads as
# "host platform" — exactly right there too.
RUN CGO_ENABLED=0 GOFLAGS=-trimpath GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/tablex ./cmd/tablex

# gcr.io/distroless/static-debian13:nonroot — pinned by digest; bump tag + digest together.
FROM gcr.io/distroless/static-debian13@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
LABEL org.opencontainers.image.title="TableX" \
      org.opencontainers.image.description="Single-binary multi-database web admin (MySQL/MariaDB, PostgreSQL, SQLite)" \
      org.opencontainers.image.url="https://tablex.dev" \
      org.opencontainers.image.source="https://github.com/tablexdev/tablex" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/tablex /tablex
# go-sql-driver/mysql is MPL-2.0: shipping its notice with the image is a
# license obligation, not decoration.
COPY LICENSE THIRD-PARTY-NOTICES /usr/share/doc/tablex/
USER nonroot:nonroot
EXPOSE 8080
# The binary self-probes GET /healthz (distroless has no shell or curl). The
# probe re-reads TABLEX_* env (and a TOML file when TABLEX_CONFIG is set) but
# CANNOT see command-line flags — including this file's own `CMD ["-listen",
# ":8080"]`. To run on a non-default address, set TABLEX_LISTEN (and any TLS
# vars) instead of overriding CMD, or the probe will silently check the wrong
# port and mark the container unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/tablex", "-healthcheck"]
ENTRYPOINT ["/tablex"]
CMD ["-listen", ":8080"]
