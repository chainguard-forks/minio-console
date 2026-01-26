# syntax=docker/dockerfile:1

FROM --platform=${BUILDPLATFORM} tonistiigi/xx:1.6.1@sha256:923441d7c25f1e2eb5789f82d987693c47b8ed987c4ab3b075d6ed2b5d6779a3 AS xx
FROM --platform=${BUILDPLATFORM} alpine:3.23@sha256:865b95f46d98cf867a156fe4a135ad3fe50d2056aa3f25ed31662dff6da4eb62 AS curl-downloader

COPY --from=xx / /

SHELL ["/bin/ash", "-euo", "pipefail", "-c"]
ARG TARGETARCH
RUN --mount=type=cache,target=/var/cache/apk \
    apk add -uU bash jq wget xz
RUN <<EOF
    case "${TARGETARCH}" in
        "amd64") PLATFORM="x86_64" ;;
        "arm64") PLATFORM="aarch64" ;;
        "ppc64le") PLATFORM="powerpc64le" ;;
        *) PLATFORM="${TARGETARCH}" ;;
    esac
    set -x
    CURL_VERSION=$(wget -qO- https://api.github.com/repos/stunnel/static-curl/releases/latest | jq -er .tag_name)
    echo "https://github.com/stunnel/static-curl/releases/download/${CURL_VERSION}/curl-linux-${PLATFORM}-musl-${CURL_VERSION}.tar.xz"
    wget -qO /tmp/curl.tar.xz "https://github.com/stunnel/static-curl/releases/download/${CURL_VERSION}/curl-linux-${PLATFORM}-musl-${CURL_VERSION}.tar.xz"
    mkdir -p /rootfs/usr/bin/
    tar -xf /tmp/curl.tar.xz -C /rootfs/usr/bin/
    rm -f /tmp/curl.tar.xz
    chmod +x /rootfs/usr/bin/curl
    xx-verify --static /rootfs/usr/bin/curl
EOF

FROM --platform=${BUILDPLATFORM} goreleaser/goreleaser:v2.9.0@sha256:da5dbdb1fe1c8fa9a73e152070e4a9b178c3500c3db383d8cff2f206b06ef748 AS build

WORKDIR /build

COPY --from=xx / /

RUN apk add -U --no-cache bash ca-certificates

COPY go.* .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

ARG TARGETPLATFORM
ARG CI_COMMIT_TAG
SHELL ["bash", "-c"]
RUN --mount=type=bind,target=.,rw \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg/mod \
<<EOF
    set -eo pipefail
    args=(
        --skip validate
        --single-target
        --clean
        --output /go/bin/console
    )
    if [ -z "${CI_COMMIT_TAG}" ]; then
        args+=(--snapshot)
    fi
    xx-go --wrap
    set -o allexport
    source "$(go env GOENV)"
    set +o allexport
    goreleaser build "${args[@]}"
    xx-verify --static /go/bin/console
EOF

FROM registry.access.redhat.com/ubi9/ubi-micro:latest

RUN chmod -R 777 /usr/bin

COPY --from=curl-downloader /rootfs/ /
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /go/bin/console /usr/bin/

COPY CREDITS /licenses/CREDITS
COPY LICENSE /licenses/LICENSE
COPY dockerscripts/docker-entrypoint.sh /usr/bin/docker-entrypoint.sh

EXPOSE 9090

ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]
CMD ["console", "server"]
