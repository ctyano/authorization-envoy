ARG ENVOY_VERSION=v1.34-latest

# note: never use the :latest tag in a production site
FROM docker.io/library/golang:1 AS builder

ARG APP_NAME=authorization-envoy
ARG VERSION=test
# date -u +'%Y-%m-%dT%H:%M:%SZ'
ARG BUILD_DATE
# git rev-parse --short HEAD
ARG VCS_REF

ENV APP_NAME=${APP_NAME}
ENV VERSION=${VERSION}
ENV BUILD_DATE=${BUILD_DATE}
ENV VCS_REF=${VCS_REF}

WORKDIR ${GOPATH}/src/${APP_NAME}

RUN apt-get update && apt-get install -y curl cmake g++ make unzip curl git tzdata tree bash

COPY . .

RUN go mod tidy
RUN set -x; \
    GOOS=wasip1 \
    GOARCH=wasm \
    go build -buildmode=c-shared -o "${APP_NAME}.wasm" \
    && mv ${GOPATH}/src/${APP_NAME}/"${APP_NAME}.wasm" /opt/"${APP_NAME}.wasm"

RUN rm -rf "${GOPATH}"

# [Required] A host environment supporting this toolchain, such as Envoy >= 1.33.0. This SDK leverages additional host imports added to the proxy-wasm-cpp-host in PR#427.
# https://github.com/proxy-wasm/proxy-wasm-go-sdk/blob/ab4161dcf9246a828008b539a82a1556cf0f2e24/README.md#requirements
# https://github.com/proxy-wasm/proxy-wasm-cpp-host/pull/427
FROM docker.io/envoyproxy/envoy:${ENVOY_VERSION}

ARG APP_NAME=authorization-envoy
ARG VERSION=test
ARG BUILD_DATE
ARG VCS_REF

LABEL org.opencontainers.image.version=${VERSION}
LABEL org.opencontainers.image.revision=${VCS_REF}
LABEL org.opencontainers.image.created=${BUILD_DATE}
LABEL org.opencontainers.image.title="Athenz Authorization Envoy"
LABEL org.opencontainers.image.authors="ctyano <ctyano@duck.com>"
LABEL org.opencontainers.image.vendor="ctyano <ctyano@duck.com>"
LABEL org.opencontainers.image.licenses="GPL-3.0 license"
LABEL org.opencontainers.image.url="ghcr.io/ctyano/authorization-envoy"
LABEL org.opencontainers.image.documentation="https://www.athenz.io/"
LABEL org.opencontainers.image.source="https://github.com/ctyano/authorization-envoy"

RUN apt-get update && \
    apt-get install -y curl openssl wabt

ENV APP_NAME=${APP_NAME}
ENV VERSION=${VERSION}
ENV BUILD_DATE=${BUILD_DATE}
ENV VCS_REF=${VCS_REF}

COPY --from=builder /opt/"${APP_NAME}.wasm" /etc/envoy/${APP_NAME}.wasm

