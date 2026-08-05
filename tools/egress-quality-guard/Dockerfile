ARG GO_VERSION=1.26
ARG ALPINE_VERSION=3.23

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src
COPY tools/egress-quality-guard/go.mod ./
RUN go mod download
COPY tools/egress-quality-guard/main.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -buildvcs=false -trimpath -ldflags="-s -w" \
    -o /out/grok2api-egress-quality-guard . && \
    mkdir -p /out/rootfs/var/lib/grok2api-quality-guard && \
    chown 10001:10001 /out/rootfs/var/lib/grok2api-quality-guard && \
    chmod 0700 /out/rootfs/var/lib/grok2api-quality-guard

FROM alpine:${ALPINE_VERSION} AS certificates
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=builder /out/grok2api-egress-quality-guard /usr/local/bin/grok2api-egress-quality-guard
COPY --from=builder --chown=10001:10001 /out/rootfs/ /
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

USER 10001:10001
VOLUME ["/var/lib/grok2api-quality-guard"]
ENTRYPOINT ["/usr/local/bin/grok2api-egress-quality-guard"]
