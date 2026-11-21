FROM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

ARG VERSION=dev
ARG BUILT=unknown

COPY . .
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags="-s -w \
        -X main.Version=${VERSION} \
        -X main.BuildTime=${BUILT}" \
      -o /bin/mcp-proxy \
      ./cmd/mcp-proxy


FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 10001 mcp && \
    adduser  -S -u 10001 -G mcp -H -h /nonexistent -s /sbin/nologin mcp

COPY --from=builder /bin/mcp-proxy /bin/mcp-proxy

# Numeric UID:GID so Kubernetes runAsNonRoot admission check passes
# without reading /etc/passwd from inside the container.
USER 10001:10001

EXPOSE 8080 8081 8082

ENTRYPOINT ["/bin/mcp-proxy"]
