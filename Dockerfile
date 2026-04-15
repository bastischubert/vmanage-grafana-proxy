FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o proxy .

FROM alpine:3.19
# CA certificates are needed for TLS connections to vManage
RUN apk add --no-cache ca-certificates && \
    adduser -D -H -s /sbin/nologin appuser

COPY --from=builder /app/proxy /proxy

USER appuser
EXPOSE 8080
ENTRYPOINT ["/proxy"]
