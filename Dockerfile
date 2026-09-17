FROM golang:1.27.1-alpine AS build

ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/aliyun-cdn-guard ./cmd/aliyun-cdn-guard

FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && adduser -S -D -H -u 10001 guard \
    && mkdir -p /app/data \
    && chown -R guard:guard /app

WORKDIR /app
COPY --from=build /out/aliyun-cdn-guard /usr/local/bin/aliyun-cdn-guard

USER guard
VOLUME ["/app/data"]
ENTRYPOINT ["aliyun-cdn-guard"]
CMD ["--config", "/app/config.yml"]
