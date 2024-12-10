FROM golang:alpine AS xrayr-builder
WORKDIR /app
# Clone the repository from GitHub
RUN apk add --no-cache git
RUN git clone https://github.com/i-panel/XrayR.git .
ENV CGO_ENABLED=0
RUN go mod download
RUN go build -v -o XrayR -trimpath -ldflags "-s -w -buildid="


FROM golang:alpine AS builder
ARG GOOS
ARG GOARCH

WORKDIR /build
COPY . .
WORKDIR cmd/routedns
RUN GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build
# Use an official Ubuntu base image
FROM ubuntu:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    curl \
    awk \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L "https://raw.githubusercontent.com/chocolate4u/Iran-v2ray-rules/release/geoip.dat" -o "/build/cmd/routedns/geoip.dat"
RUN curl -L "https://raw.githubusercontent.com/chocolate4u/Iran-v2ray-rules/release/geosite.dat" -o "/build/cmd/routedns/geosite.dat"


FROM alpine:latest as routedns
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Tehran /etc/localtime

COPY --from=builder /build/cmd/routedns/routedns .
RUN mkdir /etc/rdns/
COPY cmd/routedns/example-config/blocklist-panel.toml /etc/rdns/config.toml
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["/routedns"]
CMD ["/etc/rdns/config.toml"]


FROM routedns as routednsxtls
# RUN mkdir /etc/XrayR/
COPY --from=xrayr-builder /app/XrayR /usr/local/bin
COPY --from=xrayr-builder /app/release/config /etc/XrayR
# ENTRYPOINT [ "XrayR", "--config", "/etc/XrayR/config.yml"]

COPY cmd/routedns/example-config/XrayR/custom_outbound.json /etc/XrayR/custom_outbound.json
COPY cmd/routedns/example-config/XrayR/route.json /etc/XrayR/route.json

ENTRYPOINT ["/bin/sh", "-c", "envsubst < cmd/routedns/example-config/XrayR/config.yml.template > /etc/XrayR/config.yml && /routedns /etc    /rdns/config.toml & exec XrayR --config /etc/XrayR/config.yml"]

# Default environment variables
ENV PANEL_TYPE=SSpanel
ENV API_HOST=https://magicx.one
ENV API_KEY=SSPANEL
ENV NODE_ID=10
ENV NODE_TYPE=Http
ENV TIMEOUT=30
ENV ENABLE_VLESS=false
ENV VLESS_FLOW=xtls-rprx-vision