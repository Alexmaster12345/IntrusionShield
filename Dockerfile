FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev libpcap-dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o intrusion-shield .

# ────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache libpcap ca-certificates tzdata

WORKDIR /app
COPY --from=builder /build/intrusion-shield .
COPY rules/ ./rules/

ENTRYPOINT ["./intrusion-shield"]
CMD ["-config", "config.json"]
