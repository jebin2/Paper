# Build stage
FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /paper .

# Runtime stage
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /paper /usr/local/bin/paper
COPY index.html .
ENV LISTEN_PORT=7860 \
    LISTEN_ADDR=0.0.0.0 \
    DATA_DIR=/app/data \
    STATIC_DIR=/app
EXPOSE 7860
CMD ["/usr/local/bin/paper"]