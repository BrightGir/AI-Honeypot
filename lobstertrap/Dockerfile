FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /build
RUN git clone https://github.com/veeainc/lobstertrap.git .
RUN go build -o lobstertrap .

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /build/lobstertrap /app/lobstertrap
RUN chmod +x /app/lobstertrap
COPY mirage_policy.yaml /app/configs/mirage_policy.yaml

# Run as non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 8080
ENTRYPOINT ["/app/lobstertrap", "serve", "--backend", "https://generativelanguage.googleapis.com/v1beta/openai/", "--policy", "/app/configs/mirage_policy.yaml", "--listen", ":8080"]
