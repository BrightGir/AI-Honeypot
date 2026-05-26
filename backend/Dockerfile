FROM golang:1.24-alpine AS builder
WORKDIR /app
# Since context is now root, we copy from root
COPY go.mod go.sum ./
RUN go mod download
COPY backend/ ./backend/
RUN go build -o mirage ./backend/cmd/server

FROM alpine:3.19
# I8: Run as a non-root user to limit blast radius if the process is compromised.
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=builder /app/mirage /app/mirage
# Ensure the binary is owned by the app user.
RUN chown app:app /app/mirage
USER app
EXPOSE 8081
ENTRYPOINT ["/app/mirage"]
