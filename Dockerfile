# ---------------------------------------------------------------------------
# Stage 1: build Admin SPA (React)
# ---------------------------------------------------------------------------
FROM node:22-alpine AS spa-builder

WORKDIR /spa
COPY internal/handler/admin-spa/package.json internal/handler/admin-spa/package-lock.json ./
RUN npm ci
COPY internal/handler/admin-spa/ .
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: build Go binary
# ---------------------------------------------------------------------------
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Copy dependency manifests first to leverage layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source tree.
COPY . .

# Copy the built SPA dist into the embed directory.
COPY --from=spa-builder /spa/dist internal/handler/admin-spa/dist/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -trimpath \
    -o /out/my-auth ./cmd/server

# ---------------------------------------------------------------------------
# Stage 2: minimal runtime image
# ---------------------------------------------------------------------------
FROM scratch

# Copy CA certificates so the server can make outbound TLS calls (e.g. JWKS).
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the statically compiled binary.
COPY --from=builder /out/my-auth /my-auth

# Copy migration files required at runtime.
COPY migrations/ /migrations/

EXPOSE 8080

ENTRYPOINT ["/my-auth"]
