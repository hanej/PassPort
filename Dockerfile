# Stage 1: Build
FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /passport ./cmd/passport

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /passport /passport
COPY config.yaml.example /etc/passport/config.yaml.example

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/passport"]
CMD ["-config", "/etc/passport/config.yaml"]
