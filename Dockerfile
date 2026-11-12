# Build the manager binary.
FROM --platform=$BUILDPLATFORM golang:1.27 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy the module files first so dependency download is cached independently of
# source changes.
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/

# CGO is disabled so the binary is fully static and runs on distroless.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -a -o manager ./cmd/manager

# distroless/static:nonroot has no shell and no package manager, which keeps the
# attack surface of a process that handles TLS private keys as small as possible.
# Pinned by digest so a rebuild of the same commit yields the same image;
# Dependabot moves the digest.
FROM gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
