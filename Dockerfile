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
FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532

ENTRYPOINT ["/manager"]
