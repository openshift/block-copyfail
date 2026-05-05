FROM registry.fedoraproject.org/fedora:43 AS builder

# hadolint ignore=DL3041
RUN dnf install -y \
    --setopt=install_weak_deps=0 \
    clang bpftool \
    libbpf-devel elfutils-libelf-devel zlib-devel \
    make pkg-config gcc \
    && dnf clean all

WORKDIR /build
COPY block_copyfail.bpf.c block_copyfail.h block_copyfail.c Makefile ./
RUN make block-copyfail

# hadolint ignore=DL3007
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

# hadolint ignore=DL3041
RUN microdnf install -y libbpf elfutils-libelf zlib && microdnf clean all

COPY --from=builder /build/block-copyfail /usr/local/bin/block-copyfail

ENTRYPOINT ["/usr/local/bin/block-copyfail"]
