FROM quay.io/centos/centos:stream9 AS builder

RUN dnf install -y 'dnf-command(config-manager)' \
    && dnf config-manager --set-enabled crb \
    && dnf install -y \
    --setopt=install_weak_deps=0 \
    clang bpftool \
    libbpf-devel elfutils-libelf-devel zlib-devel \
    make pkg-config gcc \
    && dnf clean all

WORKDIR /build
COPY mitigations.bpf.c mitigations.h mitigations.c Makefile ./
RUN make

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

RUN microdnf install -y libbpf elfutils-libelf zlib && microdnf clean all

COPY --from=builder /build/mitigation-loader /usr/local/bin/mitigation-loader

ENTRYPOINT ["/usr/local/bin/mitigation-loader"]
