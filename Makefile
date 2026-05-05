CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/s390x/s390/')

BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -g \
	-Wall -Werror \
	$(shell pkg-config --cflags libbpf 2>/dev/null)

CFLAGS  := -O2 -Wall -Werror
LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

.PHONY: all clean

all: podman-build

block_copyfail.bpf.o: block_copyfail.bpf.c block_copyfail.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

block_copyfail.skel.h: block_copyfail.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

block-copyfail: block_copyfail.c block_copyfail.h block_copyfail.skel.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

podman-build:
	podman build -t block-copyfail-builder .
	podman create --name bcf-tmp --replace block-copyfail-builder
	podman cp bcf-tmp:/usr/local/bin/block-copyfail .
	podman rm bcf-tmp
	@echo "Copied to ./block-copyfail"

clean:
	rm -f block_copyfail.bpf.o block_copyfail.skel.h block-copyfail
