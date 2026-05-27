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

all: mitigation-loader

mitigations.bpf.o: mitigations.bpf.c mitigations.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

mitigations.skel.h: mitigations.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

mitigation-loader: mitigations.c mitigations.h mitigations.skel.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f mitigations.bpf.o mitigations.skel.h mitigation-loader
