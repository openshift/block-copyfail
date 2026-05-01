CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -target bpf -D__TARGET_ARCH_$(ARCH) -O2 -g \
	-Wall -Werror \
	$(shell pkg-config --cflags libbpf 2>/dev/null)

CFLAGS  := -O2 -Wall -Werror
LDFLAGS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz")

.PHONY: all clean

all: block-copyfail

block_copyfail.bpf.o: block_copyfail.bpf.c block_copyfail.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

block_copyfail.skel.h: block_copyfail.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

block-copyfail: block_copyfail.c block_copyfail.h block_copyfail.skel.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f block_copyfail.bpf.o block_copyfail.skel.h block-copyfail
