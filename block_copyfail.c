#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include "block_copyfail.h"
#include "block_copyfail.skel.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	running = 0;
}

static const char *hook_name(__u32 hook)
{
	switch (hook) {
	case BLOCK_HOOK_CF1: return "AF_ALG-AEAD";
	case BLOCK_HOOK_CF2: return "ESP-UDP-splice";
	default:             return "unknown";
	}
}

static int handle_event(void *ctx, void *data, size_t len)
{
	struct block_event *evt = data;
	time_t now = time(NULL);
	struct tm *tm = localtime(&now);
	char ts[32];

	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
	fprintf(stderr, "block-copyfail: BLOCKED [%s] pid=%-8u comm=%.*s time=%s\n",
		hook_name(evt->hook), evt->pid, 16, evt->comm, ts);
	return 0;
}

int main(int argc, char **argv)
{
	struct block_copyfail_bpf *skel;
	struct ring_buffer *rb;

	skel = block_copyfail_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "block-copyfail: failed to load BPF program\n");
		return 1;
	}

	if (block_copyfail_bpf__attach(skel)) {
		fprintf(stderr, "block-copyfail: failed to attach BPF program\n");
		block_copyfail_bpf__destroy(skel);
		return 1;
	}

	fprintf(stderr, "block-copyfail: blocker active — AF_ALG AEAD binds + UDP splice blocked\n");

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
			      handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "block-copyfail: failed to create ring buffer\n");
		block_copyfail_bpf__destroy(skel);
		return 1;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (running)
		ring_buffer__poll(rb, 250);

	fprintf(stderr, "block-copyfail: detaching blocker\n");
	ring_buffer__free(rb);
	block_copyfail_bpf__destroy(skel);
	return 0;
}
