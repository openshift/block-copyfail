#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mitigations.h"
#include "mitigations.skel.h"

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	running = 0;
}

struct mitigation_flags {
	int copyfail;
	int rxrpc;
	int udp_splice;
	int espintcp;
	int udp_encap;
};

static void enable_all_default(struct mitigation_flags *f)
{
	f->copyfail = 1;
	f->udp_splice = f->udp_encap = 1;
	f->espintcp = 1;
	f->rxrpc = 0;
}

static void enable_all_cves(struct mitigation_flags *f)
{
	enable_all_default(f);
	f->rxrpc = 1;
}

static void parse_mitigations(struct mitigation_flags *f)
{
	const char *env = getenv("MITIGATIONS");

	if (!env || !*env || strcmp(env, "all") == 0) {
		enable_all_default(f);
		return;
	}

	f->copyfail = f->rxrpc = f->udp_splice = 0;
	f->espintcp = f->udp_encap = 0;

	char buf[256];
	strncpy(buf, env, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
		while (*tok == ' ') tok++;
		if (strcmp(tok, "all") == 0) {
			enable_all_default(f);
		} else if (strcmp(tok, "all-cves") == 0) {
			enable_all_cves(f);
		} else if (strcmp(tok, "CVE-2026-31431") == 0) {
			f->copyfail = 1;
		} else if (strcmp(tok, "CVE-2026-43284") == 0) {
			f->udp_splice = f->udp_encap = 1;
		} else if (strcmp(tok, "CVE-2026-43500") == 0) {
			f->rxrpc = 1;
		} else if (strcmp(tok, "CVE-2026-46300") == 0) {
			f->espintcp = 1;
		} else {
			fprintf(stderr, "mitigation-loader: unknown mitigation '%s', ignoring\n", tok);
			fprintf(stderr, "  valid values: all, all-cves, CVE-2026-31431, CVE-2026-43284, CVE-2026-43500, CVE-2026-46300\n");
		}
	}
}

static int populate_init_net_ns(struct mitigations_bpf *skel)
{
	char link[64];
	ssize_t len = readlink("/proc/1/ns/net", link, sizeof(link) - 1);
	if (len < 0) {
		fprintf(stderr, "mitigation-loader: failed to read /proc/1/ns/net\n");
		return -1;
	}
	link[len] = '\0';

	__u32 inum = 0;
	if (sscanf(link, "net:[%u]", &inum) != 1) {
		fprintf(stderr, "mitigation-loader: failed to parse net ns inum from '%s'\n", link);
		return -1;
	}

	__u32 key = 0;
	int fd = bpf_map__fd(skel->maps.init_net_ns);
	if (bpf_map_update_elem(fd, &key, &inum, BPF_ANY)) {
		fprintf(stderr, "mitigation-loader: failed to populate init_net_ns map\n");
		return -1;
	}

	fprintf(stderr, "mitigation-loader: init net namespace inum=%u\n", inum);
	return 0;
}

static __u64 boot_time_ns;

static int handle_event(void *ctx, void *data, size_t len)
{
	if (len < sizeof(struct block_event))
		return 0;

	struct block_event *evt = data;
	time_t event_sec = (evt->ts + boot_time_ns) / 1000000000ULL;
	struct tm *tm = localtime(&event_sec);
	char ts[32];
	const char *what;

	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);
	switch (evt->reason) {
	case BLOCK_REASON_COPYFAIL:   what = "CVE-2026-31431 AF_ALG AEAD bind";         break;
	case BLOCK_REASON_RXRPC:      what = "CVE-2026-43500 AF_RXRPC socket";          break;
	case BLOCK_REASON_UDP_SPLICE: what = "CVE-2026-43284 UDP MSG_SPLICE_PAGES";     break;
	case BLOCK_REASON_ESPINTCP:   what = "CVE-2026-46300 TCP_ULP espintcp";         break;
	case BLOCK_REASON_UDP_ENCAP:  what = "CVE-2026-43284 UDP_ENCAP from container"; break;
	default:                      what = "unknown";                  break;
	}
	fprintf(stderr, "mitigation-loader: BLOCKED %s pid=%-8u comm=%.*s time=%s\n",
		what, evt->pid, 16, evt->comm, ts);
	return 0;
}

int main(int argc, char **argv)
{
	struct mitigations_bpf *skel;
	struct ring_buffer *rb;
	struct mitigation_flags flags;

	parse_mitigations(&flags);

	if (!flags.copyfail && !flags.rxrpc && !flags.udp_splice &&
	    !flags.espintcp && !flags.udp_encap) {
		fprintf(stderr, "mitigation-loader: no mitigations enabled, exiting\n");
		return 1;
	}

	skel = mitigations_bpf__open();
	if (!skel) {
		fprintf(stderr, "mitigation-loader: failed to open BPF skeleton\n");
		return 1;
	}

	if (!flags.copyfail)
		bpf_program__set_autoattach(skel->progs.block_copyfail, false);
	if (!flags.rxrpc)
		bpf_program__set_autoattach(skel->progs.block_rxrpc, false);
	if (!flags.udp_splice)
		bpf_program__set_autoattach(skel->progs.block_udp_splice, false);
	if (!flags.espintcp) {
		bpf_program__set_autoattach(skel->progs.tp_setsockopt, false);
		bpf_program__set_autoattach(skel->progs.block_espintcp, false);
	}
	if (!flags.udp_encap)
		bpf_program__set_autoattach(skel->progs.block_udp_encap, false);

	if (mitigations_bpf__load(skel)) {
		fprintf(stderr, "mitigation-loader: failed to load BPF programs\n");
		mitigations_bpf__destroy(skel);
		return 1;
	}

	if (flags.udp_encap && populate_init_net_ns(skel)) {
		mitigations_bpf__destroy(skel);
		return 1;
	}

	if (mitigations_bpf__attach(skel)) {
		fprintf(stderr, "mitigation-loader: failed to attach BPF programs\n");
		mitigations_bpf__destroy(skel);
		return 1;
	}

	fprintf(stderr, "mitigation-loader: active mitigations:");
	if (flags.copyfail)   fprintf(stderr, " CVE-2026-31431");
	if (flags.udp_splice || flags.udp_encap)
		fprintf(stderr, " CVE-2026-43284");
	if (flags.rxrpc)      fprintf(stderr, " CVE-2026-43500");
	if (flags.espintcp)   fprintf(stderr, " CVE-2026-46300");
	fprintf(stderr, "\n");

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
			      handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "mitigation-loader: failed to create ring buffer\n");
		mitigations_bpf__destroy(skel);
		return 1;
	}

	struct timespec rt, bt;
	clock_gettime(CLOCK_REALTIME, &rt);
	clock_gettime(CLOCK_BOOTTIME, &bt);
	boot_time_ns = (__u64)rt.tv_sec * 1000000000ULL + rt.tv_nsec
		     - (__u64)bt.tv_sec * 1000000000ULL - bt.tv_nsec;

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (running)
		ring_buffer__poll(rb, 250);

	fprintf(stderr, "mitigation-loader: detaching\n");
	ring_buffer__free(rb);
	mitigations_bpf__destroy(skel);
	return 0;
}
