/* BPF LSM program to block CVE-2026-31431.
 *
 * Hooks socket_bind and blocks AF_ALG binds to the "authencesn" algorithm,
 * which is the only algorithm exploited by the copy-fail vulnerability.
 * All other AF_ALG usage (hash, skcipher, rng, other AEAD) is unaffected.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "block_copyfail.h"

struct socket;
struct sockaddr;

/* struct sockaddr_alg layout (from linux/if_alg.h):
 *   offset 0:  __u16  salg_family
 *   offset 2:  __u8   salg_type[14]
 *   offset 16: __u32  salg_feat
 *   offset 20: __u32  salg_mask
 *   offset 24: __u8   salg_name[64]
 * We need at least 34 bytes to check "authencesn" (10 chars at offset 24).
 */
#define SOCKADDR_ALG_TYPE_OFFSET 2
#define SOCKADDR_ALG_MIN_LEN 34

static const char aead_type[4] = "aead";
static const char authencesn_prefix[10] = "authencesn";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

SEC("lsm/socket_bind")
int BPF_PROG(block_copyfail, struct socket *sock,
	     struct sockaddr *address, int addrlen, int ret)
{
	if (ret)
		return ret;

	if (addrlen < SOCKADDR_ALG_MIN_LEN)
		return 0;

	__u8 buf[SOCKADDR_ALG_MIN_LEN];

	if (bpf_probe_read_kernel(buf, sizeof(buf), address) < 0)
		return 0;

	__u16 family = *(__u16 *)&buf[0];
	if (family != AF_ALG)
		return 0;

	if (__builtin_memcmp(&buf[SOCKADDR_ALG_TYPE_OFFSET], aead_type, 4) != 0)
		return 0;

	if (__builtin_memcmp(&buf[SOCKADDR_ALG_NAME_OFFSET],
			     authencesn_prefix, 10) != 0)
		return 0;

	struct block_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (evt) {
		evt->pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(evt->comm, sizeof(evt->comm));
		evt->ts = bpf_ktime_get_ns();
		bpf_ringbuf_submit(evt, 0);
	}

	return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
