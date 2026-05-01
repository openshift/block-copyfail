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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

SEC("lsm/socket_bind")
int BPF_PROG(block_copyfail, struct socket *sock,
	     struct sockaddr *address, int addrlen)
{
	__u8 buf[34];

	if (bpf_probe_read_kernel(buf, sizeof(buf), address) < 0)
		return 0;

	__u16 family = *(__u16 *)&buf[0];
	if (family != AF_ALG)
		return 0;

	/* "auth" at salg_name offset 24 */
	__u32 w0 = *(__u32 *)&buf[24];
	/* "ence" at offset 28 */
	__u32 w1 = *(__u32 *)&buf[28];
	/* "sn" at offset 32 */
	__u16 w2 = *(__u16 *)&buf[32];

	if (w0 != 0x68747561 || w1 != 0x65636e65 || w2 != 0x6e73)
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
