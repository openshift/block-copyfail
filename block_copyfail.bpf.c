/* BPF LSM program to block Copy Fail vulnerabilities.
 *
 * Copy Fail 1 (CVE-2026-31431): hooks socket_bind and blocks all AF_ALG
 * AEAD binds.  The vulnerability is in algif_aead, and authencesn can be
 * nested inside wrapper templates (e.g. pcrypt), so blocking the entire
 * AEAD type is the only bypass-proof approach.  Other AF_ALG usage
 * (hash, skcipher, rng) is unaffected.
 *
 * Copy Fail 2 / Dirty Frag (ESP path): hooks socket_sendmsg and blocks
 * MSG_SPLICE_PAGES sends on UDP sockets.  The exploit splices a target
 * file's page-cache pages into a plain UDP socket (zero-copy, no data
 * copied), then an ESP-in-UDP receiver decrypts in-place, corrupting
 * the shared pages.  The sending socket is plain UDP (only the receiver
 * has ESP encap), so we block splice-to-UDP entirely.
 *
 * Normal sendmsg/write to UDP sockets is unaffected (those copy data).
 * Splice-to-UDP is extremely uncommon in practice (kernel support was
 * only added in 6.5).
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "block_copyfail.h"

/* CO-RE struct stubs — field names must match kernel BTF.
 * Actual offsets are relocated at load time by libbpf. */
struct sock_common {
	__u16 skc_family;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
} __attribute__((preserve_access_index));

struct socket {
	short type;
	struct sock *sk;
} __attribute__((preserve_access_index));

struct msghdr {
	unsigned int msg_flags;
} __attribute__((preserve_access_index));

struct sockaddr;

#define AF_INET   2
#define AF_INET6 10
#define SOCK_DGRAM 2
#define IPPROTO_UDP 17
#define MSG_SPLICE_PAGES 0x08000000

/* struct sockaddr_alg layout (from linux/if_alg.h):
 *   offset 0:  __u16  salg_family
 *   offset 2:  __u8   salg_type[14]
 *   offset 16: __u32  salg_feat
 *   offset 20: __u32  salg_mask
 *   offset 24: __u8   salg_name[64]
 * We only need 7 bytes to check salg_type == "aead\0".
 */
#define SOCKADDR_ALG_TYPE_OFFSET 2
#define SOCKADDR_ALG_CHECK_LEN 7

static const char aead_type[5] = "aead";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

static __always_inline void emit_block_event(__u32 hook)
{
	struct block_event *evt;

	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return;

	evt->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(evt->comm, sizeof(evt->comm));
	evt->hook = hook;
	evt->ts = bpf_ktime_get_ns();
	bpf_ringbuf_submit(evt, 0);
}

/* Copy Fail 1: block AF_ALG AEAD binds */
SEC("lsm/socket_bind")
int BPF_PROG(block_copyfail, struct socket *sock,
	     struct sockaddr *address, int addrlen, int ret)
{
	if (ret)
		return ret;

	if (addrlen < SOCKADDR_ALG_CHECK_LEN)
		return 0;

	__u8 buf[SOCKADDR_ALG_CHECK_LEN];

	if (bpf_probe_read_kernel(buf, sizeof(buf), address) < 0)
		return 0;

	__u16 family = *(__u16 *)&buf[0];
	if (family != AF_ALG)
		return 0;

	if (__builtin_memcmp(&buf[SOCKADDR_ALG_TYPE_OFFSET], aead_type, 5) != 0)
		return 0;

	emit_block_event(BLOCK_HOOK_CF1);
	return -EPERM;
}

/* Copy Fail 2 / Dirty Frag: block MSG_SPLICE_PAGES sends on UDP sockets.
 *
 * The exploit splices a target file's page-cache pages into a pipe,
 * then splices the pipe into a plain UDP socket.  The kernel sends
 * with MSG_SPLICE_PAGES (zero-copy, shared pages).  An ESP-in-UDP
 * receiver on loopback decrypts in-place, corrupting the shared
 * page cache.  The sending socket has no ESP encap — only the
 * receiver does — so we block splice-to-UDP entirely.
 *
 * Normal sendmsg/write to UDP sockets is unaffected (those copy).
 * Splice-to-UDP is extremely uncommon in practice.
 */
SEC("lsm/socket_sendmsg")
int BPF_PROG(block_copyfail2, struct socket *sock,
	     struct msghdr *msg, int size, int ret)
{
	struct sock *sk;

	if (ret)
		return ret;

	if (!(BPF_CORE_READ(msg, msg_flags) & MSG_SPLICE_PAGES))
		return 0;

	if (BPF_CORE_READ(sock, type) != SOCK_DGRAM)
		return 0;

	sk = BPF_CORE_READ(sock, sk);
	if (!sk)
		return 0;

	if (BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET &&
	    BPF_CORE_READ(sk, __sk_common.skc_family) != AF_INET6)
		return 0;

	if (BPF_CORE_READ(sk, sk_protocol) != IPPROTO_UDP)
		return 0;

	emit_block_event(BLOCK_HOOK_CF2);
	return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
