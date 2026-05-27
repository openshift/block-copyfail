/* BPF LSM programs to block kernel page-cache corruption exploits.
 *
 * CVE-2026-31431 — CopyFail:
 *   socket_bind — blocks AF_ALG AEAD binds (algif_aead exploit path).
 *
 * CVE-2026-43284 — Dirty Frag (IPsec ESP):
 *   socket_sendmsg — blocks MSG_SPLICE_PAGES on UDP sockets globally.
 *   socket_setsockopt — blocks UDP_ENCAP from non-init net namespaces.
 *
 * CVE-2026-43500 — Dirty Frag (rxrpc):
 *   socket_create — blocks AF_RXRPC socket creation (rxrpc/rxkad path).
 *   Does not affect Red Hat products; disabled by default.
 *
 * CVE-2026-46300 — Fragnesia (ESP-in-TCP):
 *   tracepoint + socket_setsockopt — blocks TCP_ULP "espintcp" globally.
 */

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mitigations.h"

/* --- CVE-2026-31431: sockaddr_alg layout for AF_ALG AEAD detection --- */

#define SOCKADDR_ALG_TYPE_OFFSET 2
#define SOCKADDR_ALG_CHECK_LEN 7

static const char aead_type[5] = "aead";

/* --- CO-RE struct stubs --- */

struct ns_common {
	unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
	struct ns_common ns;
} __attribute__((preserve_access_index));

struct nsproxy {
	struct net *net_ns;
} __attribute__((preserve_access_index));

struct task_struct {
	struct nsproxy *nsproxy;
} __attribute__((preserve_access_index));

struct sock_common {
	unsigned short skc_family;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
} __attribute__((preserve_access_index));

struct socket {
	short type;
	struct sock *sk;
} __attribute__((preserve_access_index));

struct msghdr {
	unsigned int msg_flags;
} __attribute__((preserve_access_index));

struct sockaddr;

#define AF_INET            2
#define AF_INET6          10
#define SOCK_DGRAM         2
#define IPPROTO_TCP        6
#define IPPROTO_UDP       17
#define TCP_ULP           31
#define UDP_ENCAP        100
#define MSG_SPLICE_PAGES   0x08000000

/* --- Shared ring buffer --- */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

/*
 * Per-task flag set by the tracepoint when TCP_ULP "espintcp" is
 * detected.  The LSM hook reads and clears it in the same syscall.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} espintcp_flag SEC(".maps");

/* Init net namespace inode number, populated by the userspace loader. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} init_net_ns SEC(".maps");

static __always_inline void emit_event(__u32 reason)
{
	struct block_event *evt;
	evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (evt) {
		evt->pid = bpf_get_current_pid_tgid() >> 32;
		bpf_get_current_comm(evt->comm, sizeof(evt->comm));
		evt->reason = reason;
		evt->ts = bpf_ktime_get_ns();
		bpf_ringbuf_submit(evt, 0);
	}
}

/* === CVE-2026-31431: block AF_ALG AEAD binds === */

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

	emit_event(BLOCK_REASON_COPYFAIL);
	return -EPERM;
}

/* === CVE-2026-43500: block AF_RXRPC socket creation === */

SEC("lsm/socket_create")
int BPF_PROG(block_rxrpc, int family, int type, int protocol,
	     int kern, int ret)
{
	if (ret)
		return ret;

	if (kern)
		return 0;

	if (family != AF_RXRPC)
		return 0;

	emit_event(BLOCK_REASON_RXRPC);
	return -EPERM;
}

/* === CVE-2026-43284: block MSG_SPLICE_PAGES on UDP sockets (6.4+) === */

SEC("lsm/socket_sendmsg")
int BPF_PROG(block_udp_splice, struct socket *sock,
	     struct msghdr *msg, int size, int ret)
{
	if (ret)
		return ret;

	if (!(msg->msg_flags & MSG_SPLICE_PAGES))
		return 0;

	if (sock->type != SOCK_DGRAM)
		return 0;

	struct sock *sk = sock->sk;
	if (!sk)
		return 0;

	__u16 family = sk->__sk_common.skc_family;
	if (family != AF_INET && family != AF_INET6)
		return 0;

	emit_event(BLOCK_REASON_UDP_SPLICE);
	return -EPERM;
}

/* === CVE-2026-46300: block TCP_ULP "espintcp" globally === */

/*
 * Tracepoint half: fires before the LSM hook in the same setsockopt
 * syscall.  Reads the optval string from userspace so kTLS ("tls") is
 * preserved while "espintcp" is flagged for blocking.
 */
struct setsockopt_args {
	__u64 __pad;
	__s32 __syscall_nr;
	__u32 __pad2;
	__u64 fd;
	__u64 level;
	__u64 optname;
	__u64 optval;
	__u64 optlen;
};

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int tp_setsockopt(struct setsockopt_args *ctx)
{
	if (ctx->level != IPPROTO_TCP || ctx->optname != TCP_ULP)
		return 0;

	char buf[16] = {};
	if (bpf_probe_read_user_str(buf, sizeof(buf),
				    (void *)ctx->optval) < 0)
		return 0;

	if (buf[0] != 'e' || buf[1] != 's' || buf[2] != 'p' ||
	    buf[3] != 'i' || buf[4] != 'n' || buf[5] != 't' ||
	    buf[6] != 'c' || buf[7] != 'p' || buf[8] != '\0')
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u8 flag = 1;
	bpf_map_update_elem(&espintcp_flag, &pid_tgid, &flag, BPF_ANY);
	return 0;
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(block_espintcp, struct socket *sock, int level,
	     int optname, int ret)
{
	if (ret)
		return ret;

	if (level != IPPROTO_TCP || optname != TCP_ULP)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u8 *flag = bpf_map_lookup_elem(&espintcp_flag, &pid_tgid);
	int is_espintcp = flag && *flag;
	bpf_map_delete_elem(&espintcp_flag, &pid_tgid);
	if (is_espintcp) {
		emit_event(BLOCK_REASON_ESPINTCP);
		return -EPERM;
	}

	return 0;
}

/* === CVE-2026-43284: block UDP_ENCAP from non-init net namespace === */

SEC("lsm/socket_setsockopt")
int BPF_PROG(block_udp_encap, struct socket *sock, int level,
	     int optname, int ret)
{
	if (ret)
		return ret;

	if (level != IPPROTO_UDP || optname != UDP_ENCAP)
		return 0;

	__u32 key = 0;
	__u32 *init_inum = bpf_map_lookup_elem(&init_net_ns, &key);
	if (!init_inum)
		return 0;

	struct task_struct *task = bpf_get_current_task_btf();
	__u32 cur_inum = task->nsproxy->net_ns->ns.inum;
	if (cur_inum == *init_inum)
		return 0;

	emit_event(BLOCK_REASON_UDP_ENCAP);
	return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
