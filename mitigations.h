#ifndef MITIGATIONS_H
#define MITIGATIONS_H

#ifndef __bpf__
#include <linux/types.h>
#endif

#define AF_ALG   38
#define AF_RXRPC 33

/* CVE-2026-31431 — CopyFail (AF_ALG AEAD) */
#define BLOCK_REASON_COPYFAIL    1

/* CVE-2026-43500 — Dirty Frag / rxrpc (does not affect Red Hat products) */
#define BLOCK_REASON_RXRPC       2

/* CVE-2026-43284 — Dirty Frag / IPsec ESP */
#define BLOCK_REASON_UDP_SPLICE  3
#define BLOCK_REASON_UDP_ENCAP   5

/* CVE-2026-46300 — Fragnesia / ESP-in-TCP */
#define BLOCK_REASON_ESPINTCP    4

struct block_event {
	__u32 pid;
	char  comm[16];
	__u32 reason;
	__u64 ts;
};

#endif
