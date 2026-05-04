#ifndef BLOCK_COPYFAIL_H
#define BLOCK_COPYFAIL_H

#ifndef __bpf__
#include <linux/types.h>
#endif

#define AF_ALG 38

struct block_event {
	__u32 pid;
	char  comm[16];
	__u32 _pad;
	__u64 ts;
};

#endif
