## Summary

This repo provides **zero-reboot BPF LSM mitigations** for Linux kernel
vulnerabilities:

**CVE-2026-31431** — CopyFail.  Privilege escalation via `algif_aead`.  An
attacker uses AF\_ALG sockets with the `authencesn` algorithm and `splice()` to
corrupt arbitrary files in the page cache (e.g. `/usr/bin/su`).

**CVE-2026-43284** — Dirty Frag (IPsec ESP).  Privilege escalation via
xfrm-ESP page-cache write paths.  Two attack vectors are blocked:
- **UDP MSG\_SPLICE\_PAGES** globally (splice-to-UDP primitive, kernel 6.4+)
- **UDP\_ENCAP** from non-init net namespaces (ESP-in-UDP from containers)

**CVE-2026-43500** — Dirty Frag (rxrpc).  Does not affect Red Hat products;
disabled by default.  Blocks:
- **AF\_RXRPC** socket creation globally (rxrpc/rxkad path)

**CVE-2026-46300** — Fragnesia (ESP-in-TCP).  Privilege escalation via
ESP-in-TCP page-cache write path.  Blocks:
- **TCP\_ULP "espintcp"** globally (kTLS `"tls"` is unaffected)

All mitigations are deployed as a single DaemonSet. By default the three CVEs
affecting Red Hat products are active (CVE-2026-43500 is excluded). Individual
mitigations can be toggled via the `MITIGATIONS` environment variable on the
DaemonSet.

## Quick Start

```bash
# 1. Verify BPF LSM is enabled (All versions of RHEL CoreOS enable this by default)
oc debug node/<any-node> -- chroot /host cat /sys/kernel/security/lsm
# Must contain "bpf"

# 2. Deploy the namespace and grant privileged SCC
oc apply -f daemonset.yaml

# 3. DaemonSet pods will start automatically on all nodes

# 4. Verify
oc get pods -n openshift-cve-mitigations     # All nodes should show Running
oc logs -n openshift-cve-mitigations -l app=kernel-ebpf-lsm-loader
# Expected: "mitigation-loader: active mitigations: CVE-2026-31431 CVE-2026-43284 CVE-2026-46300"
```

No reboots. No node drains. No pod restarts. Protection is immediate and
covers all processes on all nodes (100% coverage).

### Selecting Mitigations

By default the three CVEs affecting Red Hat products are enabled
(`MITIGATIONS=all`). To enable only specific mitigations, set the `MITIGATIONS`
environment variable to a comma-separated list of CVE numbers:

| Value              | What it enables                                           |
|--------------------|-----------------------------------------------------------|
| `all`              | CVE-2026-31431 + CVE-2026-43284 + CVE-2026-46300 (default) |
| `all-cves`         | All four CVEs including CVE-2026-43500                    |
| `CVE-2026-31431`   | CopyFail — AF\_ALG AEAD binds                            |
| `CVE-2026-43284`   | Dirty Frag (IPsec ESP) — UDP splice + UDP\_ENCAP         |
| `CVE-2026-43500`   | Dirty Frag (rxrpc) — AF\_RXRPC (not in `all`)            |
| `CVE-2026-46300`   | Fragnesia — TCP\_ULP "espintcp"                          |

Example — enable only CopyFail and Fragnesia:

```yaml
env:
- name: MITIGATIONS
  value: "CVE-2026-31431,CVE-2026-46300"
```

## Table of Contents

1. [How the Exploits Work](#how-the-exploits-work)
2. [Confirming Vulnerability on Your Cluster](#confirming-vulnerability-on-your-cluster)
3. [BPF LSM DaemonSet Deployment](#bpf-lsm-daemonset-deployment)
4. [Post-Deployment Verification](#post-deployment-verification)
5. [Building the Image from Source](#building-the-image-from-source)
6. [Removal](#removal)

---

## How the Exploits Work

### CVE-2026-31431 — CopyFail

The exploit chains three kernel features:

1. **AF\_ALG socket** — creates a userspace handle to kernel crypto via
   `socket(AF_ALG, SOCK_SEQPACKET, 0)`
2. **AEAD bind** — binds to `authencesn(hmac(sha256),cbc(aes))`, a specific
   authenticated encryption algorithm
3. **splice() + sendmsg()** — the kernel incorrectly performs an "in-place"
   operation where source and destination page mappings differ, corrupting the
   page cache of a read-only file

The attacker corrupts `/usr/bin/su` in the page cache (without write access to
the file), then executes it to gain root.

### CVE-2026-43284 — Dirty Frag (IPsec ESP)

Page-cache corruption through the kernel's IPsec/ESP network subsystem:

1. **UDP splice primitive** — MSG\_SPLICE\_PAGES on UDP sockets lets the ESP
   decryption engine overwrite page-cache pages in place (kernel 6.4+)
2. **ESP-in-UDP from containers** — `setsockopt(UDP_ENCAP)` configures UDP
   encapsulation for IPsec.  Blocked from non-init net namespaces (containers)
   while preserving host-level IPsec/VPN.

### CVE-2026-43500 — Dirty Frag (rxrpc)

Does not affect Red Hat products.  Disabled by default.

1. **rxrpc/rxkad path** — AF\_RXRPC sockets allow the rxkad security class to
   write into page-cache pages via the Rx protocol's large-packet reassembly

### CVE-2026-46300 — Fragnesia (ESP-in-TCP)

Page-cache corruption through ESP-in-TCP:

1. **ESP-in-TCP** — `setsockopt(TCP_ULP, "espintcp")` sets up ESP decryption
   on a TCP socket, enabling the same page-cache corruption.  Blocked globally;
   kTLS (`"tls"`) is unaffected.

---

## Confirming Vulnerability on Your Cluster

Create a new `cve-2026-31431-test` namespace on your cluster and run the test script by appling the manifests in [the `test` directory](test):

```bash
oc apply -f test
```

Check the results:

```bash
oc wait pod/cve-test -n cve-2026-31431-test \
  --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s
oc -n cve-2026-31431-test logs -l app=cve-2026-31431-test
```

**On a vulnerable cluster** you will see:

```
=== CVE-2026-31431 Vulnerability Test ===
Target: /usr/bin/su

Original SHA256: 8969560ae8e6e21c6184c1451f59418822ee69dd5d946d71987b55236bbc0feb
Attempting splice + AF_ALG page-cache corruption (160 bytes in 40 chunks)...
After SHA256:    30b0f5b5a054c4df65b48ca792863bf7054b4d793f15f57163792ba6c2b151ae

PAGE CACHE CORRUPTION: YES - /usr/bin/su was modified in the page cache

Attempting to execute corrupted /usr/bin/su ...
  exit code: 0

RESULT: PARTIALLY MITIGATED
  Page-cache corruption succeeded (kernel is vulnerable)
  Privilege escalation blocked (allowPrivilegeEscalation=false)
```

### Step 4: Clean up

```bash
oc delete namespace cve-2026-31431-test
```

---

## BPF LSM DaemonSet Deployment

The BPF LSM approach hooks `socket_bind`, `socket_create`, `socket_sendmsg`,
and `socket_setsockopt` at the kernel level to block the attack primitives used
by CVE-2026-31431, CVE-2026-43284, CVE-2026-43500 (disabled by default),
and CVE-2026-46300. Based on
[block-copyfail](https://github.com/atgreen/block-copyfail) and
[block-dirtyfrag](https://github.com/mrunalp/block-dirtyfrag), rewritten in C
with libbpf for OCP deployment.

### Prerequisites

BPF LSM must be enabled. RHEL CoreOS 9.8 (OCP 4.22) has it enabled by default.
Verify with:

```bash
oc debug node/<any-node> -- chroot /host cat /sys/kernel/security/lsm
```

Expected output includes `bpf`:

```
lockdown,capability,landlock,yama,selinux,bpf
```

If `bpf` is **not** present, a one-time MachineConfig is needed (this is the
only scenario requiring a reboot):

```yaml
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  labels:
    machineconfiguration.openshift.io/role: worker
  name: 99-enable-bpf-lsm
spec:
  kernelArguments:
    - lsm=lockdown,capability,selinux,bpf
```

### Step 1: Create the namespace, grant the SCC, and deploy

Create a new `openshift-cve-mitigations` namespace, grant SCC, and deploy the DaemonSet by applying [the `daemonset.yaml` manifest](daemonset.yaml).
The privileged SCC must be granted before the DaemonSet pods are created,
otherwise pod creation will fail with SCC validation errors.

```bash
oc apply -f daemonset.yaml
```

### Step 2: Wait for pods to start on all nodes

```bash
oc get pods -n openshift-cve-mitigations -o wide
```

Expected: one pod per node, all `Running`:

```
NAME                   READY   STATUS    AGE   NODE
kernel-ebpf-lsm-loader-2jhzf   1/1     Running   34s   ci-...-master-2
kernel-ebpf-lsm-loader-4dfq7   1/1     Running   34s   ci-...-master-1
kernel-ebpf-lsm-loader-c2ts8   1/1     Running   34s   ci-...-worker-c
kernel-ebpf-lsm-loader-ctblk   1/1     Running   34s   ci-...-worker-a
kernel-ebpf-lsm-loader-m26sx   1/1     Running   34s   ci-...-worker-b
kernel-ebpf-lsm-loader-xsh6d   1/1     Running   34s   ci-...-master-0
```

### Step 3: Verify the blocker is active

```bash
oc logs -n openshift-cve-mitigations -l app=kernel-ebpf-lsm-loader
```

Expected:

```
mitigation-loader: init net namespace inum=4026531840
mitigation-loader: active mitigations: CVE-2026-31431 CVE-2026-43284 CVE-2026-46300
```

---

## Post-Deployment Verification

Re-run the same exploit test from the [Confirming Vulnerability](#confirming-vulnerability-on-your-cluster) section.

**After deploying the BPF LSM DaemonSet**, the output will be:

```
=== CVE-2026-31431 Vulnerability Test ===
Target: /usr/bin/su

Original SHA256: 30b0f5b5a054c4df65b48ca792863bf7054b4d793f15f57163792ba6c2b151ae
Attempting splice + AF_ALG page-cache corruption (160 bytes in 40 chunks)...
  AF_ALG bind failed: [Errno 1] Operation not permitted

RESULT: CANNOT TEST - AF_ALG or splice not available/permitted
```

The DaemonSet logs will show the blocked attempt:

```bash
oc logs -n openshift-cve-mitigations -l app=kernel-ebpf-lsm-loader
```

```
mitigation-loader: init net namespace inum=4026531840
mitigation-loader: active mitigations: CVE-2026-31431 CVE-2026-43284 CVE-2026-46300
mitigation-loader: BLOCKED CVE-2026-31431 AF_ALG AEAD bind pid=16777    comm=python3 time=2026-05-01 16:37:23
```

### Verifying Other Algorithms Are Unaffected

Run `verify-algos.py` on a node to confirm that all AEAD algorithms are blocked
while other AF\_ALG types (hash, skcipher) continue to work:

```bash
oc debug node/<any-node> -- chroot /host python3 -c "
import socket
tests = [
    ('aead',     'gcm(aes)'),
    ('aead',     'ccm(aes)'),
    ('aead',     'rfc4106(gcm(aes))'),
    ('hash',     'sha256'),
    ('skcipher', 'cbc(aes)'),
    ('aead',     'authencesn(hmac(sha256),cbc(aes))'),
]
for t, n in tests:
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    try:
        s.bind((t, n))
        print(f'  ALLOWED  {t}/{n}')
    except OSError as e:
        print(f'  BLOCKED  {t}/{n} -- {e}')
    finally:
        s.close()
"
```

Expected output:

```
  BLOCKED  aead/gcm(aes) -- [Errno 1] Operation not permitted
  BLOCKED  aead/ccm(aes) -- [Errno 1] Operation not permitted
  BLOCKED  aead/rfc4106(gcm(aes)) -- [Errno 1] Operation not permitted
  ALLOWED  hash/sha256
  ALLOWED  skcipher/cbc(aes)
  BLOCKED  aead/authencesn(hmac(sha256),cbc(aes)) -- [Errno 1] Operation not permitted
```

This confirms the BPF LSM blocks all AEAD binds while leaving other AF_ALG types functional.

---

## Building the Image from Source

```
mitigations.bpf.c        # BPF kernel programs (CVE-2026-31431 + CVE-2026-43284 + CVE-2026-43500 + CVE-2026-46300)
mitigations.c             # Userspace loader with MITIGATIONS env var parsing (accepts CVE numbers)
mitigations.h             # Shared event struct and block reason constants
Makefile                  # Build pipeline
Dockerfile                # Multi-stage build
daemonset.yaml            # Namespace + DaemonSet manifest
trigger-test.py           # Quick CopyFail validation script
```

Build and push:

```bash
podman build -t quay.io/<org>/mitigation-loader:latest .
podman push quay.io/<org>/mitigation-loader:latest
```

The Dockerfile uses a multi-stage build: Fedora with clang/bpftool/libbpf-devel
for compilation, UBI 9 minimal for the runtime image (~122 MB).

---

## Removal

Deleting the DaemonSet immediately removes the mitigation on all nodes:

```bash
oc delete -f daemonset.yaml
# or
oc delete namespace openshift-cve-mitigations
```

The BPF program detaches automatically when the loader process exits. No reboot
or pod restart is needed.
