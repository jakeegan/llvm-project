//===-- sanitizer_stoptheworld_aix.cpp ------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// See sanitizer_stoptheworld.h for details.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_AIX

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/pthdebug.h>
#include <sys/procfs.h>
#include <sys/reg.h>

#include "sanitizer_stoptheworld.h"
#include "sanitizer_atomic.h"
#include "sanitizer_platform_limits_posix.h"
#include "sanitizer_aix.h"
#include "sanitizer_posix.h"
#include "sanitizer_placement_new.h"
#include "sanitizer_common.h"
#include "sanitizer_libc.h"
#include "sanitizer_flags.h"
#include "sanitizer_mutex.h"

#include <procinfo.h>

#define NUM_GPRS 32

#if SANITIZER_WORDSIZE == 32
#define PTRACE_ADDR_CAST(addr) ((int *)(addr))
#define GETTHRDS_CALL(pid, buf, index, count) \
  getthrds(pid, buf, sizeof(thrdsinfo), index, count)
#define THRDS_STRUCT struct thrdsinfo
#define TID_TYPE tid_t
#define GPRS_BUFFER_SIZE 128
#define GPR_TYPE u32
#else
#define PTRACE_ADDR_CAST(addr) ((long long)(addr))
#define GETTHRDS_CALL(pid, buf, index, count) \
  getthrds64(pid, buf, sizeof(struct thrdentry64), index, count)
#define THRDS_STRUCT struct thrdentry64
#define TID_TYPE tid64_t
#define GPRS_BUFFER_SIZE 256
#define GPR_TYPE u64
#endif

#define internal_sigaction_norestorer internal_sigaction

namespace __sanitizer {

class SuspendedThreadsListAIX final : public SuspendedThreadsList {
 public:
  SuspendedThreadsListAIX() { thread_ids_.reserve(1024); }
  ThreadID GetThreadID(uptr index) const override;
  uptr ThreadCount() const override;
  bool ContainsTid(ThreadID thread_id) const;
  void Append(ThreadID tid);
  PtraceRegistersStatus GetRegistersAndSP(uptr index,
                                          InternalMmapVector<uptr> *buffer,
                                          uptr *sp) const override;

 private:
  InternalMmapVector<ThreadID> thread_ids_;
};

struct TracerThreadArgument {
  StopTheWorldCallback callback;
  void *callback_argument;
  Mutex mutex;
  atomic_uintptr_t done;
  uptr parent_pid;
};

class ThreadSuspender {
  public:
    explicit ThreadSuspender(pid_t pid, TracerThreadArgument *arg) : arg(arg), pid_(pid) {
      CHECK_GE(pid, 0);
    }
  bool SuspendAllThreads();
  void ResumeAllThreads();
  void KillAllThreads();
  SuspendedThreadsListAIX &suspended_threads_list() {
    return suspended_threads_list_;
  }
  TracerThreadArgument *arg;

  private:
    void EnumerateThreads();
    SuspendedThreadsListAIX suspended_threads_list_;
    pid_t pid_;
};

void ThreadSuspender::ResumeAllThreads() {
  int pterrno;
  int reg_buffer;
  if (!internal_iserror(internal_ptrace(PT_DETACH, pid_, PTRACE_ADDR_CAST(1), 0, &reg_buffer),
                                       &pterrno)) {
    VReport(2, "Detached from process %d.\n", pid_);
  } else {
    VReport(1, "Could not detatch from process %d (errno %d).\n", pid_, pterrno);
  }
}

void ThreadSuspender::KillAllThreads() {
  internal_ptrace(PT_KILL, pid_, PTRACE_ADDR_CAST(nullptr), 0, nullptr);
}

bool ThreadSuspender::SuspendAllThreads() {
  int pterrno;
  int reg_buffer;
  if (internal_iserror(internal_ptrace(PT_ATTACH, pid_, PTRACE_ADDR_CAST(nullptr), 0, &reg_buffer),
      &pterrno)) {
    VReport(1, "Could not attach to process %d (errno %d)\n", pid_, pterrno);
    return false;
  }

  int status;
  uptr waitpid_status;
  HANDLE_EINTR(waitpid_status, internal_waitpid(pid_, &status, 0));

  VReport(2, "Attached to process %d.\n", pid_);

  const int kMaxThreadsPerCall = 256;
  THRDS_STRUCT thread_info[kMaxThreadsPerCall];
  TID_TYPE index = 0;
  int count;

  while ((count = GETTHRDS_CALL(pid_, thread_info, &index, kMaxThreadsPerCall)) > 0) {
    for (int i = 0; i < count; i++) {
      TID_TYPE tid = thread_info[i].ti_tid;
      suspended_threads_list_.Append(tid);
      VReport(2, "Appended thread %d in process %d.\n", tid, pid_);
    }
    if (count < kMaxThreadsPerCall) break;
  }

  return true;
}


static ThreadSuspender *thread_suspender_instance = nullptr;

static const int kSyncSignals[] = {SIGABRT, SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGXCPU, SIGXFSZ};


static void TracerThreadDieCallback() {
  ThreadSuspender *inst = thread_suspender_instance;
  if (inst && stoptheworld_tracer_pid == internal_getpid()) {
    inst->KillAllThreads();
    thread_suspender_instance = nullptr;
  }
}

static void TracerThreadSignalHandler(int signum, __sanitizer_siginfo *siginfo, void *uctx) {
  SignalContext ctx(siginfo, uctx);
  ThreadSuspender *inst = thread_suspender_instance;
  if (inst) {
    if (signum == SIGABRT)
      inst->KillAllThreads();
    else
      inst->ResumeAllThreads();
    RAW_CHECK(RemoveDieCallback(TracerThreadDieCallback));
    thread_suspender_instance = nullptr;
    atomic_store(&inst->arg->done, 1, memory_order_release);
  }
  internal__exit((signum == SIGABRT) ? 1 : 2);
}

static const int kHandlerStackSize = 8192;

static int TracerThread(void* argument) {
  TracerThreadArgument *tracer_thread_argument = (TracerThreadArgument *)argument;

  if (internal_getppid() != tracer_thread_argument->parent_pid)
    internal__exit(4);

  // Wait for parent thread to finish preparations.
  tracer_thread_argument->mutex.Lock();
  tracer_thread_argument->mutex.Unlock();

  RAW_CHECK(AddDieCallback(TracerThreadDieCallback));

  ThreadSuspender thread_suspender(internal_getppid(), tracer_thread_argument);
  thread_suspender_instance = &thread_suspender;

  InternalMmapVector<char> handler_stack_memory(kHandlerStackSize);
  stack_t handler_stack;
  internal_memset(&handler_stack, 0, sizeof(handler_stack));
  handler_stack.ss_sp = handler_stack_memory.data();
  handler_stack.ss_size = kHandlerStackSize;
  internal_sigaltstack(&handler_stack, nullptr);

  // Install our handler for synchronous signals. Other signals should be
  // blocked by the mask we inherited from the parent thread.
  for (uptr i = 0; i < ARRAY_SIZE(kSyncSignals); i++) {
    __sanitizer_sigaction act;
    internal_memset(&act, 0 , sizeof(act));
    act.sigaction = TracerThreadSignalHandler;
    act.sa_flags = SA_ONSTACK | SA_SIGINFO;
    internal_sigaction_norestorer(kSyncSignals[i], &act, 0);
  }

  int exit_code = 0;
  if (!thread_suspender.SuspendAllThreads()) {
    VReport(1, "Failed suspending threads.\n");
    exit_code = 3;
  } else {
    tracer_thread_argument->callback(thread_suspender.suspended_threads_list(),
                                      tracer_thread_argument->callback_argument);
    thread_suspender.ResumeAllThreads();
    exit_code = 0;
  }
  RAW_CHECK(RemoveDieCallback(TracerThreadDieCallback));
  thread_suspender_instance = nullptr;
  atomic_store(&tracer_thread_argument->done, 1, memory_order_relaxed);
  return exit_code;
}

static __sanitizer_sigset_t blocked_sigset;
static __sanitizer_sigset_t old_sigset;

struct ScopedSetTracerPID {
  explicit ScopedSetTracerPID(uptr tracer_pid) {
    stoptheworld_tracer_pid = tracer_pid;
    stoptheworld_tracer_ppid = internal_getpid();
  }
  ~ScopedSetTracerPID() {
    stoptheworld_tracer_pid = 0;
    stoptheworld_tracer_ppid = 0;
  }
};

void StopTheWorld(StopTheWorldCallback callback, void *argument) {
  // Have to use shared memory here for cross process communication.
  struct TracerThreadArgument *tracer_thread_argument =
    (struct TracerThreadArgument *)internal_mmap(nullptr, sizeof(struct TracerThreadArgument),        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  new (tracer_thread_argument) TracerThreadArgument();

  tracer_thread_argument->callback = callback;
  tracer_thread_argument->callback_argument = argument;
  tracer_thread_argument->parent_pid = internal_getpid();
  atomic_store(&tracer_thread_argument->done, 0, memory_order_relaxed);

  tracer_thread_argument->mutex.Lock();

  internal_sigfillset(&blocked_sigset);
  for (uptr i = 0; i < ARRAY_SIZE(kSyncSignals); i++)
    internal_sigdelset(&blocked_sigset, kSyncSignals[i]);
  int rv = internal_sigprocmask(SIG_BLOCK, &blocked_sigset, &old_sigset);
  CHECK_EQ(rv, 0);
  uptr tracer_pid = internal_fork();
  if (tracer_pid == 0) {
    VReport(2, "In tracer process, calling TracerThread.\n");
    internal__exit(TracerThread(tracer_thread_argument));
  }
  VReport(2, "Tracer forked with PID %lu.\n", tracer_pid);
  internal_sigprocmask(SIG_SETMASK, &old_sigset, 0);
  int local_errno = 0;
  if (internal_iserror(tracer_pid, &local_errno)) {
    VReport(1, "Failed spawning a tracer thread (errno %d).\n", local_errno);
    tracer_thread_argument->mutex.Unlock();
  } else {
    ScopedSetTracerPID scoped_set_tracer_pid(tracer_pid);
    tracer_thread_argument->mutex.Unlock();
    while (atomic_load(&tracer_thread_argument->done, memory_order_relaxed) == 0)
      sched_yield();
    for (;;) {
      uptr waitpid_status = internal_waitpid(tracer_pid, nullptr, 0);
      if (!internal_iserror(waitpid_status, &local_errno)) break;
      if (local_errno == EINTR) continue;
      VReport(1, "Waiting on the tracer thread failed (errno %d).\n", local_errno);
      break;
    }
  }
  tracer_thread_argument->~TracerThreadArgument();
  internal_munmap(tracer_thread_argument, sizeof(struct TracerThreadArgument));
}

PtraceRegistersStatus SuspendedThreadsListAIX::GetRegistersAndSP(
    uptr index, InternalMmapVector<uptr> *buffer, uptr *sp) const {
  CHECK_LT(index, thread_ids_.size());
  ThreadID tid = thread_ids_[index];
  buffer->resize(RoundUpTo(GPRS_BUFFER_SIZE, sizeof(uptr)) / sizeof(uptr));
  int pterrno;

  if (internal_iserror(internal_ptrace(PTT_READ_GPRS, tid,
    PTRACE_ADDR_CAST(buffer->data()), 0,
    nullptr), &pterrno)) {
    VReport(1, "Could not get registers from thread %d (errno %d)\n", tid, pterrno);
    return pterrno == ESRCH ? REGISTERS_UNAVAILABLE_FATAL : REGISTERS_UNAVAILABLE;
  }

  GPR_TYPE *gprs = reinterpret_cast<GPR_TYPE*>(buffer->data());
  *sp = (uptr)gprs[GPR1];

  return REGISTERS_AVAILABLE;
}
 

ThreadID SuspendedThreadsListAIX::GetThreadID(uptr index) const {
  CHECK_LT(index, thread_ids_.size());
  return thread_ids_[index];
}

uptr SuspendedThreadsListAIX::ThreadCount() const {
  return thread_ids_.size();
}

bool SuspendedThreadsListAIX::ContainsTid(ThreadID thread_id) const {
  for (uptr i = 0; i < thread_ids_.size(); i++) {
    if (thread_ids_[i] == thread_id) {
      return true;
    }
  }
  return false;
}

void SuspendedThreadsListAIX::Append(ThreadID tid) {
  thread_ids_.push_back(tid);
}

}  // namespace __sanitizer

#endif  // SANITIZER_AIX
