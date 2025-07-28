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
#define PTRACE_NULL_ADDR ((int *)nullptr)
#define GETTHRDS_CALL(pid, buf, index, count) \
  getthrds(pid, buf, sizeof(thrdsinfo), index, count)
#define THRDS_STRUCT struct thrdsinfo
#define TID_TYPE tid_t
#define GPRS_BUFFER_SIZE 128
#define GPR_TYPE u32
#else
#define PTRACE_ADDR_CAST(addr) ((long long)(addr))
#define PTRACE_NULL_ADDR (0LL)
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
  Mutex mutex = Mutex(MutexUnchecked);
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
    bool EnumerateThreads();
    SuspendedThreadsListAIX suspended_threads_list_;
    pid_t pid_;
};

bool ThreadSuspender::EnumerateThreads() {
  const int kMaxThreads = 1024;
  THRDS_STRUCT thread_info[kMaxThreads];
  TID_TYPE index = 0;
  int count;

  // Should update this to be called in a loop instead
  count = GETTHRDS_CALL(pid_, thread_info, &index, kMaxThreads);

  bool all_threads_stopped = true;
  for (int i = 0; i < count; i++) {
    TID_TYPE tid = thread_info[i].ti_tid;
    suspended_threads_list_.Append(tid);

    if (thread_info[i].ti_state == 1 || thread_info[i].ti_state == 2 ) {
      VReport(1, "EnumerateThreads: Thread %lu not stopped\n", tid);
    } else {
      VReport(1, "EnumerateThreads: Thread %lu is in state %d\n", tid, thread_info[i].ti_state);
    }
  }

  if (!all_threads_stopped) {
    VReport(1, "EnumerateThreads: Not all threads suspended\n");
  }

  VReport(1, "EnumerateThreads: thread count = %d\n", suspended_threads_list_.ThreadCount());
  return suspended_threads_list_.ThreadCount() > 0;
}

void ThreadSuspender::ResumeAllThreads() {
  int pterrno;
  int reg_buffer;
    if (!internal_iserror(internal_ptrace(PT_DETACH, pid_, PTRACE_ADDR_CAST(1), 0, &reg_buffer),
                                          &pterrno)) {
      VReport(1, "ResumeAllThreads: Detached from process %d\n", pid_);
    } else {
      VReport(1, "ResumeAllThreads: Could not detatch from process %d (errno %d)\n", pid_, pterrno);
    }
}

void ThreadSuspender::KillAllThreads() {
  for (uptr i = 0; i < suspended_threads_list_.ThreadCount(); i++) {
    ThreadID tid = suspended_threads_list_.GetThreadID(i);
    internal_ptrace(PT_KILL, tid, PTRACE_NULL_ADDR, 0, nullptr);
  }
}

bool ThreadSuspender::SuspendAllThreads() {
  int pterrno;
  int reg_buffer;
  if (internal_iserror(internal_ptrace(PT_ATTACH, pid_, PTRACE_NULL_ADDR, 0, &reg_buffer),
      &pterrno)) {
    VReport(1, "SuspendAllThreads:Could not attach to process %d (errno %d)\n", pid_, pterrno);
    return false;
  }
  VReport(1, "SuspendAllThreads: Attached to process %d\n", pid_);

  int status;
  uptr waitpid_status;
  HANDLE_EINTR(waitpid_status, internal_waitpid(pid_, &status, 0));

  if (internal_iserror(waitpid_status, &pterrno)) {
    VReport(1, "SuspendAllThreads: waitpid failed process %d (errno %d)\n", pid_, pterrno);
    internal_ptrace(PT_DETACH, pid_, PTRACE_ADDR_CAST(1), 0, &reg_buffer);
    return false;
  }

  if (!WIFSTOPPED(status)) {
    VReport(1, "SuspendAllThreads: Process %d did not stop after attach (status %d)\n", pid_, status);
    internal_ptrace(PT_DETACH, pid_, PTRACE_ADDR_CAST(1), 0, &reg_buffer);
    return false;
  }

  if (!EnumerateThreads()) {
    return false;
  }
  VReport(1, "SuspendAllThreads: Success\n");
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
  VReport(1, "TracerThread: starting\n");
  TracerThreadArgument *tracer_thread_argument = (TracerThreadArgument *)argument;

  VReport(1, "TracerThread: checking parent pid\n");
  if (internal_getppid() != tracer_thread_argument->parent_pid)
    internal__exit(4);

  tracer_thread_argument->mutex.~Mutex();
  new (&tracer_thread_argument->mutex) Mutex(MutexUnchecked);

  VReport(1, "TrackerThread: Waiting for mutex\n");
  tracer_thread_argument->mutex.Lock();
  tracer_thread_argument->mutex.Unlock();

  VReport(1, "TracerThread: Adding die callback\n");
  RAW_CHECK(AddDieCallback(TracerThreadDieCallback));

  VReport(1, "TracerThread: Creating ThreadSuspender\n");
  ThreadSuspender thread_suspender(internal_getppid(), tracer_thread_argument);
  thread_suspender_instance = &thread_suspender;

  VReport(1, "TracerThread: Setting up signal stack\n");
  InternalMmapVector<char> handler_stack_memory(kHandlerStackSize);

  stack_t handler_stack;
  internal_memset(&handler_stack, 0, sizeof(handler_stack));
  handler_stack.ss_sp = handler_stack_memory.data();
  handler_stack.ss_size = kHandlerStackSize;
  internal_sigaltstack(&handler_stack, nullptr);

  VReport(1, "TracerThread: Installing signal handlers\n");
  for (uptr i = 0; i < ARRAY_SIZE(kSyncSignals); i++) {
    __sanitizer_sigaction act;
    internal_memset(&act, 0 , sizeof(act));
    act.sigaction = TracerThreadSignalHandler;
    act.sa_flags = SA_ONSTACK | SA_SIGINFO;
    internal_sigaction_norestorer(kSyncSignals[i], &act, 0);
  }

  VReport(1, "TracerThread: About to call SuspendAllThreads\n");
  int exit_code = 0;
  if (!thread_suspender.SuspendAllThreads()) {
    VReport(1, "TracerThread: SuspendAllThreads failed\n");
    exit_code = 3;
  } else {
    VReport(1, "TracerThread: SuspendAllThreads succeeded\n");
    const SuspendedThreadsList &suspended_list = thread_suspender.suspended_threads_list();
    VReport(1, "TracerThread: passing %lu suspended threads to callback\n",
    suspended_list.ThreadCount());
    tracer_thread_argument->callback(thread_suspender.suspended_threads_list(),
                                      tracer_thread_argument->callback_argument);
    VReport(1, "TracerThread: Callback complete\n");
    thread_suspender.ResumeAllThreads();
    VReport(1, "TracerThread: Threads resumed.\n");
    exit_code = 0;
  }
  VReport(1, "TracerThread: Cleaning die callback\n");
  RAW_CHECK(RemoveDieCallback(TracerThreadDieCallback));
  thread_suspender_instance = nullptr;
  VReport(1, "TracerThread: Setting done flag\n");
  atomic_store(&tracer_thread_argument->done, 1, memory_order_release);
  return exit_code;
}

class ScopedStackSpaceWithGuard {
  public:
    explicit ScopedStackSpaceWithGuard(uptr stack_size) {
      stack_size_ = stack_size;
      guard_size_ = GetPageSizeCached();
      guard_start_ = (uptr)MmapOrDie(stack_size_ + guard_size_, "ScopedStackWithGuard");
      CHECK(MprotectNoAccess((uptr)guard_start_, guard_size_));
  }
  ~ScopedStackSpaceWithGuard() {
    UnmapOrDie((void *)guard_start_, stack_size_ + guard_size_);
  }
  void *Bottom() const {
    return (void *)(guard_start_ + stack_size_ + guard_size_);
  }

  private:
    uptr stack_size_;
    uptr guard_size_;
    uptr guard_start_;
};

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
  //SuspendedThreadsListAIX dummy;
  //callback(dummy, argument);
  //return;
  VReport(1, "LeakSanitizer: Stopping the world.\n");
  struct TracerThreadArgument *tracer_thread_argument =
    (struct TracerThreadArgument *)internal_mmap(nullptr, sizeof(struct TracerThreadArgument),        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  new (tracer_thread_argument) TracerThreadArgument();

  tracer_thread_argument->callback = callback;
  tracer_thread_argument->callback_argument = argument;
  tracer_thread_argument->parent_pid = internal_getpid();
  atomic_store(&tracer_thread_argument->done, 0, memory_order_relaxed);
  const uptr kTracerStackSize = 2 * 1024 * 1024;
  ScopedStackSpaceWithGuard tracer_stack(kTracerStackSize);

  tracer_thread_argument->mutex.Lock();

  internal_sigfillset(&blocked_sigset);
  for (uptr i = 0; i < ARRAY_SIZE(kSyncSignals); i++)
    internal_sigdelset(&blocked_sigset, kSyncSignals[i]);
  int rv = internal_sigprocmask(SIG_BLOCK, &blocked_sigset, &old_sigset);
  CHECK_EQ(rv, 0);
  VReport(1, "StopTheWorld: Forking tracer process.\n");
  uptr tracer_pid = internal_fork();
  if (tracer_pid == 0) {
    VReport(1, "StopTheWorld: In tracer process, calling TracerThread.\n");
    internal__exit(TracerThread(tracer_thread_argument));
  }
  VReport(1, "StopTheWorld: Tracer forked with PID %lu.\n", tracer_pid);
  internal_sigprocmask(SIG_SETMASK, &old_sigset, 0);
  int local_errno = 0;
  if (internal_iserror(tracer_pid, &local_errno)) {
    VReport(1, "StopTheWorld: Fork failed with errno %d\n", local_errno);
    tracer_thread_argument->mutex.Unlock();
  } else {
    ScopedSetTracerPID scoped_set_tracer_pid(tracer_pid);
    tracer_thread_argument->mutex.Unlock();
    VReport(1, "StopTheWorld: Waiting for tracer to complete\n");
    uptr wait_iterations = 0;
    while (atomic_load(&tracer_thread_argument->done, memory_order_acquire) == 0) {
      wait_iterations++;
      if (wait_iterations % 10000 == 0) {
        VReport(1, "StopTheWorld: Waiting ... (iteration %lu)\n", wait_iterations);
      }
      sched_yield();
    }
    VReport(1, "StopTheWorld: Waiting for tracer process %lu to exit\n", tracer_pid);
    for (;;) {
      uptr waitpid_status = internal_waitpid(tracer_pid, nullptr, 0);
      if (!internal_iserror(waitpid_status, &local_errno)) {
        VReport(1, "StopTheWorld: Tracer process exited sucessfully\n");
        break;
      }
      if (local_errno == EINTR) {
        VReport(1, "StopTheWorld: waitpid interrupted\n");
        continue;
      }
      VReport(1, "StopTheWorld: waitpid failed with errno %d\n", local_errno);
      break;
    }
  }
  VReport(1, "StopTheWorld: Complete.\n");

  tracer_thread_argument->~TracerThreadArgument();
  internal_munmap(tracer_thread_argument, sizeof(struct TracerThreadArgument));
}

PtraceRegistersStatus SuspendedThreadsListAIX::GetRegistersAndSP(
    uptr index, InternalMmapVector<uptr> *buffer, uptr *sp) const {
  CHECK_LT(index, thread_ids_.size());
  ThreadID tid = thread_ids_[index];

  int pterrno;

  char gprs_raw_buffer[GPRS_BUFFER_SIZE];

  if (internal_iserror(internal_ptrace(PTT_READ_GPRS, tid, PTRACE_ADDR_CAST(gprs_raw_buffer), 0,
    nullptr), &pterrno)) {
    VReport(1, "Failed to read GPRs for thread %lu (errno %d)\n", tid, pterrno);
    return pterrno == ESRCH ? REGISTERS_UNAVAILABLE_FATAL : REGISTERS_UNAVAILABLE;
  }

  GPR_TYPE *gprs = (GPR_TYPE*)gprs_raw_buffer;
  *sp = (uptr)gprs[GPR1];

  VReport(1, "First 4 GPRS for thread %lu: 0x%lx 0x%lx 0x%lx 0x%lx\n", tid, (uptr)gprs[0],
  (uptr)gprs[1], (uptr)gprs[2], (uptr)gprs[3]);

  buffer->resize(RoundUpTo(GPRS_BUFFER_SIZE, sizeof(uptr)) / sizeof(uptr));
  internal_memcpy(buffer->data(), gprs_raw_buffer, GPRS_BUFFER_SIZE);
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
  VReport(1, "ContainsTid: called for thread %lu\n", thread_id);
  for (uptr i = 0; i < thread_ids_.size(); i++) {
    if (thread_ids_[i] == thread_id) {
      VReport(1, "ContainsTid: found thread %lu at index %lu\n", thread_id, i);
      return true;
    }
  }
  VReport(1, "ContainsTid: Thread %lu not found\n", thread_id);
  return false;
}

void SuspendedThreadsListAIX::Append(ThreadID tid) {
  thread_ids_.push_back(tid);
}

}  // namespace __sanitizer

#endif  // SANITIZER_AIX
