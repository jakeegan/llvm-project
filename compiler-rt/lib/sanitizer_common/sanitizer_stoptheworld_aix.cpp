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
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/pthdebug.h>

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

#ifndef __WALL
#define __WALL 0x40000000
#endif

#ifndef PT_READ_GPR
#define PT_READ_GPR 20
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
    SuspendedThreadsListAIX suspended_threads_list_;
    pid_t pid_;
};

void ThreadSuspender::ResumeAllThreads() {
  int pterrno;
  if (!internal_iserror(internal_ptrace(PT_DETACH, pid_, (void *)(uptr)1, 0), &pterrno)) {
    VReport(2, "Detached from process %d.\n", pid_);
  } else {
    VReport(1, "Could not detach from process %d (errno %d).\n", pid_, pterrno);
  }
}

void ThreadSuspender::KillAllThreads() {
  internal_ptrace(PT_KILL, pid_, nullptr, 0);
}

bool ThreadSuspender::SuspendAllThreads() {
  int pterrno;
  if (internal_iserror(internal_ptrace(PT_ATTACH, pid_, nullptr, 0), &pterrno)) {
    VReport(1, "Could not attach to process %d (errno %d).\n", pid_, pterrno);
  }

  int status;
  uptr waitpid_status;
  HANDLE_EINTR(waitpid_status, internal_waitpid(pid_, &status, 0));

  VReport(2, "Attached to process %d.\n", pid_);

  struct __pthrdsinfo pinfo;
  char regbuf[256];
  int regbufsize = sizeof(regbuf);
  pthread_t pthread_id = 0;

  while(pthread_getthrds_np(&pthread_id, PTHRDSINFO_QUERY_ALL, &pinfo, sizeof(pinfo), regbuf,
      &regbufsize) == 0) {
    suspended_threads_list_.Append(pinfo.__pi_tid);
    if (pthread_id == 0) break;
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
    atomic_store(&inst->arg->done, 1, memory_order_relaxed);
  }
  internal__exit((signum == SIGABRT) ? 1 : 2);
}

static const int kHandlerStackSize = 8192;

static int TracerThread(void* argument) {
  TracerThreadArgument *tracer_thread_argument = (TracerThreadArgument *)argument;

  if (internal_getppid() != tracer_thread_argument->parent_pid)
    internal__exit(4);

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

  for (uptr i = 0; i < ARRAY_SIZE(kSyncSignals); i++) {
    __sanitizer_sigaction act;
    internal_memset(&act, 0 , sizeof(act));
    act.sigaction = TracerThreadSignalHandler;
    act.sa_flags = SA_ONSTACK | SA_SIGINFO;
    internal_sigaction_norestorer(kSyncSignals[i], &act, 0);
  }

  int exit_code = 0;
  if (!thread_suspender.SuspendAllThreads()) {
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
  struct TracerThreadArgument tracer_thread_argument;
  tracer_thread_argument.callback = callback;
  tracer_thread_argument.callback_argument = argument;
  tracer_thread_argument.parent_pid = internal_getpid();
  atomic_store(&tracer_thread_argument.done, 0, memory_order_relaxed);
  const uptr kTracerStackSize = 2 * 1024 * 1024;
  ScopedStackSpaceWithGuard tracer_stack(kTracerStackSize);

  tracer_thread_argument.mutex.Lock();

  internal_sigfillset(&blocked_sigset);
  for (uptr i = 0; i < ARRAY_SIZE(kSyncSignals); i++)
    internal_sigdelset(&blocked_sigset, kSyncSignals[i]);
  int rv = internal_sigprocmask(SIG_BLOCK, &blocked_sigset, &old_sigset);
  CHECK_EQ(rv, 0);
  uptr tracer_pid = internal_fork();
  if (tracer_pid == 0) {
    internal__exit(TracerThread(&tracer_thread_argument));
  }
  internal_sigprocmask(SIG_SETMASK, &old_sigset, 0);
  int local_errno = 0;
  if (internal_iserror(tracer_pid, &local_errno)) {
    tracer_thread_argument.mutex.Unlock();
  } else {
    ScopedSetTracerPID scoped_set_tracer_pid(tracer_pid);
    tracer_thread_argument.mutex.Unlock();
    while (atomic_load(&tracer_thread_argument.done, memory_order_relaxed) == 0) 
      sched_yield();
    for (;;) {
      uptr waitpid_status = internal_waitpid(tracer_pid, nullptr, __WALL);
      if (!internal_iserror(waitpid_status, &local_errno))
        break;
      if (local_errno == EINTR)
        continue;
      break;
    }
  }
}

PtraceRegistersStatus SuspendedThreadsListAIX::GetRegistersAndSP(
    uptr index, InternalMmapVector<uptr> *buffer, uptr *sp) const {
  ThreadID tid = GetThreadID(index);
  pid_t target_pid = internal_getppid();

  struct {
    uptr gpr[32];
    uptr pc;
    uptr msr;
    uptr lr;
    uptr ctr;
    uptr xer;
    uptr cr;
  } aix_regs;

  int pterrno;

  internal_memset(&aix_regs, 0, sizeof(aix_regs));

  uptr stack_pointer;
  if (internal_iserror(internal_ptrace(PT_READ_GPR, target_pid, (void*)1, &tid), &pterrno)) {
    return pterrno == ESRCH ? REGISTERS_UNAVAILABLE_FATAL : REGISTERS_UNAVAILABLE;
  } else {
    stack_pointer = (uptr)internal_ptrace(PT_READ_GPR, target_pid, (void*)1, &tid);
    *sp = stack_pointer;
    aix_regs.gpr[1] = stack_pointer;
  }

  buffer->resize(RoundUpTo(sizeof(aix_regs), sizeof(uptr) / sizeof(uptr)));
  internal_memcpy(buffer->data(), &aix_regs, sizeof(aix_regs));
    
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
    if (thread_ids_[i] == thread_id)
      return true;
  }
  return false;
}

void SuspendedThreadsListAIX::Append(ThreadID tid) {
  thread_ids_.push_back(tid);
}

}  // namespace __sanitizer

#endif  // SANITIZER_AIX
