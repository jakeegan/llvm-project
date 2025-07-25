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

#include <pthread.h>
#include <procinfo.h>
#include <sys/types.h>
#include <errno.h>

#include "sanitizer_stoptheworld.h"
#include "sanitizer_placement_new.h"
#include "sanitizer_common.h"
#include "sanitizer_libc.h"

namespace __sanitizer {

typedef struct {
  ThreadID tid;
  pthread_t thread;
} SuspendedThreadInfo;

class SuspendedThreadsListAIX final : public SuspendedThreadsList {
 public:
  SuspendedThreadsListAIX() = default;
  ThreadID GetThreadID(uptr index) const override;
  pthread_t GetThread(uptr index) const;
  uptr ThreadCount() const override;
  bool ContainsThread(pthread_t thread) const;
  void Append(pthread_t thread, ThreadID tid);
  PtraceRegistersStatus GetRegistersAndSP(uptr index,
                                          InternalMmapVector<uptr> *buffer,
                                          uptr *sp) const override;

 private:
  InternalMmapVector<SuspendedThreadInfo> threads_;
};

static bool EnumerateThreads(InternalMmapVector<SuspendedThreadInfo> *threads) {
  struct __pthrdsinfo pinfo;
  char regbuf[256];
  int regbufsize = sizeof(regbuf);
  pthread_t pthread_id = 0;

  while (pthread_getthrds_np(&pthread_id, PTHRDSINFO_QUERY_ALL, &pinfo, sizeof(pinfo), regbuf,
    &regbufsize) == 0) {
    SuspendedThreadInfo info;
    info.thread = pthread_id;
    info.tid = pinfo.__pi_tid;
    threads->push_back(info);
    VReport(1, "LeakSanitizer: thread=%d, tid%d\n", info.thread, info.tid);
    if (pthread_id == 0) break;
  }

  if (threads->size() == 0) {
    VReport(1, "LeakSanitizer: No threads found.\n");
    return false;
  }

  return true;
}

struct RunThreadArgs {
  StopTheWorldCallback callback;
  void *argument;
};

void *RunThread(void *arg) {
  struct RunThreadArgs *run_args = (struct RunThreadArgs *)arg;
  SuspendedThreadsListAIX suspended_threads_list;
  InternalMmapVector<SuspendedThreadInfo> threads;

  if (!EnumerateThreads(&threads)) {
    VReport(1, "LeakSanitizer: Failed to enumerate threads\n");
    run_args->callback(suspended_threads_list, run_args->argument);
    return nullptr;
  }

  VReport(1, "LeakSanitizer: Enumerated %zu threads\n", threads.size());
  pthread_t thread_self = pthread_self();
  uptr successfully_suspended = 0;
  VReport(1, "LeakSanitizer: Current thread (RunThread) is %lu\n", (unsigned long)thread_self);

  for (uptr i = 0; i < threads.size(); ++i) {
    VReport(1, "LeakSanitizer: Found thread %lu (tid %lu)\n", (unsigned long)threads[i].thread,
    (unsigned long)threads[i].tid);
    if (threads[i].thread == thread_self) {
      VReport(1, "LeakSanitizer: Skipping current thread %lu\n", (unsigned long)thread_self);
      continue;
    }

    VReport(1, "LeakSanitizer: Attempting to suspend thread %lu\n", (unsigned long)threads[i].thread);

    int ret = pthread_suspend_np(threads[i].thread);
    if (ret != 0 ) { 
      VReport(1, "LeakSanitizer: Failed to suspend thread (thread=%d) with error %d\n",
      threads[i].thread, ret);
      continue;
    }
    suspended_threads_list.Append(threads[i].thread, (ThreadID)threads[i].tid);
    successfully_suspended++;
  }
  VReport(1, "LeakSanitizer: suspended %zu out of %zu threads\n", successfully_suspended,
  threads.size()-1);

  run_args->callback(suspended_threads_list, run_args->argument);

  uptr num_suspended = suspended_threads_list.ThreadCount();
  for (unsigned int i = 0; i < num_suspended; ++i) {
    pthread_t thread = suspended_threads_list.GetThread(i);
    int ret = pthread_continue_np(thread);
    if (ret != 0) {
      VReport(1, "LeakSanitizer: Failed to resume thread\n");
    }
  }
  return nullptr;
}

void StopTheWorld(StopTheWorldCallback callback, void *argument) {
  //SuspendedThreadsListAIX dummy;
  //callback(dummy, argument);
  struct RunThreadArgs arg = {callback, argument};
  void* run_thread = internal_start_thread(RunThread, &arg);
  internal_join_thread(run_thread);
}

PtraceRegistersStatus SuspendedThreadsListAIX::GetRegistersAndSP(
    uptr index, InternalMmapVector<uptr> *buffer, uptr *sp) const {

  CHECK_LT(index, threads_.size());
  pthread_t thread = threads_[index].thread;

  struct __pthrdsinfo pinfo;
  char regbuf[1024];
  int regbufsize = sizeof(regbuf);

  pthread_t search_thread = 0;
  while (pthread_getthrds_np(&search_thread, PTHRDSINFO_QUERY_ALL,
                             &pinfo, sizeof(pinfo), regbuf, &regbufsize) == 0) {
    if (search_thread == thread) break;
    if (search_thread == 0) break;
    regbufsize = sizeof(regbuf);
  }

  constexpr uptr uptr_sz = sizeof(uptr);

  if (regbufsize > 0 && (uptr)regbufsize <= sizeof(regbuf)) {
    uptr reg_words = RoundUpTo(regbufsize, uptr_sz) / uptr_sz;
    buffer->resize(reg_words);
  }

  internal_memcpy(buffer->data(), regbuf, regbufsize);

  if (pinfo.__pi_stackaddr && pinfo.__pi_stacksize) {
    uptr stack_base = (uptr)pinfo.__pi_stackaddr;
    uptr stack_size = (uptr)pinfo.__pi_stacksize;

    *sp = stack_base + (stack_size * 3) / 4;
  } else {
    return REGISTERS_UNAVAILABLE;
  }

  return REGISTERS_AVAILABLE;
}

ThreadID SuspendedThreadsListAIX::GetThreadID(uptr index) const {
  CHECK_LT(index, threads_.size());
  return threads_[index].tid;
}

pthread_t SuspendedThreadsListAIX::GetThread(uptr index) const {
  CHECK_LT(index, threads_.size());
  return threads_[index].thread;
}

uptr SuspendedThreadsListAIX::ThreadCount() const {
  return threads_.size();
}

bool SuspendedThreadsListAIX::ContainsThread(pthread_t thread) const {
  for (uptr i = 0; i < threads_.size(); i++) {
    if (threads_[i].thread == thread) return true;
  }
  return false;
}

void SuspendedThreadsListAIX::Append(pthread_t thread, ThreadID tid) {
  threads_.push_back({tid, thread});
}

}  // namespace __sanitizer

#endif  // SANITIZER_AIX
