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

#include "sanitizer_stoptheworld.h"
#include "sanitizer_placement_new.h"
#include "sanitizer_common.h"
#include "sanitizer_libc.h"

namespace __sanitizer {

typedef struct {
  tid_t tid;
  pthread_t thread;
} SuspendedThreadInfo;

class SuspendedThreadsListAIX final : public SuspendedThreadsList {
 public:
  SuspendedThreadsListAIX() = default;
  tid_t GetThreadID(uptr index) const override;
  pthread_t GetThread(uptr index) const;
  uptr ThreadCount() const override;
  bool ContainsThread(pthread_t thread) const;
  void Append(pthread_t thread, tid_t tid);

 private:
  InternalMmapVector<SuspendedThreadInfo> threads_;
};

static void EnumerateThreads(InternalMmapVector<pthread_t> *threads) {
  struct procsinfo proc_info;
  pid_t pid = getpid();

  getprocs(&proc_info, sizeof(proc_info), nullptr, 0, &pid, 1);
  int nthreads = proc_info.pi_thcount;
  InternalMmapVector<thrdsinfo> thrd_info(nthreads);

  int actual_threads = getthrds(pid, thrd_info.data(), sizeof(struct thrdsinfo), nullptr, nthreads);

  for (int i = 0; i < actual_threads; i++) {
    threads->push_back((pthread_t)thrd_info[i].ti_tid);
  }

}

struct RunThreadArgs {
  StopTheWorldCallback callback;
  void *argument;
};

void *RunThread(void *arg) {
  struct RunThreadArgs *run_args = (struct RunThreadArgs *)arg;
  SuspendedThreadsListAIX suspended_threads_list;
  InternalMmapVector<pthread_t> threads;

  EnumerateThreads(&threads);

  pthread_t thread_self = pthread_self();

  for (uptr i = 0; i < threads.size(); ++i) {
    if (threads[i] == thread_self) continue;

    pthread_suspend_np(threads[i]);
    suspended_threads_list.Append(threads[i], (tid_t)threads[i]);
  }

  run_args->callback(suspended_threads_list, run_args->argument);

  uptr num_suspended = suspended_threads_list.ThreadCount();
  for (unsigned int i = 0; i < num_suspended; ++i) {
    pthread_t thread = suspended_threads_list.GetThread(i);
    pthread_continue_np(thread);
  }
  return nullptr;
}

void StopTheWorld(StopTheWorldCallback callback, void *argument) {
  //SuspendedThreadsListAIX dummy;
  //callback(dummy, argument);
  struct RunThreadArgs arg = {callback, argument};
  pthread_t run_thread = (pthread_t)(reinterpret_cast<uptr>(internal_start_thread(RunThread, &arg)));
  internal_join_thread(&run_thread);
}

tid_t SuspendedThreadsListAIX::GetThreadID(uptr index) const {
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

void SuspendedThreadsListAIX::Append(pthread_t thread, tid_t tid) {
  threads_.push_back({tid, thread});
}

}  // namespace __sanitizer

#endif  // SANITIZER_AIX
