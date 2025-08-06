//=-- lsan_common_aix.cpp ------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------===//
//
// This file is a part of LeakSanitizer.
// Implementation of common leak checking functionality. AIX-specific code.
//
//===---------------------------------------------------------------------===//

#include "lsan_common.h"
#include "sanitizer_common/sanitizer_platform.h"

#if CAN_SANITIZE_LEAKS && SANITIZER_AIX

#include <sys/mman.h>

#include "lsan_allocator.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_posix.h"
#include "sanitizer_common/sanitizer_placement_new.h"
#include "sanitizer_common/sanitizer_thread_registry.h"
#include "sanitizer_common/sanitizer_procmaps.h"
#include "sanitizer_common/sanitizer_file.h"

namespace __lsan {

void InitializePlatformSpecificModules() {}

__attribute__((tls_model("initial-exec"))) THREADLOCAL int disable_counter;
bool DisabledInThisThread() { return disable_counter > 0; }
void DisableInThisThread() { disable_counter++; }
void EnableInThisThread() {
  if (disable_counter == 0) {
    DisableCounterUnderflow();
  }
  disable_counter--;
}

static const char *kAIXSkippedSecNames[] = {
  ".loader",
  ".debug",
  ".tdata",
  ".tbss",
  ".except",
  ".typchk",
  ".info",
  ".ovrflo",
  ".tocbase"
};

static bool ShouldSkipAIXSection(const char *section_name) {
  if (!section_name) return false;

  for (auto name: kAIXSkippedSecNames)
    if (internal_strcmp(section_name, name) == 0) return true;
  return false;
}

void ProcessGlobalRegions(Frontier *frontier) {
  if (!flags()->use_globals) return;
  MemoryMappingLayout memory_mapping(false);
  InternalMmapVector<LoadedModule> modules;
  modules.reserve(128);
  memory_mapping.DumpListOfModules(&modules);

  for (uptr i = 0; i < modules.size(); ++i) {
    if (modules[i].instrumented()) continue;

    for (const __sanitizer::LoadedModule::AddressRange &range : modules[i].ranges()) {
      if (range.executable || !range.writable) continue;
      if (ShouldSkipAIXSection(range.name)) continue;
      ScanGlobalRange(range.beg, range.end, frontier);
    }
  }
}

void ProcessPlatformSpecificAllocations(Frontier *frontier) {}

void HandleLeaks() {
  internal__exit(common_flags()->exitcode);
}

static const uptr kMaxSharedLeaks = 1024;
static const uptr kMaxSharedFrontier = 1024;

struct AIXSharedLeakData {
  StopTheWorldCallback original_callback;
  ThreadID caller_tid;
  uptr caller_sp;
  bool success;
  uptr frontier_count;
  uptr leaks_count;
  LeakedChunk leaks[kMaxSharedLeaks];
  uptr frontier[kMaxSharedFrontier];
};

static void AIXSharedCallback(const SuspendedThreadsList &suspended_threads, void *arg) {
  AIXSharedLeakData *shared = (AIXSharedLeakData *)arg;

  CheckForLeaksParam temp_param;
  temp_param.caller_tid = shared->caller_tid;
  temp_param.caller_sp = shared->caller_sp;
  temp_param.success = false;

  shared->original_callback(suspended_threads, &temp_param);
  shared->success = temp_param.success;
  shared->frontier_count = temp_param.frontier.size();
  shared->leaks_count = temp_param.leaks.size();

  uptr leaks_copy_count = Min(shared->leaks_count, kMaxSharedLeaks);
  for (uptr i = 0; i < leaks_copy_count; ++i) {
    shared->leaks[i] = temp_param.leaks[i];
  }
  shared->leaks_count = leaks_copy_count;

  uptr frontier_copy_count = Min(shared->frontier_count, kMaxSharedFrontier);
  for (uptr i = 0; i < frontier_copy_count; ++i) {
    shared->frontier[i] = temp_param.frontier[i];
  }
  shared->frontier_count = frontier_copy_count;
}

void LockStuffAndStopTheWorld(StopTheWorldCallback callback,
                              CheckForLeaksParam *argument) {
  ScopedStopTheWorldLock lock;
  
  // The AIX stop the world implementation uses fork, so AIXSharedLeakData is needed
  // to share CheckForLeaksParam data across processes
  AIXSharedLeakData *shared_data = (AIXSharedLeakData *)internal_mmap(nullptr,
    sizeof(AIXSharedLeakData), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);

  shared_data->original_callback = callback;
  shared_data->caller_tid = argument->caller_tid;
  shared_data->caller_sp = argument->caller_sp;
  shared_data->success = argument->success;
  shared_data->frontier_count = 0;
  shared_data->leaks_count = 0;

  StopTheWorld(AIXSharedCallback, shared_data);

  // Update argument with data from the child process
  argument->success = shared_data->success;
  argument->leaks.clear();
  for (uptr i = 0; i < shared_data->leaks_count; ++i) {
    argument->leaks.push_back(shared_data->leaks[i]);
  }
  argument->frontier.clear();
  for (uptr i = 0; i < shared_data->frontier_count; ++i) {
    argument->frontier.push_back(shared_data->frontier[i]);
  }
  internal_munmap(shared_data, sizeof(AIXSharedLeakData));
}

LoadedModule *GetLinker() { return nullptr; }

}  // namespace __lsan

#endif
