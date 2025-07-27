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

void ProcessGlobalRegions(Frontier *frontier) {}

void ProcessPlatformSpecificAllocations(Frontier *frontier) {}

void HandleLeaks() {}

void LockStuffAndStopTheWorld(StopTheWorldCallback callback,
                              CheckForLeaksParam *argument) {
  ScopedStopTheWorldLock lock;

  bool original_success = argument->success;
  VReport(1, "LockStuffAndStopTheWorld: original_success = %s\n", original_success ? "true" :
  "false");
  
  CheckForLeaksParam *shared_argument = (CheckForLeaksParam *)internal_mmap(nullptr,
  sizeof(CheckForLeaksParam), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  new (shared_argument) CheckForLeaksParam();
  shared_argument->caller_tid = argument->caller_tid;
  shared_argument->caller_sp = argument->caller_sp;
  shared_argument->success = argument->success;
  StopTheWorld(callback, shared_argument);

  VReport(1, "LockStuffAndStopTheWorld: after_success = %s\n", argument->success ? "true" :
  "false");

  argument->success = shared_argument->success;
  internal_munmap(shared_argument, sizeof(CheckForLeaksParam));

  if (!argument->success && !original_success){
    VReport(1, "LeakSanitizer: StopTheWorld failed\n");

    if (flags()->thread_suspend_fail ==0) {
      argument->success=true;
      VReport(1, "LeakSanitizer: Continuing leak check without thread suspension\n");
    }
  }
}

LoadedModule *GetLinker() { return nullptr; }

}  // namespace __lsan



#endif
