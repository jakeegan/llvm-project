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

#include "lsan_allocator.h"
#include "sanitizer_common/sanitizer_flags.h"
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
  StopTheWorld(callback, argument);
}

LoadedModule *GetLinker() { return nullptr; }

}  // namespace __lsan



#endif
