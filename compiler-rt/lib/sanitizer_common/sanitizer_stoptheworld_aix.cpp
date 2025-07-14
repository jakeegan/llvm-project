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

#  include "sanitizer_stoptheworld.h"

namespace __sanitizer {

class SuspendedThreadsListAIX final : public SuspendedThreadsList {
 public:
  SuspendedThreadsListAIX() = default;
  uptr ThreadCount() const override {return 0;};
  tid_t GetThreadID(uptr index) const override {return 0;};
};

void StopTheWorld(StopTheWorldCallback callback, void *argument) {
  SuspendedThreadsListAIX dummy;
  callback(dummy, argument);
}

}  // namespace __sanitizer

#endif  // SANITIZER_AIX
