//=-- lsan_aix.h ---------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------===//
//
// This file is a part of LeakSanitizer.
// Standalone LSan RTL code specific to AIX.
//
//===---------------------------------------------------------------------===//

#ifndef LSAN_FUCHSIA_H
#define LSAN_FUCHSIA_H

#include "lsan_thread.h"
#include "sanitizer_common/sanitizer_platform.h"

#if !SANITIZER_AIX
#error "lsan_aix.h is used only on AIX systems (SANITIZER_AIX)"
#endif

namespace __lsan {

}  // namespace __lsan

#endif  // LSAN_AIX_H
