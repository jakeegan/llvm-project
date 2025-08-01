//===-- Linux implementation of tcgetattr ---------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/termios/tcgetattr.h"
#include "kernel_termios.h"

#include "src/__support/OSUtil/syscall.h"
#include "src/__support/common.h"
#include "src/__support/libc_errno.h"
#include "src/__support/macros/config.h"

#include <asm/ioctls.h> // Safe to include without the risk of name pollution.
#include <sys/syscall.h> // For syscall numbers
#include <termios.h>

namespace LIBC_NAMESPACE_DECL {

LLVM_LIBC_FUNCTION(int, tcgetattr, (int fd, struct termios *t)) {
  LIBC_NAMESPACE::kernel_termios kt;
  int ret = LIBC_NAMESPACE::syscall_impl<int>(SYS_ioctl, fd, TCGETS, &kt);
  if (ret < 0) {
    libc_errno = -ret;
    return -1;
  }
  t->c_iflag = kt.c_iflag;
  t->c_oflag = kt.c_oflag;
  t->c_cflag = kt.c_cflag;
  t->c_lflag = kt.c_lflag;
  t->c_ispeed = kt.c_cflag & CBAUD;
  t->c_ospeed = kt.c_cflag & CBAUD;

  size_t nccs = KERNEL_NCCS <= NCCS ? KERNEL_NCCS : NCCS;
  for (size_t i = 0; i < nccs; ++i)
    t->c_cc[i] = kt.c_cc[i];
  if (NCCS > nccs) {
    for (size_t i = nccs; i < NCCS; ++i)
      t->c_cc[i] = 0;
  }
  return 0;
}

} // namespace LIBC_NAMESPACE_DECL
