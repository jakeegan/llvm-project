// RUN: llvm-mc -filetype=obj %s -o - -triple i686-pc-linux | llvm-objdump --no-print-imm-hex -d -r - | FileCheck --check-prefix=X86 %s
// RUN: llvm-mc -filetype=obj %s -o - -triple x86_64-pc-linux | llvm-objdump --no-print-imm-hex -d -r - | FileCheck --check-prefix=X64 %s

// X86: 0: 83 ff 00  cmpl $0, %edi
// X86:   00000002:  R_386_8 foo
// X64: 0: 83 ff 00  cmpl $0, %edi
// X64:  0000000000000002:  R_X86_64_8 foo
cmp $foo@ABS8, %edi
