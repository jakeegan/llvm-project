// REQUIRES: riscv-registered-target
// RUN: %clang --target=riscv64 -mcpu=andes-nx45 --print-enabled-extensions | FileCheck %s

// CHECK: Extensions enabled for the given RISC-V target
// CHECK-EMPTY:
// CHECK-NEXT:     Name                 Version   Description
// CHECK-NEXT:     i                    2.1       'I' (Base Integer Instruction Set)
// CHECK-NEXT:     m                    2.0       'M' (Integer Multiplication and Division)
// CHECK-NEXT:     a                    2.1       'A' (Atomic Instructions)
// CHECK-NEXT:     f                    2.2       'F' (Single-Precision Floating-Point)
// CHECK-NEXT:     d                    2.2       'D' (Double-Precision Floating-Point)
// CHECK-NEXT:     c                    2.0       'C' (Compressed Instructions)
// CHECK-NEXT:     zicsr                2.0       'Zicsr' (CSRs)
// CHECK-NEXT:     zifencei             2.0       'Zifencei' (fence.i)
// CHECK-NEXT:     zmmul                1.0       'Zmmul' (Integer Multiplication)
// CHECK-NEXT:     zaamo                1.0       'Zaamo' (Atomic Memory Operations)
// CHECK-NEXT:     zalrsc               1.0       'Zalrsc' (Load-Reserved/Store-Conditional)
// CHECK-NEXT:     zca                  1.0       'Zca' (part of the C extension, excluding compressed floating point loads/stores)
// CHECK-NEXT:     zcd                  1.0       'Zcd' (Compressed Double-Precision Floating-Point Instructions)
// CHECK-NEXT:     xandesperf           5.0       'XAndesPerf' (Andes Performance Extension)
// CHECK-EMPTY:
// CHECK-NEXT: Experimental extensions
// CHECK-EMPTY:
// CHECK-NEXT: ISA String: rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zifencei2p0_zmmul1p0_zaamo1p0_zalrsc1p0_zca1p0_zcd1p0_xandesperf5p0
