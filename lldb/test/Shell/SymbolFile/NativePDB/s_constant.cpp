// clang-format off
// REQUIRES: lld, x86

// Test that we can display S_CONSTANT records.

// RUN: llvm-mc -filetype=obj -triple=x86_64-pc-win32 %p/Inputs/s_constant.s > %t.obj
// RUN: %build --compiler=clang-cl --nodefaultlib --mode=link -o %t.exe -- %t.obj
// RUN: %lldb -f %t.exe -s \
// RUN:     %p/Inputs/s_constant.lldbinit | FileCheck %s

// clang-cl cannot generate S_CONSTANT records, but we need to test that we can
// handle them for compatibility with MSVC, which does emit them.  This test
// case was generated by compiling this file with MSVC and copying the bytes
// that they emit for S_CONSTANT records.  Then we compile the same code with
// clang to get a .s file, and replace all S_LDATA32 records with the bytes from
// the S_CONSTANT records.  This way we end up with a .s file that contains
// symbol records that clang-cl won't generate.

namespace A {
namespace B {
namespace C {
  enum LargeUnsignedEnum : unsigned long long {
    LUE_A = 0ULL,
    LUE_B = 1000ULL,
    LUE_C = 18446744073709551600ULL,
  };

  enum LargeSignedEnum : long long {
    LSE_A = 0LL,
    LSE_B = 9223372036854775000LL,
    LSE_C = -9223372036854775000LL,
  };

  enum UnsignedEnum : unsigned int {
    UE_A = 0,
    UE_B = 1000,
    UE_C = 4294000000,
  };

  enum SignedEnum : int {
    SE_A = 0,
    SE_B = 2147000000,
    SE_C = -2147000000,
  };

  enum SmallUnsignedEnum : unsigned char {
    SUE_A = 0,
    SUE_B = 100,
    SUE_C = 200,
  };

  enum SmallSignedEnum : char {
    SSE_A = 0,
    SSE_B = 100,
    SSE_C = -100,
  };
}
}
}

using namespace A::B::C;

constexpr LargeUnsignedEnum GlobalLUEA = LUE_A;
constexpr LargeUnsignedEnum GlobalLUEB = LUE_B;
constexpr LargeUnsignedEnum GlobalLUEC = LUE_C;

constexpr LargeSignedEnum GlobalLSEA = LSE_A;
constexpr LargeSignedEnum GlobalLSEB = LSE_B;
constexpr LargeSignedEnum GlobalLSEC = LSE_C;

constexpr UnsignedEnum GlobalUEA = UE_A;
constexpr UnsignedEnum GlobalUEB = UE_B;
constexpr UnsignedEnum GlobalUEC = UE_C;

constexpr SignedEnum GlobalSEA = SE_A;
constexpr SignedEnum GlobalSEB = SE_B;
constexpr SignedEnum GlobalSEC = SE_C;

constexpr SmallUnsignedEnum GlobalSUEA = SUE_A;
constexpr SmallUnsignedEnum GlobalSUEB = SUE_B;
constexpr SmallUnsignedEnum GlobalSUEC = SUE_C;

constexpr SmallSignedEnum GlobalSSEA = SSE_A;
constexpr SmallSignedEnum GlobalSSEB = SSE_B;
constexpr SmallSignedEnum GlobalSSEC = SSE_C;

int main(int argc, char **argv) {
  return 0;
}

// CHECK: (const A::B::C::LargeUnsignedEnum) GlobalLUEA = LUE_A
// CHECK: (const A::B::C::LargeUnsignedEnum) GlobalLUEB = LUE_B

// X-FAIL: Something is outputting bad debug info here, maybe cl.
// CHECK: (const A::B::C::LargeUnsignedEnum) GlobalLUEC = {{.*}}

// CHECK: (const A::B::C::LargeSignedEnum) GlobalLSEA = LSE_A
// CHECK: (const A::B::C::LargeSignedEnum) GlobalLSEB = LSE_B
// CHECK: (const A::B::C::LargeSignedEnum) GlobalLSEC = LSE_C

// CHECK: (const A::B::C::UnsignedEnum) GlobalUEA = UE_A
// CHECK: (const A::B::C::UnsignedEnum) GlobalUEB = UE_B
// CHECK: (const A::B::C::UnsignedEnum) GlobalUEC = UE_C

// CHECK: (const A::B::C::SignedEnum) GlobalSEA = SE_A
// CHECK: (const A::B::C::SignedEnum) GlobalSEB = SE_B
// CHECK: (const A::B::C::SignedEnum) GlobalSEC = SE_C

// CHECK: (const A::B::C::SmallUnsignedEnum) GlobalSUEA = SUE_A
// CHECK: (const A::B::C::SmallUnsignedEnum) GlobalSUEB = SUE_B
// CHECK: (const A::B::C::SmallUnsignedEnum) GlobalSUEC = SUE_C

// CHECK: (const A::B::C::SmallSignedEnum) GlobalSSEA = SSE_A
// CHECK: (const A::B::C::SmallSignedEnum) GlobalSSEB = SSE_B
// CHECK: (const A::B::C::SmallSignedEnum) GlobalSSEC = SSE_C
