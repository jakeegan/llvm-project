// RUN: %clang_cc1 -fsyntax-only -verify=both,ref      -triple x86_64-linux %s -Wno-tautological-pointer-compare -Wno-pointer-to-int-cast
// RUN: %clang_cc1 -fsyntax-only -verify=both,expected -triple x86_64-linux %s -Wno-tautological-pointer-compare -Wno-pointer-to-int-cast -fexperimental-new-constant-interpreter -DNEW_INTERP
// RUN: %clang_cc1 -fsyntax-only -verify=both,ref      -triple powerpc64-ibm-aix-xcoff %s -Wno-tautological-pointer-compare -Wno-pointer-to-int-cast
// RUN: %clang_cc1 -fsyntax-only -verify=both,expected -triple powerpc64-ibm-aix-xcoff %s -Wno-tautological-pointer-compare -Wno-pointer-to-int-cast -fexperimental-new-constant-interpreter -DNEW_INTERP

/// This is a version of test/Sema/const-eval.c with the
/// tests commented out that the new constant expression interpreter does
/// not support yet. They are all marked with the NEW_INTERP define:
///
///   - builtin_constant_p
///   - unions


#define EVAL_EXPR(testno, expr) enum { test##testno = (expr) }; struct check_positive##testno { int a[test##testno]; };
int x;
EVAL_EXPR(1, (_Bool)&x)
EVAL_EXPR(2, (int)(1.0+(double)4))
EVAL_EXPR(3, (int)(1.0+(float)4.0))
EVAL_EXPR(4, (_Bool)(1 ? (void*)&x : 0))
EVAL_EXPR(5, (_Bool)(int[]){0})
struct y {int x,y;};
EVAL_EXPR(6, (int)(1+(struct y*)0))
_Static_assert((long)&((struct y*)0)->y > 0, "");
EVAL_EXPR(7, (int)&((struct y*)0)->y)
EVAL_EXPR(8, (_Bool)"asdf")
EVAL_EXPR(9, !!&x)
EVAL_EXPR(10, ((void)1, 12))
void g0(void);
EVAL_EXPR(11, (g0(), 12)) // both-error {{not an integer constant expression}}
EVAL_EXPR(12, 1.0&&2.0)
EVAL_EXPR(13, x || 3.0) // both-error {{not an integer constant expression}}

unsigned int l_19 = 1;
EVAL_EXPR(14, (1 ^ l_19) && 1); // both-error {{not an integer constant expression}}

void f(void)
{
  int a;
  EVAL_EXPR(15, (_Bool)&a);
}

_Complex float g16 = (1.0f + 1.0fi);

// ?: in constant expressions.
int g17[(3?:1) - 2];

EVAL_EXPR(18, ((int)((void*)10 + 10)) == 20 ? 1 : -1);

struct s {
  int a[(int)-1.0f]; // both-error {{array size is negative}}
};

EVAL_EXPR(19, ((int)&*(char*)10 == 10 ? 1 : -1));

#ifndef NEW_INTERP
EVAL_EXPR(20, __builtin_constant_p(*((int*) 10)));
#endif

EVAL_EXPR(21, (__imag__ 2i) == 2 ? 1 : -1);

EVAL_EXPR(22, (__real__ (2i+3)) == 3 ? 1 : -1);

int g23[(int)(1.0 / 1.0)] = { 1 }; // both-warning {{folded to constant array}}
int g24[(int)(1.0 / 1.0)] = { 1 , 2 }; // both-warning {{folded to constant array}} \
                                       // both-warning {{excess elements in array initializer}}
int g25[(int)(1.0 + 1.0)], g26 = sizeof(g25); // both-warning {{folded to constant array}}

EVAL_EXPR(26, (_Complex double)0 ? -1 : 1)
EVAL_EXPR(27, (_Complex int)0 ? -1 : 1)
EVAL_EXPR(28, (_Complex double)1 ? 1 : -1)
EVAL_EXPR(29, (_Complex int)1 ? 1 : -1)

// PR4027
struct a { int x, y; };
static struct a V2 = (struct a)(struct a){ 1, 2};
static const struct a V1 = (struct a){ 1, 2};

EVAL_EXPR(30, (int)(_Complex float)((1<<30)-1) == (1<<30) ? 1 : -1)
EVAL_EXPR(31, (int*)0 == (int*)0 ? 1 : -1)
EVAL_EXPR(32, (int*)0 != (int*)0 ? -1 : 1)
EVAL_EXPR(33, (void*)0 - (void*)0 == 0 ? 1 : -1)

void foo(void) {}
EVAL_EXPR(34, (foo == (void *)0) ? -1 : 1)

// No PR. Mismatched bitwidths lead to a crash on second evaluation.
const _Bool constbool = 0;
EVAL_EXPR(35, constbool)
EVAL_EXPR(36, constbool)

EVAL_EXPR(37, ((void)1,2.0) == 2.0 ? 1 : -1)
EVAL_EXPR(38, __builtin_expect(1,1) == 1 ? 1 : -1)

// PR7884
EVAL_EXPR(39, __real__(1.f) == 1 ? 1 : -1)
EVAL_EXPR(40, __imag__(1.f) == 0 ? 1 : -1)

// From gcc testsuite
EVAL_EXPR(41, (int)(1+(_Complex unsigned)2))

void rdar8875946(void) {
  double _Complex  P;
  float _Complex  P2 = 3.3f + P;
}

double d = (d = 0.0); // both-error {{not a compile-time constant}}
double d2 = ++d; // both-error {{not a compile-time constant}}

int n = 2;
int intLvalue[*(int*)((long)&n ?: 1)] = { 1, 2 }; // both-error {{variable length array}}

union u { int a; char b[4]; };
char c = ((union u)(123456)).b[0]; // both-error {{not a compile-time constant}}

#ifndef NEW_INTERP
extern const int weak_int __attribute__((weak));
const int weak_int = 42;
int weak_int_test = weak_int; // both-error {{not a compile-time constant}}
#endif

int literalVsNull1 = "foo" == 0;
int literalVsNull2 = 0 == "foo";

// PR11385.
int castViaInt[*(int*)(unsigned long)"test"]; // both-error {{variable length array}}

// PR11391.
#ifndef NEW_INTERP
struct PR11391 { _Complex float f; } pr11391;
EVAL_EXPR(42, __builtin_constant_p(pr11391.f = 1))
#endif

// PR12043
float varfloat;
const float constfloat = 0;
EVAL_EXPR(43, varfloat && constfloat) // both-error {{not an integer constant expression}}
EVAL_EXPR(45, ((char*)-1) + 1 == 0 ? 1 : -1)
EVAL_EXPR(46, ((char*)-1) + 1 < (char*) -1 ? 1 : -1)
EVAL_EXPR(47, &x < &x + 1 ? 1 : -1)
EVAL_EXPR(48, &x != &x - 1 ? 1 : -1)
EVAL_EXPR(49, &x < &x - 100 ? 1 : -1) // ref-error {{not an integer constant expression}}

extern struct Test50S Test50;
EVAL_EXPR(50, &Test50 < (struct Test50S*)((unsigned long)&Test50 + 10)) // both-error {{not an integer constant expression}}

EVAL_EXPR(51, 0 != (float)1e99)

// PR21945
void PR21945(void) { int i = (({}), 0l); }

void PR24622(void);
struct PR24622 {} pr24622;
EVAL_EXPR(52, &pr24622 == (void *)&PR24622);

// We evaluate these by providing 2s' complement semantics in constant
// expressions, like we do for integers.
void *PR28739a = (__int128)(unsigned long)-1 + &PR28739a;                  // both-warning {{the pointer incremented by 18446744073709551615 refers past the last possible element for an array in 64-bit address space containing 64-bit (8-byte) elements (max possible 2305843009213693952 elements)}}

void *PR28739b = &PR28739b + (__int128)(unsigned long)-1;                  // both-warning {{refers past the last possible element}}
__int128 PR28739c = (&PR28739c + (__int128)(unsigned long)-1) - &PR28739c; // both-warning {{refers past the last possible element}}
void *PR28739d = &(&PR28739d)[(__int128)(unsigned long)-1];                // both-warning {{refers past the last possible element}}

struct PR35214_X {
  int k;
  int arr[];
};
int PR35214_x;
int PR35214_y = ((struct PR35214_X *)&PR35214_x)->arr[1]; // both-error {{not a compile-time constant}}
#ifndef NEW_INTERP
int *PR35214_z = &((struct PR35214_X *)&PR35214_x)->arr[1]; // ok, &PR35214_x + 2
#endif

/// From const-eval-64.c
EVAL_EXPR(53, ((char*)-1LL) + 1 == 0 ? 1 : -1)
EVAL_EXPR(54, ((char*)-1LL) + 1 < (char*) -1 ? 1 : -1)

/// === Additions ===
#if __SIZEOF_INT__ == 4
typedef __INTPTR_TYPE__ intptr_t;
const intptr_t A = (intptr_t)(((int*) 0) + 1);
const intptr_t B = (intptr_t)(((char*)0) + 3);
_Static_assert(A > B, "");
int * GH149500_p = &(*(int *)0x400);
static const void *GH149500_q = &(*(const struct sysrq_key_op *)0);

#else
#error :(
#endif
