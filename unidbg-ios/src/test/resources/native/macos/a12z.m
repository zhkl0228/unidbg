#include <stdio.h>
#include <Foundation/Foundation.h>

__attribute__((naked))
int test_ldadd(int *p) {
  __asm__ volatile(
    "sub sp, sp, #0x10\n"
    "stp x29, x30, [sp]\n"

    "mov x8, x0\n"

    "mov w9, #1\n"
    "ldadd w9, w8, [x8]\n"

    "mov w0, w8\n"
    "ldp x29, x30, [sp]\n"
    "add sp, sp, #0x10\n"
    "ret\n"
  );
}

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  NSLog(@"A12Z double=%lu, long double=%lu, long=%lu", sizeof(double), sizeof(long double), sizeof(long));
  printf("hello world A12Z, double=%lu, long double=%lu, long=%lu\n", sizeof(double), sizeof(long double), sizeof(long));

  int v = 0x88;
  int ret = test_ldadd(&v);
  printf("Test v=0x%x, ret=0x%x\n", v, ret);

  char vc;
  short vs;
  int vi;
  long vl;
  float vf;
  double vd;
  printf("Memory test: vc[%p]=0x%x, vs[%p]=0x%x, vi[%p]=0x%x, vl[%p]=0x%lx, vf[%p]=%f, vd[%p]=%lf\n", &vc, vc, &vs, vs, &vi, vi, &vl, vl, &vf, vf, &vd, vd);

  return 0;
}
