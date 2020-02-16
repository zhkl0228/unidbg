#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/sysctl.h>

static void test_printf() {
  char buf[0x40];
  memset(buf, 0, 0x40);
  snprintf(buf, 0x40, "snprintf: %p\n", buf);
  fprintf(stderr, "printf[%p] test: %s", buf, buf);
}

void test_sysctl_KERN_USRSTACK() {
  int mib[2];
  void *stack = NULL;
  size_t size = sizeof(stack);

  mib[0] = CTL_KERN;
  mib[1] = KERN_USRSTACK;
  int ret = sysctl(mib, 2, &stack, &size, NULL, 0);
  printf("sysctl ret=%d, stack=%p, mib=%p, offset=0x%lx\n", ret, stack, mib, ((long) stack - (long) mib));
}

void do_test() {
  test_printf();
  test_sysctl_KERN_USRSTACK();
}
