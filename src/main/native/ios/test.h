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

void test_sysctl() {
  int ctl[] = { 1, 59 };
  int *name = &ctl[0];
  void *buffer = NULL;
  size_t bufferSize = 8;
  int ret = sysctl(name, 2, &buffer, &bufferSize, NULL, 0);
  printf("sysctl ret=%d, buffer=%p, name=%p, pos=0x%lx\n", ret, buffer, name, ((long) buffer - (long) name));
}

void do_test() {
  test_printf();
  test_sysctl();
}
