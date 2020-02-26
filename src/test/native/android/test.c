#include <stdio.h>
#include <sys/stat.h>

void test_stat() {
  struct stat st;
  fprintf(stderr, "st_ino=0x%lx, st_blocks=0x%lx, st_rdev=0x%lx, st_uid=0x%lx, size=%lu\n", (long) &st.st_ino - (long) &st, (long) &st.st_blocks - (long) &st, (long) &st.st_rdev - (long) &st, (long) &st.st_uid - (long) &st, (unsigned long) sizeof(st));
}

int main() {
  printf("Start test, stdin=%p, stdout=%p, stderr=%p, size=%lu\n", stdin, stdout, stderr, (unsigned long) sizeof(*stdout));
  test_stat();
  return 0;
}
