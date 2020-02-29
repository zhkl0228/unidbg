#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>

void test_stat() {
  struct stat st;
  printf("st_nlink=0x%lx, st_blocks=0x%lx, st_rdev=0x%lx, st_uid=0x%lx, st_mtime=0x%lx, size=%lu\n", (long) &st.st_nlink - (long) &st, (long) &st.st_blocks - (long) &st, (long) &st.st_rdev - (long) &st, (long) &st.st_uid - (long) &st, (long) &st.st_mtime - (long) &st, (unsigned long) sizeof(st));
}

void test_dirent() {
  struct dirent dt;
  fprintf(stdout, "dirent size=%lu\n", (unsigned long) sizeof(dt));
}

int main() {
  fprintf(stderr, "Start test, stdin=%p, stdout=%p, stderr=%p, size=%lu\n", stdin, stdout, stderr, (unsigned long) sizeof(*stdout));
  test_stat();
  test_dirent();
  printf("Press any key to exit\n");
  getchar();
  return 0;
}
