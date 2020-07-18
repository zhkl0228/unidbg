#include "test.h"

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("Hello, unidbg!\n");
  do_test();
  return 0;
}
