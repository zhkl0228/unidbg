#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("Hello, unidbg!\n");
  return 0;
}
