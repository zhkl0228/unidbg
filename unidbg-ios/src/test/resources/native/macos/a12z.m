#include <stdio.h>
#include <Foundation/Foundation.h>

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  NSLog(@"A12Z double=%lu, long double=%lu, long=%lu", sizeof(double), sizeof(long double), sizeof(long));
  printf("hello world A12Z, double=%lu, long double=%lu, long=%lu\n", sizeof(double), sizeof(long double), sizeof(long));
  return 0;
}
