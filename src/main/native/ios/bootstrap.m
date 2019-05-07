#include <stdlib.h>
#include <stdio.h>
#import <Foundation/Foundation.h>

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  NSLog(@"Hello, unidbg!");
  return 0;
}
