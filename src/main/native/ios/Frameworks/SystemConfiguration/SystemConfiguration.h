#include <stdlib.h>
#include <stdio.h>

void *SCNetworkReachabilityCreateWithAddress(void *allocator, void *address) {
  printf("SCNetworkReachabilityCreateWithAddress allocator=%p, address=%p\n", allocator, address);
  return NULL;
}
