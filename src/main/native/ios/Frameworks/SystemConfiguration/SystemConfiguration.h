#include <stdlib.h>
#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>

CFStringRef SCNetworkReachabilityCreateWithAddress(void *allocator, void *address) {
  printf("SCNetworkReachabilityCreateWithAddress allocator=%p, address=%p\n", allocator, address);
  CFStringRef str = CFStringCreateWithCString(NULL, "SCNetworkReachabilityCreateWithAddress", kCFStringEncodingUTF8);
  return str;
}

typedef enum SCNetworkReachabilityFlags : uint32_t {
  kSCNetworkReachabilityFlagsReachable = 1<<1,
  kSCNetworkReachabilityFlagsIsLocalAddress = 1<<16,
} SCNetworkReachabilityFlags;

Boolean SCNetworkReachabilityGetFlags(void *target, SCNetworkReachabilityFlags *flags) {
  *flags |= kSCNetworkReachabilityFlagsReachable;
  *flags |= kSCNetworkReachabilityFlagsIsLocalAddress;
  printf("SCNetworkReachabilityGetFlags target=%p, flags=%p\n", target, flags);
  return true;
}

Boolean SCNetworkReachabilitySetCallback(void *target, void *callback, void *context) {
  printf("SCNetworkReachabilitySetCallback target=%p, callback=%p, context=%p\n", target, callback, context);
  return false;
}
