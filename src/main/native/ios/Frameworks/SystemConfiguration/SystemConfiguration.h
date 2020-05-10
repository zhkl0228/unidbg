#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <CoreFoundation/CoreFoundation.h>

const CFStringRef kCNNetworkInfoKeySSID = CFSTR("SSID");
const CFStringRef kCNNetworkInfoKeyBSSID = CFSTR("BSSID");

CFStringRef SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address) {
  fprintf(stderr, "SCNetworkReachabilityCreateWithAddress allocator=%p, address=%p\n", allocator, address);
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
  fprintf(stderr, "SCNetworkReachabilityGetFlags target=%p, flags=%p\n", target, flags);
  return true;
}

Boolean SCNetworkReachabilitySetCallback(void *target, void *callback, void *context) {
  fprintf(stderr, "SCNetworkReachabilitySetCallback target=%p, callback=%p, context=%p\n", target, callback, context);
  return false;
}

CFArrayRef CNCopySupportedInterfaces() {
  CFStringRef array[] = { CFSTR("en0") };
  CFArrayRef arrayRef = CFArrayCreate(kCFAllocatorDefault, (void *)array, (CFIndex)1, NULL);
  fprintf(stderr, "CNCopySupportedInterfaces array=%p\n", arrayRef);
  return arrayRef;
}

CFDictionaryRef CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
  fprintf(stderr, "CNCopyCurrentNetworkInfo\n");
  CFStringRef keys[] = { kCNNetworkInfoKeySSID, kCNNetworkInfoKeyBSSID };
  CFStringRef values[] = { CFSTR("SSID"), CFSTR("00:00:00:00:00:01") };
  CFDictionaryRef dictionary = CFDictionaryCreate(kCFAllocatorDefault, (const void**) keys, (const void**) values, 2, NULL, NULL);
  return dictionary;
}
