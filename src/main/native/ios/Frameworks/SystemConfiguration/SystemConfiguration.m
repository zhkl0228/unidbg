#import "SystemConfiguration.h"

CFStringRef SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address) {
  fprintf(stderr, "SCNetworkReachabilityCreateWithAddress allocator=%p, address=%p\n", allocator, address);
  CFStringRef str = CFStringCreateWithCString(NULL, "SCNetworkReachabilityCreateWithAddress", kCFStringEncodingUTF8);
  return str;
}

Boolean SCNetworkReachabilityGetFlags(void *target, SCNetworkReachabilityFlags *flags) {
  *flags = defaultReachabilityFlags;
  fprintf(stderr, "SCNetworkReachabilityGetFlags target=%p, flags=%p\n", target, flags);
  return TRUE;
}

Boolean SCNetworkReachabilitySetCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityCallBack callback, SCNetworkReachabilityContext* context) {
  fprintf(stderr, "SCNetworkReachabilitySetCallback target=%p, callback=%p, context=%p\n", target, callback, context);
  void *info = NULL;
  if(context) {
    info = context->info;
  }
  callback(target, defaultReachabilityFlags, info);
  return TRUE;
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

Boolean SCNetworkReachabilityScheduleWithRunLoop(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode) {
  fprintf(stderr, "SCNetworkReachabilityScheduleWithRunLoop target=%p\n", target);
  return TRUE;
}

CFDictionaryRef SCDynamicStoreCopyProxies(SCDynamicStoreRef store) {
  fprintf(stderr, "SCDynamicStoreCopyProxies store=%p\n", store);
  return NULL;
}
