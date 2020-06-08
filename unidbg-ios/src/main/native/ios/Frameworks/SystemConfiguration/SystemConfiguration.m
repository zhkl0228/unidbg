#import "SystemConfiguration.h"

CFStringRef SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address) {
  long lr = 0;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  fprintf(stderr, "SCNetworkReachabilityCreateWithAddress allocator=%p, address=%p, LR=%p\n", allocator, address, (void *) lr);
  CFStringRef str = CFStringCreateWithCString(NULL, "SCNetworkReachabilityCreateWithAddress", kCFStringEncodingUTF8);
  return str;
}

Boolean SCNetworkReachabilityGetFlags(void *target, SCNetworkReachabilityFlags *flags) {
  long lr = 0;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  *flags = defaultReachabilityFlags;
  fprintf(stderr, "SCNetworkReachabilityGetFlags target=%p, flags=%p, LR=%p\n", target, flags, (void *) lr);
  return TRUE;
}

Boolean SCNetworkReachabilitySetCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityCallBack callback, SCNetworkReachabilityContext* context) {
  long lr = 0;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  fprintf(stderr, "SCNetworkReachabilitySetCallback target=%p, callback=%p, context=%p, LR=%p\n", target, callback, context, (void *) lr);
  void *info = NULL;
  if(context) {
    info = context->info;
  }
  callback(target, defaultReachabilityFlags, info);
  return TRUE;
}

CFArrayRef CNCopySupportedInterfaces() {
  long lr = 0;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  CFStringRef array[] = { CFSTR("en0") };
  CFArrayRef arrayRef = CFArrayCreate(kCFAllocatorDefault, (void *)array, (CFIndex)1, NULL);
  fprintf(stderr, "CNCopySupportedInterfaces array=%p, LR=%p\n", arrayRef, (void *) lr);
  return arrayRef;
}

CFDictionaryRef CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
  long lr = 0;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  fprintf(stderr, "CNCopyCurrentNetworkInfo LR=%p\n", (void *) lr);
  CFStringRef keys[] = { kCNNetworkInfoKeySSID, kCNNetworkInfoKeyBSSID };
  CFStringRef values[] = { CFSTR("SSID"), CFSTR("00:00:00:00:00:01") };
  CFDictionaryRef dictionary = CFDictionaryCreate(kCFAllocatorDefault, (const void**) keys, (const void**) values, 2, NULL, NULL);
  return dictionary;
}

Boolean SCNetworkReachabilityScheduleWithRunLoop(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode) {
  long lr = 0;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  fprintf(stderr, "SCNetworkReachabilityScheduleWithRunLoop target=%p, LR=%p\n", target, (void *) lr);
  return TRUE;
}

CFDictionaryRef SCDynamicStoreCopyProxies(SCDynamicStoreRef store) {
  long lr = 0;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  fprintf(stderr, "SCDynamicStoreCopyProxies store=%p\n, LR=%p", store, (void *) lr);
  return NULL;
}
