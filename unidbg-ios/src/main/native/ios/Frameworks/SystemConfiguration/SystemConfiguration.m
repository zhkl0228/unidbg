#import "SystemConfiguration.h"

CFStringRef SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "SCNetworkReachabilityCreateWithAddress allocator=%p, address=%p, LR=%s\n", allocator, address, buf);
  }
  CFStringRef str = CFStringCreateWithCString(NULL, "SCNetworkReachabilityCreateWithAddress", kCFStringEncodingUTF8);
  return str;
}

Boolean SCNetworkReachabilityGetFlags(void *target, SCNetworkReachabilityFlags *flags) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  *flags = defaultReachabilityFlags;
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "SCNetworkReachabilityGetFlags target=%p, flags=%p, LR=%s\n", target, flags, buf);
  }
  return TRUE;
}

Boolean SCNetworkReachabilitySetCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityCallBack callback, SCNetworkReachabilityContext* context) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "SCNetworkReachabilitySetCallback target=%p, callback=%p, context=%p, LR=%s\n", target, callback, context, buf);
  }
  void *info = NULL;
  if(context) {
    info = context->info;
  }
  callback(target, defaultReachabilityFlags, info);
  return TRUE;
}

CFArrayRef CNCopySupportedInterfaces() {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  CFStringRef array[] = { CFSTR("en0") };
  CFArrayRef arrayRef = CFArrayCreate(kCFAllocatorDefault, (void *)array, (CFIndex)1, NULL);
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CNCopySupportedInterfaces array=%p, LR=%s\n", arrayRef, buf);
  }
  return arrayRef;
}

CFDictionaryRef CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CNCopyCurrentNetworkInfo LR=%s\n", buf);
  }
  CFStringRef keys[] = { kCNNetworkInfoKeySSID, kCNNetworkInfoKeyBSSID };
  CFStringRef values[] = { CFSTR("SSID"), CFSTR("00:00:00:00:00:01") };
  CFDictionaryRef dictionary = CFDictionaryCreate(kCFAllocatorDefault, (const void**) keys, (const void**) values, 2, NULL, NULL);
  return dictionary;
}

Boolean SCNetworkReachabilityScheduleWithRunLoop(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "SCNetworkReachabilityScheduleWithRunLoop target=%p, LR=%s\n", target, buf);
  }
  return TRUE;
}

CFDictionaryRef SCDynamicStoreCopyProxies(SCDynamicStoreRef store) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "SCDynamicStoreCopyProxies store=%p\n, LR=%s", store, buf);
  }
  return NULL;
}
