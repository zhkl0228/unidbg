#import "SystemConfiguration.h"

CFStringRef SCNetworkReachabilityCreateWithAddress(CFAllocatorRef allocator, const struct sockaddr *address) {
  if(is_debug()) {
    long lr = get_lr_reg();
    fprintf(stderr, "SCNetworkReachabilityCreateWithAddress allocator=%p, address=%p, LR=%p\n", allocator, address, (void *) lr);
  }
  CFStringRef str = CFStringCreateWithCString(NULL, "SCNetworkReachabilityCreateWithAddress", kCFStringEncodingUTF8);
  return str;
}

Boolean SCNetworkReachabilityGetFlags(void *target, SCNetworkReachabilityFlags *flags) {
  *flags = defaultReachabilityFlags;
  if(is_debug()) {
    long lr = get_lr_reg();
    fprintf(stderr, "SCNetworkReachabilityGetFlags target=%p, flags=%p, LR=%p\n", target, flags, (void *) lr);
  }
  return TRUE;
}

Boolean SCNetworkReachabilitySetCallback(SCNetworkReachabilityRef target, SCNetworkReachabilityCallBack callback, SCNetworkReachabilityContext* context) {
  if(is_debug()) {
    long lr = get_lr_reg();
    fprintf(stderr, "SCNetworkReachabilitySetCallback target=%p, callback=%p, context=%p, LR=%p\n", target, callback, context, (void *) lr);
  }
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
  if(is_debug()) {
    long lr = get_lr_reg();
    fprintf(stderr, "CNCopySupportedInterfaces array=%p, LR=%p\n", arrayRef, (void *) lr);
  }
  return arrayRef;
}

CFDictionaryRef CNCopyCurrentNetworkInfo(CFStringRef interfaceName) {
  if(is_debug()) {
    long lr = get_lr_reg();
    fprintf(stderr, "CNCopyCurrentNetworkInfo LR=%p\n", (void *) lr);
  }
  CFStringRef keys[] = { kCNNetworkInfoKeySSID, kCNNetworkInfoKeyBSSID };
  CFStringRef values[] = { CFSTR("SSID"), CFSTR("00:00:00:00:00:01") };
  CFDictionaryRef dictionary = CFDictionaryCreate(kCFAllocatorDefault, (const void**) keys, (const void**) values, 2, NULL, NULL);
  return dictionary;
}

Boolean SCNetworkReachabilityScheduleWithRunLoop(SCNetworkReachabilityRef target, CFRunLoopRef runLoop, CFStringRef runLoopMode) {
  if(is_debug()) {
    long lr = get_lr_reg();
    fprintf(stderr, "SCNetworkReachabilityScheduleWithRunLoop target=%p, LR=%p\n", target, (void *) lr);
  }
  return TRUE;
}

CFDictionaryRef SCDynamicStoreCopyProxies(SCDynamicStoreRef store) {
  if(is_debug()) {
    long lr = get_lr_reg();
    fprintf(stderr, "SCDynamicStoreCopyProxies store=%p\n, LR=%p", store, (void *) lr);
  }
  return NULL;
}
