#import "CFNetwork.h"
#import <stdio.h>

CFMutableURLRequestRef CFURLRequestCreateMutable(
  CFAllocatorRef			alloc,
  CFURLRef				  URL,
  CFURLRequestCachePolicy   cachePolicy,
  CFTimeInterval			timeout,
  CFURLRef				  mainDocumentURL) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  CFMutableURLRequestRef ref = malloc(sizeof(struct CFURLRequest));
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CFURLRequestCreateMutable request=%p, LR=%s\n", ref, buf);
  }
  ref->url = CFRetain(URL);
  ref->httpMethod = CFSTR("GET");
  ref->cachePolicy = cachePolicy;
  ref->headerFields = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  ref->httpBody = NULL;
  return ref;
}

CFStringRef CFURLRequestCopyHTTPHeaderFieldValue(
  CFURLRequestRef   request,
  CFStringRef	   headerField) {
  if(!request->headerFields || !headerField) {
    return NULL;
  }
  CFStringRef value = CFDictionaryGetValue(request->headerFields, headerField);
  if(!value) {
    return NULL;
  }
  return CFStringCreateCopy(kCFAllocatorDefault, value);
}

CFStringRef CFURLRequestCopyHTTPRequestMethod(CFURLRequestRef request) {
  return CFStringCreateCopy(kCFAllocatorDefault, request->httpMethod);
}

CFDictionaryRef CFURLRequestCopyAllHTTPHeaderFields(CFURLRequestRef request) {
  return CFDictionaryCreateCopy(kCFAllocatorDefault, request->headerFields);
}

CFDataRef CFURLRequestCopyHTTPRequestBody(CFURLRequestRef request) {
  return request->httpBody ? CFDataCreateCopy(kCFAllocatorDefault, request->httpBody) : NULL;
}

CFURLRef CFURLRequestGetURL(CFURLRequestRef request) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CFURLRequestGetURL request=%p, url=%p, LR=%s\n", request, request->url, buf);
  }
  return request->url;
}

void CFURLRequestSetHTTPHeaderFieldValue(
  CFMutableURLRequestRef   mutableHTTPRequest,
  CFStringRef			  httpHeaderField,
  CFStringRef			  httpHeaderFieldValue) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  CFDictionarySetValue(mutableHTTPRequest->headerFields, httpHeaderField, httpHeaderFieldValue);
  const char *field = CFStringGetCStringPtr(httpHeaderField, kCFStringEncodingUTF8);
  const char *value = CFStringGetCStringPtr(httpHeaderFieldValue, kCFStringEncodingUTF8);
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CFURLRequestSetHTTPHeaderFieldValue httpHeaderField=%s, httpHeaderFieldValue=%s, LR=%s\n", field, value, buf);
  }
}

void CFURLRequestSetURL(
  CFMutableURLRequestRef   mutableRequest,
  CFURLRef				 url) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CFURLRequestSetURL request=%p, url=%p, LR=%s\n", mutableRequest, url, buf);
  }
  mutableRequest->url = CFRetain(url);
}

void CFURLRequestSetMultipleHTTPHeaderFields(
  CFMutableURLRequestRef   mutableHTTPRequest,
  CFDictionaryRef		  headerFields) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CFURLRequestSetMultipleHTTPHeaderFields request=%p, LR=%s\n", mutableHTTPRequest, buf);
  }
  if(headerFields) {
    mutableHTTPRequest->multipleHeaderFields = CFRetain(headerFields);
  }
}

void CFURLRequestSetHTTPRequestMethod(
  CFMutableURLRequestRef   mutableHTTPRequest,
  CFStringRef			  httpMethod) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CFURLRequestSetHTTPRequestMethod request=%p, LR=%s\n", mutableHTTPRequest, buf);
  }
  mutableHTTPRequest->httpMethod = CFRetain(httpMethod);
}

void CFURLRequestSetCachePolicy(
  CFMutableURLRequestRef	mutableRequest,
  CFURLRequestCachePolicy   cachePolicy) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CFURLRequestSetCachePolicy request=%p, LR=%s\n", mutableRequest, buf);
  }
  mutableRequest->cachePolicy = cachePolicy;
}

void CFURLRequestSetHTTPRequestBody(
  CFMutableURLRequestRef   mutableHTTPRequest,
  CFDataRef				httpBody) {
  mutableHTTPRequest->httpBody = CFRetain(httpBody);
}

void CFURLRequestSetTimeoutInterval(CFMutableURLRequestRef request, double timeoutInterval) {
}

void _CFURLProtocolRegisterFoundationBridge(void *impl, Boolean preferCFURLProtocol) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "_CFURLProtocolRegisterFoundationBridge impl=%p, preferCFURLProtocol=%d, LR=%s\n", impl, preferCFURLProtocol, buf);
  }
}

CFDictionaryRef CFNetworkCopySystemProxySettings() {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CFNetworkCopySystemProxySettings LR=%s\n", buf);
  }

  id objects[] = { @"*.local", @"169.254/16" };
  NSArray *array = [NSArray arrayWithObjects:objects count:2];

  const int one = 1;
  CFNumberRef ftpPassive = CFNumberCreate(NULL, kCFNumberSInt32Type, (const void *) &one);

  id en_objects[] = { array, (__bridge NSNumber*) ftpPassive };
  id en_keys[] = { @"ExceptionsList", @"FTPPassive" };
  NSDictionary *en = [NSDictionary dictionaryWithObjects:en_objects forKeys:en_keys count:2];

  id scope_keys[] = { @"en0" };
  id scope_values[] = { en };
  NSDictionary *scope = [NSDictionary dictionaryWithObjects:scope_values forKeys:scope_keys count:1];

  NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithCapacity: 3];
  [dict setObject: array forKey: @"ExceptionsList"];
  [dict setObject: (__bridge NSNumber*) ftpPassive forKey: @"FTPPassive"];
  [dict setObject: scope forKey: @"__SCOPED__"];

  CFRelease(ftpPassive);
  return (__bridge CFDictionaryRef) dict;
}
