#import "Security.h"
#import <CoreFoundation/CoreFoundation.h>
#import <stdio.h>

static CFMutableDictionaryRef plist = NULL;

__attribute__((constructor))
void init() {
  plist = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

int SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
  long lr = get_lr_reg();
  int debug = is_debug();
  if(debug) {
    CFShow(query);
  }
  int ret = errSecItemNotFound;
  CFStringRef class = CFDictionaryGetValue(query, kSecClass);
  CFStringRef acct = CFDictionaryGetValue(query, kSecAttrAccount);
  CFStringRef limit = CFDictionaryGetValue(query, kSecMatchLimit);
  CFDictionaryRef classDict = class == NULL ? NULL : CFDictionaryGetValue(plist, class);
  CFTypeRef value = acct == NULL || classDict == NULL ? NULL : CFDictionaryGetValue(classDict, acct);
  if(value && CFDictionaryGetValue(query, kSecReturnData) && CFStringCompare(limit, kSecMatchLimitOne, 0) == kCFCompareEqualTo) {
    if(result) {
      *result = CFRetain(value);
    }
    ret = errSecSuccess;
  }
  if(debug) {
    CFShow(plist);
    fprintf(stderr, "SecItemCopyMatching query=%p, result=%p, value=%p, ret=%d, LR=%p\n", query, result, value, ret, (void *) lr);
  }
  return ret;
}

int SecItemDelete(CFDictionaryRef query) {
  long lr = get_lr_reg();
  int debug = is_debug();
  if(debug) {
    CFShow(query);
  }
  CFStringRef class = CFDictionaryGetValue(query, kSecClass);
  CFStringRef acct = CFDictionaryGetValue(query, kSecAttrAccount);
  if(class && acct) {
    CFMutableDictionaryRef classDict = (CFMutableDictionaryRef) CFDictionaryGetValue(plist, class);
    if(classDict) {
      CFDictionaryRemoveValue(classDict, acct);
    }
  }
  if(debug) {
    CFShow(plist);
    fprintf(stderr, "SecItemDelete query=%p, LR=%p\n", query, (void *) lr);
  }
  return errSecSuccess;
}

int SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
  long lr = get_lr_reg();
  int debug = is_debug();
  if(debug) {
    CFShow(attributes);
  }
  int ret = errSecUnimplemented;
  CFStringRef class = CFDictionaryGetValue(attributes, kSecClass);
  CFStringRef acct = CFDictionaryGetValue(attributes, kSecAttrAccount);
  CFTypeRef data = CFDictionaryGetValue(attributes, kSecValueData);
  if(class && acct && data) {
    CFMutableDictionaryRef classDict = (CFMutableDictionaryRef) CFDictionaryGetValue(plist, class);
    if(!classDict) {
      classDict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
      CFDictionarySetValue(plist, class, classDict);
    }
    CFDictionarySetValue(classDict, acct, data);
    if(result) {
      *result = CFRetain(data);
    }
    ret = errSecSuccess;

    const UInt8 *ptr = CFDataGetBytePtr(data);
    CFIndex length = CFDataGetLength(data);
    char *buf = malloc(length * 2 + 1);
    int idx = 0;
    for(int i = 0; i < length; i++) {
      idx += sprintf(&buf[idx], "%02x", ptr[i]);
    }
    buf[idx] = 0;
    if(debug) {
      fprintf(stderr, "SecItemAdd ptr=%p, length=%ld, hex=%s\n", ptr, length, buf);
    }
    free(buf);
  }
  if(debug) {
    CFShow(plist);
    fprintf(stderr, "SecItemAdd attributes=%p, acct=%s, ret=%d, LR=%p\n", attributes, CFStringGetCStringPtr(acct, kCFStringEncodingUTF8), ret, (void *) lr);
  }
  return ret;
}
