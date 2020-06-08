#import "Security.h"
#import <CoreFoundation/CoreFoundation.h>
#import <stdio.h>

static CFMutableDictionaryRef plist = NULL;

__attribute__((constructor))
void init() {
  plist = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

int SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
  CFShow(query);
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
  CFShow(plist);
  fprintf(stderr, "SecItemCopyMatching query=%p, result=%p, value=%p, ret=%d\n", query, result, value, ret);
  return ret;
}

int SecItemDelete(CFDictionaryRef query) {
  CFShow(query);
  CFStringRef class = CFDictionaryGetValue(query, kSecClass);
  CFStringRef acct = CFDictionaryGetValue(query, kSecAttrAccount);
  if(class && acct) {
    CFMutableDictionaryRef classDict = (CFMutableDictionaryRef) CFDictionaryGetValue(plist, class);
    if(classDict) {
      CFDictionaryRemoveValue(classDict, acct);
    }
  }
  CFShow(plist);
  fprintf(stderr, "SecItemDelete query=%p\n", query);
  return errSecSuccess;
}

int SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
  CFShow(attributes);
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
  }
  CFShow(plist);
  fprintf(stderr, "SecItemAdd attributes=%p, acct=%s, ret=%d\n", attributes, CFStringGetCStringPtr(acct, kCFStringEncodingUTF8), ret);
  return ret;
}
