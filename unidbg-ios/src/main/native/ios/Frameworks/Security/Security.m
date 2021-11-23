#import "Security.h"
#import <CoreFoundation/CoreFoundation.h>
#import <stdio.h>

static CFStringRef path = CFSTR("Documents/__ignore.unidbg_keychain.plist");
static CFMutableDictionaryRef plist = NULL;

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

__attribute__((constructor))
void init() {
  CFURLRef home = CFCopyHomeDirectoryURL();
  CFURLRef fileURL = CFURLCreateWithFileSystemPathRelativeToBase(kCFAllocatorDefault, path, kCFURLPOSIXPathStyle, false, home);
  CFDataRef resourceData = NULL;
  SInt32 errorCode;
  Boolean success = CFURLResourceIsReachable(fileURL, NULL) && CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, fileURL, &resourceData, NULL, NULL, &errorCode);
  if (success) {
    CFErrorRef error = NULL;
    plist = (CFMutableDictionaryRef) CFPropertyListCreateWithData(kCFAllocatorDefault, resourceData, kCFPropertyListMutableContainers, NULL, &error);
    if(error) {
      CFRelease(error);
    }
  }
  if(resourceData) {
    CFRelease(resourceData);
  }
  CFRelease(fileURL);
  CFRelease(home);
  if(!plist) {
    plist = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  }
}

static void WritePropertyToFile(CFPropertyListRef propertyList) {
  CFURLRef home = CFCopyHomeDirectoryURL();
  CFURLRef fileURL = CFURLCreateWithFileSystemPathRelativeToBase(kCFAllocatorDefault, path, kCFURLPOSIXPathStyle, false, home);
  CFErrorRef error = NULL;
  CFDataRef xmlData = CFPropertyListCreateData(kCFAllocatorDefault, propertyList, kCFPropertyListXMLFormat_v1_0, 0, &error);
  SInt32 errorCode;
  Boolean success = CFURLWriteDataAndPropertiesToResource(fileURL, xmlData, NULL, &errorCode);
  if (!success) {
    fprintf(stderr, "WritePlistToFile failed: errorCode=%d\n", (int) errorCode);
  }
  if(xmlData) {
    CFRelease(xmlData);
  }
  if(error) {
    CFRelease(error);
  }
  CFRelease(fileURL);
  CFRelease(home);
}

int SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "Begin SecItemCopyMatching LR=%s\n", buf);
    CFShow(query);
  }
  int ret = errSecItemNotFound;
  CFStringRef class = CFDictionaryGetValue(query, kSecClass);
  CFTypeRef acct = CFDictionaryGetValue(query, kSecAttrAccount);
  CFStringRef limit = CFDictionaryGetValue(query, kSecMatchLimit);
  CFDictionaryRef classDict = class == NULL ? NULL : CFDictionaryGetValue(plist, class);
  CFTypeRef value = acct == NULL || classDict == NULL ? NULL : CFDictionaryGetValue(classDict, acct);
  if(CFGetTypeID(acct) != CFStringGetTypeID()) {
    fprintf(stderr, "SecItemCopyMatching kSecAttrAccount is not CFString LR=%s\n", buf);
    return ret;
  }
  if(value && CFDictionaryGetValue(query, kSecReturnData) && CFStringCompare(limit, kSecMatchLimitOne, 0) == kCFCompareEqualTo) {
    if(result) {
      *result = CFRetain(value);
    }
    ret = errSecSuccess;
  }
  if(debug) {
    CFShow(plist);
    fprintf(stderr, "End SecItemCopyMatching query=%p, result=%p, value=%p, ret=%d, LR=%s\n", query, result, value, ret, buf);
  }
  return ret;
}

int SecItemDelete(CFDictionaryRef query) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "Begin SecItemDelete LR=%s\n", buf);
    CFShow(query);
  }
  CFStringRef class = CFDictionaryGetValue(query, kSecClass);
  CFTypeRef acct = CFDictionaryGetValue(query, kSecAttrAccount);
  if(CFGetTypeID(acct) != CFStringGetTypeID()) {
    fprintf(stderr, "SecItemDelete kSecAttrAccount is not CFString LR=%s\n", buf);
    return errSecUnimplemented;
  }
  if(class && acct) {
    CFMutableDictionaryRef classDict = (CFMutableDictionaryRef) CFDictionaryGetValue(plist, class);
    if(classDict) {
      CFDictionaryRemoveValue(classDict, acct);
      WritePropertyToFile(plist);
    }
  }
  if(debug) {
    CFShow(plist);
    fprintf(stderr, "End SecItemDelete query=%p, LR=%s\n", query, buf);
  }
  return errSecSuccess;
}

int SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "Begin SecItemAdd LR=%s\n", buf);
    CFShow(attributes);
  }
  int ret = errSecUnimplemented;
  CFStringRef class = CFDictionaryGetValue(attributes, kSecClass);
  CFTypeRef acct = CFDictionaryGetValue(attributes, kSecAttrAccount);
  if(CFGetTypeID(acct) != CFStringGetTypeID()) {
    fprintf(stderr, "SecItemAdd kSecAttrAccount is not CFString LR=%s\n", buf);
    return ret;
  }
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
    WritePropertyToFile(plist);

    const UInt8 *ptr = CFDataGetBytePtr(data);
    CFIndex length = CFDataGetLength(data);
    char *hex = malloc(length * 2 + 1);
    int idx = 0;
    for(int i = 0; i < length; i++) {
      idx += sprintf(&hex[idx], "%02x", ptr[i]);
    }
    hex[idx] = 0;
    if(debug) {
      fprintf(stderr, "SecItemAdd ptr=%p, length=%ld, hex=%s, LR=%s\n", ptr, length, hex, buf);
    }
    free(hex);
  }
  if(debug) {
    CFShow(plist);
    fprintf(stderr, "End SecItemAdd attributes=%p, acct=%s, ret=%d, LR=%s\n", attributes, CFStringGetCStringPtr(acct, kCFStringEncodingUTF8), ret, buf);
  }
  return ret;
}
