#import "Security.h"
#import <CoreFoundation/CoreFoundation.h>
#import <stdio.h>
#include <pthread.h>

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
  uintptr_t lr = (uintptr_t) __builtin_return_address(0);
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
  if(value && CFDictionaryGetValue(query, kSecReturnData) && limit && CFStringCompare(limit, kSecMatchLimitOne, 0) == kCFCompareEqualTo) {
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
    return errSecSuccess;
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

#define _kCFRuntimeNotATypeID 0

typedef struct __CFRuntimeClass {	// Version 0 struct
    CFIndex version;
    const char *className;
    void (*init)(CFTypeRef cf);
    CFTypeRef (*copy)(CFAllocatorRef allocator, CFTypeRef cf);
    void (*dealloc)(CFTypeRef cf);
    Boolean (*equal)(CFTypeRef cf1, CFTypeRef cf2);
    CFHashCode (*hash)(CFTypeRef cf);
    CFStringRef (*copyFormattingDesc)(CFTypeRef cf, CFDictionaryRef formatOptions);	// str with retain
    CFStringRef (*copyDebugDesc)(CFTypeRef cf);	// str with retain
} CFRuntimeClass;

static pthread_once_t kSecCertificateRegisterClass = PTHREAD_ONCE_INIT;
static CFTypeID kSecCertificateTypeID = _kCFRuntimeNotATypeID;

static void SecCertificateDestroy(CFTypeRef cf) {
}

static Boolean SecCertificateEqual(CFTypeRef cf1, CFTypeRef cf2) {
    SecCertificateRef cert1 = (SecCertificateRef)cf1;
    SecCertificateRef cert2 = (SecCertificateRef)cf2;
    if (cert1 == cert2)
        return true;
    if (!cert2 || cert1->_der.length != cert2->_der.length)
        return false;
    return !memcmp(cert1->_der.data, cert2->_der.data, cert1->_der.length);
}

/* Hash of the certificate is der length + signature length + last 4 bytes
   of signature. */
static CFHashCode SecCertificateHash(CFTypeRef cf) {
    SecCertificateRef certificate = (SecCertificateRef)cf;
	size_t der_length = certificate->_der.length;
	CFHashCode hashCode = 0;
	for (size_t ix = 0; ix < der_length; ++ix)
		hashCode = (hashCode << 8) + certificate->_der.data[ix];

	return (hashCode + der_length);
}

/* Static functions. */
static CFStringRef SecCertificateDescribe(CFTypeRef cf) {
    SecCertificateRef certificate = (SecCertificateRef)cf;
    CFStringRef subject = CFSTR("subject");
    CFStringRef issuer = CFSTR("issuer");
    CFStringRef desc = CFStringCreateWithFormat(kCFAllocatorDefault, NULL,
        CFSTR("<cert(%p) s: %@ i: %@>"), certificate, subject, issuer);
    return desc;
}

void *_CFRuntimeCreateInstance(CFAllocatorRef, CFTypeID, size_t, size_t);
CFTypeID _CFRuntimeRegisterClass(const CFRuntimeClass*);

static void SecCertificateRegisterClass() {
    static const CFRuntimeClass kSecCertificateClass = {
        0,												/* version */
        "SecCertificate",					     		/* class name */
        NULL,											/* init */
        NULL,											/* copy */
        SecCertificateDestroy,                          /* dealloc */
        SecCertificateEqual,							/* equal */
        SecCertificateHash,								/* hash */
        NULL,											/* copyFormattingDesc */
        SecCertificateDescribe                          /* copyDebugDesc */
    };
    kSecCertificateTypeID = _CFRuntimeRegisterClass(&kSecCertificateClass);
}

CFTypeID SecCertificateGetTypeID(void) {
    pthread_once(&kSecCertificateRegisterClass, SecCertificateRegisterClass);
    return kSecCertificateTypeID;
}

SecCertificateRef SecCertificateCreateWithData(CFAllocatorRef allocator, CFDataRef data) {
  uintptr_t lr = (uintptr_t) __builtin_return_address(0);
  char buf[512];
  print_lr(buf, lr);

  const UInt8 *ptr = CFDataGetBytePtr(data);
  CFIndex length = CFDataGetLength(data);
  char *hex = malloc(length * 2 + 1);
  int idx = 0;
  for(int i = 0; i < length; i++) {
    idx += sprintf(&hex[idx], "%02x", ptr[i]);
  }
  hex[idx] = 0;

  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "SecCertificateCreateWithData ptr=%p, length=%ld, _CFRuntimeRegisterClass=%p, kSecCertificateTypeID=%lu, hex=%s, LR=%s\n", ptr, length, &_CFRuntimeRegisterClass, SecCertificateGetTypeID(), hex, buf);
  }
  free(hex);

  CFIndex size = sizeof(struct SecCertificate);
  SecCertificateRef result = (SecCertificateRef) _CFRuntimeCreateInstance(allocator, SecCertificateGetTypeID(), size - sizeof(CFRuntimeBase), 0);
  result->data = CFDataCreateCopy(kCFAllocatorDefault, data);
  result->_der.data = (DERByte *) CFDataGetBytePtr(result->data);
  result->_der.length = CFDataGetLength(result->data);
  return result;
}

int SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes) {
  uintptr_t lr = (uintptr_t) __builtin_return_address(0);
  char buf[512];
  print_lr(buf, lr);
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "SecRandomCopyBytes count=%zu, LR=%s\n", count, buf);
  }
  for(int i = 0; i < count; i++) {
    bytes[i] = (uint8_t) i;
  }
  return errSecSuccess;
}
