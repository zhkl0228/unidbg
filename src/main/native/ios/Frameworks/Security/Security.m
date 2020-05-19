#import "Security.h"
#import <stdio.h>

int SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
  fprintf(stderr, "SecItemCopyMatching query=%p, result=%p\n", query, result);
  return errSecItemNotFound;
}

int SecItemDelete(CFDictionaryRef query) {
  fprintf(stderr, "SecItemDelete query=%p\n", query);
  return errSecSuccess;
}

int SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
  fprintf(stderr, "SecItemAdd attributes=%p, result=%p\n", attributes, result);
  return errSecUnimplemented;
}
