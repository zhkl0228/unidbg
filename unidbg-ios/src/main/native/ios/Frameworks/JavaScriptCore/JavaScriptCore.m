#import "JavaScriptCore.h"
#import <stdlib.h>

JSStringRef JSStringCreateWithCharacters(const JSChar *chars, size_t numChars) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "JSStringCreateWithCharacters chars=%p, numChars=%zu, LR=%s\n", chars, numChars, buf);
  }
  struct OpaqueJSString *str = malloc(sizeof(struct OpaqueJSString));
  return str;
}
