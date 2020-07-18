#import "MobileCoreServices.h"
#import <stdio.h>

void _LSRegisterFilePropertyProvider() {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "_LSRegisterFilePropertyProvider LR=%s\n", buf);
  }
}
