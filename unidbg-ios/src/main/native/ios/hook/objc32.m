#import "objc_common.h"

__attribute__((naked))
void new_objc_msgSend(id self, SEL _cmd) {
  __asm__ volatile(
    // Call our pre_objc_msgSend hook - returns old_objc_msgSend.
    "push {r0-r4, r7, lr}\n"
    "mov r12, lr\n"
    "blx _pre_objc_msgSend\n"
    "mov r12, r0\n"
    "pop {r0-r4, r7, lr}\n"
    // Call through to the original objc_msgSend.
    "bx r12\n"
  );
}
