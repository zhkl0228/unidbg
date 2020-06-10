#import "objc_common.h"

__attribute__((naked))
void new_objc_msgSend(id self, SEL _cmd) {
  __asm__ volatile (
    // push {q0-q7}
    "stp q6, q7, [sp, #-32]!\n"
    "stp q4, q5, [sp, #-32]!\n"
    "stp q2, q3, [sp, #-32]!\n"
    "stp q0, q1, [sp, #-32]!\n"
    // push {x0-x8, lr}
    "stp x8, lr, [sp, #-16]!\n"
    "stp x6, x7, [sp, #-16]!\n"
    "stp x4, x5, [sp, #-16]!\n"
    "stp x2, x3, [sp, #-16]!\n"
    "stp x0, x1, [sp, #-16]!\n"
    // Call our pre_objc_msgSend hook - returns old_objc_msgSend.
    "mov x12, lr\n"
    "bl _pre_objc_msgSend\n"
    "mov x9, x0\n"
    // pop {x0-x8, lr}
    "ldp x0, x1, [sp], #16\n"
    "ldp x2, x3, [sp], #16\n"
    "ldp x4, x5, [sp], #16\n"
    "ldp x6, x7, [sp], #16\n"
    "ldp x8, lr, [sp], #16\n"
    // pop {q0-q7}
    "ldp q0, q1, [sp], #32\n"
    "ldp q2, q3, [sp], #32\n"
    "ldp q4, q5, [sp], #32\n"
    "ldp q6, q7, [sp], #32\n"
    // Call through to the original objc_msgSend.
    "br x9\n"
  );
}
