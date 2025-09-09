typedef unsigned long size_t;

void operator delete(void *ptr, size_t size) {
    operator delete(ptr);
}

void operator delete[](void *ptr, size_t size) {
    operator delete[](ptr);
}

#import <Foundation/Foundation.h>

extern "C" id objc_retain(id);

extern "C" id objc_retain_x8(id obj) {
    __asm__ (
        "str x8, [sp, #8]"
    );
    return objc_retain(obj);
}

#include <iostream>
#include <cassert>

void operator delete(void *ptr, size_t size, std::align_val_t alignment) _NOEXCEPT {
    free(ptr);
}

void *operator new(size_t size, std::align_val_t alignment) {
    void *ptr = NULL;
    int ret = posix_memalign(&ptr, (size_t) alignment, size);
    assert(ret == 0);
    return ptr;
}
