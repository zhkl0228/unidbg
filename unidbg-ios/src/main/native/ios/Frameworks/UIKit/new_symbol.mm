typedef unsigned long size_t;

void operator delete(void *ptr, size_t size) {
    operator delete(ptr);
}

void operator delete[](void *ptr, size_t size) {
    operator delete[](ptr);
}

#import <Foundation/Foundation.h>

extern "C" {
    id objc_retain(id);
    void objc_release(id);
    id objc_retainAutoreleasedReturnValue(id);

    id objc_claimAutoreleasedReturnValue(id obj) {
        return objc_retainAutoreleasedReturnValue(obj);
    }

    id objc_retain_x1(id obj) {
        __asm__ (
            "str x1, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x1(id obj) {
        __asm__ (
            "str x1, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x2(id obj) {
        __asm__ (
            "str x2, [sp, #8]"
        );
        return objc_retain(obj);
    }

    id objc_retain_x3(id obj) {
        __asm__ (
            "str x3, [sp, #8]"
        );
        return objc_retain(obj);
    }

    id objc_retain_x4(id obj) {
        __asm__ (
            "str x4, [sp, #8]"
        );
        return objc_retain(obj);
    }

    id objc_retain_x5(id obj) {
        __asm__ (
            "str x5, [sp, #8]"
        );
        return objc_retain(obj);
    }

    id objc_retain_x7(id obj) {
        __asm__ (
            "str x7, [sp, #8]"
        );
        return objc_retain(obj);
    }

    id objc_retain_x8(id obj) {
        __asm__ (
            "str x8, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x8(id obj) {
        __asm__ (
            "str x8, [sp, #8]"
        );
        objc_release(obj);
    }

    void objc_release_x9(id obj) {
        __asm__ (
            "str x9, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x19(id obj) {
        __asm__ (
            "str x19, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x19(id obj) {
        __asm__ (
            "str x19, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x20(id obj) {
        __asm__ (
            "str x20, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x20(id obj) {
        __asm__ (
            "str x20, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x21(id obj) {
        __asm__ (
            "str x21, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x21(id obj) {
        __asm__ (
            "str x21, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x22(id obj) {
        __asm__ (
            "str x22, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x22(id obj) {
        __asm__ (
            "str x22, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x23(id obj) {
        __asm__ (
            "str x23, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x23(id obj) {
        __asm__ (
            "str x23, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x24(id obj) {
        __asm__ (
            "str x24, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x24(id obj) {
        __asm__ (
            "str x24, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x25(id obj) {
        __asm__ (
            "str x25, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x25(id obj) {
        __asm__ (
            "str x25, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x26(id obj) {
        __asm__ (
            "str x26, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x26(id obj) {
        __asm__ (
            "str x26, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x27(id obj) {
        __asm__ (
            "str x27, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x27(id obj) {
        __asm__ (
            "str x27, [sp, #8]"
        );
        objc_release(obj);
    }

    id objc_retain_x28(id obj) {
        __asm__ (
            "str x28, [sp, #8]"
        );
        return objc_retain(obj);
    }

    void objc_release_x28(id obj) {
        __asm__ (
            "str x28, [sp, #8]"
        );
        objc_release(obj);
    }
}

#include <iostream>
#include <cassert>

void operator delete(void *ptr, size_t size, std::align_val_t alignment) _NOEXCEPT {
    free(ptr);
}

void operator delete[](void *ptr, std::align_val_t alignment) _NOEXCEPT {
    free(ptr);
}

void operator delete(void *ptr, std::align_val_t alignment) _NOEXCEPT {
    free(ptr);
}

void *operator new(size_t size, std::align_val_t alignment) {
    void *ptr = NULL;
    int ret = posix_memalign(&ptr, (size_t) alignment, size);
    assert(ret == 0);
    return ptr;
}

void *operator new[](size_t size, std::align_val_t alignment) {
    return operator new(size, alignment);
}

void *operator new[](size_t size, std::align_val_t alignment, std::nothrow_t const& throw_t) _NOEXCEPT {
    return operator new(size, alignment);
}

void *operator new(size_t size, std::align_val_t alignment, std::nothrow_t const& throw_t) _NOEXCEPT {
    return operator new(size, alignment);
}
