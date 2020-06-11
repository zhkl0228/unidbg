#import "objc.h"
#import <stdio.h>
#import <dlfcn.h>
#import <objc/runtime.h>

static BOOL isSystemClass(Class clazz) {
	void *address = (__bridge void *)clazz;

	if(!address) {
		return NO;
	}

	Dl_info info;
	int success = dladdr(address, &info);
	if(!success) {
	  return NO;
	}

	const char *libpath = info.dli_fname;
	const char *system_path = "/System/Library/";
	const char *libobjc_path = "/usr/lib/libobjc.A.dylib";

	if(strncmp(system_path, libpath, sizeof(system_path) - 1) == 0 || strncmp(libobjc_path, libpath, sizeof(libobjc_path) - 1) == 0) {
		return YES;
	} else {
		return NO;
	}
}

objc_msg_function old_objc_msgSend = NULL;

objc_msgSend_callback callback = NULL;

uintptr_t pre_objc_msgSend(id self, SEL _cmd, va_list args) {
  uintptr_t lr = 1;
#if defined(__arm__)
  __asm__(
    "mov %[LR], r12\n"
    :[LR]"=r"(lr)
  );
#elif defined(__aarch64__)
  __asm__(
    "mov %[LR], x12\n"
    :[LR]"=r"(lr)
  );
#endif
  Class class = object_getClass(self);
  bool systemClass = isSystemClass(class);
  if(callback) {
    callback(systemClass, class ? class_getName(class) : NULL, sel_getName(_cmd), lr);
  } else {
    char buf[512];
    print_lr(buf, lr);
    if(class) {
      if(!systemClass) {
        printf("objc_msgSend called [%s %s] from %s\n", class_getName(class), sel_getName(_cmd), buf);
      }
    } else {
      fprintf(stderr, "objc_msgSend called [%s] from %s\n", sel_getName(_cmd), buf);
    }
  }
  return (uintptr_t) old_objc_msgSend;
}
