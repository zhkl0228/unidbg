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
  long lr = 0;
#if defined(__arm__)
  __asm__(
    "mov %[LR], r9\n"
    :[LR]"=r"(lr)
  );
#elif defined(__aarch64__)
  __asm__(
    "mov %[LR], x9\n"
    :[LR]"=r"(lr)
  );
#endif
  Dl_info info;
  info.dli_fname = NULL;
  int success = dladdr((const void *) lr, &info);
  long offset = success ? lr - (long) info.dli_fbase : lr;
  const char *name = info.dli_fname;
  if(name) {
    const char* find = name;
    while(true) {
      const char *next = strchr(find, '/');
      if(next) {
        find = &next[1];
      } else {
        break;
      }
    }
    if(find) {
      name = find;
    }
  }
  Class class = object_getClass(self);
  bool systemClass = isSystemClass(class);
  if(callback) {
    callback(systemClass, class ? class_getName(class) : NULL, sel_getName(_cmd), lr);
  } else {
    if(class) {
      if(!systemClass) {
        printf("objc_msgSend called [%s %s] from [%s]%p\n", class_getName(class), sel_getName(_cmd), name, (void *) offset);
      }
    } else {
      fprintf(stderr, "objc_msgSend called [%s] from [%s]%p\n", sel_getName(_cmd), name, (void *) offset);
    }
  }
  return (uintptr_t) old_objc_msgSend;
}
