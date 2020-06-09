#import <Foundation/Foundation.h>
#import <CydiaSubstrate/CydiaSubstrate.h>
#import <Fishhook/Fishhook.h>

NSInteger (*old_integerForKey)(id self, SEL _cmd, NSString *defaultName) = NULL;

NSInteger new_integerForKey(id self, SEL _cmd, NSString *defaultName) {
  NSInteger ret = old_integerForKey(self, _cmd, defaultName);
  NSLog(@"NSUserDefaults integerForKey defaultName=%@, ret=%ld", defaultName, (long) ret);
  return ret;
}

NSString *(*old_pathForResource)(id self, SEL _cmd, NSString *name, NSString *ext) = NULL;

NSString *new_pathForResource(id self, SEL _cmd, NSString *name, NSString *ext) {
  NSString *ret = old_pathForResource(self, _cmd, name, ext);
  NSLog(@"NSBundle pathForResource name=%@, ext=%@, ret=%@", name, ext, ret);
  return ret;
}

static int (*orig_close)(int);
static int (*orig_open)(const char *, int, ...);

int my_close(int fd) {
  printf("Calling real close(%d)\n", fd);
  return orig_close(fd);
}

int my_open(const char *path, int oflag, ...) {
  va_list ap = {0};
  mode_t mode = 0;

  if ((oflag & O_CREAT) != 0) {
    // mode only applies to O_CREAT
    va_start(ap, oflag);
    mode = va_arg(ap, int);
    va_end(ap);
    printf("Calling real open('%s', %d, %d)\n", path, oflag, mode);
    return orig_open(path, oflag, mode);
  } else {
    printf("Calling real open('%s', %d)\n", path, oflag);
    return orig_open(path, oflag, mode);
  }
}

__attribute__((constructor))
void init() {
  NSLog(@"Initializing libhook");

  rebind_symbols((struct rebinding[2]){{"close", my_close, (void *)&orig_close}, {"open", my_open, (void *)&orig_open}}, 2);

  MSHookMessageEx([NSUserDefaults class], @selector(integerForKey:), (IMP) &new_integerForKey, (IMP *) &old_integerForKey);
  MSHookMessageEx([NSBundle class], @selector(pathForResource:ofType:), (IMP) &new_pathForResource, (IMP *) &old_pathForResource);

  NSLog(@"Initialized libhook");
}
