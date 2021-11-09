#import <string.h>
#import <dlfcn.h>
#import <stdio.h>
#import <sys/sysctl.h>

static void print_lr(char *buf, uintptr_t lr) {
  Dl_info info;
  int success = dladdr((const void *) lr, &info);
  if(success) {
    long offset = lr - (long) info.dli_fbase;
    const char *name = info.dli_fname;
    const char *find = name;
    while(find) {
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
    sprintf(buf, "[%s]%p", name, (void *) offset);
  } else {
    sprintf(buf, "%p", (void *) lr);
  }
}

// Logger.getLogger("com.github.unidbg.ios.debug").setLevel(Level.DEBUG);
static int is_debug() {
  int mib[2];
  int values[2];
  size_t size = sizeof(values);

  char *name = "unidbg.debug";
  mib[0] = CTL_UNSPEC;
  mib[1] = 3;
  return sysctl(mib, 2, values, &size, name, strlen(name));
}
