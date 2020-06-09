#import <string.h>
#import <sys/sysctl.h>

static inline long get_lr_reg() {
  long lr = 0;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  return lr;
}

static inline int is_debug() {
  int mib[2];
  int values[2];
  size_t size = sizeof(values);

  // Logger.getLogger("com.github.unidbg.ios.debug").setLevel(Level.DEBUG);
  char *name = "unidbg.debug";
  mib[0] = CTL_UNSPEC;
  mib[1] = 3;
  return sysctl(mib, 2, values, &size, name, strlen(name));
}
