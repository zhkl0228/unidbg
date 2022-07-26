#include <stdio.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <Foundation/Foundation.h>

@interface TestObjc : NSObject
-(void) test;
@end

@implementation TestObjc
+(void) load {
  NSLog(@"TestObjc.load");
}
+(void) initialize {
  NSLog(@"TestObjc.initialize");
}
-(id) init {
  NSLog(@"TestObjc.init");
  return [super init];
}
-(void) test {
  NSLog(@"%@ test", self);
}
@end

__attribute__((naked))
int test_ldadd(int *p) {
  __asm__ volatile(
    "sub sp, sp, #0x10\n"
    "stp x29, x30, [sp]\n"

    "mov x8, x0\n"

    "mov w9, #1\n"
    "ldadd w9, w8, [x8]\n"

    "mov w0, w8\n"
    "ldp x29, x30, [sp]\n"
    "add sp, sp, #0x10\n"
    "ret\n"
  );
}

static void map_images(unsigned count, const char * const paths[],
                       const struct mach_header * const mhdrs[]) {
    for(int i = 0; i < count; i++) {
        NSLog(@"map_images i=%d, path=%s, mh=%p", i, paths[i], mhdrs[i]);
    }
}

static void load_images(const char *path, const struct mach_header *mh) {
    NSLog(@"load_images path=%s, mh=%p", path, mh);
}

static void unmap_image(const char *path, const struct mach_header *mh) {
    NSLog(@"unmap_image path=%s, mh=%p", path, mh);
}

typedef void (*_dyld_objc_notify_mapped)(unsigned count, const char* const paths[], const struct mach_header* const mh[]);
typedef void (*_dyld_objc_notify_init)(const char* path, const struct mach_header* mh);
typedef void (*_dyld_objc_notify_unmapped)(const char* path, const struct mach_header* mh);

//
// Note: only for use by objc runtime
// Register handlers to be called when objc images are mapped, unmapped, and initialized.
// Dyld will call back the "mapped" function with an array of images that contain an objc-image-info section.
// Those images that are dylibs will have the ref-counts automatically bumped, so objc will no longer need to
// call dlopen() on them to keep them from being unloaded.  During the call to _dyld_objc_notify_register(),
// dyld will call the "mapped" function with already loaded objc images.  During any later dlopen() call,
// dyld will also call the "mapped" function.  Dyld will call the "init" function when dyld would be called
// initializers in that image.  This is when objc calls any +load methods in that image.
//
extern void _dyld_objc_notify_register(_dyld_objc_notify_mapped    mapped,
                                _dyld_objc_notify_init      init,
                                _dyld_objc_notify_unmapped  unmapped);

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  NSLog(@"A12Z double=%lu, long double=%lu, long=%lu", sizeof(double), sizeof(long double), sizeof(long));
  printf("hello world A12Z, double=%lu, long double=%lu, long=%lu\n", sizeof(double), sizeof(long double), sizeof(long));

  int v = 0x88;
  int ret = test_ldadd(&v);
  printf("Test v=0x%x, ret=0x%x\n", v, ret);

  char vc;
  short vs;
  int vi;
  long vl;
  float vf;
  double vd;
  printf("Memory test: vc[%p]=0x%x, vs[%p]=0x%x, vi[%p]=0x%x, vl[%p]=0x%lx, vf[%p]=%f, vd[%p]=%lf\n", &vc, vc, &vs, vs, &vi, vi, &vl, vl, &vf, vf, &vd, vd);

  NSLog(@"a12z _dyld_objc_notify_register=%p, map_images=%p", &_dyld_objc_notify_register, &map_images);
  // _dyld_objc_notify_register(&map_images, load_images, unmap_image);

  TestObjc *test = [TestObjc new];
  [test test];

  NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile: @"/System/Library/CoreServices/SystemVersion.plist"];
  NSLog(@"dict=%@", dict);

  NSUserDefaults *standardUserDefaults = [NSUserDefaults standardUserDefaults];
  NSLog(@"standardUserDefaults=%@", standardUserDefaults);
  return 0;
}
