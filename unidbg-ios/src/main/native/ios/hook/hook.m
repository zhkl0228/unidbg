#import <CydiaSubstrate/CydiaSubstrate.h>
#import <Foundation/Foundation.h>

NSInteger (*old_integerForKey)(id self, SEL _cmd, NSString *defaultName) = NULL;

NSInteger new_integerForKey(id self, SEL _cmd, NSString *defaultName) {
  NSInteger ret = old_integerForKey(self, _cmd, defaultName);
  NSLog(@"NSUserDefaults integerForKey defaultName=%@, ret=%ld", defaultName, (long) ret);
  return ret;
}

__attribute__((constructor))
void init() {
  NSLog(@"Initializing libhook");

  MSHookMessageEx([NSUserDefaults class], @selector(integerForKey:), (IMP) &new_integerForKey, (IMP *) &old_integerForKey);

  NSLog(@"Initialized libhook");
}
