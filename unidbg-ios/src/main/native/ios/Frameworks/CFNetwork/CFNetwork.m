#import "CFNetwork.h"
#import <stdio.h>
#import <CoreFoundation/CoreFoundation.h>

CFDictionaryRef CFNetworkCopySystemProxySettings() {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    fprintf(stderr, "CFNetworkCopySystemProxySettings LR=%s\n", buf);
  }

  id objects[] = { @"*.local", @"169.254/16" };
  NSArray *array = [NSArray arrayWithObjects:objects count:2];

  const int one = 1;
  CFNumberRef ftpPassive = CFNumberCreate(NULL, kCFNumberSInt32Type, (const void *) &one);

  id en_objects[] = { array, (__bridge NSNumber*) ftpPassive };
  id en_keys[] = { @"ExceptionsList", @"FTPPassive" };
  NSDictionary *en = [NSDictionary dictionaryWithObjects:en_objects forKeys:en_keys count:2];

  id scope_keys[] = { @"en0" };
  id scope_values[] = { en };
  NSDictionary *scope = [NSDictionary dictionaryWithObjects:scope_values forKeys:scope_keys count:1];

  NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithCapacity: 3];
  [dict setObject: array forKey: @"ExceptionsList"];
  [dict setObject: (__bridge NSNumber*) ftpPassive forKey: @"FTPPassive"];
  [dict setObject: scope forKey: @"__SCOPED__"];

  CFRelease(ftpPassive);
  return (__bridge CFDictionaryRef) dict;
}
