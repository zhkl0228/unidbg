#include <objc/runtime.h>
#import <Foundation/Foundation.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <UIKit/UIKit.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <Security/Security.h>
#import <AVFoundation/AVFoundation.h>
#include "test.h"

@interface BootstrapTest : NSObject {}
-(void)testObjc;
@end

static CFMutableDictionaryRef makeDictionary() {
  const static int one = 1;

  CFStringRef array[] = { CFSTR("*.local"), CFSTR("169.254/16") };
  CFArrayRef arrayRef = CFArrayCreate(NULL, (void *)array, (CFIndex) 2, NULL);
  CFNumberRef ftpPassive = CFNumberCreate(NULL, kCFNumberSInt32Type, (const void *) &one);

  CFStringRef en_keys[] = { CFSTR("ExceptionsList"), CFSTR("FTPPassive") };
  CFTypeRef en_values[] = { arrayRef, ftpPassive };
  CFDictionaryRef en = CFDictionaryCreate(NULL, (const void**) en_keys, (const void**) en_values, (CFIndex) 2, NULL, NULL);

  CFStringRef scope_keys[] = { CFSTR("awdl0"), CFSTR("en0") };
  CFDictionaryRef scope_values[] = { en, en };
  CFDictionaryRef scope = CFDictionaryCreate(NULL, (const void**) scope_keys, (const void**) scope_values, (CFIndex) 2, NULL, NULL);

  CFMutableDictionaryRef dict = CFDictionaryCreateMutable(NULL, (CFIndex) 0, NULL, NULL);
  CFDictionarySetValue(dict, CFSTR("__SCOPED__"), scope);
  return dict;
}

@implementation BootstrapTest
-(void) testObjc {
  CTTelephonyNetworkInfo *info = [[CTTelephonyNetworkInfo alloc]init];
  CTCarrier *carrier = [info subscriberCellularProvider];
  NSLog(@"CTTelephonyNetworkInfo: carrier=%@", carrier);

  NSString *scope_key = [[NSString alloc] initWithCString: "__SCOPED__" encoding: NSUTF8StringEncoding];

  NSDictionary *dictionary = (__bridge NSDictionary*) makeDictionary();
  NSLog(@"CFNetworkCopySystemProxySettings __SCOPED__=%@, dictionary=%@", [dictionary objectForKey: scope_key], dictionary);

  NSMutableDictionary *proxySettings = (__bridge NSMutableDictionary*) CFNetworkCopySystemProxySettings();
  proxySettings = (__bridge NSMutableDictionary*) CFNetworkCopySystemProxySettings();

  id scoped = [proxySettings objectForKey: scope_key];
  id exceptionsList = proxySettings[@"ExceptionsList"];
  if(scoped == nil) {
    [proxySettings setObject: @"__SCOPED__values" forKey: @"__SCOPED__"];
  }
  NSLog(@"CFNetworkCopySystemProxySettings __SCOPED__=%@, ExceptionsList=%@, FTPPassive=%@, proxySettings=%@", scoped, exceptionsList, proxySettings[@"FTPPassive"], proxySettings);
  NSLog(@"CFNetworkCopySystemProxySettings allKeys=%@, count=%lu, key=%@, pointer=%p", [proxySettings allKeys], (unsigned long) [proxySettings count], scope_key, scope_key);
  for(id key in [proxySettings allKeys]) {
    id value = [proxySettings objectForKey: key];
    NSLog(@"CFNetworkCopySystemProxySettings key=%@, value=%@, class=%@, pointer=%p", key, value, [key class], key);
  }

  NSMutableDictionary *mutableDict = [NSMutableDictionary dictionaryWithCapacity: 8];
  [mutableDict setObject: @"Hello, World!" forKey: @"__SCOPED__"];
  [mutableDict setObject: @"Test" forKey: scope_key];
  NSLog(@"CFNetworkCopySystemProxySettings mutableDict=%@, value=%@", mutableDict, [mutableDict objectForKey: scope_key]);

  CFStringRef keys[] = { CFSTR("__SCOPED__") };
  CFTypeRef values[] = { CFSTR("FTPPassive") };
  NSDictionary *dict = (__bridge NSDictionary*) CFDictionaryCreate(NULL, (const void**) keys, (const void**) values, (CFIndex) 1, NULL, NULL);
  NSString *key = [[NSString alloc] initWithCString: "__SCOPED__" encoding: NSUTF8StringEncoding];
  NSLocale *locale = [NSLocale currentLocale];
  NSString *countryCode = [locale objectForKey: NSLocaleCountryCode];
  NSString *languageCode = [locale objectForKey: NSLocaleLanguageCode];
  NSLog(@"NSDictionary dict=%@, value=%@, countryCode=%@, languageCode=%@", dict, [dict objectForKey: key], countryCode, languageCode);
}
-(NSString *) description {
  return @"This is ObjC TEST";
}
@end

static BOOL isSystemClass(Class clazz) {
  const char *name = class_getName(clazz);
  const char *cmp_name = name;

  while(*cmp_name == '_') {
    cmp_name++;
  }
  if(strncmp("NS", cmp_name, 2) == 0 || strncmp("CF", cmp_name, 2) == 0 || strncmp("OS", cmp_name, 2) == 0 || strncmp("DD", cmp_name, 2) == 0 || strncmp("MD", cmp_name, 2) == 0 || strncmp("XN", cmp_name, 2) == 0) {
    return YES;
  }

  void *address = (__bridge void *)clazz;
  if(!address) {
    return NO;
  }

  Dl_info info;
  dladdr(address, &info);
  const char *libpath = info.dli_fname;
  const char *system_path = "/System/Library/";
  const char *libobjc_path = "/usr/lib/libobjc.A.dylib";
  if(strncmp(system_path, libpath, sizeof(system_path) - 1) == 0 || strncmp(libobjc_path, libpath, sizeof(libobjc_path) - 1) == 0) {
    return YES;
  } else {
    return NO;
  }
}

static void test_UIKit() {
  NSLog(@"UIApplicationDidReceiveMemoryWarningNotification=%@", UIApplicationDidReceiveMemoryWarningNotification);
  NSLog(@"UIApplicationDidEnterBackgroundNotification=%@", UIApplicationDidEnterBackgroundNotification);
  NSLog(@"UIApplicationDidFinishLaunchingNotification=%@", UIApplicationDidFinishLaunchingNotification);
  NSLog(@"UIApplicationBackgroundFetchIntervalMinimum=%f", UIApplicationBackgroundFetchIntervalMinimum);
  NSLog(@"CTRadioAccessTechnologyLTE=%@", CTRadioAccessTechnologyLTE);

  NSString *path = [[NSBundle mainBundle] bundlePath];
  NSString *documentPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
  NSString *cachePath = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).firstObject;
  NSString *supportPath = [NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,   NSUserDomainMask, YES) objectAtIndex:0];
  NSString *tmpPath = NSTemporaryDirectory();
  NSString *homePath = NSHomeDirectory();
  NSLog(@"test_UIKit bundlePath=%@, documentPath=%@, cachePath=%@, supportPath=%@, tmpPath=%@, homePath=%@", path, documentPath, cachePath, supportPath, tmpPath, homePath);

  NSFileManager* fm = [NSFileManager defaultManager];
  printf("NSFileManager defaultManager\n");
  NSArray *files = [fm subpathsAtPath: tmpPath];
  printf("NSFileManager subpathsAtPath, count=%lu\n", (unsigned long) files.count);
  for (int i = 0;  i < files.count; ++i) {
    id object = files[i];
    NSLog(@"test_NSFileManager file=%@", object);
  }
}

static void test_Bundle() {
  NSBundle *bundle = [NSBundle mainBundle];
  NSURL *url = [bundle appStoreReceiptURL];
  NSLog(@"bundle=%@, url=%@, path=%@", bundle, url, [url path]);
}

static void test_SCNetworkReachabilityGetFlags() {
  struct sockaddr_in zeroAddress;
  bzero(&zeroAddress, sizeof(zeroAddress));
  zeroAddress.sin_len = sizeof(zeroAddress);
  zeroAddress.sin_family = AF_INET;
  SCNetworkReachabilityRef defaultRouteReachability = SCNetworkReachabilityCreateWithAddress(NULL, (struct sockaddr *)&zeroAddress);
  SCNetworkReachabilityFlags flags = 0;
  bool didRetrieveFlags = SCNetworkReachabilityGetFlags(defaultRouteReachability, &flags);
  CFRelease(defaultRouteReachability);
  printf("test_SCNetworkReachabilityGetFlags didRetrieveFlags=%d, flags=0x%x, kSCNetworkFlagsReachable=0x%x, kSCNetworkFlagsConnectionRequired=0x%x, kSCNetworkReachabilityFlagsIsWWAN=0x%x, kSCNetworkReachabilityFlagsIsLocalAddress=0x%x\n", didRetrieveFlags, flags, kSCNetworkFlagsReachable, kSCNetworkFlagsConnectionRequired, kSCNetworkReachabilityFlagsIsWWAN, kSCNetworkReachabilityFlagsIsLocalAddress);
}

static void test_Wifi() {
  CFArrayRef array = CNCopySupportedInterfaces();
  NSLog(@"test_Wifi array=%@", array);
}

static void test_Security() {
  NSLog(@"test_Security kSecClassGenericPassword=%@, kSecClass=%@, kSecAttrAccessGroup=%@, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly=%@", kSecClassGenericPassword, kSecClass, kSecAttrAccessGroup, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
  NSLog(@"test_Security AVAudioSessionOrientationBack=%@, AVAudioSessionPolarPatternCardioid=%@", AVAudioSessionOrientationBack, AVAudioSessionPolarPatternCardioid);
}

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  BootstrapTest *test = [[BootstrapTest alloc] init];

  NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
  dateFormatter.dateFormat = @"yyyy-MM-dd HH:mm:ss";
  NSDate *date = [NSDate date];
  NSString *str = [date description];
  NSLog(@"[%@]Hello, unidbg: %@, date=%@, NO=%lu", [dateFormatter stringFromDate:date], test, str, (unsigned long) NO);

  [test testObjc];

  int classCount = objc_getClassList(NULL, 0);
  __unsafe_unretained Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * classCount);
  objc_getClassList(classes, classCount);
  for(int i = 0; i < classCount; i++) {
    Class clazz = classes[i];
    if(!isSystemClass(clazz)) {
      NSLog(@"Loaded ObjC Class: %s", class_getName(clazz));
    }
  }
  free(classes);

  do_test();
  test_UIKit();
  test_Bundle();
  test_SCNetworkReachabilityGetFlags();
  test_Wifi();
  test_Security();

  return 0;
}
