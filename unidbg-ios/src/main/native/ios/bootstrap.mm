#include <objc/runtime.h>
#import <Foundation/Foundation.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <CoreTelephony/CTCall.h>
#import <UIKit/UIKit.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <SystemConfiguration/CaptiveNetwork.h>
#import <Security/Security.h>
#import <AVFoundation/AVFoundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#include <sys/mman.h>
#include "test.h"

@interface BootstrapTest : NSObject {}
-(void)testObjc;
@end

static CFMutableDictionaryRef makeDictionary() {
  const static int one = 1;

  CFStringRef array[] = { CFSTR("*.local"), CFSTR("169.254/16") };
  CFArrayRef arrayRef = CFArrayCreate(NULL, (const void **)array, (CFIndex) 2, NULL);
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
  NSLog(@"CTTelephonyNetworkInfo: carrier=%@, CTCallStateDisconnected=%@", carrier, CTCallStateDisconnected);

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

  NSUserDefaults *userDefault = [NSUserDefaults standardUserDefaults];
  id name = [userDefault objectForKey: @"name"];
  [userDefault setObject: @"unidbg" forKey: @"name"];
  BOOL success = [userDefault synchronize];
  NSLog(@"NSUserDefaults name=%@, synchronize=%d", name, success);

  NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
  NSLog(@"NSURLSessionConfiguration configuration=%@, NSUUID=%@", configuration, [[NSUUID new] UUIDString]);
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
  NSLog(@"test_UIKit bundlePath=%@, documentPath=%@[%p], cachePath=%@, supportPath=%@, tmpPath=%@, homePath=%@", path, documentPath, [documentPath UTF8String], cachePath, supportPath, tmpPath, homePath);

  NSFileManager* fm = [NSFileManager defaultManager];
  printf("NSFileManager defaultManager\n");
  NSArray *files = [fm subpathsAtPath: tmpPath];
  printf("NSFileManager subpathsAtPath, count=%lu\n", (unsigned long) files.count);
  for (int i = 0;  i < files.count; ++i) {
    id object = files[i];
    NSLog(@"test_NSFileManager file=%@", object);
  }

  path = [documentPath stringByAppendingPathComponent: @"WechatPrivate/wx.txt"];
  NSLog(@"NSFileManager fileExistsAtPath=%hhd, createFileAtPath=%hhd", [fm fileExistsAtPath: path], [fm createFileAtPath: path contents: [path dataUsingEncoding: NSUTF8StringEncoding] attributes: nil]);
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
  NSLog(@"test_Security AVAudioSessionOrientationBack=%@, AVAudioSessionRouteChangeNotification=%@", AVAudioSessionOrientationBack, AVAudioSessionRouteChangeNotification);
}

static void test_CoreGraphics(char *path) {
  CGDataProviderRef provider = CGDataProviderCreateWithFilename(path);
  NSLog(@"test_CoreGraphics provider=%p", provider);
  if(!provider) {
    return;
  }
  CGImageRef image = CGImageCreateWithPNGDataProvider(provider, NULL, true, kCGRenderingIntentDefault);
  size_t width = CGImageGetWidth(image);
  size_t height = CGImageGetHeight(image);
  CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
  int bitsPerComponent = 8;
  size_t bytesPerRow = width * 4;
  void *data = malloc(bytesPerRow * height);
  memset(data, 0, bytesPerRow * height);
  CGContextRef context = CGBitmapContextCreate(data, width, height, bitsPerComponent, bytesPerRow, colorSpace, kCGImageAlphaPremultipliedLast);
  CGRect rect = CGRectMake( 0.0, 0.0, width, height );
  CGContextDrawImage(context, rect, image);
  char *imageData = (char *) CGBitmapContextGetData(context);
  size_t bytes = CGBitmapContextGetBytesPerRow(context);
  NSLog(@"test_CoreGraphics data=%p, bytesPerRow=%lu, imageData=%p, bytes=%lu", data, bytesPerRow, imageData, bytes);
  for(int i = 0; i < height; i++) {
    char *row = &imageData[i * bytes];
    uint8_t buffer[CC_MD5_DIGEST_LENGTH];
    CC_MD5(row, (CC_LONG) bytes, buffer);
    NSMutableString *md5 = [NSMutableString string];
    for (int m = 0; m < CC_MD5_DIGEST_LENGTH; m++) {
      [md5 appendFormat:@"%02x", buffer[m]];
    }
    for(int m = 0; m < bytes; m++) {
      if(m % 45 == 0) {
        printf("\n%03d[%s]:", i, [md5 UTF8String]);
      }
      int val = row[m] & 0xff;
      printf(" %02x", val);
    }
  }
  printf("\n");
  CGContextRelease(context);
  free(data);
  CGColorSpaceRelease(colorSpace);
  CGDataProviderRelease(provider);
}

static void test_CommonDigest() {
  char key[16] = { 0xda, 0x5a, 0x18, 0xe9, 0x2, 0x76, 0xee, 0x6a, 0xc3, 0x9c, 0x25, 0x6a, 0x98, 0xcc, 0x20, 0x45 };
  char iv[16] = { 0x3e, 0x39, 0x4f, 0x62, 0x38, 0x3f, 0x53, 0x4d, 0x29, 0x46, 0x2e, 0x7b, 0x40, 0x65, 0x55, 0x35 };
  char data[16] = { 0xa5, 0x65, 0x42, 0xf3, 0xa9, 0x9, 0xff, 0xbc, 0x95, 0x53, 0xad, 0x34, 0xb3, 0xc0, 0x21, 0xf1 };
  char out[32];
  size_t outSize = 0;
  memset(out, 0, 32);
  CCCryptorStatus status = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, key, 16, iv, data, 16, out, 32, &outSize);
  NSLog(@"test_CommonDigest status=%d, outSize=%lu", status, outSize);
  fprintf(stderr, "test_CommonDigest outSize=%lu:", outSize);
  for(size_t i = 0; i < 16; i++) {
    fprintf(stderr, " %02x", out[i] & 0xff);
  }
  fprintf(stderr, "\n");
}

static void test_mmap() {
  void *addr = mmap(NULL, 0x4000 * 2, 0, 0x1002, -1, 0);
  void *fix = mmap(addr, 0x4000, 3, 0x1012, -1, 0);
  NSLog(@"test_mmap addr=%p, fix=%p", addr, fix);
}

static void test_NSException() {
  NSException *exce = [NSException exceptionWithName: @"UniException" reason: @"Test" userInfo: nil];
  NSArray *stackSymbols = [NSThread callStackSymbols];
  NSLog(@"test_NSException=%@, stackSymbols=%@", exce, stackSymbols);
  [exce raise];
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

  if(argc == 2) {
    test_CoreGraphics(argv[1]);
  }
  test_CommonDigest();
  test_mmap();
  @try {
    test_NSException();
  } @catch (NSException *exception) {
    NSLog(@"main: Caught %@: %@", [exception name], [exception reason]);
  }

  return 0;
}
