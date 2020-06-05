#import "UIKit.h"
#import "../AdSupport/AdSupport.h"
#import "../CoreTelephony/CoreTelephony.h"

static id delegate = nil;
static NSString *systemName = @"iPhone OS";
static NSString *systemVersion = @"7.1";
static NSString *model = @"iPhone";
static NSString *name = @"iPhone5S";
static NSString *identifierForVendor = @"00000000-0000-0000-0000-000000000000";

int UIApplicationMain(int argc, char *argv[], NSString *principalClassName, NSString *delegateClassName) {
  if(delegateClassName) {
    Class delegateClass = NSClassFromString(delegateClassName);
    delegate = [[delegateClass alloc] init];
  }
  if(argc != 3 || strcmp(argv[1], "-args") != 0) {
    NSLog(@"UIApplicationMain argc=%d, delegate=%@", argc, delegate);
    return 0;
  }
  NSString *json = [[NSString alloc] initWithCString: argv[2] encoding: NSUTF8StringEncoding];
  NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:[json dataUsingEncoding: NSUTF8StringEncoding] options:kNilOptions error:nil];
  NSLog(@"UIApplicationMain argc=%d, argv=%p, principalClassName=%@, delegateClassName=%@, delegate=%@, dict=%@", argc, argv, principalClassName, delegateClassName, delegate, dict);

  NSString *_systemName = dict[@"systemName"];
  if(_systemName) {
    systemName = [_systemName retain];
  }
  NSString *_systemVersion = dict[@"systemVersion"];
  if(_systemVersion) {
    systemVersion = [_systemVersion retain];
  }
  NSString *_model = dict[@"model"];
  if(_model) {
    model = [_model retain];
  }
  NSString *_name = dict[@"name"];
  if(_name) {
    name = [_name retain];
  }
  NSString *_identifierForVendor = dict[@"identifierForVendor"];
  if(_identifierForVendor) {
    identifierForVendor = [_identifierForVendor retain];
  }
  NSString *_advertisingIdentifier = dict[@"advertisingIdentifier"];
  if(_advertisingIdentifier) {
    ASIdentifierManager *asim = [ASIdentifierManager sharedManager];
    NSUUID *uuid = [NSUUID alloc];
    [uuid initWithUUIDString:_advertisingIdentifier];
    [asim setAdvertisingIdentifier: uuid];
  }
  NSString *_carrierName = dict[@"carrierName"];
  if(_carrierName) {
    CTTelephonyNetworkInfo *networkInfo = [CTTelephonyNetworkInfo new];
    CTCarrier *carrier = [networkInfo subscriberCellularProvider];
    [carrier setCarrierName: [_carrierName retain]];
  }

  NSNumber *callFinishLaunchingWithOptions = dict[@"callFinishLaunchingWithOptions"];
  if(delegate && [callFinishLaunchingWithOptions boolValue]) {
    UIApplication *application = [UIApplication sharedApplication];
    NSDictionary *options = [[NSDictionary alloc] init];
    [delegate application: application didFinishLaunchingWithOptions: options];
    NSLog(@"UIApplicationMain didFinishLaunchingWithOptions delegate=%@", delegate);
  }
  return 0;
}

const CGRect g_frame = { 0, 0, 768, 1024 };

@implementation UIScreen
+ (UIScreen *)mainScreen {
    return [[UIScreen alloc] init];
}
- (CGRect)bounds {
    return g_frame;
}
- (CGFloat)scale {
    return 1.0;
}
@end

@implementation UIColor
+ (UIColor *)clearColor {
    return [[UIColor alloc] init];
}
+ (UIColor *)colorWithRed:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha {
    return [[UIColor alloc] init];
}
+ (UIColor *)whiteColor {
    return [UIColor new];
}
+ (UIColor *)blackColor {
    return [UIColor new];
}
@end

@implementation UIView
- (id)initWithFrame:(CGRect)rect {
    if(self = [super init]) {
        self.frame = rect;
    }
    return self;
}
@end

@implementation UIWindow
- (id)init {
    if(self = [super init]) {
        self.frame = g_frame;
    }
    return self;
}
- (void)makeKeyAndVisible {
}
@end

@implementation MyUIApplicationDelegate
- (UIWindow *)window {
    return [[UIWindow alloc] init];
}
- (id) m_appViewControllerMgr {
    return nil;
}
@end

@implementation UIApplication

+ (UIApplication *)sharedApplication {
    static dispatch_once_t once;
    static id instance;
    dispatch_once(&once, ^{ instance = [[self alloc] init]; });
    return instance;
}

- (id)init {
    if(self = [super init]) {
        self.statusBarHidden = YES;
    }
    return self;
}

- (id)delegate {
    if(delegate) {
        return delegate;
    } else {
        return [[MyUIApplicationDelegate alloc] init];
    }
}

- (UIApplicationState)applicationState {
    return UIApplicationStateActive;
}

- (UIInterfaceOrientation)statusBarOrientation {
    return UIInterfaceOrientationPortrait;
}

- (CGRect)statusBarFrame {
    return CGRectZero;
}

- (void)setMinimumBackgroundFetchInterval:(NSTimeInterval)minimumBackgroundFetchInterval {
}

- (NSArray *)windows {
    return [[NSArray alloc] init];
}

@end

@implementation UIDevice

+ (UIDevice *)currentDevice {
    return [[UIDevice alloc] init];
}

- (id)init {
    if(self = [super init]) {
        self.batteryMonitoringEnabled = YES;
    }
    return self;
}

- (NSString *)systemVersion {
    return systemVersion;
}
- (NSString *)model {
    return model;
}
- (NSString *)systemName {
    return systemName;
}
- (NSUUID *)identifierForVendor {
    NSUUID *uuid = [NSUUID alloc];
    [uuid initWithUUIDString:identifierForVendor];
    return uuid;
}
- (NSString *)name {
    return name;
}

- (UIDeviceBatteryState)batteryState {
    return UIDeviceBatteryStateUnplugged;
}

@end

@implementation NSString (Number)
- (unsigned int)unsignedIntValue {
    int value = [self intValue];
    return (unsigned int) value;
}
@end

@implementation UIViewController
@end

@implementation UIResponder
@end
