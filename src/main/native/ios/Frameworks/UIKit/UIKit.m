#import "UIKit.h"

static id delegate = nil;

int UIApplicationMain(int argc, char *argv[], NSString *principalClassName, NSString *delegateClassName) {
  if(delegateClassName) {
    Class delegateClass = NSClassFromString(delegateClassName);
    delegate = [[delegateClass alloc] init];
  }
  NSLog(@"UIApplicationMain argc=%d, argv=%p, principalClassName=%@, delegateClassName=%@, delegate=%@", argc, argv, principalClassName, delegateClassName, delegate);
  if(delegate && argc == 3 && strcmp(argv[1], "call") == 0 && strcmp(argv[2], "didFinishLaunchingWithOptions") == 0) {
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
    return @"7.1";
}
- (NSString *)model {
    return @"iPhone";
}
- (NSString *)systemName {
    return @"iPhone OS";
}
- (NSUUID *)identifierForVendor {
    NSUUID *uuid = [NSUUID alloc];
    [uuid initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
    return uuid;
}
- (NSString *)name {
    return @"iPhone5S";
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
