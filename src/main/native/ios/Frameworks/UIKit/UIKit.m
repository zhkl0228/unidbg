#import "UIKit.h"

int UIApplicationMain(int argc, char *argv, NSString *principalClassName, NSString *delegateClassName) {
  id delegate = nil;
  if(delegateClassName) {
    Class delegateClass = NSClassFromString(delegateClassName);
    delegate = [[delegateClass alloc] init];
  }
  NSLog(@"UIApplicationMain argc=%d, argv=%p, principalClassName=%@, delegateClassName=%@, delegate=%@", argc, argv, principalClassName, delegateClassName, delegate);
  return 0;
}

const CGRect _frame = { 0, 0, 768, 1024 };

@implementation UIWindow
- (CGRect)frame {
    return _frame;
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
    return [[UIApplication alloc] init];
}

- (id)init {
    if(self = [super init]) {
        self.statusBarHidden = YES;
    }
    return self;
}

- (id)delegate {
    return [[MyUIApplicationDelegate alloc] init];
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
