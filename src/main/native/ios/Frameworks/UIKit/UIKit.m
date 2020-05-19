#import "UIKit.h"

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
