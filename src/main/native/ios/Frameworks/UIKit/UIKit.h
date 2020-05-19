#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

const NSString *UIApplicationDidReceiveMemoryWarningNotification = @"UIApplicationDidReceiveMemoryWarningNotification";
const NSString *UIApplicationDidEnterBackgroundNotification = @"UIApplicationDidEnterBackgroundNotification";
const NSString *UIApplicationDidBecomeActiveNotification = @"UIApplicationDidBecomeActiveNotification";
const NSString *UIApplicationWillEnterForegroundNotification = @"UIApplicationWillEnterForegroundNotification";
const NSString *UIApplicationWillResignActiveNotification = @"UIApplicationWillResignActiveNotification";
const NSString *UIApplicationWillTerminateNotification = @"UIApplicationWillTerminateNotification";

typedef enum UIApplicationState : NSInteger {
    UIApplicationStateActive,
    UIApplicationStateInactive,
    UIApplicationStateBackground
} UIApplicationState;

int UIApplicationMain(int argc, char *argv, NSString *principalClassName, NSString *delegateClassName) {
  NSLog(@"UIApplicationMain argc=%d, argv=%p, principalClassName=%@, delegateClassName=%@", argc, argv, principalClassName, delegateClassName);
  return 0;
}

@protocol UIApplicationDelegate<NSObject>
@end

typedef enum UIInterfaceOrientation : NSInteger {
    UIInterfaceOrientationUnknown,
    UIInterfaceOrientationPortrait,
} UIInterfaceOrientation;

@interface UIApplication : NSObject

@property(nonatomic, assign) id<UIApplicationDelegate> delegate;
@property(nonatomic, getter=isStatusBarHidden) BOOL statusBarHidden;

+ (UIApplication *)sharedApplication;

- (UIApplicationState)applicationState;

- (UIInterfaceOrientation)statusBarOrientation;

- (CGRect)statusBarFrame;

@end

typedef enum UIDeviceBatteryState : NSInteger {
  UIDeviceBatteryStateUnknown,
  UIDeviceBatteryStateUnplugged,
  UIDeviceBatteryStateCharging,
  UIDeviceBatteryStateFull
} UIDeviceBatteryState;

@interface UIDevice : NSObject

@property(nonatomic, getter=isBatteryMonitoringEnabled) BOOL batteryMonitoringEnabled;

+ (UIDevice *)currentDevice;

- (NSString *)systemVersion;
- (NSString *)model;
- (NSUUID *)identifierForVendor;
- (NSString *)systemName;
- (NSString *)name;

- (UIDeviceBatteryState)batteryState;

@end

@interface NSString (Number)
- (unsigned int)unsignedIntValue;
@end

@interface UIViewController : NSObject
@end
