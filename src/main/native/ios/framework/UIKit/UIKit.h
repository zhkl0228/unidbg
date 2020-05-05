#import <Foundation/Foundation.h>

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

@interface UIApplication : NSObject

+ (UIApplication *)sharedApplication;

- (UIApplicationState)applicationState;

@end
