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

int UIApplicationMain(int argc, char *argv, NSString *principalClassName, NSString *delegateClassName) {
  NSLog(@"UIApplicationMain argc=%d, argv=%p, principalClassName=%@, delegateClassName=%@", argc, argv, principalClassName, delegateClassName);
  return 0;
}

@interface UIApplication : NSObject

+ (UIApplication *)sharedApplication;

- (UIApplicationState)applicationState;

@end
