#import "UIKit.h"

@implementation UIApplication

+ (UIApplication *)sharedApplication {
    return [[UIApplication alloc] init];
}

- (UIApplicationState)applicationState {
    return UIApplicationStateActive;
}

@end
