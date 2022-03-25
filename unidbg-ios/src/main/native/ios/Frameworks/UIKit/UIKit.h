#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import "../frameworks.h"

typedef NSString *NSNotificationName;
const NSNotificationName UIApplicationDidReceiveMemoryWarningNotification = @"UIApplicationDidReceiveMemoryWarningNotification";
const NSNotificationName UIApplicationDidEnterBackgroundNotification = @"UIApplicationDidEnterBackgroundNotification";
const NSNotificationName UIApplicationDidBecomeActiveNotification = @"UIApplicationDidBecomeActiveNotification";
const NSNotificationName UIApplicationWillEnterForegroundNotification = @"UIApplicationWillEnterForegroundNotification";
const NSNotificationName UIApplicationWillResignActiveNotification = @"UIApplicationWillResignActiveNotification";
const NSNotificationName UIApplicationWillTerminateNotification = @"UIApplicationWillTerminateNotification";
const NSNotificationName UIApplicationDidFinishLaunchingNotification = @"UIApplicationDidFinishLaunchingNotification";
const NSNotificationName UIApplicationDidChangeStatusBarOrientationNotification = @"UIApplicationDidChangeStatusBarOrientationNotification";
const NSNotificationName UIApplicationDidChangeStatusBarFrameNotification = @"UIApplicationDidChangeStatusBarFrameNotification";
const NSNotificationName UIApplicationSignificantTimeChangeNotification = @"UIApplicationSignificantTimeChangeNotification";
const NSNotificationName UIApplicationWillChangeStatusBarOrientationNotification = @"UIApplicationWillChangeStatusBarOrientationNotification";
const NSNotificationName UIApplicationWillChangeStatusBarFrameNotification = @"UIApplicationWillChangeStatusBarFrameNotification";
const NSNotificationName UIApplicationBackgroundRefreshStatusDidChangeNotification = @"UIApplicationBackgroundRefreshStatusDidChangeNotification";
const NSNotificationName UIApplicationProtectedDataWillBecomeUnavailable = @"UIApplicationProtectedDataWillBecomeUnavailable";
const NSNotificationName UIApplicationProtectedDataDidBecomeAvailable = @"UIApplicationProtectedDataDidBecomeAvailable";
const NSNotificationName UIApplicationUserDidTakeScreenshotNotification = @"UIApplicationUserDidTakeScreenshotNotification";
const NSNotificationName UIAccessibilityVoiceOverStatusChanged = @"UIAccessibilityVoiceOverStatusChanged";
const NSNotificationName UIKeyboardWillShowNotification = @"UIKeyboardWillShowNotification";
const NSNotificationName UIKeyboardWillHideNotification = @"UIKeyboardWillHideNotification";
const NSNotificationName NSProcessInfoThermalStateDidChangeNotification = @"NSProcessInfoThermalStateDidChangeNotification";
const NSNotificationName NSProcessInfoPowerStateDidChangeNotification = @"NSProcessInfoPowerStateDidChangeNotification";
const NSNotificationName UIDeviceBatteryStateDidChangeNotification = @"UIDeviceBatteryStateDidChangeNotification";

typedef NSString *UIApplicationLaunchOptionsKey;
const UIApplicationLaunchOptionsKey UIApplicationLaunchOptionsLocalNotificationKey = @"UIApplicationLaunchOptionsLocalNotificationKey";
const UIApplicationLaunchOptionsKey UIApplicationLaunchOptionsRemoteNotificationKey = @"UIApplicationLaunchOptionsRemoteNotificationKey";
const UIApplicationLaunchOptionsKey UIApplicationLaunchOptionsURLKey = @"UIApplicationLaunchOptionsURLKey";

typedef CGFloat UIScrollViewDecelerationRate;
const UIScrollViewDecelerationRate UIScrollViewDecelerationRateNormal = 0.0;
const UIScrollViewDecelerationRate UIScrollViewDecelerationRateFast = 0.0;

typedef CGFloat UIWindowLevel;
const UIWindowLevel UIWindowLevelNormal = 0.0;

typedef double NSTimeInterval;
const NSTimeInterval UIApplicationBackgroundFetchIntervalMinimum = 0.0;

typedef enum UIApplicationState : NSInteger {
    UIApplicationStateActive,
    UIApplicationStateInactive,
    UIApplicationStateBackground
} UIApplicationState;

typedef enum UIUserInterfaceStyle : NSInteger {
    UIUserInterfaceStyleUnspecified,
    UIUserInterfaceStyleLight,
    UIUserInterfaceStyleDark
} UIUserInterfaceStyle;

typedef struct UIEdgeInsets {
    CGFloat top, left, bottom, right;  // specify amount to inset (positive) for each of the edges. values can be negative to 'outset'
} UIEdgeInsets;

const UIEdgeInsets UIEdgeInsetsZero = { 0.0, 0.0, 0.0, 0.0 };

typedef enum UIViewAutoresizing : NSUInteger {
    UIViewAutoresizingNone
} UIViewAutoresizing;

@interface UITraitCollection : NSObject
@property(nonatomic) UIUserInterfaceStyle userInterfaceStyle;
@end

@interface UIColor : NSObject
- (UIColor *)initWithDynamicProvider:(UIColor * (^)(UITraitCollection *traitCollection))dynamicProvider;
- (UIColor *)resolvedColorWithTraitCollection:(UITraitCollection *)traitCollection;
- (CGColorRef)CGColor;
- (void)setFill;
@end

@interface UIImageAsset : NSObject
@end

@interface UIResponder : NSObject
@end

@interface UIView : UIResponder
@property(nonatomic) BOOL accessibilityViewIsModal;
@property(nonatomic, retain) UIColor *backgroundColor;
@property(nonatomic) CGRect frame;
@property(nonatomic, getter=isHidden) BOOL hidden;
@property(nonatomic, readonly) UIView *superview;
@property(nonatomic) UIViewAutoresizing autoresizingMask;
- (id)initWithFrame:(CGRect)rect;
- (void)setAccessibilityViewIsModal:(BOOL)flag;
- (void)setOverrideUserInterfaceStyle:(UIUserInterfaceStyle)style;
- (CGPoint)convertPoint:(CGPoint)point fromView:(UIView *)view;
@end

@interface UIViewController : UIResponder
@property(nonatomic, copy) NSString *title;
@property(nonatomic, strong) UIView *view;
@end

@interface UIWindow : UIView
@property(nonatomic) UIWindowLevel windowLevel;
@property(nonatomic, strong) UIViewController *rootViewController;
- (void)makeKeyAndVisible;
@end

typedef enum UIInterfaceOrientation : NSInteger {
    UIInterfaceOrientationUnknown,
    UIInterfaceOrientationPortrait,
} UIInterfaceOrientation;

typedef enum UIStatusBarStyle : NSInteger {
    UIStatusBarStyleDefault,
} UIStatusBarStyle;

@interface UIApplication : NSObject

@property(nonatomic, getter=isStatusBarHidden) BOOL statusBarHidden;
@property(nonatomic) UIStatusBarStyle statusBarStyle;
@property(nonatomic, getter=isIgnoringInteractionEvents) BOOL ignoringInteractionEvents;
@property(nonatomic, getter=isProtectedDataAvailable) BOOL protectedDataAvailable;
@property(nonatomic) NSInteger applicationIconBadgeNumber;

+ (UIApplication *)sharedApplication;

- (id)delegate;

- (UIApplicationState)applicationState;

- (UIInterfaceOrientation)statusBarOrientation;

- (CGRect)statusBarFrame;

- (void)setMinimumBackgroundFetchInterval:(NSTimeInterval)minimumBackgroundFetchInterval;

- (NSArray *)windows;

- (void)beginIgnoringInteractionEvents;

- (void)registerForRemoteNotifications;

@end

@protocol UIApplicationDelegate<NSObject>
- (UIWindow *)window;
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions;
@end

@interface MyUIApplicationDelegate <UIApplicationDelegate> : NSObject
- (id) m_appViewControllerMgr;
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

@interface NSURLSessionConfiguration (CFNetwork)
+ (NSURLSessionConfiguration *)defaultSessionConfiguration;
@end

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunguarded-availability-new"
@interface NSProcessInfo (Foundation)
- (NSOperatingSystemVersion) operatingSystemVersion;
- (NSProcessInfoThermalState) thermalState;
@end
#pragma clang diagnostic pop

@interface NSTimerInvocation : NSObject
@property(nonatomic, copy) void (^block)(NSTimer *timer);
+ (NSTimerInvocation *)invocationWithBlock: (void (^)(NSTimer *timer))block;
- (void) callWithTimer: (NSTimer *) timer;
@end

@interface NSTimer (Foundation)
+ (NSTimer *)timerWithTimeInterval:(NSTimeInterval)interval repeats:(BOOL)repeats block:(void (^)(NSTimer *timer))block;
- (void) callWithInvocation: (NSTimerInvocation *) invocation;
@end

@interface NSURLSession (CFNetwork)
+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration;
+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration delegate:(id)delegate delegateQueue:(NSOperationQueue *)queue;
@end

@interface UIScreen : NSObject
@property(nonatomic, readonly, getter=isCaptured) BOOL captured;
+ (UIScreen *)mainScreen;
- (CGRect)bounds;
- (CGFloat)scale;
- (CGFloat)nativeScale;
@end

@protocol UIAccessibilityIdentification
@property(nonatomic, copy) NSString *accessibilityIdentifier;
@end

@interface UIImage : NSObject <UIAccessibilityIdentification>
@property(nonatomic) CGImageRef CGImage;
@end

id __NSArray0__;

@interface UICollectionReusableView : UIView
@end

@interface UICollectionViewCell : UICollectionReusableView
@end

@interface UITableViewController : UIViewController
@end

@interface LSResourceProxy : NSObject
@end

@interface LSApplicationProxy : LSResourceProxy <NSSecureCoding>
@property(nonatomic, copy) NSString *identifier;
@end
