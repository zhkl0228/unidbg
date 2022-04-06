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
const NSNotificationName UIAccessibilityDarkerSystemColorsStatusDidChangeNotification = @"UIAccessibilityDarkerSystemColorsStatusDidChangeNotification";
const NSNotificationName UIContentSizeCategoryDidChangeNotification = @"UIContentSizeCategoryDidChangeNotification";
const NSNotificationName UIDeviceBatteryLevelDidChangeNotification = @"UIDeviceBatteryLevelDidChangeNotification";

NSString *const NSExtensionHostDidEnterBackgroundNotification = @"NSExtensionHostDidEnterBackgroundNotification";
NSString *const NSExtensionHostDidBecomeActiveNotification = @"NSExtensionHostDidBecomeActiveNotification";

typedef NSString *UIApplicationLaunchOptionsKey;
const UIApplicationLaunchOptionsKey UIApplicationLaunchOptionsLocalNotificationKey = @"UIApplicationLaunchOptionsLocalNotificationKey";
const UIApplicationLaunchOptionsKey UIApplicationLaunchOptionsRemoteNotificationKey = @"UIApplicationLaunchOptionsRemoteNotificationKey";
const UIApplicationLaunchOptionsKey UIApplicationLaunchOptionsURLKey = @"UIApplicationLaunchOptionsURLKey";

typedef CGFloat UIScrollViewDecelerationRate;
const UIScrollViewDecelerationRate UIScrollViewDecelerationRateNormal = 0.0;
const UIScrollViewDecelerationRate UIScrollViewDecelerationRateFast = 0.0;

typedef CGFloat UIWindowLevel;
const UIWindowLevel UIWindowLevelNormal = 0.0;
const UIWindowLevel UIWindowLevelStatusBar = 0.0;

typedef double NSTimeInterval;
const NSTimeInterval UIApplicationBackgroundFetchIntervalMinimum = 0.0;

const size_t UIBackgroundTaskInvalid = 0;

typedef NSString *UIFontTextStyle;
const UIFontTextStyle UIFontTextStyleSubheadline = @"UIFontTextStyleSubheadline";
const UIFontTextStyle UIFontTextStyleCaption1 = @"UIFontTextStyleCaption1";
const UIFontTextStyle UIFontTextStyleBody = @"UIFontTextStyleBody";
const UIFontTextStyle UIFontTextStyleFootnote = @"UIFontTextStyleFootnote";
const UIFontTextStyle UIFontTextStyleTitle2 = @"UIFontTextStyleTitle2";
const UIFontTextStyle UIFontTextStyleCallout = @"UIFontTextStyleCallout";
const UIFontTextStyle UIFontTextStyleHeadline = @"UIFontTextStyleHeadline";

typedef NSString *UIFontDescriptorFeatureKey;
const UIFontDescriptorFeatureKey UIFontFeatureTypeIdentifierKey = @"UIFontFeatureTypeIdentifierKey";
const UIFontDescriptorFeatureKey UIFontFeatureSelectorIdentifierKey = @"UIFontFeatureSelectorIdentifierKey";

typedef NSString *UIFontDescriptorAttributeName;
const UIFontDescriptorAttributeName UIFontDescriptorFeatureSettingsAttribute = @"UIFontDescriptorFeatureSettingsAttribute";

typedef NSString *NSAttributedStringKey;
const NSAttributedStringKey NSForegroundColorAttributeName = @"NSForegroundColorAttributeName";

typedef NSString *NSURLResourceKey;
const NSURLResourceKey NSURLVolumeAvailableCapacityForImportantUsageKey = @"NSURLVolumeAvailableCapacityForImportantUsageKey";

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
- (UIColor *)colorWithAlphaComponent:(CGFloat)alpha;
- (UIColor *)initWithWhite:(CGFloat)white alpha:(CGFloat)alpha;
@end

@interface UIImageAsset : NSObject
@end

@interface UIResponder : NSObject
@end

@interface UIGestureRecognizer : NSObject
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
- (void)setAlpha: (CGFloat) alpha;
- (void)setClipsToBounds: (BOOL)flag;
- (void)addGestureRecognizer:(UIGestureRecognizer *)gestureRecognizer;
- (void)setTintColor:(UIColor *)tintColor;
- (UIView *)snapshotViewAfterScreenUpdates:(BOOL)afterUpdates;
@end

@interface UINavigationItem : NSObject
@end

@interface UIViewController : UIResponder
@property(nonatomic, copy) NSString *title;
@property(nonatomic, strong) UIView *view;
@property(nonatomic, copy) NSString *nibName;
@property(nonatomic, strong) NSBundle *nibBundle;
@property(nonatomic, strong) UINavigationItem *navigationItem;
- (UIViewController *)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil;
- (void)setExtendedLayoutIncludesOpaqueBars: (BOOL)flag;
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

typedef enum UIBackgroundRefreshStatus : NSInteger {
    UIBackgroundRefreshStatusRestricted,
    UIBackgroundRefreshStatusDenied,
    UIBackgroundRefreshStatusAvailable
} UIBackgroundRefreshStatus;

@interface UIEvent : NSObject
@end

@interface UIApplication : NSObject

@property(nonatomic, getter=isStatusBarHidden) BOOL statusBarHidden;
@property(nonatomic) UIStatusBarStyle statusBarStyle;
@property(nonatomic, getter=isIgnoringInteractionEvents) BOOL ignoringInteractionEvents;
@property(nonatomic, getter=isProtectedDataAvailable) BOOL protectedDataAvailable;
@property(nonatomic) NSInteger applicationIconBadgeNumber;
@property(nonatomic) UIBackgroundRefreshStatus backgroundRefreshStatus;

+ (UIApplication *)sharedApplication;

- (id)delegate;

- (UIApplicationState)applicationState;

- (UIInterfaceOrientation)statusBarOrientation;

- (CGRect)statusBarFrame;

- (void)setMinimumBackgroundFetchInterval:(NSTimeInterval)minimumBackgroundFetchInterval;

- (NSArray *)windows;

- (void)beginIgnoringInteractionEvents;

- (void)registerForRemoteNotifications;

- (BOOL)sendAction:(SEL)action to:(id)target from:(id)sender forEvent:(UIEvent *)event;

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

typedef enum UIUserInterfaceIdiom : NSInteger {
    UIUserInterfaceIdiomUnspecified,
    UIUserInterfaceIdiomPhone
} UIUserInterfaceIdiom;

@interface UIDevice : NSObject

@property(nonatomic, getter=isBatteryMonitoringEnabled) BOOL batteryMonitoringEnabled;
@property(nonatomic) UIUserInterfaceIdiom userInterfaceIdiom;
@property(nonatomic) float batteryLevel;

+ (UIDevice *)currentDevice;

- (NSString *)systemVersion;
- (NSString *)model;
- (NSUUID *)identifierForVendor;
- (NSString *)systemName;
- (NSString *)name;

- (UIDeviceBatteryState)batteryState;

@end

@interface NSString (Fix)
- (unsigned int)unsignedIntValue;
- (BOOL)containsString:(NSString *)str;
@end

@interface NSURLSessionConfiguration (CFNetwork)
+ (NSURLSessionConfiguration *)defaultSessionConfiguration;
+ (NSURLSessionConfiguration *)ephemeralSessionConfiguration;
+ (NSURLSessionConfiguration *)backgroundSessionConfigurationWithIdentifier:(NSString *)identifier;
- (void) setShouldUseExtendedBackgroundIdleMode: (BOOL) flag;
@end

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunguarded-availability-new"
@interface NSProcessInfo (Foundation)
- (NSOperatingSystemVersion) operatingSystemVersion;
- (NSProcessInfoThermalState) thermalState;
- (BOOL) isLowPowerModeEnabled;
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

@interface NSOperationQueue (Foundation)
- (void) setQualityOfService: (NSQualityOfService) qualityOfService;
- (void) setUnderlyingQueue: (dispatch_queue_t) queue;
@end

@interface NSDateFormatter (Foundation)
- (void)setLocalizedDateFormatFromTemplate:(NSString *)dateFormatTemplate;
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

BOOL UIAccessibilityDarkerSystemColorsEnabled();

@protocol UIAppearanceContainer
@end

@protocol UIAppearance
+ (id)appearanceWhenContainedInInstancesOfClasses:(NSArray<Class<UIAppearanceContainer>> *)containerTypes;
@end

@interface UIControl : UIView
@end

@interface UITextField : UIControl <UIAppearance>
@property(nonatomic, copy) NSDictionary<NSAttributedStringKey, id> *defaultTextAttributes;
@end

@interface UISearchTextField : UITextField
@end

@interface UISearchBar : UIView
@property(nonatomic, retain) UISearchTextField *searchTextField;
@end
