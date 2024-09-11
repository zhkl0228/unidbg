#import "UIKit.h"
#import "../AdSupport/AdSupport.h"
#import "../CoreTelephony/CoreTelephony.h"

static id delegate = nil;
static NSString *systemName = @"iPhone OS";
static NSString *systemVersion = @"7.1";
static NSString *model = @"iPhone";
static NSString *name = @"iPhone5S";
static NSString *identifierForVendor = @"00000000-0000-0000-0000-000000000000";
const NSOperatingSystemVersion g_systemVersion = { 7, 1, 2 };

@implementation NSProcessInfo (Foundation)
- (NSOperatingSystemVersion) operatingSystemVersion {
  return g_systemVersion;
}
- (NSProcessInfoThermalState) thermalState {
  return NSProcessInfoThermalStateNominal;
}
- (BOOL) isLowPowerModeEnabled {
  return YES;
}
@end

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
  if(is_debug()) {
    NSLog(@"UIApplicationMain argc=%d, argv=%p, principalClassName=%@, delegateClassName=%@, delegate=%@, dict=%@", argc, argv, principalClassName, delegateClassName, delegate, dict);
  }
  [json release];

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

  NSUserDefaults *userDefault = [NSUserDefaults standardUserDefaults];
  [userDefault setBool: YES forKey: @"NSFileCoordinatorDoesNothing"];
  NSNumber *callFinishLaunchingWithOptions = dict[@"callFinishLaunchingWithOptions"];
  if(delegate && [callFinishLaunchingWithOptions boolValue]) {
    UIApplication *application;
    if(principalClassName) {
      Class principalClass = NSClassFromString(principalClassName);
      application = [[principalClass alloc] init];
    } else {
      application = [UIApplication sharedApplication];
    }
    NSDictionary *options = [NSDictionary dictionary];
    if(is_debug()) {
      NSLog(@"UIApplicationMain didFinishLaunchingWithOptions delegate=%@, application=%@", delegate, application);
    }
    [delegate application: application didFinishLaunchingWithOptions: options];
  }
  return 0;
}

const CGRect g_frame = { 0, 0, 768, 1024 };

@implementation UIScreen
+ (UIScreen *)mainScreen {
    static dispatch_once_t once;
    static id instance;
    dispatch_once(&once, ^{ instance = [[UIScreen alloc] init]; });
    return instance;
}
- (CGRect)bounds {
    return g_frame;
}
- (CGFloat)scale {
    return 1.0;
}
- (CGFloat)nativeScale {
    return 1.0;
}
@end

@implementation UITraitCollection
- (id)init {
    if(self = [super init]) {
        self.userInterfaceStyle = UIUserInterfaceStyleLight;
        self.userInterfaceLevel = UIUserInterfaceLevelBase;
        self.accessibilityContrast = UIAccessibilityContrastNormal;
    }
    return self;
}
+ (UITraitCollection *)traitCollectionWithUserInterfaceStyle:(UIUserInterfaceStyle)_userInterfaceStyle {
    UITraitCollection *trait = [UITraitCollection new];
    trait.userInterfaceStyle = _userInterfaceStyle;
    return trait;
}
+ (UITraitCollection *)currentTraitCollection {
    return [UITraitCollection traitCollectionWithUserInterfaceStyle: UIUserInterfaceStyleLight];
}
+ (UITraitCollection *)traitCollectionWithDisplayScale:(CGFloat)scale {
    return [UITraitCollection traitCollectionWithUserInterfaceStyle: UIUserInterfaceStyleLight];
}
+ (UITraitCollection *)traitCollectionWithTraitsFromCollections:(NSArray<UITraitCollection *> *)traitCollections {
    return [UITraitCollection traitCollectionWithUserInterfaceStyle: UIUserInterfaceStyleLight];
}
- (CGFloat)displayScale {
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
+ (UIColor *)colorNamed:(NSString *)name inBundle:(NSBundle *)bundle compatibleWithTraitCollection:(UITraitCollection *)traitCollection {
    return [UIColor new];
}
- (UIColor *)initWithDynamicProvider:(UIColor * (^)(UITraitCollection *traitCollection))dynamicProvider {
    return dynamicProvider([UITraitCollection new]);
}
- (UIColor *)resolvedColorWithTraitCollection:(UITraitCollection *)traitCollection {
    return [UIColor new];
}
- (CGColorRef)CGColor {
    CGColorSpaceRef colorSpace = CGColorSpaceCreateDeviceRGB();
    CGFloat components[] = { 0.0, 0.0, 0.0, 0.0 };
    CGColorRef color = CGColorCreate(colorSpace, components);
    CGColorSpaceRelease(colorSpace);
    return color;
}
- (void)setFill {
}
- (UIColor *)colorWithAlphaComponent:(CGFloat)alpha {
    return [UIColor new];
}
- (UIColor *)initWithWhite:(CGFloat)white alpha:(CGFloat)alpha {
    return [UIColor new];
}
- (UIColor *)initWithRed:(CGFloat)red green:(CGFloat)green blue:(CGFloat)blue alpha:(CGFloat)alpha {
    return [UIColor new];
}
@end

@implementation UIGestureRecognizer
@end

@implementation CALayer
@end

@implementation UIView
+ (id)appearance {
  return nil;
}
- (id)initWithFrame:(CGRect)rect {
    if(self = [super init]) {
        self.frame = rect;
    }
    return self;
}
- (void)setAccessibilityViewIsModal:(BOOL)flag {
}
- (void)setOverrideUserInterfaceStyle:(UIUserInterfaceStyle)style {
}
- (void)addSubview:(UIView *)view {
}
- (CGPoint)convertPoint:(CGPoint)point fromView:(UIView *)view {
  return point;
}
- (void)setAlpha: (CGFloat) alpha {
}
- (void)setClipsToBounds: (BOOL)flag {
}
- (void)addGestureRecognizer:(UIGestureRecognizer *)gestureRecognizer {
}
- (void)setTintColor:(UIColor *)tintColor {
}
- (UIView *)snapshotViewAfterScreenUpdates:(BOOL)afterUpdates {
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
    static dispatch_once_t once;
    static id instance;
    dispatch_once(&once, ^{ instance = [[UIWindow alloc] init]; });
    return instance;
}
- (id) m_appViewControllerMgr {
    return nil;
}
@end

@implementation UIEvent
@end

@implementation UIScene
@end

@implementation UIWindowScene
@end

static UIApplication *sharedApplication;

@implementation UIApplication

+ (UIApplication *)sharedApplication {
    if(sharedApplication) {
        return sharedApplication;
    }
    static dispatch_once_t once;
    static id instance;
    dispatch_once(&once, ^{ instance = [[self alloc] init]; });
    return instance;
}

- (id)init {
    if(self = [super init]) {
        self.statusBarHidden = YES;
        self.protectedDataAvailable = YES;
        self.backgroundRefreshStatus = UIBackgroundRefreshStatusRestricted;
        self.userInterfaceLayoutDirection = UIUserInterfaceLayoutDirectionLeftToRight;
        self.connectedScenes = nil;
    }
    sharedApplication = self;
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
    return [NSArray array];
}

- (void)beginIgnoringInteractionEvents {
  self.ignoringInteractionEvents = true;
}

- (void)registerForRemoteNotifications {
    NSLog(@"registerForRemoteNotifications delegate=%@", delegate);
}

- (BOOL)sendAction:(SEL)action to:(id)target from:(id)sender forEvent:(UIEvent *)event {
    return NO;
}

- (UIBackgroundTaskIdentifier)beginBackgroundTaskWithName:(NSString *)taskName expirationHandler:(void (^)(void))handler {
    return UIBackgroundTaskInvalid;
}

- (BOOL)canOpenURL:(NSURL *)url {
    return NO;
}

@end

@implementation UIDevice

+ (UIDevice *)currentDevice {
    static dispatch_once_t once;
    static id instance;
    dispatch_once(&once, ^{ instance = [[UIDevice alloc] init]; });
    return instance;
}

- (id)init {
    if(self = [super init]) {
        self.batteryMonitoringEnabled = YES;
        self.userInterfaceIdiom = UIUserInterfaceIdiomPhone;
        self.batteryLevel = 1.0;
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

@implementation NSString (Fix)
- (unsigned int)unsignedIntValue {
    int value = [self intValue];
    return (unsigned int) value;
}
- (BOOL)containsString:(NSString *)str {
    NSRange range = [self rangeOfString:str];
    return range.location != NSNotFound;
}
@end

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"
@implementation NSCalendar (Fix)
+ (NSCalendar *)calendarWithIdentifier:(NSCalendarIdentifier)calendarIdentifierConstant {
    return [[NSCalendar alloc] initWithCalendarIdentifier: calendarIdentifierConstant];
}
@end

@implementation NSURLSessionConfiguration (CFNetwork)
+ (NSURLSessionConfiguration *)defaultSessionConfiguration {
  return [NSURLSessionConfiguration new];
}
+ (NSURLSessionConfiguration *)ephemeralSessionConfiguration {
  return [NSURLSessionConfiguration new];
}
+ (NSURLSessionConfiguration *)backgroundSessionConfigurationWithIdentifier:(NSString *)identifier {
  return [NSURLSessionConfiguration new];
}
- (void) setShouldUseExtendedBackgroundIdleMode: (BOOL) flag {
}
@end
#pragma clang diagnostic pop

@implementation NSTimerInvocation
+ (NSTimerInvocation *)invocationWithBlock: (void (^)(NSTimer *timer))block {
  NSTimerInvocation *invocation = [NSTimerInvocation new];
  invocation.block = block;
  return invocation;
}
- (void) callWithTimer: (NSTimer *) timer {
  self.block(timer);
}
@end

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"
@implementation NSTimer (Foundation)
+ (NSTimer *)timerWithTimeInterval:(NSTimeInterval)interval repeats:(BOOL)repeats block:(void (^)(NSTimer *timer))block {
  NSTimerInvocation *timerInvocation = [NSTimerInvocation invocationWithBlock: block];
  NSMethodSignature *signature = [[NSTimer class] instanceMethodSignatureForSelector: @selector(callWithInvocation:)];
  NSInvocation *invocation = [NSInvocation invocationWithMethodSignature: signature];
  invocation.target = self;
  [invocation setArgument: &timerInvocation atIndex: 0];
  [invocation retainArguments];
  return [NSTimer timerWithTimeInterval:interval invocation:invocation repeats:repeats];
}
- (void) callWithInvocation: (NSTimerInvocation *) invocation {
  [invocation callWithTimer: self];
}
@end

@implementation NSIndexPath (Foundation)
+ (id)indexPathForRow:(NSInteger)row inSection:(NSInteger)section {
  return nil;
}
@end

@implementation NSError (Foundation)
+ (id (^)(NSError *, NSErrorUserInfoKey))userInfoValueProviderForDomain:(NSErrorDomain)errorDomain {
  return nil;
}
+ (void)setUserInfoValueProviderForDomain:(NSErrorDomain)errorDomain
                                 provider:(id (^)(NSError *err, NSErrorUserInfoKey userInfoKey))provider {
}
@end

@implementation NSOperationQueue (Foundation)
- (void) setQualityOfService: (NSQualityOfService) qualityOfService {
}
- (void) setUnderlyingQueue: (dispatch_queue_t) queue {
}
@end

@implementation NSOperation (Foundation)
- (void) setQualityOfService: (NSQualityOfService) qualityOfService {
}
@end

@implementation NSDateFormatter (Foundation)
- (void)setLocalizedDateFormatFromTemplate:(NSString *)dateFormatTemplate {
}
@end
@implementation NSKeyedArchiver (Foundation)
- (id)initRequiringSecureCoding:(BOOL)requiresSecureCoding {
    return nil;
}
@end
#pragma clang diagnostic pop

@implementation UINavigationItem
@end

@implementation UIViewController
- (UIViewController *)initWithNibName:(NSString *)nibNameOrNil bundle:(NSBundle *)nibBundleOrNil {
    if(self = [super init]) {
        self.nibName = nibNameOrNil;
        self.nibBundle = nibBundleOrNil;
    }
    return self;
}
- (void)setExtendedLayoutIncludesOpaqueBars: (BOOL)flag {
}
@end

@implementation UIResponder
@end

@implementation UIImage
@synthesize accessibilityIdentifier;
+ (UIImage *)imageWithContentsOfFile: (NSString *)path {
  UIImage *image = [UIImage new];
  CGDataProviderRef provider = CGDataProviderCreateWithFilename([path UTF8String]);
  image.CGImage = CGImageCreateWithPNGDataProvider(provider, NULL, true, kCGRenderingIntentDefault);
  CGDataProviderRelease(provider);
  return image;
}
+ (UIImage *)imageNamed:(NSString *)name {
  return nil;
}
+ (UIImage *)imageNamed:(NSString *)name inBundle:(NSBundle *)bundle compatibleWithTraitCollection:(UITraitCollection *)traitCollection {
  return nil;
}
- (UIImage *)resizableImageWithCapInsets:(UIEdgeInsets)capInsets {
  return self;
}
- (CGFloat)scale {
  return 1.0;
}
- (CGSize)size {
  return CGSizeZero;
}
- (UITraitCollection *)traitCollection {
  return [UITraitCollection new];
}
- (UIImageAsset *)imageAsset {
  return [UIImageAsset new];
}
@end

@implementation UIImageAsset
- (UIImage *)imageWithTraitCollection:(UITraitCollection *)traitCollection {
  return [UIImage new];
}
- (void)registerImage:(UIImage *)image withTraitCollection:(UITraitCollection *)traitCollection {
}
@end

@implementation UICollectionReusableView
@end

@implementation UICollectionViewCell
@end

@implementation UITableViewController
@end

@implementation LSResourceProxy
@end

@implementation LSApplicationProxy
+ (BOOL)supportsSecureCoding {
  return YES;
}
+ (id)applicationProxyForIdentifier:(NSString *)identifier {
  LSApplicationProxy *proxy = [LSApplicationProxy new];
  proxy.identifier = identifier;
  NSLog(@"LSApplicationProxy.applicationProxyForIdentifier: %@", identifier);
  return proxy;
}
- (NSDictionary *)groupContainers {
  NSString *shared = [NSString stringWithFormat: @"group.%@.shared", self.identifier];
  NSString *private = [NSString stringWithFormat: @"group.%@.private", self.identifier];
  NSString *SMB_shared = [NSString stringWithFormat: @"group.%@SMB.shared", self.identifier];

  id objects[] = {
    [NSString stringWithFormat: @"/groupContainers/%@", shared],
    [NSString stringWithFormat: @"/groupContainers/%@", private],
    [NSString stringWithFormat: @"/groupContainers/%@", SMB_shared]
  };
  id keys[] = { shared, private, SMB_shared };
  NSUInteger count = sizeof(objects) / sizeof(id);
  NSDictionary *dictionary = [NSDictionary dictionaryWithObjects:objects
                                                         forKeys:keys
                                                         count:count];
  return dictionary;
}
- (id)initWithCoder:(NSCoder *)coder; {
  return self;
}
- (void)encodeWithCoder:(NSCoder *)coder {
}
@end

void UIGraphicsBeginImageContextWithOptions(CGSize size, BOOL opaque, CGFloat scale) {
}

void UIRectFill(CGRect rect) {
}

UIImage *UIGraphicsGetImageFromCurrentImageContext() {
  return [UIImage new];
}

void UIGraphicsEndImageContext() {
}

BOOL UIAccessibilityDarkerSystemColorsEnabled() {
  return NO;
}

@implementation UISearchBar
- (id)init {
    if(self = [super init]) {
        self.searchTextField = [UISearchTextField new];
    }
    return self;
}
@end

@implementation UIControl
@end

@implementation UISearchTextField
@end

@implementation UITextField
+ (id)appearance {
  return nil;
}
+ (UITextField *)appearanceWhenContainedInInstancesOfClasses:(NSArray<Class<UIAppearanceContainer>> *)containerTypes {
    return [UITextField new];
}
- (id)init {
    if(self = [super init]) {
        self.defaultTextAttributes = [NSDictionary dictionary];
    }
    return self;
}
@end

@implementation BRQuery
@end

@implementation NSConstantIntegerNumber
- (const char *)objCType {
  return self->_encoding;
}
- (bool)boolValue {
  return self->_value == 1 ? YES : NO;
}
- (BOOL)charValue {
  return (BOOL) self->_value;
}
- (int)intValue {
  return (int) self->_value;
}
- (long long)integerValue {
  return (long long) self->_value;
}
- (long long)longLongValue {
  return (long long) self->_value;
}
- (long long)longValue {
  return (long long) self->_value;
}
- (short)shortValue {
  return (short) self->_value;
}
- (unsigned char)unsignedCharValue {
  return (unsigned char) self->_value;
}
- (unsigned int)unsignedIntValue {
  return (unsigned int) self->_value;
}
- (unsigned long long)unsignedIntegerValue {
  return (unsigned long long) self->_value;
}
- (unsigned long long)unsignedLongLongValue {
  return (unsigned long long) self->_value;
}
- (unsigned long long)unsignedLongValue {
  return (unsigned long long) self->_value;
}
- (unsigned short)unsignedShortValue {
  return (unsigned short) self->_value;
}
- (double)doubleValue {
  [self doesNotRecognizeSelector:_cmd];
  return 0.0;
}
- (float)floatValue {
  [self doesNotRecognizeSelector:_cmd];
  return 0.0;
}
@end

@implementation LAContext
- (BOOL) canEvaluatePolicy:(LAPolicy) policy
                     error:(NSError * *) error {
  return TRUE;
}
@end

__attribute__((constructor))
void init() {
  __NSArray0__ = [NSArray array];
  __NSDictionary0__ = [NSDictionary dictionary];
}
