#import "UIKit.h"
#import "../AdSupport/AdSupport.h"
#import "../CoreTelephony/CoreTelephony.h"

static id delegate = nil;
static NSString *systemName = @"iPhone OS";
static NSString *systemVersion = @"7.1";
static NSString *model = @"iPhone";
static NSString *name = @"iPhone5S";
static NSString *identifierForVendor = @"00000000-0000-0000-0000-000000000000";

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

  NSNumber *callFinishLaunchingWithOptions = dict[@"callFinishLaunchingWithOptions"];
  if(delegate && [callFinishLaunchingWithOptions boolValue]) {
    UIApplication *application = [UIApplication sharedApplication];
    NSDictionary *options = [NSDictionary dictionary];
    [delegate application: application didFinishLaunchingWithOptions: options];
    if(is_debug()) {
      NSLog(@"UIApplicationMain didFinishLaunchingWithOptions delegate=%@", delegate);
    }
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
@end

@implementation UITraitCollection
- (id)init {
    if(self = [super init]) {
        self.userInterfaceStyle = UIUserInterfaceStyleLight;
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
@end

@implementation UIView
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
    return [NSArray array];
}

- (void)beginIgnoringInteractionEvents {
  self.ignoringInteractionEvents = true;
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

@implementation NSString (Number)
- (unsigned int)unsignedIntValue {
    int value = [self intValue];
    return (unsigned int) value;
}
@end

@implementation NSURLSessionConfiguration (CFNetwork)
+ (NSURLSessionConfiguration *)defaultSessionConfiguration {
  return [NSURLSessionConfiguration new];
}
@end

@implementation NSURLSession (CFNetwork)
+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration delegate:(id)delegate delegateQueue:(NSOperationQueue *)queue {
  return [NSURLSession new];
}
@end

@implementation UIViewController
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
  UIImage *image = [UIImage new];
  return image;
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

void UIGraphicsBeginImageContextWithOptions(CGSize size, BOOL opaque, CGFloat scale) {
}

void UIRectFill(CGRect rect) {
}

UIImage *UIGraphicsGetImageFromCurrentImageContext() {
  return [UIImage new];
}

void UIGraphicsEndImageContext() {
}
