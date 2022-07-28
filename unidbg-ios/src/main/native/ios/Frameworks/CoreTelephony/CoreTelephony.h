#import <Foundation/Foundation.h>
#import "../frameworks.h"

NSString * _Nonnull const CTRadioAccessTechnologyLTE = @"CTRadioAccessTechnologyLTE";
NSString * _Nonnull const CTRadioAccessTechnologyGPRS = @"CTRadioAccessTechnologyGPRS";
NSString * _Nonnull const CTRadioAccessTechnologyEdge = @"CTRadioAccessTechnologyEdge";
NSString * _Nonnull const CTRadioAccessTechnologyWCDMA = @"CTRadioAccessTechnologyWCDMA";
NSString * _Nonnull const CTRadioAccessTechnologyHSDPA = @"CTRadioAccessTechnologyHSDPA";
NSString * _Nonnull const CTRadioAccessTechnologyHSUPA = @"CTRadioAccessTechnologyHSUPA";
NSString * _Nonnull const CTRadioAccessTechnologyCDMA1x = @"CTRadioAccessTechnologyCDMA1x";
NSString * _Nonnull const CTRadioAccessTechnologyeHRPD = @"CTRadioAccessTechnologyeHRPD";
NSString * _Nonnull const CTRadioAccessTechnologyCDMAEVDORev0 = @"CTRadioAccessTechnologyCDMAEVDORev0";
NSString * _Nonnull const CTRadioAccessTechnologyCDMAEVDORevA = @"CTRadioAccessTechnologyCDMAEVDORevA";
NSString * _Nonnull const CTRadioAccessTechnologyCDMAEVDORevB = @"CTRadioAccessTechnologyCDMAEVDORevB";

NSString * _Nonnull const CTCallStateDisconnected = @"CTCallStateDisconnected";
NSString * _Nonnull const CTServiceRadioAccessTechnologyDidChangeNotification = @"CTServiceRadioAccessTechnologyDidChangeNotification";
NSString * _Nonnull const CTRadioAccessTechnologyDidChangeNotification = @"CTRadioAccessTechnologyDidChangeNotification";

@interface CTCarrier : NSObject
@property(nonatomic, assign) NSString * _Nonnull carrierName;
- (NSString * _Nonnull) isoCountryCode;
- (NSString * _Nonnull)mobileCountryCode;
- (NSString * _Nonnull)mobileNetworkCode;
@end

@interface CTTelephonyNetworkInfo : NSObject
@property(nonatomic, retain, nullable) NSDictionary<NSString *, NSString *> *serviceCurrentRadioAccessTechnology;
@property(copy, nullable) NSString *dataServiceIdentifier;
@property(nonatomic, copy, nullable) void (^subscriberCellularProviderDidUpdateNotifier)(CTCarrier * _Nonnull);
@property(nonatomic, copy, nullable) void (^serviceSubscriberCellularProvidersDidUpdateNotifier)(NSString * _Nonnull);
@property(readonly, retain, nullable) NSDictionary<NSString *,CTCarrier *> *serviceSubscriberCellularProviders;
- (CTCarrier * _Nullable)subscriberCellularProvider;
- (NSString * _Nullable)currentRadioAccessTechnology;
@end
