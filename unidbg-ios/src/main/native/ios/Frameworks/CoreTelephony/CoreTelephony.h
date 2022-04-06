#import <Foundation/Foundation.h>
#import "../frameworks.h"

NSString * _Nonnull const CTRadioAccessTechnologyLTE = @"CTRadioAccessTechnologyLTE";
NSString * _Nonnull const CTCallStateDisconnected = @"CTCallStateDisconnected";
NSString * _Nonnull const CTServiceRadioAccessTechnologyDidChangeNotification = @"CTServiceRadioAccessTechnologyDidChangeNotification";

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
- (CTCarrier * _Nullable)subscriberCellularProvider;
- (NSString * _Nullable)currentRadioAccessTechnology;
@end
