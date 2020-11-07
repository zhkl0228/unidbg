#import <Foundation/Foundation.h>
#import "../frameworks.h"

NSString *const CTRadioAccessTechnologyLTE = @"CTRadioAccessTechnologyLTE";
NSString *const CTCallStateDisconnected = @"CTCallStateDisconnected";

@interface CTCarrier : NSObject
@property(nonatomic, assign) NSString *carrierName;
- (NSString *)isoCountryCode;
- (NSString *)mobileCountryCode;
- (NSString *)mobileNetworkCode;
@end

@interface CTTelephonyNetworkInfo : NSObject
- (CTCarrier *)subscriberCellularProvider;
- (NSString *)currentRadioAccessTechnology;
@end
