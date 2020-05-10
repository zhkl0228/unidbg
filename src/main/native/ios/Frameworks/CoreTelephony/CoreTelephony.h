#import <Foundation/Foundation.h>

@interface CTCarrier : NSObject
- (NSString *)carrierName;
- (NSString *)isoCountryCode;
@end

@interface CTTelephonyNetworkInfo : NSObject
- (CTCarrier *)subscriberCellularProvider;
@end
