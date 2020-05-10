#import "CoreTelephony.h"

@implementation CTCarrier
- (NSString *)carrierName {
    return @"中国联通";
}
- (NSString *)isoCountryCode {
    return @"cn";
}
@end

@implementation CTTelephonyNetworkInfo
- (CTCarrier *)subscriberCellularProvider {
    return [[CTCarrier alloc] init];
}
- (NSString *)currentRadioAccessTechnology {
    return CTRadioAccessTechnologyLTE;
}
@end
