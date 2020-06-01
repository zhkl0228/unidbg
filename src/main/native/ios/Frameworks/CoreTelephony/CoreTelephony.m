#import "CoreTelephony.h"

@implementation CTCarrier
- (NSString *)carrierName {
    return @"中国联通";
}
- (NSString *)isoCountryCode {
    return @"cn";
}
- (NSString *)mobileCountryCode {
    return @"MCC";
}
- (NSString *)mobileNetworkCode {
    return @"MNC";
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
