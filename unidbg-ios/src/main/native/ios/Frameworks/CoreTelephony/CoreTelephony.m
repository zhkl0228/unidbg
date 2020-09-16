#import "CoreTelephony.h"

@implementation CTCarrier
- (id)init {
    if(self = [super init]) {
        self.carrierName = @"中国联通";
    }
    return self;
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
    static dispatch_once_t once;
    static id instance;
    dispatch_once(&once, ^{ instance = [[CTCarrier alloc] init]; });
    return instance;
}
- (NSString *)currentRadioAccessTechnology {
    return CTRadioAccessTechnologyLTE;
}
@end
