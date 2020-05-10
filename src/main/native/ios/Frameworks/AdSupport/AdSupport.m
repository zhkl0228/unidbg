#import "AdSupport.h"

@implementation ASIdentifierManager

+ (ASIdentifierManager *)sharedManager {
    return [[ASIdentifierManager alloc] init];
}

- (id)init {
    if(self = [super init]) {
        self.advertisingTrackingEnabled = YES;
    }
    return self;
}

- (NSUUID *)advertisingIdentifier {
    NSUUID *uuid = [NSUUID alloc];
    [uuid initWithUUIDString:@"00000000-1111-0000-1111-000000000000"];
    return uuid;
}

@end
