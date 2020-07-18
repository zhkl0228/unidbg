#import "AdSupport.h"

@implementation ASIdentifierManager

+ (ASIdentifierManager *)sharedManager {
    static dispatch_once_t once;
    static id instance;
    dispatch_once(&once, ^{ instance = [[self alloc] init]; });
    return instance;
}

- (id)init {
    if(self = [super init]) {
        self.advertisingTrackingEnabled = YES;

        NSUUID *uuid = [NSUUID alloc];
        [uuid initWithUUIDString:@"00000000-1111-0000-1111-000000000000"];
        self.advertisingIdentifier = uuid;
    }
    return self;
}

@end
