#import <Foundation/Foundation.h>
#import "../frameworks.h"

@interface ASIdentifierManager : NSObject

@property(nonatomic, getter=isAdvertisingTrackingEnabled) BOOL advertisingTrackingEnabled;
@property(nonatomic, assign) NSUUID *advertisingIdentifier;

+ (ASIdentifierManager *)sharedManager;

- (NSUUID *)advertisingIdentifier;

@end
