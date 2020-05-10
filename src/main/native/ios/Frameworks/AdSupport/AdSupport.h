#import <Foundation/Foundation.h>

@interface ASIdentifierManager : NSObject

@property(nonatomic, getter=isAdvertisingTrackingEnabled) BOOL advertisingTrackingEnabled;

+ (ASIdentifierManager *)sharedManager;

- (NSUUID *)advertisingIdentifier;

@end
