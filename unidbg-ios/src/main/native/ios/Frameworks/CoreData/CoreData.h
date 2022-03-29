#import <Foundation/Foundation.h>

id NSOverwriteMergePolicy;
NSString *const NSManagedObjectContextDidSaveNotification = @"NSManagedObjectContextDidSaveNotification";

@interface NSManagedObjectModel : NSObject
@property(nonatomic, retain) NSURL *url;
- (id)initWithContentsOfURL:(NSURL *)url;
@end
