#import "CoreData.h"

@implementation NSManagedObjectModel
- (id)initWithContentsOfURL:(NSURL *)url {
    if(self = [super init]) {
        self.url = url;
    }
    return self;
}
@end
