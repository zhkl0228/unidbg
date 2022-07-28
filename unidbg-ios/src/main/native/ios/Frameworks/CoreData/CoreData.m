#import "CoreData.h"

@implementation NSManagedObjectModel
- (id)initWithContentsOfURL:(NSURL *)url {
    if(self = [super init]) {
        self.url = url;
    }
    return self;
}
- (BOOL)isConfiguration:(NSString *)configuration compatibleWithStoreMetadata:(NSDictionary<NSString *,id> *)metadata {
    return YES;
}
@end

@implementation NSPersistentStore
- (NSDictionary *)options {
    return [NSDictionary dictionary];
}
@end

@implementation NSPersistentStoreCoordinator
+ (NSDictionary<NSString *,id> *)metadataForPersistentStoreOfType:(NSString *)storeType URL:(NSURL *)url options:(NSDictionary *)options error:(NSError **)error {
    return [NSDictionary dictionary];
}
- (NSPersistentStoreCoordinator *)initWithManagedObjectModel:(NSManagedObjectModel *)model {
    return [super init];
}
- (void)performBlockAndWait:(void (^)(void))block {
    block();
}
- (__kindof NSPersistentStore *)addPersistentStoreWithType:(NSString *)storeType configuration:(NSString *)configuration URL:(NSURL *)storeURL options:(NSDictionary *)options error:(NSError **)error {
    return [NSPersistentStore new];
}
- (BOOL)removePersistentStore:(NSPersistentStore *)store error:(NSError **)error {
    return YES;
}
@end

@implementation NSManagedObject
+ (id)fetchRequest {
    return nil;
}
@end
