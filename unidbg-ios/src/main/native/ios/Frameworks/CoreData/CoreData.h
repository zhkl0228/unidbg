#import <Foundation/Foundation.h>

id NSOverwriteMergePolicy;
NSString *const NSManagedObjectContextDidSaveNotification = @"NSManagedObjectContextDidSaveNotification";
NSString *const NSMigratePersistentStoresAutomaticallyOption = @"NSMigratePersistentStoresAutomaticallyOption";
NSString *const NSInferMappingModelAutomaticallyOption = @"NSInferMappingModelAutomaticallyOption";
NSString *const NSSQLitePragmasOption = @"NSSQLitePragmasOption";
NSString *const NSSQLiteStoreType = @"NSSQLiteStoreType";

@interface NSManagedObjectModel : NSObject
@property(nonatomic, retain) NSURL *url;
- (id)initWithContentsOfURL:(NSURL *)url;
- (BOOL)isConfiguration:(NSString *)configuration compatibleWithStoreMetadata:(NSDictionary<NSString *,id> *)metadata;
@end

@interface NSPersistentStore : NSObject
- (NSDictionary *)options;
@end

@interface NSPersistentStoreCoordinator : NSObject
+ (NSDictionary<NSString *,id> *)metadataForPersistentStoreOfType:(NSString *)storeType URL:(NSURL *)url options:(NSDictionary *)options error:(NSError **)error;
- (NSPersistentStoreCoordinator *)initWithManagedObjectModel:(NSManagedObjectModel *)model;
- (void)performBlockAndWait:(void (^)(void))block;
- (__kindof NSPersistentStore *)addPersistentStoreWithType:(NSString *)storeType configuration:(NSString *)configuration URL:(NSURL *)storeURL options:(NSDictionary *)options error:(NSError **)error;
- (BOOL)removePersistentStore:(NSPersistentStore *)store error:(NSError **)error;
@end

@interface NSManagedObject : NSObject
@end
