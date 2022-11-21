#import "CFNetwork.h"

@implementation UniDbgURLSessionDataTask
+ (UniDbgURLSessionDataTask *)dataTaskWithURL:(NSURL *)url {
  return nil;
}
+ (UniDbgURLSessionDataTask *)dataTaskWithURL:(NSURL *)url
                        completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
  return nil;
}
+ (UniDbgURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
  return nil;
}
@end

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"
@implementation NSURLSession (CFNetwork)
+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration {
  return [NSURLSession new];
}
+ (NSURLSession *)sessionWithConfiguration:(NSURLSessionConfiguration *)configuration delegate:(id)delegate delegateQueue:(NSOperationQueue *)queue {
  return [NSURLSession new];
}
- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url {
  return [UniDbgURLSessionDataTask dataTaskWithURL: url];
}
- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url
                        completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
  return [UniDbgURLSessionDataTask dataTaskWithURL: url completionHandler: completionHandler];
}
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                            completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
  return [UniDbgURLSessionDataTask dataTaskWithRequest: request completionHandler: completionHandler];
}
- (void)finishTasksAndInvalidate {
}
@end
#pragma clang diagnostic pop
