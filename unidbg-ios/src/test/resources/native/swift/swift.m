#include <stdio.h>
#include <pthread.h>
#include <Foundation/Foundation.h>
#import "swift_library-Swift.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  dispatch_queue_t queue = dispatch_queue_create(NULL, NULL);
  const char *label = dispatch_queue_get_label(queue);
  printf("Before queue=%p, label=%s\n", queue, label);
  dispatch_sync(queue, ^{
    dispatch_queue_t current = dispatch_get_current_queue();
    printf("dispatch_sync queue=%p, current=%p\n", queue, current);
  });
  dispatch_apply(2, queue, ^(size_t index){
    dispatch_queue_t current = dispatch_get_current_queue();
    printf("dispatch_apply queue=%p, current=%p, index=%zu\n", queue, current, index);
 });

  dispatch_queue_t current = dispatch_get_current_queue();

  int QOS_CLASS_UTILITY = 0x11;
  dispatch_queue_t global_queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
  label = dispatch_queue_get_label(global_queue);
  printf("Before global_queue=%p, label=%s, current=%p\n", global_queue, label, current);
  dispatch_sync(global_queue, ^{
    dispatch_queue_t current = dispatch_get_current_queue();
    printf("dispatch_sync1 global_queue=%p, current=%p\n", global_queue, current);
  });
  dispatch_async(global_queue, ^{
    dispatch_queue_t current = dispatch_get_current_queue();
    printf("dispatch_async1 global_queue=%p, current=%p\n", global_queue, current);
  });
  dispatch_async(global_queue, ^{
    dispatch_queue_t current = dispatch_get_current_queue();
    printf("dispatch_async2 global_queue=%p, current=%p\n", global_queue, current);
  });
  dispatch_sync(global_queue, ^{
    dispatch_queue_t current = dispatch_get_current_queue();
    printf("dispatch_sync2 global_queue=%p, current=%p\n", global_queue, current);
  });

  dispatch_queue_t main_queue = dispatch_get_main_queue();

  label = dispatch_queue_get_label(main_queue);
  current = dispatch_get_current_queue();
  printf("Before main_queue=%p, label=%s, current=%p\n", main_queue, label, current);
  dispatch_async(main_queue, ^{
    dispatch_queue_t current = dispatch_get_current_queue();
    printf("dispatch_async main_queue=%p, current=%p\n", main_queue, current);
  });
  dispatch_sync(main_queue, ^{
    dispatch_queue_t current = dispatch_get_current_queue();
    printf("dispatch_sync main_queue=%p, current=%p\n", main_queue, current);
  });

  NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
  SwiftLibrary *library = [SwiftLibrary new];
  NSLog(@"Swift library=%p, version=%@", library, version);

  [library hello];

  return 0;
}
#pragma clang diagnostic pop
