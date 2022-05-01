#include <stdio.h>
#include <Foundation/Foundation.h>
#import "swift_library-Swift.h"

int main(int argc, char *argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  dispatch_queue_t queue = dispatch_queue_create("create", NULL);
  printf("Before queue=%p\n", queue);
  dispatch_sync(queue, ^{
    printf("dispatch_sync queue=%p\n", queue);
  });

  int QOS_CLASS_UTILITY = 0x11;
  dispatch_queue_t global_queue = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
  printf("Before global_queue=%p\n", global_queue);
  dispatch_async(global_queue, ^{
    printf("dispatch_async global_queue=%p\n", global_queue);
  });
  dispatch_sync(global_queue, ^{
    printf("dispatch_sync global_queue=%p\n", global_queue);
  });

  dispatch_queue_t main_queue = dispatch_get_main_queue();
  printf("Before main_queue=%p\n", main_queue);
  dispatch_sync(main_queue, ^{
    printf("dispatch_sync main_queue=%p\n", main_queue);
  });

  NSString *version = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
  SwiftLibrary *library = [SwiftLibrary new];
  NSLog(@"Swift library=%p, version=%@", library, version);

  [library hello];

  return 0;
}
