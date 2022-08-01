#import "AppKit.h"

@implementation NSResponder
@end

@implementation NSApplication
@synthesize delegate;
+ (NSApplication *)sharedApplication {
  static NSApplication *_instance = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    _instance = [[self alloc] init];
    // Class delegateClass = NSClassFromString(@"AppDelegate");
    // _instance.delegate = [[delegateClass alloc] init];
  });
  return _instance;
}
- (void)run {
  NSLog(@"Starts the main event loop: delegate=%@", self.delegate);
  NSNotification *notification = [NSNotification notificationWithName: NSApplicationDidFinishLaunchingNotification object: self];
  [self.delegate applicationDidFinishLaunching: notification];
}
@end

@implementation NSBundle (AppKit)
- (BOOL)loadNibNamed:(NSNibName)nibName owner:(id)owner topLevelObjects:(NSArray **)topLevelObjects {
  return NO;
}
@end

int NSApplicationMain(int argc, const char **argv) {
  NSLog(@"NSApplicationMain");
  return 0;
}

const NSApplication *NSApp;

__attribute__((constructor))
void init() {
  NSApp = [NSApplication sharedApplication];
}
