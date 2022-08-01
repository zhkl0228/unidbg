#import "AppKit.h"

@implementation NSResponder
@end

const NSApplication *NSApp = nil;

@implementation NSApplication
@synthesize delegate;
+ (id)sharedApplication {
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    NSApp = [[self alloc] init];
    Class delegateClass = NSClassFromString(@"AppDelegate");
    NSApp.delegate = [[delegateClass alloc] init];
  });
  return NSApp;
}
- (void)run {
  NSLog(@"Run application=%@, delegate=%@", self, self.delegate);
  [self.delegate applicationWillFinishLaunching: [NSNotification notificationWithName: NSApplicationWillFinishLaunchingNotification object: self]];
  [self.delegate applicationWillBecomeActive: [NSNotification notificationWithName: NSApplicationWillBecomeActiveNotification object: self]];
  [self.delegate applicationDidBecomeActive: [NSNotification notificationWithName: NSApplicationDidBecomeActiveNotification object: self]];
  [self.delegate applicationDidFinishLaunching: [NSNotification notificationWithName: NSApplicationDidFinishLaunchingNotification object: self]];
}
@end

@implementation NSBundle (AppKit)
- (BOOL)loadNibNamed:(NSNibName)nibName owner:(id)owner topLevelObjects:(NSArray **)topLevelObjects {
  NSLog(@"loadNibNamed bundle=%@, nib=%@, owner=%@", self, nibName, owner);
  return YES;
}
@end

int NSApplicationMain(int argc, const char **argv) {
  NSLog(@"NSApplicationMain");
  return 0;
}

__attribute__((constructor))
void init() {
}
