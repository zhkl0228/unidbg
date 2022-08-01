#import <Foundation/Foundation.h>

typedef NSString *NSNibName;

typedef NSString *NSNotificationName;
NSNotificationName NSApplicationDidFinishLaunchingNotification = @"NSApplicationDidFinishLaunchingNotification";
NSNotificationName NSApplicationWillBecomeActiveNotification = @"NSApplicationWillBecomeActiveNotification";
NSNotificationName NSApplicationDidBecomeActiveNotification = @"NSApplicationDidBecomeActiveNotification";
NSNotificationName NSApplicationWillFinishLaunchingNotification = @"NSApplicationWillFinishLaunchingNotification";

@interface NSResponder : NSObject
@end

@protocol NSApplicationDelegate
- (void)applicationWillFinishLaunching:(NSNotification *)notification;
- (void)applicationWillBecomeActive:(NSNotification *)notification;
- (void)applicationDidBecomeActive:(NSNotification *)notification;
- (void)applicationDidFinishLaunching:(NSNotification *)notification;
@end

@interface NSApplication : NSResponder
@property(class, readonly, strong) NSApplication *sharedApplication;
@property(strong) id<NSApplicationDelegate> delegate;
- (void)run;
@end

@interface NSBundle (AppKit)
- (BOOL)loadNibNamed:(NSNibName)nibName owner:(id)owner topLevelObjects:(NSArray **)topLevelObjects;
@end
