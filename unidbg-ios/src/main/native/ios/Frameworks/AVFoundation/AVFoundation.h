#import <Foundation/Foundation.h>

typedef NSString *AVAudioSessionLocation;
typedef NSString *NSNotificationName;

const AVAudioSessionLocation AVAudioSessionPolarPatternSubcardioid = @"Subcardioid";
const AVAudioSessionLocation AVAudioSessionOrientationTop = @"Top";
const AVAudioSessionLocation AVAudioSessionOrientationBottom = @"Bottom";
const AVAudioSessionLocation AVAudioSessionOrientationFront = @"Front";
const AVAudioSessionLocation AVAudioSessionOrientationBack = @"Back";
const AVAudioSessionLocation AVAudioSessionPolarPatternOmnidirectional = @"Omnidirectional";
const AVAudioSessionLocation AVAudioSessionPolarPatternCardioid = @"Cardioid";

const NSNotificationName AVAudioSessionRouteChangeNotification = @"AVAudioSessionRouteChangeNotification";
