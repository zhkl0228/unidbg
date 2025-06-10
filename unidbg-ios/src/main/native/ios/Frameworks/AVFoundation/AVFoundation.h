#import "../frameworks.h"
#import "../CoreMedia/CoreMedia.h"
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

typedef NSString *AVCaptureSessionPreset;
const AVCaptureSessionPreset AVCaptureSessionPreset1280x720 = @"AVCaptureSessionPreset1280x720";

typedef NSString *AVCaptureDeviceType;
const AVCaptureDeviceType AVCaptureDeviceTypeBuiltInWideAngleCamera = @"AVCaptureDeviceTypeBuiltInWideAngleCamera";

typedef NSString * AVMediaType;
const AVMediaType AVMediaTypeVideo = @"AVMediaTypeVideo";

typedef enum AVCaptureDevicePosition : NSInteger {
    AVCaptureDevicePositionFront,
    AVCaptureDevicePositionBack,
    AVCaptureDevicePositionUnspecified
} AVCaptureDevicePosition;

typedef enum AVCaptureFocusMode : NSInteger {
    AVCaptureFocusModeLocked,
    AVCaptureFocusModeAutoFocus,
    AVCaptureFocusModeContinuousAutoFocus
} AVCaptureFocusMode;

typedef enum AVCaptureVideoStabilizationMode : NSInteger {
    AVCaptureVideoStabilizationModeOff,
    AVCaptureVideoStabilizationModeStandard
} AVCaptureVideoStabilizationMode;

typedef const struct opaqueCMFormatDescription * CMFormatDescriptionRef;

@interface AVCaptureDeviceFormat : NSObject
@property(nonatomic, assign) CMFormatDescriptionRef formatDescription;
@property (nonatomic) float minISO;
@property (nonatomic) float maxISO;
@property (nonatomic, getter=isVideoHDRSupported) BOOL videoHDRSupported;
@end

@interface AVCaptureDevice : NSObject
@property (nonatomic) AVCaptureDevicePosition position;
@property (nonatomic) BOOL hasFlash;
@property (nonatomic, retain) AVCaptureDeviceFormat * activeFormat;
@property (nonatomic, retain) NSString * modelID;
@property (nonatomic, retain) NSString * uniqueID;
+ (AVCaptureDevice *) front;
+ (AVCaptureDevice *) back;
@end

@interface AVCaptureDeviceDiscoverySession : NSObject
+ (AVCaptureDeviceDiscoverySession *) discoverySessionWithDeviceTypes:(NSArray<NSString *> *) deviceTypes
                                       mediaType:(AVMediaType) mediaType
                                        position:(AVCaptureDevicePosition) position;
- (NSArray<AVCaptureDevice *> *) devices;
@end
