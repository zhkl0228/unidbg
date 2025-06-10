#import "AVFoundation.h"

@implementation AVCaptureDevice
+ (AVCaptureDevice *) front {
  AVCaptureDevice *device = [AVCaptureDevice new];
  device.position = AVCaptureDevicePositionFront;
  device.hasFlash = NO;
  device.activeFormat = [AVCaptureDeviceFormat new];
  device.modelID = @"model_id_for_capture_device_front";
  device.uniqueID = @"unique_id_for_capture_device_front";
  return device;
}
+ (AVCaptureDevice *) back {
  AVCaptureDevice *device = [AVCaptureDevice new];
  device.position = AVCaptureDevicePositionBack;
  device.hasFlash = YES;
  device.activeFormat = [AVCaptureDeviceFormat new];
  device.modelID = @"model_id_for_capture_device_back";
  device.uniqueID = @"unique_id_for_capture_device_back";
  return device;
}
- (BOOL) isFocusModeSupported:(AVCaptureFocusMode) focusMode {
  return YES;
}
@end

@implementation AVCaptureDeviceFormat
- (CMTime)minExposureDuration {
  const CMTime time = { 10000, 4000 };
  return time;
}
- (CMTime)maxExposureDuration {
  const CMTime time = { 10000, 2000 };
  return time;
}
- (BOOL) isVideoStabilizationModeSupported:(AVCaptureVideoStabilizationMode) videoStabilizationMode {
  return YES;
}
@end

@implementation AVCaptureDeviceDiscoverySession
+ (AVCaptureDeviceDiscoverySession *) discoverySessionWithDeviceTypes:(NSArray<NSString *> *) deviceTypes
                                       mediaType:(AVMediaType) mediaType
                                        position:(AVCaptureDevicePosition) position {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  if(is_debug()) {
    char buf[512];
    print_lr(buf, lr);
    NSLog(@"AVCaptureDeviceDiscoverySession.discoverySessionWithDeviceTypes deviceTypes=%@, mediaType=%@, position=%ld, LR=%s", deviceTypes, mediaType, position, buf);
  }
  return [AVCaptureDeviceDiscoverySession new];
}
- (NSArray<AVCaptureDevice *> *) devices {
  id objects[] = { [AVCaptureDevice front], [AVCaptureDevice back] };
  NSArray *array = [NSArray arrayWithObjects:objects count:2];
  return array;
}
@end
