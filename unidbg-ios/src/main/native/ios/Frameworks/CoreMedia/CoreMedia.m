#import "CoreMedia.h"

CMTime* CMTimeMakeWithSeconds(CMTime* ret, Float64 seconds, int32_t preferredTimescale) {
  return ret;
}

CMTime* CMTimeMake(CMTime* ret, CMTimeValue value, CMTimeScale timescale) {
  return ret;
}

Float64 CMTimeGetSeconds(CMTime time) {
  return time.value / time.timescale;
}
