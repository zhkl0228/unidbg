#import "QuartzCore.h"
#import <mach/mach_time.h>
#import <CoreFoundation/CoreFoundation.h>

static double initialize_time_scale() {
  struct mach_timebase_info info;
  mach_timebase_info(&info);
  return (double)info.numer / (double)info.denom * 0.000000001;
}

CFTimeInterval CACurrentMediaTime() {
  uint64_t time = mach_absolute_time();
  double scale = initialize_time_scale();
  return time * scale;
}
