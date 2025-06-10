#include <CoreFoundation/CoreFoundation.h>

enum OSType {
    kCVPixelFormatType_32BGRA         = 'BGRA'
};

const CFStringRef kCVPixelBufferPixelFormatTypeKey = CFSTR("kCVPixelBufferPixelFormatTypeKey");
const CFStringRef kCVPixelBufferWidthKey = CFSTR("kCVPixelBufferWidthKey");
const CFStringRef kCVPixelBufferHeightKey = CFSTR("kCVPixelBufferHeightKey");

typedef int32_t CVReturn;
typedef struct __CVBuffer * CVBufferRef;
typedef CVBufferRef CVImageBufferRef;
typedef CVImageBufferRef CVPixelBufferRef;
