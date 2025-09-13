#import <stdlib.h>
#import "../frameworks.h"
#import "spng.h"

typedef struct CGDataProvider {
    long size;
    char *data;
} *CGDataProviderRef;

typedef struct CGImage {
    spng_ctx *ctx;
    unsigned char *out;
    size_t out_size;
} *CGImageRef;

typedef enum CGColorRenderingIntent : int32_t {
    kCGRenderingIntentDefault
} CGColorRenderingIntent;

typedef double CGFloat;

typedef struct CGColorSpace {} *CGColorSpaceRef;

typedef struct CGContext {
    void *data;
    size_t bytesPerRow;
} *CGContextRef;

const CGRect CGRectZero = { 0, 0, 0, 0 };

const CGSize CGSizeZero = { 0, 0 };

typedef struct CGColor {
} *CGColorRef;
