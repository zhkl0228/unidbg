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

typedef struct CGPoint {
    CGFloat x;
    CGFloat y;
} CGPoint;

typedef struct CGSize {
    CGFloat width;
    CGFloat height;
} CGSize;

typedef struct CGRect {
    CGPoint origin;
    CGSize size;
} CGRect;

const CGRect CGRectZero = { 0, 0, 0, 0 };

const CGSize CGSizeZero = { 0, 0 };

typedef struct CGColor {
} *CGColorRef;
