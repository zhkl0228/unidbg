#import "CoreGraphics.h"
#import <stdio.h>
#import <CoreFoundation/CoreFoundation.h>

CGDataProviderRef CGDataProviderCreateWithFilename(const char *filename) {
  FILE *fp = fopen(filename, "r");
  if(fp == NULL) {
    fprintf(stderr, "CGDataProviderCreateWithFilename filename=%s, err=%s\n", filename, strerror(errno));
    return NULL;
  }
  fseek(fp, 0, SEEK_END);
  long size = ftell(fp);
  rewind(fp);
  CGDataProviderRef ref = malloc(sizeof(struct CGDataProvider));
  ref->size = size;
  ref->data = malloc(size);
  size_t read = fread(ref->data, 1, size, fp);
  fclose(fp);
  fprintf(stderr, "CGDataProviderCreateWithFilename filename=%s, size=%ld, read=%zu\n", filename, size, read);
  return ref;
}

void CGDataProviderRelease(CGDataProviderRef provider) {
  fprintf(stderr, "CGDataProviderRelease provider=%p\n", provider);
  free(provider->data);
  free(provider);
}

CGImageRef CGImageCreateWithPNGDataProvider(CGDataProviderRef source, const CGFloat *decode, bool shouldInterpolate, CGColorRenderingIntent intent) {
  /* Create a context */
  spng_ctx *ctx = spng_ctx_new(0);

  int r = 0;

  /* Set an input buffer */
  r = spng_set_png_buffer(ctx, source->data, source->size);
  if(r) {
    fprintf(stderr, "CGImageCreateWithPNGDataProvider spng_set_png_buffer() error: %s\n", spng_strerror(r));
    return NULL;
  }

  size_t out_size = 0;
  /* Determine output image size */
  r = spng_decoded_image_size(ctx, SPNG_FMT_RGBA8, &out_size);
  if(r) {
    fprintf(stderr, "CGImageCreateWithPNGDataProvider spng_decoded_image_size() error: %s\n", spng_strerror(r));
    return NULL;
  }

  unsigned char *out = malloc(out_size);
  /* Decode to 8-bit RGBA */
  r = spng_decode_image(ctx, out, out_size, SPNG_FMT_RGBA8, 0);
  if(r) {
    fprintf(stderr, "CGImageCreateWithPNGDataProvider spng_decode_image() error: %s\n", spng_strerror(r));
    return NULL;
  }

  CGImageRef ref = malloc(sizeof(struct CGImage));
  ref->ctx = ctx;
  ref->out = out;
  ref->out_size = out_size;
  fprintf(stderr, "CGImageCreateWithPNGDataProvider source=%p, decode=%p, shouldInterpolate=%d, intent=%d, ref=%p, out_size=%zu\n", source, decode, shouldInterpolate, intent, ref, out_size);
  return ref;
}

size_t CGImageGetWidth(CGImageRef image) {
  struct spng_ihdr ihdr;
  int r = spng_get_ihdr(image->ctx, &ihdr);
  if(r) {
    fprintf(stderr, "CGImageGetWidth spng_get_ihdr() error: %s\n", spng_strerror(r));
    return 0;
  } else {
    fprintf(stderr, "CGImageGetWidth width=%u\n", ihdr.width);
    return ihdr.width;
  }
}

size_t CGImageGetHeight(CGImageRef image) {
  struct spng_ihdr ihdr;
  int r = spng_get_ihdr(image->ctx, &ihdr);
  if(r) {
    fprintf(stderr, "CGImageGetWidth spng_get_ihdr() error: %s\n", spng_strerror(r));
    return 0;
  } else {
    fprintf(stderr, "CGImageGetWidth height=%u\n", ihdr.height);
    return ihdr.height;
  }
}

CGColorSpaceRef CGColorSpaceCreateDeviceRGB() {
  CGColorSpaceRef ref = malloc(sizeof(struct CGColorSpace));
  fprintf(stderr, "CGColorSpaceCreateDeviceRGB ref=%p\n", ref);
  return ref;
}

void CGColorSpaceRelease(CGColorSpaceRef space) {
  fprintf(stderr, "CGColorSpaceRelease space=%p\n", space);
  free(space);
}

CGContextRef CGBitmapContextCreate(void *data, size_t width, size_t height, size_t bitsPerComponent, size_t bytesPerRow, CGColorSpaceRef space, uint32_t bitmapInfo) {
  CGContextRef ref = malloc(sizeof(struct CGContext));
  if(data == NULL) {
    data = malloc(bytesPerRow * height);
  }
  ref->data = data;
  ref->bytesPerRow = bytesPerRow;
  fprintf(stderr, "CGBitmapContextCreate data=%p, width=%zu, height=%zu, bitsPerComponent=%zu, bytesPerRow=%zu, space=%p, bitmapInfo=%u, ref=%p\n", data, width, height, bitsPerComponent, bytesPerRow, space, bitmapInfo, ref);
  return ref;
}

void CGContextRelease(CGContextRef c) {
  fprintf(stderr, "CGContextRelease c=%p\n", c);
  free(c);
}

void * CGBitmapContextGetData(CGContextRef context) {
  fprintf(stderr, "CGBitmapContextGetData context=%p\n", context);
  return context->data;
}

void CGContextDrawImage(CGContextRef c, CGRect rect, CGImageRef image) {
  fprintf(stderr, "CGContextDrawImage c=%p, image=%p, x=%f, y=%f, width=%f, height=%f\n", c, image, rect.origin.x, rect.origin.y, rect.size.width, rect.size.height);
  memcpy(c->data, image->out, image->out_size);
}

size_t CGBitmapContextGetBytesPerRow(CGContextRef context) {
  fprintf(stderr, "CGBitmapContextGetBytesPerRow context=%p\n", context);
  return context->bytesPerRow;
}

CGFloat CGRectGetHeight(CGRect rect) {
  return rect.size.height;
}

CGFloat CGRectGetWidth(CGRect rect) {
  return rect.size.width;
}
