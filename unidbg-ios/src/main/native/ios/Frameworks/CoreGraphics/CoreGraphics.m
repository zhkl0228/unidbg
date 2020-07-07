#import "CoreGraphics.h"
#import <stdio.h>
#import <CoreFoundation/CoreFoundation.h>

CGDataProviderRef CGDataProviderCreateWithFilename(const char *filename) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
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
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGDataProviderCreateWithFilename filename=%s, size=%ld, read=%zu, LR=%s\n", filename, size, read, buf);
  }
  return ref;
}

void CGDataProviderRelease(CGDataProviderRef provider) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGDataProviderRelease provider=%p, LR=%s\n", provider, buf);
  }
  free(provider->data);
  free(provider);
}

CGImageRef CGImageCreateWithPNGDataProvider(CGDataProviderRef source, const CGFloat *decode, bool shouldInterpolate, CGColorRenderingIntent intent) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);

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
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGImageCreateWithPNGDataProvider source=%p, decode=%p, shouldInterpolate=%d, intent=%d, ref=%p, out_size=%zu, LR=%s\n", source, decode, shouldInterpolate, intent, ref, out_size, buf);
  }
  return ref;
}

size_t CGImageGetWidth(CGImageRef image) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  struct spng_ihdr ihdr;
  int r = spng_get_ihdr(image->ctx, &ihdr);
  if(r) {
    fprintf(stderr, "CGImageGetWidth spng_get_ihdr() error: %s\n", spng_strerror(r));
    return 0;
  } else {
    int debug = is_debug();
    if(debug) {
      fprintf(stderr, "CGImageGetWidth width=%u, LR=%s\n", ihdr.width, buf);
    }
    return ihdr.width;
  }
}

size_t CGImageGetHeight(CGImageRef image) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  struct spng_ihdr ihdr;
  int r = spng_get_ihdr(image->ctx, &ihdr);
  if(r) {
    fprintf(stderr, "CGImageGetHeight spng_get_ihdr() error: %s\n", spng_strerror(r));
    return 0;
  } else {
    int debug = is_debug();
    if(debug) {
      fprintf(stderr, "CGImageGetHeight height=%u, LR=%s\n", ihdr.height, buf);
    }
    return ihdr.height;
  }
}

CGColorSpaceRef CGColorSpaceCreateDeviceRGB() {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  CGColorSpaceRef ref = malloc(sizeof(struct CGColorSpace));
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGColorSpaceCreateDeviceRGB ref=%p, LR=%s\n", ref, buf);
  }
  return ref;
}

CGColorSpaceRef CGColorSpaceCreateDeviceGray() {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  CGColorSpaceRef ref = malloc(sizeof(struct CGColorSpace));
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGColorSpaceCreateDeviceGray ref=%p, LR=%s\n", ref, buf);
  }
  return ref;
}

void CGColorSpaceRelease(CGColorSpaceRef space) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGColorSpaceRelease space=%p, LR=%s\n", space, buf);
  }
  free(space);
}

CGContextRef CGBitmapContextCreate(void *data, size_t width, size_t height, size_t bitsPerComponent, size_t bytesPerRow, CGColorSpaceRef space, uint32_t bitmapInfo) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  CGContextRef ref = malloc(sizeof(struct CGContext));
  if(data == NULL) {
    data = malloc(bytesPerRow * height);
  }
  ref->data = data;
  ref->bytesPerRow = bytesPerRow;
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGBitmapContextCreate data=%p, width=%zu, height=%zu, bitsPerComponent=%zu, bytesPerRow=%zu, space=%p, bitmapInfo=%u, ref=%p, LR=%s\n", data, width, height, bitsPerComponent, bytesPerRow, space, bitmapInfo, ref, buf);
  }
  return ref;
}

void CGContextRelease(CGContextRef c) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGContextRelease c=%p, LR=%s\n", c, buf);
  }
  free(c);
}

void * CGBitmapContextGetData(CGContextRef context) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGBitmapContextGetData context=%p, LR=%s\n", context, buf);
  }
  return context->data;
}

void CGContextDrawImage(CGContextRef c, CGRect rect, CGImageRef image) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGContextDrawImage c=%p, image=%p, x=%f, y=%f, width=%f, height=%f, LR=%s\n", c, image, rect.origin.x, rect.origin.y, rect.size.width, rect.size.height, buf);
  }
  memcpy(c->data, image->out, image->out_size);
}

size_t CGBitmapContextGetBytesPerRow(CGContextRef context) {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char buf[512];
  print_lr(buf, lr);
  int debug = is_debug();
  if(debug) {
    fprintf(stderr, "CGBitmapContextGetBytesPerRow context=%p, LR=%s\n", context, buf);
  }
  return context->bytesPerRow;
}

CGFloat CGRectGetHeight(CGRect rect) {
  return rect.size.height;
}

CGFloat CGRectGetWidth(CGRect rect) {
  return rect.size.width;
}

CGColorRef CGColorCreate(CGColorSpaceRef space, const CGFloat *components) {
  CGColorRef color = malloc(sizeof(struct CGColor));
  return color;
}

bool CGColorEqualToColor(CGColorRef color1, CGColorRef color2) {
  return false;
}
