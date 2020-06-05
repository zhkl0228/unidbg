/* SPDX-License-Identifier: (BSD-2-Clause AND libpng-2.0) */
#include "spng.h"

#include <limits.h>
#include <string.h>
#include <math.h>

#define ZLIB_CONST

#ifdef __FRAMAC__
    #define SPNG_DISABLE_OPT
    #include "tests/framac_stubs.h"
#else
    #include <zlib.h>
#endif

#ifdef SPNG_ENABLE_MT
    #include <pthread.h>
#endif

#define SPNG_READ_SIZE 8192

#define SPNG_TARGET_CLONES(x)

#ifndef SPNG_DISABLE_OPT

    #if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64)
        #define SPNG_X86

        #if defined(__x86_64__) || defined(_M_X64)
            #define SPNG_X86_64
        #endif

    #elif defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_NEON)
        /* #define SPNG_ARM */ /* buffer overflow for rgb8 images */
        #define SPNG_DISABLE_OPT
    #else
        #warning "disabling optimizations for unknown platform"
        #define SPNG_DISABLE_OPT
    #endif

    #if defined(SPNG_X86_64) && defined(SPNG_ENABLE_TARGET_CLONES)
        #undef SPNG_TARGET_CLONES
        #define SPNG_TARGET_CLONES(x) __attribute__((target_clones(x)))
    #else
        #define SPNG_TARGET_CLONES(x)
    #endif

    #ifndef SPNG_DISABLE_OPT
        static void defilter_sub3(size_t rowbytes, unsigned char *row);
        static void defilter_sub4(size_t rowbytes, unsigned char *row);
        static void defilter_avg3(size_t rowbytes, unsigned char *row, const unsigned char *prev);
        static void defilter_avg4(size_t rowbytes, unsigned char *row, const unsigned char *prev);
        static void defilter_paeth3(size_t rowbytes, unsigned char *row, const unsigned char *prev);
        static void defilter_paeth4(size_t rowbytes, unsigned char *row, const unsigned char *prev);
    #endif
#endif

#if defined(_MSC_VER)
    #pragma warning(push)
    #pragma warning(disable: 4244)
#endif

#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__) || defined(__BIG_ENDIAN__)
    #define SPNG_BIG_ENDIAN
#else
    #define SPNG_LITTLE_ENDIAN
#endif

enum spng_state
{
    SPNG_STATE_INVALID = 0,
    SPNG_STATE_INIT = 1, /* No PNG buffer/stream is set */
    SPNG_STATE_INPUT, /* Input PNG was set */
    SPNG_STATE_IHDR, /* IHDR was read */
    SPNG_STATE_FIRST_IDAT,  /* Reached first IDAT */
    SPNG_STATE_DECODE_INIT, /* Decoder is ready for progressive reads */
    SPNG_STATE_EOI, /* Reached the last scanline/row */
    SPNG_STATE_LAST_IDAT, /* Reached last IDAT, set at end of decode_image() */
    SPNG_STATE_AFTER_IDAT, /*  */
    SPNG_STATE_IEND, /* Reached IEND */
};

#define SPNG_STR(x) _SPNG_STR(x)
#define _SPNG_STR(x) #x

#define SPNG_VERSION_STRING SPNG_STR(SPNG_VERSION_MAJOR) "." \
                            SPNG_STR(SPNG_VERSION_MINOR) "." \
                            SPNG_STR(SPNG_VERSION_PATCH)

#define SPNG_GET_CHUNK_BOILERPLATE(chunk) \
    if(ctx == NULL || chunk == NULL) return 1; \
    int ret = read_chunks(ctx, 0); \
    if(ret) return ret;

#define SPNG_SET_CHUNK_BOILERPLATE(chunk) \
    if(ctx == NULL || chunk == NULL) return 1; \
    if(ctx->data == NULL) ctx->encode_only = 1; \
    int ret = read_chunks(ctx, 0); \
    if(ret) return ret;

struct spng_subimage
{
    uint32_t width;
    uint32_t height;
    size_t scanline_width;
};

struct spng_plte_entry16
{
    uint16_t red;
    uint16_t green;
    uint16_t blue;
    uint16_t alpha;
};

struct decode_flags
{
    unsigned apply_trns:  1;
    unsigned apply_gamma: 1;
    unsigned use_sbit:    1;
    unsigned indexed:     1;
    unsigned do_scaling:  1;
    unsigned interlaced:  1;
    unsigned same_layout: 1;
    unsigned zerocopy:    1;
};

struct spng_chunk_bitfield
{
    unsigned ihdr: 1;
    unsigned plte: 1;
    unsigned chrm: 1;
    unsigned iccp: 1;
    unsigned gama: 1;
    unsigned sbit: 1;
    unsigned srgb: 1;
    unsigned text: 1;
    unsigned bkgd: 1;
    unsigned hist: 1;
    unsigned trns: 1;
    unsigned phys: 1;
    unsigned splt: 1;
    unsigned time: 1;
    unsigned offs: 1;
    unsigned exif: 1;
};

struct spng_ctx
{
    size_t data_size;
    size_t bytes_read;
    unsigned char *stream_buf;
    const unsigned char *data;

    /* User-defined pointers for streaming */
    spng_read_fn *read_fn;
    void *read_user_ptr;

    /* Used for buffer reads */
    const unsigned char *png_buf; /* base pointer for the buffer */
    size_t bytes_left;
    size_t last_read_size;

    /* These are updated by read_header()/read_chunk_bytes() */
    struct spng_chunk current_chunk;
    uint32_t cur_chunk_bytes_left;
    uint32_t cur_actual_crc;

    struct spng_alloc alloc;

    int flags;
    int fmt;

    unsigned state: 4;
    unsigned streaming: 1;

    unsigned encode_only: 1;

    /* input file contains this chunk */
    struct spng_chunk_bitfield file;

    /* chunk was stored with spng_set_*() */
    struct spng_chunk_bitfield user;

    /* chunk was stored by reading or with spng_set_*() */
    struct spng_chunk_bitfield stored;

    struct spng_chunk first_idat, last_idat;

    uint32_t max_width, max_height;

    uint32_t max_chunk_size;
    size_t chunk_cache_limit;
    size_t chunk_cache_usage;

    int crc_action_critical;
    int crc_action_ancillary;

    struct spng_ihdr ihdr;

    struct spng_plte plte;

    struct spng_chrm_int chrm_int;
    struct spng_iccp iccp;

    uint32_t gama;

    struct spng_sbit sbit;

    uint8_t srgb_rendering_intent;

    uint32_t n_text;
    struct spng_text *text_list;

    struct spng_bkgd bkgd;
    struct spng_hist hist;
    struct spng_trns trns;
    struct spng_phys phys;

    uint32_t n_splt;
    struct spng_splt *splt_list;

    struct spng_time time;
    struct spng_offs offs;
    struct spng_exif exif;

    struct spng_subimage subimage[7];

    z_stream zstream;
    unsigned char *scanline_buf, *prev_scanline_buf, *row_buf;
    unsigned char *scanline, *prev_scanline, *row;

    size_t total_out_size;
    size_t out_width; /* total_out_size / ihdr.height */

    unsigned channels;
    unsigned bytes_per_pixel;
    int widest_pass;
    int last_pass; /* last non-empty pass */

    uint16_t *gamma_lut; /* points to either _lut8 or _lut16 */
    uint16_t *gamma_lut16;
    uint16_t gamma_lut8[256];
    unsigned char trns_px[8];
    struct spng_plte_entry16 decode_plte[256];
    struct spng_sbit decode_sb;
    struct decode_flags decode_flags;
    struct spng_row_info row_info;
};

static const uint32_t png_u32max = 2147483647;

static const uint8_t png_signature[8] = { 137, 80, 78, 71, 13, 10, 26, 10 };

static const unsigned int adam7_x_start[7] = { 0, 4, 0, 2, 0, 1, 0 };
static const unsigned int adam7_y_start[7] = { 0, 0, 4, 0, 2, 0, 1 };
static const unsigned int adam7_x_delta[7] = { 8, 8, 4, 4, 2, 2, 1 };
static const unsigned int adam7_y_delta[7] = { 8, 8, 8, 4, 4, 2, 2 };

static const uint8_t type_ihdr[4] = { 73, 72, 68, 82 };
static const uint8_t type_plte[4] = { 80, 76, 84, 69 };
static const uint8_t type_idat[4] = { 73, 68, 65, 84 };
static const uint8_t type_iend[4] = { 73, 69, 78, 68 };

static const uint8_t type_trns[4] = { 116, 82, 78, 83 };
static const uint8_t type_chrm[4] = { 99,  72, 82, 77 };
static const uint8_t type_gama[4] = { 103, 65, 77, 65 };
static const uint8_t type_iccp[4] = { 105, 67, 67, 80 };
static const uint8_t type_sbit[4] = { 115, 66, 73, 84 };
static const uint8_t type_srgb[4] = { 115, 82, 71, 66 };
static const uint8_t type_text[4] = { 116, 69, 88, 116 };
static const uint8_t type_ztxt[4] = { 122, 84, 88, 116 };
static const uint8_t type_itxt[4] = { 105, 84, 88, 116 };
static const uint8_t type_bkgd[4] = { 98,  75, 71, 68 };
static const uint8_t type_hist[4] = { 104, 73, 83, 84 };
static const uint8_t type_phys[4] = { 112, 72, 89, 115 };
static const uint8_t type_splt[4] = { 115, 80, 76, 84 };
static const uint8_t type_time[4] = { 116, 73, 77, 69 };

static const uint8_t type_offs[4] = { 111, 70, 70, 115 };
static const uint8_t type_exif[4] = { 101, 88, 73, 102 };

static inline void *spng__malloc(spng_ctx *ctx,  size_t size)
{
    return ctx->alloc.malloc_fn(size);
}

static inline void *spng__calloc(spng_ctx *ctx, size_t nmemb, size_t size)
{
    return ctx->alloc.calloc_fn(nmemb, size);
}

static inline void *spng__realloc(spng_ctx *ctx, void *ptr, size_t size)
{
    return ctx->alloc.realloc_fn(ptr, size);
}

static inline void spng__free(spng_ctx *ctx, void *ptr)
{
    ctx->alloc.free_fn(ptr);
}

static void *spng__zalloc(void *opaque, unsigned items, unsigned size)
{
    spng_ctx *ctx = opaque;

    if(size > SIZE_MAX / items) return NULL;

    size_t len = (size_t)items * size;

    return spng__malloc(ctx, len);
}

static void spng__zfree(void *opqaue, void *ptr)
{
    spng_ctx *ctx = opqaue;
    spng__free(ctx, ptr);
}

static int spng__inflate_init(spng_ctx *ctx)
{
    if(ctx->zstream.state) inflateEnd(&ctx->zstream);

    ctx->zstream.zalloc = spng__zalloc;
    ctx->zstream.zfree = spng__zfree;
    ctx->zstream.opaque = ctx;

    if(inflateInit(&ctx->zstream) != Z_OK) return SPNG_EZLIB;

#if ZLIB_VERNUM >= 0x1290
//    if(inflateValidate(&ctx->zstream, ctx->flags & SPNG_CTX_IGNORE_ADLER32)) return SPNG_EZLIB; // iOS 11.0 or newer required for inflateValidate
#else
    #warning "zlib >= 1.2.11 is required for SPNG_CTX_IGNORE_ADLER32"
#endif

    return 0;
}

static inline uint16_t read_u16(const void *_data)
{
    const unsigned char *data = _data;

    return (data[0] & 0xFFU) << 8 | (data[1] & 0xFFU);
}

static inline uint32_t read_u32(const void *_data)
{
    const unsigned char *data = _data;

    return (data[0] & 0xFFUL) << 24 | (data[1] & 0xFFUL) << 16 |
           (data[2] & 0xFFUL) << 8  | (data[3] & 0xFFUL);
}

static inline int32_t read_s32(const void *_data)
{
    const unsigned char *data = _data;

    int32_t ret;
    uint32_t val = (data[0] & 0xFFUL) << 24 | (data[1] & 0xFFUL) << 16 |
                   (data[2] & 0xFFUL) << 8  | (data[3] & 0xFFUL);

    memcpy(&ret, &val, 4);

    return ret;
}

static void u16_row_to_host(void *row, size_t size)
{
    uint16_t *px = row;
    size_t i, n = size / 2;
    for(i=0; i < n; i++)
    {
        px[i] = read_u16(&px[i]);
    }
}

static void rgb8_row_to_rgba8(const unsigned char *row, unsigned char *out, uint32_t n)
{
    uint32_t i;
    for(i=0; i < n; i++)
    {
        memcpy(out + i * 4, row + i * 3, 3);
        out[i*4+3] = 255;
    }
}

/* Calculate scanline width in bits, round up to the nearest byte */
static int calculate_scanline_width(struct spng_ctx *ctx, struct spng_subimage *sub)
{
    if(!sub->width || !sub->height) return 1;

    size_t scanline_width = ctx->channels * ctx->ihdr.bit_depth;

    if(scanline_width > SIZE_MAX / ctx->ihdr.width) return SPNG_EOVERFLOW;
    scanline_width = scanline_width * sub->width;

    scanline_width += 15; /* Filter byte + 7 for rounding */

    if(scanline_width < 15) return SPNG_EOVERFLOW;

    scanline_width /= 8;

    sub->scanline_width = scanline_width;

    return 0;
}

static int calculate_subimages(struct spng_ctx *ctx)
{
    if(ctx == NULL) return 1;

    struct spng_ihdr *ihdr = &ctx->ihdr;
    struct spng_subimage *sub = ctx->subimage;

    if(ihdr->interlace_method == 1)
    {
        sub[0].width = (ihdr->width + 7) >> 3;
        sub[0].height = (ihdr->height + 7) >> 3;
        sub[1].width = (ihdr->width + 3) >> 3;
        sub[1].height = (ihdr->height + 7) >> 3;
        sub[2].width = (ihdr->width + 3) >> 2;
        sub[2].height = (ihdr->height + 3) >> 3;
        sub[3].width = (ihdr->width + 1) >> 2;
        sub[3].height = (ihdr->height + 3) >> 2;
        sub[4].width = (ihdr->width + 1) >> 1;
        sub[4].height = (ihdr->height + 1) >> 2;
        sub[5].width = ihdr->width >> 1;
        sub[5].height = (ihdr->height + 1) >> 1;
        sub[6].width = ihdr->width;
        sub[6].height = ihdr->height >> 1;
    }
    else
    {
        sub[0].width = ihdr->width;
        sub[0].height = ihdr->height;
    }

    int i;
    for(i=0; i < 7; i++)
    {
        if(sub[i].width == 0 || sub[i].height == 0) continue;

        int ret = calculate_scanline_width(ctx, &sub[i]);
        if(ret) return ret;

        if(sub[ctx->widest_pass].scanline_width < sub[i].scanline_width) ctx->widest_pass = i;

        ctx->last_pass = i;
    }

    return 0;
}

static int is_critical_chunk(struct spng_chunk *chunk)
{
    if(chunk == NULL) return 0;
    if((chunk->type[0] & (1 << 5)) == 0) return 1;

    return 0;
}

static inline int read_data(spng_ctx *ctx, size_t bytes)
{
    if(ctx == NULL) return 1;
    if(!bytes) return 0;

    if(ctx->streaming && (bytes > SPNG_READ_SIZE)) return 1;

    int ret;
    ret = ctx->read_fn(ctx, ctx->read_user_ptr, ctx->stream_buf, bytes);
    if(ret) return ret;

    ctx->bytes_read += bytes;
    if(ctx->bytes_read < bytes) return SPNG_EOVERFLOW;

    return 0;
}

/* Read and check the current chunk's crc,
   returns -SPNG_CRC_DISCARD if the chunk should be discarded */
static inline int read_and_check_crc(spng_ctx *ctx)
{
    if(ctx == NULL) return 1;

    int ret;
    ret = read_data(ctx, 4);
    if(ret) return ret;

    ctx->current_chunk.crc = read_u32(ctx->data);

    if(ctx->cur_actual_crc != ctx->current_chunk.crc)
    {
        if(is_critical_chunk(&ctx->current_chunk))
        {
            if(ctx->crc_action_critical == SPNG_CRC_USE) return 0;
        }
        else
        {
            if(ctx->crc_action_ancillary == SPNG_CRC_USE) return 0;
            if(ctx->crc_action_ancillary == SPNG_CRC_DISCARD) return -SPNG_CRC_DISCARD;
        }

        return SPNG_ECHUNK_CRC;
    }

    return 0;
}

/* Read and validate the current chunk's crc and the next chunk header */
static inline int read_header(spng_ctx *ctx, int *discard)
{
    if(ctx == NULL) return 1;

    int ret;
    struct spng_chunk chunk = { 0 };

    ret = read_and_check_crc(ctx);
    if(ret)
    {
        if(ret == -SPNG_CRC_DISCARD)
        {
            if(discard != NULL) *discard = 1;
        }
        else return ret;
    }

    ret = read_data(ctx, 8);
    if(ret) return ret;

    chunk.offset = ctx->bytes_read - 8;

    chunk.length = read_u32(ctx->data);

    memcpy(&chunk.type, ctx->data + 4, 4);

    if(chunk.length > png_u32max) return SPNG_ECHUNK_SIZE;

    ctx->cur_chunk_bytes_left = chunk.length;

    ctx->cur_actual_crc = crc32(0, NULL, 0);
    ctx->cur_actual_crc = crc32(ctx->cur_actual_crc, chunk.type, 4);

    memcpy(&ctx->current_chunk, &chunk, sizeof(struct spng_chunk));

    return 0;
}

/* Read chunk bytes and update crc */
static int read_chunk_bytes(spng_ctx *ctx, uint32_t bytes)
{
    if(ctx == NULL) return 1;
    if(!bytes) return 0;
    if(bytes > ctx->cur_chunk_bytes_left) return 1; /* XXX: more specific error? */

    int ret;

    ret = read_data(ctx, bytes);
    if(ret) return ret;

    if(is_critical_chunk(&ctx->current_chunk) &&
       ctx->crc_action_critical == SPNG_CRC_USE) goto skip_crc;
    else if(ctx->crc_action_ancillary == SPNG_CRC_USE) goto skip_crc;

    ctx->cur_actual_crc = crc32(ctx->cur_actual_crc, ctx->data, bytes);

skip_crc:
    ctx->cur_chunk_bytes_left -= bytes;

    return ret;
}

static int discard_chunk_bytes(spng_ctx *ctx, uint32_t bytes)
{
    if(ctx == NULL) return 1;

    int ret;

    if(ctx->streaming) /* Do small, consecutive reads */
    {
        while(bytes)
        {
            uint32_t len = SPNG_READ_SIZE;

            if(len > bytes) len = bytes;

            ret = read_chunk_bytes(ctx, len);
            if(ret) return ret;

            bytes -= len;
        }
    }
    else
    {
        ret = read_chunk_bytes(ctx, bytes);
        if(ret) return ret;
    }

    return 0;
}

/* Inflate a zlib stream from current position - offset to the end,
   allocating and writing the inflated stream to *out,
   final buffer length is *len.
   Takes into account the chunk cache limit
*/
static int spng__inflate_stream(spng_ctx *ctx, char **out, size_t *len, uint32_t offset)
{
    int ret = spng__inflate_init(ctx);
    if(ret) return ret;

    uint32_t read_size;
    size_t size = 1 << 13; /* 8192 */
    void *t, *buf = spng__malloc(ctx, size);
    if(buf == NULL) return SPNG_EMEM;

    size_t max = ctx->chunk_cache_limit - ctx->chunk_cache_usage;

    z_stream *stream = &ctx->zstream;

    stream->avail_in = ctx->last_read_size - offset;
    stream->next_in = ctx->data + offset;

    stream->avail_out = size;
    stream->next_out = buf;

    do
    {
        ret = inflate(stream, Z_SYNC_FLUSH);

        if(ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR)
        {
            spng__free(ctx, buf);
            return SPNG_EZLIB;
        }

        if(!stream->avail_out)
        {
            if(2 > SIZE_MAX / size)
            {
                spng__free(ctx, buf);
                return SPNG_EOVERFLOW;
            }

            size *= 2;

            if(size > max)
            {
                spng__free(ctx, buf);
                return SPNG_EMEM; /* chunk cache limit */
            }

            t = spng__realloc(ctx, buf, size);
            if(t == NULL) goto mem;

            stream->avail_out = size / 2;
            stream->next_out = buf + size / 2;
        }

        if(!stream->avail_in) /* Read more chunk bytes */
        {
            read_size = ctx->cur_chunk_bytes_left;
            if(read_size > SPNG_READ_SIZE) read_size = SPNG_READ_SIZE;

            ret = read_chunk_bytes(ctx, read_size);
            if(ret) return ret;

            stream->avail_in = read_size;
            stream->next_in = ctx->data;
        }

        ret = inflate(stream, Z_SYNC_FLUSH);

    }while(ret != Z_STREAM_END);

    size = stream->total_out;

    t = spng__realloc(ctx, buf, size);
    if(t == NULL) goto mem;

    *out = buf;
    *len = size;

    return 0;

mem:
    spng__free(ctx, buf);
    return SPNG_EMEM;
}

/* Read at least one byte from the IDAT stream */
static int read_idat_bytes(spng_ctx *ctx, uint32_t *bytes_read)
{
    if(ctx == NULL || bytes_read == NULL) return 1;
    if(memcmp(ctx->current_chunk.type, type_idat, 4)) return SPNG_EIDAT_TOO_SHORT;

    int ret;
    uint32_t len;

    while(!ctx->cur_chunk_bytes_left)
    {
        ret = read_header(ctx, NULL);
        if(ret) return ret;

        if(memcmp(ctx->current_chunk.type, type_idat, 4)) return SPNG_EIDAT_TOO_SHORT;
    }

    if(ctx->streaming)
    {/* TODO: calculate bytes to read for progressive reads */
        len = SPNG_READ_SIZE;
        if(len > ctx->cur_chunk_bytes_left) len = ctx->cur_chunk_bytes_left;
    }
    else len = ctx->current_chunk.length;

    ret = read_chunk_bytes(ctx, len);

    *bytes_read = len;

    return ret;
}

static int read_scanline_bytes(spng_ctx *ctx, unsigned char *dest, size_t len)
{
    if(ctx == NULL || dest == NULL) return 1;

    int ret;
    uint32_t bytes_read;

    ctx->zstream.avail_out = len;
    ctx->zstream.next_out = dest;

    while(ctx->zstream.avail_out != 0)
    {
        if(ctx->zstream.avail_in == 0) /* Need more IDAT bytes */
        {
            ret = read_idat_bytes(ctx, &bytes_read);
            if(ret) return ret;

            ctx->zstream.avail_in = bytes_read;
            ctx->zstream.next_in = ctx->data;
        }

        ret = inflate(&ctx->zstream, Z_SYNC_FLUSH);

        if(ret != Z_OK)
        {
            if(ret == Z_STREAM_END) /* zlib reached an end-marker */
            {
                if(ctx->zstream.avail_out != 0) return SPNG_EIDAT_TOO_SHORT;
            }
            else if(ret != Z_BUF_ERROR) return SPNG_EIDAT_STREAM;
        }
    }

    return 0;
}

static uint8_t paeth(uint8_t a, uint8_t b, uint8_t c)
{
    int16_t p = (int16_t)a + (int16_t)b - (int16_t)c;
    int16_t pa = abs(p - (int16_t)a);
    int16_t pb = abs(p - (int16_t)b);
    int16_t pc = abs(p - (int16_t)c);

    if(pa <= pb && pa <= pc) return a;
    else if(pb <= pc) return b;

    return c;
}

SPNG_TARGET_CLONES("default,avx2")
static void defilter_up(size_t bytes, unsigned char *row, const unsigned char *prev)
{
    size_t i;
    for(i=0; i < bytes; i++)
    {
        row[i] += prev[i];
    }
}

/* Defilter *scanline in-place.
   *prev_scanline and *scanline should point to the first pixel,
   scanline_width is the width of the scanline including the filter byte.
*/
static int defilter_scanline(const unsigned char *prev_scanline, unsigned char *scanline,
                             size_t scanline_width, unsigned bytes_per_pixel, unsigned filter)
{
    if(prev_scanline == NULL || scanline == NULL || !scanline_width) return 1;

    size_t i;
    scanline_width--;

    if(filter == 0) return 0;

#ifndef SPNG_DISABLE_OPT
    if(filter == SPNG_FILTER_UP) goto no_opt;

    if(bytes_per_pixel == 4)
    {
        if(filter == SPNG_FILTER_SUB)
            defilter_sub4(scanline_width, scanline);
        else if(filter == SPNG_FILTER_AVERAGE)
            defilter_avg4(scanline_width, scanline, prev_scanline);
        else if(filter == SPNG_FILTER_PAETH)
            defilter_paeth4(scanline_width, scanline, prev_scanline);
        else return SPNG_EFILTER;

        return 0;
    }
    else if(bytes_per_pixel == 3)
    {
        if(filter == SPNG_FILTER_SUB)
            defilter_sub3(scanline_width, scanline);
        else if(filter == SPNG_FILTER_AVERAGE)
            defilter_avg3(scanline_width, scanline, prev_scanline);
        else if(filter == SPNG_FILTER_PAETH)
            defilter_paeth3(scanline_width, scanline, prev_scanline);
        else return SPNG_EFILTER;

        return 0;
    }
no_opt:
#endif

    if(filter == SPNG_FILTER_UP)
    {
        defilter_up(scanline_width, scanline, prev_scanline);
        return 0;
    }

    for(i=0; i < scanline_width; i++)
    {
        uint8_t x, a, b, c;

        if(i >= bytes_per_pixel)
        {
            memcpy(&a, scanline + i - bytes_per_pixel, 1);
            memcpy(&b, prev_scanline + i, 1);
            memcpy(&c, prev_scanline + i - bytes_per_pixel, 1);
        }
        else /* First pixel in row */
        {
            a = 0;
            memcpy(&b, prev_scanline + i, 1);
            c = 0;
        }

        memcpy(&x, scanline + i, 1);

        switch(filter)
        {
            case SPNG_FILTER_SUB:
            {
                x = x + a;
                break;
            }
            case SPNG_FILTER_AVERAGE:
            {
                uint16_t avg = (a + b) / 2;
                x = x + avg;
                break;
            }
            case SPNG_FILTER_PAETH:
            {
                x = x + paeth(a,b,c);
                break;
            }
        }

        memcpy(scanline + i, &x, 1);
    }

    return 0;
}

/* Scale "sbits" significant bits in "sample" from "bit_depth" to "target"

   "bit_depth" must be a valid PNG depth
   "sbits" must be less than or equal to "bit_depth"
   "target" must be between 1 and 16
*/
static uint16_t sample_to_target(uint16_t sample, unsigned bit_depth, unsigned sbits, unsigned target)
{
    if(bit_depth == sbits)
    {
        if(target == sbits) return sample; /* No scaling */
    }/* bit_depth > sbits */
    else sample = sample >> (bit_depth - sbits); /* Shift significant bits to bottom */

    /* Downscale */
    if(target < sbits) return sample >> (sbits - target);

    /* Upscale using left bit replication */
    int8_t shift_amount = target - sbits;
    uint16_t sample_bits = sample;
    sample = 0;

    while(shift_amount >= 0)
    {
        sample = sample | (sample_bits << shift_amount);
        shift_amount -= sbits;
    }

    int8_t partial = shift_amount + (int8_t)sbits;

    if(partial != 0) sample = sample | (sample_bits >> abs(shift_amount));

    return sample;
}

static inline void gamma_correct_row(unsigned char *row, uint32_t pixels, int fmt, const uint16_t *gamma_lut)
{
    uint32_t i;

    if(fmt == SPNG_FMT_RGBA8)
    {
        unsigned char *px;
        for(i=0; i < pixels; i++)
        {
            px = row + i * 4;

            px[0] = gamma_lut[px[0]];
            px[1] = gamma_lut[px[1]];
            px[2] = gamma_lut[px[2]];
        }
    }
    else if(fmt == SPNG_FMT_RGBA16)
    {
        for(i=0; i < pixels; i++)
        {
            uint16_t px[4];
            memcpy(px, row + i * 8, 8);

            px[0] = gamma_lut[px[0]];
            px[1] = gamma_lut[px[1]];
            px[2] = gamma_lut[px[2]];

            memcpy(row + i * 8, px, 8);
        }
    }
    else if(fmt == SPNG_FMT_RGB8)
    {
        unsigned char *px;
        for(i=0; i < pixels; i++)
        {
            px = row + i * 3;

            px[0] = gamma_lut[px[0]];
            px[1] = gamma_lut[px[1]];
            px[2] = gamma_lut[px[2]];
        }
    }
}

/* Apply transparency to truecolor output row */
static inline void trns_row(unsigned char *row,
                            const unsigned char *scanline,
                            const unsigned char *trns,
                            uint32_t pixels,
                            int fmt,
                            unsigned ctype,
                            unsigned depth)
{
    if(ctype != SPNG_COLOR_TYPE_TRUECOLOR) return;

    uint32_t i;
    unsigned scanline_stride = 3; /* depth == 8 */
    if(depth == 16) scanline_stride = 6;

    if(fmt == SPNG_FMT_RGBA8)
    {
        for(i=0; i < pixels; i++, scanline+=scanline_stride, row+=4)
        {
            if(!memcmp(scanline, trns, scanline_stride)) row[3] = 0;
        }
    }
    else if(fmt == SPNG_FMT_RGBA16)
    {
        for(i=0; i < pixels; i++, scanline+=scanline_stride, row+=8)
        {
            if(!memcmp(scanline, trns, scanline_stride)) memset(row+6, 0, 2);
        }
    }
}

static inline void scale_row(unsigned char *row, uint32_t pixels, int fmt, unsigned depth, struct spng_sbit *sbit)
{
    uint32_t i;

    if(fmt == SPNG_FMT_RGBA8)
    {
        unsigned char px[4];
        for(i=0; i < pixels; i++)
        {
            memcpy(px, row + i * 4, 4);

            px[0] = sample_to_target(px[0], depth, sbit->red_bits, 8);
            px[1] = sample_to_target(px[1], depth, sbit->green_bits, 8);
            px[2] = sample_to_target(px[2], depth, sbit->blue_bits, 8);
            px[3] = sample_to_target(px[3], depth, sbit->alpha_bits, 8);

            memcpy(row + i * 4, px, 4);
        }
    }
    else if(fmt == SPNG_FMT_RGBA16)
    {
        uint16_t px[4];
        for(i=0; i < pixels; i++)
        {
            memcpy(px, row + i * 8, 8);

            px[0] = sample_to_target(px[0], depth, sbit->red_bits, 16);
            px[1] = sample_to_target(px[1], depth, sbit->green_bits, 16);
            px[2] = sample_to_target(px[2], depth, sbit->blue_bits, 16);
            px[3] = sample_to_target(px[3], depth, sbit->alpha_bits, 16);

            memcpy(row + i * 8, px, 8);
        }
    }
    else if(fmt == SPNG_FMT_RGB8)
    {
        unsigned char px[4];
        for(i=0; i < pixels; i++)
        {
            memcpy(px, row + i * 3, 3);

            px[0] = sample_to_target(px[0], depth, sbit->red_bits, 8);
            px[1] = sample_to_target(px[1], depth, sbit->green_bits, 8);
            px[2] = sample_to_target(px[2], depth, sbit->blue_bits, 8);

            memcpy(row + i * 3, px, 3);
        }
    }
}

/* Expand to *row using 8-bit palette indices from *scanline */
void expand_row(unsigned char *row, unsigned char *scanline, struct spng_plte_entry16 *plte, uint32_t width, int fmt)
{
    uint32_t i;
    unsigned char *px;
    unsigned char entry;
    if(fmt == SPNG_FMT_RGBA8)
    {
        for(i=0; i < width; i++)
        {
            px = row + i * 4;
            entry = scanline[i];
            px[0] = plte[entry].red;
            px[1] = plte[entry].green;
            px[2] = plte[entry].blue;
            px[3] = plte[entry].alpha;
        }
    }
    else if(fmt == SPNG_FMT_RGB8)
    {
        for(i=0; i < width; i++)
        {
            px = row + i * 3;
            entry = scanline[i];
            px[0] = plte[entry].red;
            px[1] = plte[entry].green;
            px[2] = plte[entry].blue;
        }
    }
}

static int check_ihdr(const struct spng_ihdr *ihdr, uint32_t max_width, uint32_t max_height)
{
    if(ihdr->width > png_u32max || ihdr->width > max_width || !ihdr->width) return SPNG_EWIDTH;
    if(ihdr->height > png_u32max || ihdr->height > max_height || !ihdr->height) return SPNG_EHEIGHT;

    switch(ihdr->color_type)
    {
        case SPNG_COLOR_TYPE_GRAYSCALE:
        {
            if( !(ihdr->bit_depth == 1 || ihdr->bit_depth == 2 ||
                  ihdr->bit_depth == 4 || ihdr->bit_depth == 8 ||
                  ihdr->bit_depth == 16) )
                  return SPNG_EBIT_DEPTH;

            break;
        }
        case SPNG_COLOR_TYPE_TRUECOLOR:
        case SPNG_COLOR_TYPE_GRAYSCALE_ALPHA:
        case SPNG_COLOR_TYPE_TRUECOLOR_ALPHA:
        {
            if( !(ihdr->bit_depth == 8 || ihdr->bit_depth == 16) )
                return SPNG_EBIT_DEPTH;

            break;
        }
        case SPNG_COLOR_TYPE_INDEXED:
        {
            if( !(ihdr->bit_depth == 1 || ihdr->bit_depth == 2 ||
                  ihdr->bit_depth == 4 || ihdr->bit_depth == 8) )
                return SPNG_EBIT_DEPTH;

            break;
        }
        default: return SPNG_ECOLOR_TYPE;
    }

    if(ihdr->compression_method) return SPNG_ECOMPRESSION_METHOD;
    if(ihdr->filter_method) return SPNG_EFILTER_METHOD;

    if(ihdr->interlace_method > 1) return SPNG_EINTERLACE_METHOD;

    return 0;
}

static int check_plte(const struct spng_plte *plte, const struct spng_ihdr *ihdr)
{
    if(plte == NULL || ihdr == NULL) return 1;

    if(plte->n_entries == 0) return 1;
    if(plte->n_entries > 256) return 1;

    if(ihdr->color_type == SPNG_COLOR_TYPE_INDEXED)
    {
        if(plte->n_entries > (1U << ihdr->bit_depth)) return 1;
    }

    return 0;
}

static int check_sbit(const struct spng_sbit *sbit, const struct spng_ihdr *ihdr)
{
    if(sbit == NULL || ihdr == NULL) return 1;

    if(ihdr->color_type == 0)
    {
        if(sbit->grayscale_bits == 0) return SPNG_ESBIT;
        if(sbit->grayscale_bits > ihdr->bit_depth) return SPNG_ESBIT;
    }
    else if(ihdr->color_type == 2 || ihdr->color_type == 3)
    {
        if(sbit->red_bits == 0) return SPNG_ESBIT;
        if(sbit->green_bits == 0) return SPNG_ESBIT;
        if(sbit->blue_bits == 0) return SPNG_ESBIT;

        uint8_t bit_depth;
        if(ihdr->color_type == 3) bit_depth = 8;
        else bit_depth = ihdr->bit_depth;

        if(sbit->red_bits > bit_depth) return SPNG_ESBIT;
        if(sbit->green_bits > bit_depth) return SPNG_ESBIT;
        if(sbit->blue_bits > bit_depth) return SPNG_ESBIT;
    }
    else if(ihdr->color_type == 4)
    {
        if(sbit->grayscale_bits == 0) return SPNG_ESBIT;
        if(sbit->alpha_bits == 0) return SPNG_ESBIT;

        if(sbit->grayscale_bits > ihdr->bit_depth) return SPNG_ESBIT;
        if(sbit->alpha_bits > ihdr->bit_depth) return SPNG_ESBIT;
    }
    else if(ihdr->color_type == 6)
    {
        if(sbit->red_bits == 0) return SPNG_ESBIT;
        if(sbit->green_bits == 0) return SPNG_ESBIT;
        if(sbit->blue_bits == 0) return SPNG_ESBIT;
        if(sbit->alpha_bits == 0) return SPNG_ESBIT;

        if(sbit->red_bits > ihdr->bit_depth) return SPNG_ESBIT;
        if(sbit->green_bits > ihdr->bit_depth) return SPNG_ESBIT;
        if(sbit->blue_bits > ihdr->bit_depth) return SPNG_ESBIT;
        if(sbit->alpha_bits > ihdr->bit_depth) return SPNG_ESBIT;
    }

    return 0;
}

static int check_chrm_int(const struct spng_chrm_int *chrm_int)
{
    if(chrm_int == NULL) return 1;

    if(chrm_int->white_point_x > png_u32max ||
       chrm_int->white_point_y > png_u32max ||
       chrm_int->red_x > png_u32max ||
       chrm_int->red_y > png_u32max ||
       chrm_int->green_x  > png_u32max ||
       chrm_int->green_y  > png_u32max ||
       chrm_int->blue_x > png_u32max ||
       chrm_int->blue_y > png_u32max) return SPNG_ECHRM;

    return 0;
}

static int check_phys(const struct spng_phys *phys)
{
    if(phys == NULL) return 1;

    if(phys->unit_specifier > 1) return SPNG_EPHYS;

    if(phys->ppu_x > png_u32max) return SPNG_EPHYS;
    if(phys->ppu_y > png_u32max) return SPNG_EPHYS;

    return 0;
}

static int check_time(const struct spng_time *time)
{
    if(time == NULL) return 1;

    if(time->month == 0 || time->month > 12) return 1;
    if(time->day == 0 || time->day > 31) return 1;
    if(time->hour > 23) return 1;
    if(time->minute > 59) return 1;
    if(time->second > 60) return 1;

    return 0;
}

static int check_offs(const struct spng_offs *offs)
{
    if(offs == NULL) return 1;

    if(offs->unit_specifier > 1) return 1;

    return 0;
}

static int check_exif(const struct spng_exif *exif)
{
    if(exif == NULL) return 1;
    if(exif->data == NULL) return 1;

    if(exif->length < 4) return SPNG_ECHUNK_SIZE;
    if(exif->length > png_u32max) return SPNG_ECHUNK_SIZE;

    const uint8_t exif_le[4] = { 73, 73, 42, 0 };
    const uint8_t exif_be[4] = { 77, 77, 0, 42 };

    if(memcmp(exif->data, exif_le, 4) && memcmp(exif->data, exif_be, 4)) return 1;

    return 0;
}

/* Validate PNG keyword *str, *str must be 80 bytes */
static int check_png_keyword(const char str[80])
{
    if(str == NULL) return 1;
    char *end = memchr(str, '\0', 80);

    if(end == NULL) return 1; /* Unterminated string */
    if(end == str) return 1; /* Zero-length string */
    if(str[0] == ' ') return 1; /* Leading space */
    if(end[-1] == ' ') return 1; /* Trailing space */
    if(strstr(str, "  ") != NULL) return 1; /* Consecutive spaces */

    uint8_t c;
    while(str != end)
    {
        memcpy(&c, str, 1);

        if( (c >= 32 && c <= 126) || (c >= 161) ) str++;
        else return 1; /* Invalid character */
    }

    return 0;
}

/* Validate PNG text *str up to 'len' bytes */
static int check_png_text(const char *str, size_t len)
{/* XXX: are consecutive newlines permitted? */
    if(str == NULL || len == 0) return 1;

    uint8_t c;
    size_t i = 0;
    while(i < len)
    {
        memcpy(&c, str + i, 1);

        if( (c >= 32 && c <= 126) || (c >= 161) || c == 10) i++;
        else return 1; /* Invalid character */
    }

    return 0;
}

static int chunk_fits_in_cache(spng_ctx *ctx, size_t *new_usage)
{
    if(ctx == NULL || new_usage == NULL) return 0;

    size_t usage = ctx->chunk_cache_usage + (size_t)ctx->current_chunk.length;

    if(usage < ctx->chunk_cache_usage) return 0; /* Overflow */

    if(usage > ctx->chunk_cache_limit) return 0;

    *new_usage = usage;

    return 1;
}

/* Returns non-zero for standard chunks which are stored without allocating memory */
static int is_small_chunk(uint8_t type[4])
{
    if(!memcmp(type, type_plte, 4)) return 1;
    else if(!memcmp(type, type_chrm, 4)) return 1;
    else if(!memcmp(type, type_gama, 4)) return 1;
    else if(!memcmp(type, type_sbit, 4)) return 1;
    else if(!memcmp(type, type_srgb, 4)) return 1;
    else if(!memcmp(type, type_bkgd, 4)) return 1;
    else if(!memcmp(type, type_trns, 4)) return 1;
    else if(!memcmp(type, type_hist, 4)) return 1;
    else if(!memcmp(type, type_phys, 4)) return 1;
    else if(!memcmp(type, type_time, 4)) return 1;
    else if(!memcmp(type, type_offs, 4)) return 1;
    else return 0;
}

static int read_ihdr(spng_ctx *ctx)
{
    int ret;
    struct spng_chunk chunk;
    const unsigned char *data;

    chunk.offset = 8;
    chunk.length = 13;
    size_t sizeof_sig_ihdr = 29;

    ret = read_data(ctx, sizeof_sig_ihdr);
    if(ret) return ret;

    data = ctx->data;

    if(memcmp(data, png_signature, sizeof(png_signature))) return SPNG_ESIGNATURE;

    chunk.length = read_u32(data + 8);
    memcpy(&chunk.type, data + 12, 4);

    if(chunk.length != 13) return SPNG_EIHDR_SIZE;
    if(memcmp(chunk.type, type_ihdr, 4)) return SPNG_ENOIHDR;

    ctx->cur_actual_crc = crc32(0, NULL, 0);
    ctx->cur_actual_crc = crc32(ctx->cur_actual_crc, data + 12, 17);

    ctx->ihdr.width = read_u32(data + 16);
    ctx->ihdr.height = read_u32(data + 20);
    memcpy(&ctx->ihdr.bit_depth, data + 24, 1);
    memcpy(&ctx->ihdr.color_type, data + 25, 1);
    memcpy(&ctx->ihdr.compression_method, data + 26, 1);
    memcpy(&ctx->ihdr.filter_method, data + 27, 1);
    memcpy(&ctx->ihdr.interlace_method, data + 28, 1);

    if(!ctx->max_width) ctx->max_width = png_u32max;
    if(!ctx->max_height) ctx->max_height = png_u32max;

    ret = check_ihdr(&ctx->ihdr, ctx->max_width, ctx->max_height);
    if(ret) return ret;

    ctx->file.ihdr = 1;
    ctx->stored.ihdr = 1;

    ctx->channels = 1; /* grayscale or indexed color */

    if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR) ctx->channels = 3;
    else if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_GRAYSCALE_ALPHA) ctx->channels = 2;
    else if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR_ALPHA) ctx->channels = 4;

    if(ctx->ihdr.bit_depth < 8) ctx->bytes_per_pixel = 1;
    else ctx->bytes_per_pixel = ctx->channels * (ctx->ihdr.bit_depth / 8);

    ret = calculate_subimages(ctx);
    if(ret) return ret;

    return 0;
}

static int read_non_idat_chunks(spng_ctx *ctx)
{
    int ret, discard = 0;
    int prev_was_idat = ctx->state == SPNG_STATE_AFTER_IDAT ? 1 : 0;
    struct spng_chunk chunk;
    const unsigned char *data;

    struct spng_chunk_bitfield stored;
    memcpy(&stored, &ctx->stored, sizeof(struct spng_chunk_bitfield));

    while( !(ret = read_header(ctx, &discard)))
    {
        if(discard)
        {
            memcpy(&ctx->stored, &stored, sizeof(struct spng_chunk_bitfield));
        }

        memcpy(&stored, &ctx->stored, sizeof(struct spng_chunk_bitfield));

        memcpy(&chunk, &ctx->current_chunk, sizeof(struct spng_chunk));

        if(!memcmp(chunk.type, type_idat, 4))
        {
            if(ctx->state < SPNG_STATE_FIRST_IDAT)
            {
                if(ctx->ihdr.color_type == 3 && !ctx->stored.plte) return SPNG_ENOPLTE;

                memcpy(&ctx->first_idat, &chunk, sizeof(struct spng_chunk));
                return 0;
            }

            if(prev_was_idat)
            {
                /* Ignore extra IDAT's */
                ret = discard_chunk_bytes(ctx, chunk.length);
                if(ret) return ret;

                continue;
            }
            else return SPNG_ECHUNK_POS; /* IDAT chunk not at the end of the IDAT sequence */
        }

        prev_was_idat = 0;

        if(is_small_chunk(chunk.type))
        {/* The largest of these chunks is PLTE with 256 entries */
            ret = read_chunk_bytes(ctx, chunk.length > 768 ? 768 : chunk.length);
            if(ret) return ret;
        }

        data = ctx->data;

        if(is_critical_chunk(&chunk))
        {
            if(!memcmp(chunk.type, type_plte, 4))
            {
                if(ctx->file.trns || ctx->file.hist || ctx->file.bkgd) return SPNG_ECHUNK_POS;
                if(chunk.length % 3 != 0) return SPNG_ECHUNK_SIZE;

                ctx->plte.n_entries = chunk.length / 3;

                if(check_plte(&ctx->plte, &ctx->ihdr)) return SPNG_ECHUNK_SIZE; /* XXX: EPLTE? */

                size_t i;
                for(i=0; i < ctx->plte.n_entries; i++)
                {
                    memcpy(&ctx->plte.entries[i].red,   data + i * 3, 1);
                    memcpy(&ctx->plte.entries[i].green, data + i * 3 + 1, 1);
                    memcpy(&ctx->plte.entries[i].blue,  data + i * 3 + 2, 1);
                }

                ctx->file.plte = 1;
                ctx->stored.plte = 1;
            }
            else if(!memcmp(chunk.type, type_iend, 4))
            {
                if(ctx->state == SPNG_STATE_AFTER_IDAT)
                {
                    if(chunk.length) return SPNG_ECHUNK_SIZE;

                    ret = read_and_check_crc(ctx);
                    if(ret == -SPNG_CRC_DISCARD) ret = 0;

                    return ret;
                }
                else return SPNG_ECHUNK_POS;
            }
            else if(!memcmp(chunk.type, type_ihdr, 4)) return SPNG_ECHUNK_POS;
            else return SPNG_ECHUNK_UNKNOWN_CRITICAL;
        }
        else if(!memcmp(chunk.type, type_chrm, 4)) /* Ancillary chunks */
        {
            if(ctx->file.plte) return SPNG_ECHUNK_POS;
            if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
            if(ctx->file.chrm) return SPNG_EDUP_CHRM;

            if(chunk.length != 32) return SPNG_ECHUNK_SIZE;

            ctx->chrm_int.white_point_x = read_u32(data);
            ctx->chrm_int.white_point_y = read_u32(data + 4);
            ctx->chrm_int.red_x = read_u32(data + 8);
            ctx->chrm_int.red_y = read_u32(data + 12);
            ctx->chrm_int.green_x = read_u32(data + 16);
            ctx->chrm_int.green_y = read_u32(data + 20);
            ctx->chrm_int.blue_x = read_u32(data + 24);
            ctx->chrm_int.blue_y = read_u32(data + 28);

            if(check_chrm_int(&ctx->chrm_int)) return SPNG_ECHRM;

            ctx->file.chrm = 1;
            ctx->stored.chrm = 1;
        }
        else if(!memcmp(chunk.type, type_gama, 4))
        {
            if(ctx->file.plte) return SPNG_ECHUNK_POS;
            if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
            if(ctx->file.gama) return SPNG_EDUP_GAMA;

            if(chunk.length != 4) return SPNG_ECHUNK_SIZE;

            ctx->gama = read_u32(data);

            if(!ctx->gama) return SPNG_EGAMA;
            if(ctx->gama > png_u32max) return SPNG_EGAMA;

            ctx->file.gama = 1;
            ctx->stored.gama = 1;
        }
        else if(!memcmp(chunk.type, type_sbit, 4))
        {
            if(ctx->file.plte) return SPNG_ECHUNK_POS;
            if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
            if(ctx->file.sbit) return SPNG_EDUP_SBIT;

            if(ctx->ihdr.color_type == 0)
            {
                if(chunk.length != 1) return SPNG_ECHUNK_SIZE;

                memcpy(&ctx->sbit.grayscale_bits, data, 1);
            }
            else if(ctx->ihdr.color_type == 2 || ctx->ihdr.color_type == 3)
            {
                if(chunk.length != 3) return SPNG_ECHUNK_SIZE;

                memcpy(&ctx->sbit.red_bits, data, 1);
                memcpy(&ctx->sbit.green_bits, data + 1 , 1);
                memcpy(&ctx->sbit.blue_bits, data + 2, 1);
            }
            else if(ctx->ihdr.color_type == 4)
            {
                if(chunk.length != 2) return SPNG_ECHUNK_SIZE;

                memcpy(&ctx->sbit.grayscale_bits, data, 1);
                memcpy(&ctx->sbit.alpha_bits, data + 1, 1);
            }
            else if(ctx->ihdr.color_type == 6)
            {
                if(chunk.length != 4) return SPNG_ECHUNK_SIZE;

                memcpy(&ctx->sbit.red_bits, data, 1);
                memcpy(&ctx->sbit.green_bits, data + 1, 1);
                memcpy(&ctx->sbit.blue_bits, data + 2, 1);
                memcpy(&ctx->sbit.alpha_bits, data + 3, 1);
            }

            if(check_sbit(&ctx->sbit, &ctx->ihdr)) return SPNG_ESBIT;

            ctx->file.sbit = 1;
            ctx->stored.sbit = 1;
        }
        else if(!memcmp(chunk.type, type_srgb, 4))
        {
            if(ctx->file.plte) return SPNG_ECHUNK_POS;
            if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
            if(ctx->file.srgb) return SPNG_EDUP_SRGB;

            if(chunk.length != 1) return SPNG_ECHUNK_SIZE;

            memcpy(&ctx->srgb_rendering_intent, data, 1);

            if(ctx->srgb_rendering_intent > 3) return SPNG_ESRGB;

            ctx->file.srgb = 1;
            ctx->stored.srgb = 1;
        }
        else if(!memcmp(chunk.type, type_bkgd, 4))
        {
            if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
            if(ctx->file.bkgd) return SPNG_EDUP_BKGD;

            uint16_t mask = ~0;
            if(ctx->ihdr.bit_depth < 16) mask = (1 << ctx->ihdr.bit_depth) - 1;

            if(ctx->ihdr.color_type == 0 || ctx->ihdr.color_type == 4)
            {
                if(chunk.length != 2) return SPNG_ECHUNK_SIZE;

                ctx->bkgd.gray = read_u16(data) & mask;
            }
            else if(ctx->ihdr.color_type == 2 || ctx->ihdr.color_type == 6)
            {
                if(chunk.length != 6) return SPNG_ECHUNK_SIZE;

                ctx->bkgd.red = read_u16(data) & mask;
                ctx->bkgd.green = read_u16(data + 2) & mask;
                ctx->bkgd.blue = read_u16(data + 4) & mask;
            }
            else if(ctx->ihdr.color_type == 3)
            {
                if(chunk.length != 1) return SPNG_ECHUNK_SIZE;
                if(!ctx->file.plte) return SPNG_EBKGD_NO_PLTE;

                ctx->bkgd.plte_index = data[0];
                if(ctx->bkgd.plte_index >= ctx->plte.n_entries) return SPNG_EBKGD_PLTE_IDX;
            }

            ctx->file.bkgd = 1;
            ctx->stored.bkgd = 1;
        }
        else if(!memcmp(chunk.type, type_trns, 4))
        {
            if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
            if(ctx->file.trns) return SPNG_EDUP_TRNS;
            if(!chunk.length) return SPNG_ECHUNK_SIZE;

            uint16_t mask = ~0;
            if(ctx->ihdr.bit_depth < 16) mask = (1 << ctx->ihdr.bit_depth) - 1;

            if(ctx->ihdr.color_type == 0)
            {
                if(chunk.length != 2) return SPNG_ECHUNK_SIZE;

                ctx->trns.gray = read_u16(data) & mask;
            }
            else if(ctx->ihdr.color_type == 2)
            {
                if(chunk.length != 6) return SPNG_ECHUNK_SIZE;

                ctx->trns.red = read_u16(data) & mask;
                ctx->trns.green = read_u16(data + 2) & mask;
                ctx->trns.blue = read_u16(data + 4) & mask;
            }
            else if(ctx->ihdr.color_type == 3)
            {
                if(chunk.length > ctx->plte.n_entries) return SPNG_ECHUNK_SIZE;
                if(!ctx->file.plte) return SPNG_ETRNS_NO_PLTE;

                size_t k;
                for(k=0; k < chunk.length; k++)
                {
                    memcpy(&ctx->trns.type3_alpha[k], data + k, 1);
                }
                ctx->trns.n_type3_entries = chunk.length;
            }
            else return SPNG_ETRNS_COLOR_TYPE;

            ctx->file.trns = 1;
            ctx->stored.trns = 1;
        }
        else if(!memcmp(chunk.type, type_hist, 4))
        {
            if(!ctx->file.plte) return SPNG_EHIST_NO_PLTE;
            if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
            if(ctx->file.hist) return SPNG_EDUP_HIST;

            if( (chunk.length / 2) != (ctx->plte.n_entries) ) return SPNG_ECHUNK_SIZE;

            size_t k;
            for(k=0; k < (chunk.length / 2); k++)
            {
                ctx->hist.frequency[k] = read_u16(data + k*2);
            }

            ctx->file.hist = 1;
            ctx->stored.hist = 1;
        }
        else if(!memcmp(chunk.type, type_phys, 4))
        {
            if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
            if(ctx->file.phys) return SPNG_EDUP_PHYS;

            if(chunk.length != 9) return SPNG_ECHUNK_SIZE;

            ctx->phys.ppu_x = read_u32(data);
            ctx->phys.ppu_y = read_u32(data + 4);
            memcpy(&ctx->phys.unit_specifier, data + 8, 1);

            if(check_phys(&ctx->phys)) return SPNG_EPHYS;

            ctx->file.phys = 1;
            ctx->stored.phys = 1;
        }
        else if(!memcmp(chunk.type, type_time, 4))
        {
            if(ctx->file.time) return SPNG_EDUP_TIME;

            if(chunk.length != 7) return SPNG_ECHUNK_SIZE;

            struct spng_time time;

            time.year = read_u16(data);
            memcpy(&time.month, data + 2, 1);
            memcpy(&time.day, data + 3, 1);
            memcpy(&time.hour, data + 4, 1);
            memcpy(&time.minute, data + 5, 1);
            memcpy(&time.second, data + 6, 1);

            if(check_time(&time)) return SPNG_ETIME;

            ctx->file.time = 1;

            if(!ctx->user.time) memcpy(&ctx->time, &time, sizeof(struct spng_time));

            ctx->stored.time = 1;
        }
        else if(!memcmp(chunk.type, type_offs, 4))
        {
            if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
            if(ctx->file.offs) return SPNG_EDUP_OFFS;

            if(chunk.length != 9) return SPNG_ECHUNK_SIZE;

            ctx->offs.x = read_s32(data);
            ctx->offs.y = read_s32(data + 4);
            memcpy(&ctx->offs.unit_specifier, data + 8, 1);

            if(check_offs(&ctx->offs)) return SPNG_EOFFS;

            ctx->file.offs = 1;
            ctx->stored.offs = 1;
        }
        else /* Arbitrary-length chunk */
        {
            ret = discard_chunk_bytes(ctx, chunk.length);
            if(ret) return ret;

            continue;

            if(!memcmp(chunk.type, type_iccp, 4))
            {
                if(ctx->file.plte) return SPNG_ECHUNK_POS;
                if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
                if(ctx->file.iccp) return SPNG_EDUP_ICCP;
                if(!chunk.length) return SPNG_ECHUNK_SIZE;

                uint32_t keyword_len = 81 > chunk.length ? chunk.length : 81;
                ret = read_chunk_bytes(ctx, 81);

                unsigned char *keyword_nul = memchr(ctx->data, '\0', keyword_len);
                if(keyword_nul == NULL) return SPNG_EICCP_NAME;

                memcpy(ctx->iccp.profile_name, ctx->data, keyword_nul - ctx->data);

                if(check_png_keyword(ctx->iccp.profile_name)) return SPNG_EICCP_NAME;

                if(chunk.length - keyword_len - 1) return SPNG_ECHUNK_SIZE;

                if(ctx->data[keyword_len + 1] != 0) return SPNG_EICCP_COMPRESSION_METHOD;

                ctx->last_read_size = keyword_len;
                ret = spng__inflate_stream(ctx, &ctx->iccp.profile, &ctx->iccp.profile_len, keyword_len + 1);

                continue;
            }

            if(!chunk_fits_in_cache(ctx, &ctx->chunk_cache_usage))
            {
                ret = discard_chunk_bytes(ctx, chunk.length);
                if(ret) return ret;
                continue;
            }

            ret = read_chunk_bytes(ctx, chunk.length);
            if(ret) return ret;

            data = ctx->data;

            if(!memcmp(chunk.type, type_splt, 4))
            {
                if(ctx->state == SPNG_STATE_AFTER_IDAT) return SPNG_ECHUNK_POS;
                if(ctx->user.splt) continue; /* XXX: should check profile names for uniqueness */
                if(!chunk.length) return SPNG_ECHUNK_SIZE;

                ctx->file.splt = 1;

                if(!ctx->stored.splt)
                {
                    ctx->n_splt = 1;
                    ctx->splt_list = spng__calloc(ctx, 1, sizeof(struct spng_splt));
                    if(ctx->splt_list == NULL) return SPNG_EMEM;
                }
                else
                {
                    ctx->n_splt++;
                    if(ctx->n_splt < 1) return SPNG_EOVERFLOW;
                    if(sizeof(struct spng_splt) > SIZE_MAX / ctx->n_splt) return SPNG_EOVERFLOW;

                    void *buf = spng__realloc(ctx, ctx->splt_list, ctx->n_splt * sizeof(struct spng_splt));
                    if(buf == NULL) return SPNG_EMEM;
                    ctx->splt_list = buf;
                    memset(&ctx->splt_list[ctx->n_splt - 1], 0, sizeof(struct spng_splt));
                }

                uint32_t i = ctx->n_splt - 1;

                size_t keyword_len = chunk.length > 80 ? 80 : chunk.length;
                char *keyword_nul = memchr(data, '\0', keyword_len);
                if(keyword_nul == NULL) return SPNG_ESPLT_NAME;

                memcpy(&ctx->splt_list[i].name, data, keyword_len);

                if(check_png_keyword(ctx->splt_list[i].name)) return SPNG_ESPLT_NAME;

                keyword_len = strlen(ctx->splt_list[i].name);

                if( (chunk.length - keyword_len - 1) ==  0) return SPNG_ECHUNK_SIZE;

                memcpy(&ctx->splt_list[i].sample_depth, data + keyword_len + 1, 1);

                if(ctx->n_splt > 1)
                {
                    uint32_t j;
                    for(j=0; j < i; j++)
                    {
                        if(!strcmp(ctx->splt_list[j].name, ctx->splt_list[i].name)) return SPNG_ESPLT_DUP_NAME;
                    }
                }

                uint32_t entries_len = chunk.length - keyword_len - 2;

                if(ctx->splt_list[i].sample_depth == 16)
                {
                    if(entries_len % 10 != 0) return SPNG_ECHUNK_SIZE;
                    ctx->splt_list[i].n_entries = entries_len / 10;
                }
                else if(ctx->splt_list[i].sample_depth == 8)
                {
                    if(entries_len % 6 != 0) return SPNG_ECHUNK_SIZE;
                    ctx->splt_list[i].n_entries = entries_len / 6;
                }
                else return SPNG_ESPLT_DEPTH;

                if(ctx->splt_list[i].n_entries == 0) return SPNG_ECHUNK_SIZE;
                if(sizeof(struct spng_splt_entry) > SIZE_MAX / ctx->splt_list[i].n_entries) return SPNG_EOVERFLOW;

                ctx->splt_list[i].entries = spng__malloc(ctx, sizeof(struct spng_splt_entry) * ctx->splt_list[i].n_entries);
                if(ctx->splt_list[i].entries == NULL) return SPNG_EMEM;

                const unsigned char *splt = data + keyword_len + 2;

                size_t k;
                if(ctx->splt_list[i].sample_depth == 16)
                {
                    for(k=0; k < ctx->splt_list[i].n_entries; k++)
                    {
                        ctx->splt_list[i].entries[k].red = read_u16(splt + k * 10);
                        ctx->splt_list[i].entries[k].green = read_u16(splt + k * 10 + 2);
                        ctx->splt_list[i].entries[k].blue = read_u16(splt + k * 10 + 4);
                        ctx->splt_list[i].entries[k].alpha = read_u16(splt + k * 10 + 6);
                        ctx->splt_list[i].entries[k].frequency = read_u16(splt + k * 10 + 8);
                    }
                }
                else if(ctx->splt_list[i].sample_depth == 8)
                {
                    for(k=0; k < ctx->splt_list[i].n_entries; k++)
                    {
                        uint8_t red, green, blue, alpha;
                        memcpy(&red,   splt + k * 6, 1);
                        memcpy(&green, splt + k * 6 + 1, 1);
                        memcpy(&blue,  splt + k * 6 + 2, 1);
                        memcpy(&alpha, splt + k * 6 + 3, 1);
                        ctx->splt_list[i].entries[k].frequency = read_u16(splt + k * 6 + 4);

                        ctx->splt_list[i].entries[k].red = red;
                        ctx->splt_list[i].entries[k].green = green;
                        ctx->splt_list[i].entries[k].blue = blue;
                        ctx->splt_list[i].entries[k].alpha = alpha;
                    }
                }

                ctx->stored.splt = 1;
            }
            else if(!memcmp(chunk.type, type_text, 4) ||
                    !memcmp(chunk.type, type_ztxt, 4) ||
                    !memcmp(chunk.type, type_itxt, 4))
            {
                ctx->file.text = 1;

                continue;
            }
            else if(!memcmp(chunk.type, type_exif, 4))
            {
                if(ctx->file.exif) return SPNG_EDUP_EXIF;

                ctx->file.exif = 1;

                struct spng_exif exif;

                exif.data = (char *)data;
                exif.length = chunk.length;

                if(!check_exif(&exif))
                {
                    if(ctx->user.exif) continue;

                    exif.data = spng__malloc(ctx, chunk.length);
                    if(exif.data == NULL) return SPNG_EMEM;

                    memcpy(exif.data, data, chunk.length);
                    memcpy(&ctx->exif, &exif, sizeof(struct spng_exif));
                    ctx->stored.exif = 1;
                }
                else return SPNG_EEXIF;
            }
        }

    }

    return ret;
}

/* Read chunks before or after the IDAT chunks depending on state */
static int read_chunks(spng_ctx *ctx, int only_ihdr)
{
    if(ctx == NULL) return 1;
    if(!ctx->state) return SPNG_EBADSTATE;
    if(ctx->data == NULL)
    {
        if(ctx->encode_only) return 0;
        else return 1;
    }

    int ret = 0;

    if(ctx->state == SPNG_STATE_INPUT)
    {
        ret = read_ihdr(ctx);
        if(ret)
        {
            ctx->state = SPNG_STATE_INVALID;
            return ret;
        }

        ctx->state = SPNG_STATE_IHDR;
    }

    if(only_ihdr) return 0;

    if(ctx->state == SPNG_STATE_EOI) ctx->state = SPNG_STATE_AFTER_IDAT;

    if(ctx->state < SPNG_STATE_FIRST_IDAT ||
       ctx->state == SPNG_STATE_AFTER_IDAT) ret = read_non_idat_chunks(ctx);

    if(ret) ctx->state = SPNG_STATE_INVALID;

    return ret;
}

static int decode_err(spng_ctx *ctx, int err)
{
    ctx->state = SPNG_STATE_INVALID;

    return err;
}

int spng_decode_scanline(spng_ctx *ctx, unsigned char *out, size_t len)
{
    if(ctx == NULL || out == NULL) return 1;

    if(ctx->state >= SPNG_STATE_EOI) return SPNG_EOI;

    struct decode_flags f = {0};

    memcpy(&f, &ctx->decode_flags, sizeof(struct decode_flags));

    int ret;
    int fmt = ctx->fmt;

    struct spng_row_info *ri = &ctx->row_info;
    struct spng_subimage *sub = ctx->subimage;

    uint16_t *gamma_lut = ctx->gamma_lut;
    unsigned char *trns_px = ctx->trns_px;
    struct spng_sbit *sb = &ctx->decode_sb;
    struct spng_plte_entry16 *plte = ctx->decode_plte;

    unsigned char *scanline = ctx->scanline;

    int pass = ri->pass;
    uint8_t next_filter = 0;
    size_t scanline_width = sub[pass].scanline_width;
    uint32_t k;
    uint32_t scanline_idx = ri->scanline_idx;
    uint32_t width = sub[pass].width;
    uint8_t r_8, g_8, b_8, a_8, gray_8;
    uint16_t r_16, g_16, b_16, a_16, gray_16;
    r_8=0; g_8=0; b_8=0; a_8=0; gray_8=0;
    r_16=0; g_16=0; b_16=0; a_16=0; gray_16=0;
    const uint8_t samples_per_byte = 8 / ctx->ihdr.bit_depth;
    const uint8_t mask = (uint16_t)(1 << ctx->ihdr.bit_depth) - 1;
    const uint8_t initial_shift = 8 - ctx->ihdr.bit_depth;
    uint8_t shift_amount = initial_shift;
    size_t pixel_size = 4; /* SPNG_FMT_RGBA8 */
    size_t pixel_offset = 0;
    unsigned char *pixel;
    unsigned processing_depth = ctx->ihdr.bit_depth;

    if(f.indexed) processing_depth = 8;

    if(fmt == SPNG_FMT_RGBA16) pixel_size = 8;
    else if(fmt == SPNG_FMT_RGB8) pixel_size = 3;

    if(fmt == SPNG_FMT_PNG)
    {
        if(len < (scanline_width - 1)) return SPNG_EBUFSIZ;
    }
    else
    {
        if(len < (width * pixel_size)) return SPNG_EBUFSIZ;
    }

    if(scanline_idx == (sub[pass].height - 1) && ri->pass == ctx->last_pass)
    {
        ret = read_scanline_bytes(ctx, ctx->scanline, scanline_width - 1);
    }
    else
    {
        ret = read_scanline_bytes(ctx, ctx->scanline, scanline_width);
        if(ret) return decode_err(ctx, ret);

        memcpy(&next_filter, ctx->scanline + scanline_width - 1, 1);
        if(next_filter > 4) ret = SPNG_EFILTER;
    }

    if(ret) return decode_err(ctx, ret);

    if(!scanline_idx && ri->filter > 1)
    {
        /* prev_scanline is all zeros for the first scanline */
        memset(ctx->prev_scanline, 0, scanline_width);
    }

    if(ctx->ihdr.bit_depth == 16) u16_row_to_host(ctx->scanline, scanline_width - 1);

    ret = defilter_scanline(ctx->prev_scanline, ctx->scanline, scanline_width, ctx->bytes_per_pixel, ri->filter);
    if(ret) return decode_err(ctx, ret);

    ri->filter = next_filter;

    for(k=0; k < width; k++)
    {
        pixel = out + pixel_offset;
        pixel_offset += pixel_size;

        if(f.same_layout)
        {
            if(f.zerocopy) break;

            memcpy(out, scanline, scanline_width - 1);
            break;
        }

        if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR)
        {
            if(ctx->ihdr.bit_depth == 16)
            {
                memcpy(&r_16, scanline + (k * 6), 2);
                memcpy(&g_16, scanline + (k * 6) + 2, 2);
                memcpy(&b_16, scanline + (k * 6) + 4, 2);

                a_16 = 65535;
            }
            else /* == 8 */
            {
                if(fmt == SPNG_FMT_RGBA8)
                {
                    rgb8_row_to_rgba8(scanline, out, width);
                    break;
                }

                memcpy(&r_8, scanline + (k * 3), 1);
                memcpy(&g_8, scanline + (k * 3) + 1, 1);
                memcpy(&b_8, scanline + (k * 3) + 2, 1);

                a_8 = 255;
            }
        }
        else if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_INDEXED)
        {
            uint8_t entry = 0;

            if(ctx->ihdr.bit_depth == 8)
            {
                if(fmt & (SPNG_FMT_RGBA8 | SPNG_FMT_RGB8))
                {
                    expand_row(out, scanline, plte, width, fmt);
                    break;
                }

                memcpy(&entry, scanline + k, 1);
            }
            else /* < 8 */
            {
                memcpy(&entry, scanline + k / samples_per_byte, 1);

                if(shift_amount > 8) shift_amount = initial_shift;

                entry = (entry >> shift_amount) & mask;

                shift_amount -= ctx->ihdr.bit_depth;
            }

            if(fmt & (SPNG_FMT_RGBA8 | SPNG_FMT_RGB8))
            {
                pixel[0] = plte[entry].red;
                pixel[1] = plte[entry].green;
                pixel[2] = plte[entry].blue;
                if(fmt == SPNG_FMT_RGBA8) pixel[3] = plte[entry].alpha;

                continue;
            }
            else /* RGBA16 */
            {
                r_16 = plte[entry].red;
                g_16 = plte[entry].green;
                b_16 = plte[entry].blue;
                a_16 = plte[entry].alpha;

                memcpy(pixel, &r_16, 2);
                memcpy(pixel + 2, &g_16, 2);
                memcpy(pixel + 4, &b_16, 2);
                memcpy(pixel + 6, &a_16, 2);

                continue;
            }
        }
        else if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR_ALPHA)
        {
            if(ctx->ihdr.bit_depth == 16)
            {
                memcpy(&r_16, scanline + (k * 8), 2);
                memcpy(&g_16, scanline + (k * 8) + 2, 2);
                memcpy(&b_16, scanline + (k * 8) + 4, 2);
                memcpy(&a_16, scanline + (k * 8) + 6, 2);
            }
            else /* == 8 */
            {
                memcpy(&r_8, scanline + (k * 4), 1);
                memcpy(&g_8, scanline + (k * 4) + 1, 1);
                memcpy(&b_8, scanline + (k * 4) + 2, 1);
                memcpy(&a_8, scanline + (k * 4) + 3, 1);
            }
        }
        else if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_GRAYSCALE)
        {
            if(ctx->ihdr.bit_depth == 16)
            {
                memcpy(&gray_16, scanline + k * 2, 2);

                if(f.apply_trns && ctx->trns.gray == gray_16) a_16 = 0;
                else a_16 = 65535;

                r_16 = gray_16;
                g_16 = gray_16;
                b_16 = gray_16;
            }
            else /* <= 8 */
            {
                memcpy(&gray_8, scanline + k / samples_per_byte, 1);

                if(shift_amount > 7) shift_amount = initial_shift;

                gray_8 = (gray_8 >> shift_amount) & mask;

                shift_amount -= ctx->ihdr.bit_depth;

                if(f.apply_trns && ctx->trns.gray == gray_8) a_8 = 0;
                else a_8 = 255;

                r_8 = gray_8; g_8 = gray_8; b_8 = gray_8;
            }
        }
        else if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_GRAYSCALE_ALPHA)
        {
            if(ctx->ihdr.bit_depth == 16)
            {
                memcpy(&gray_16, scanline + (k * 4), 2);
                memcpy(&a_16, scanline + (k * 4) + 2, 2);

                r_16 = gray_16;
                g_16 = gray_16;
                b_16 = gray_16;
            }
            else /* == 8 */
            {
                memcpy(&gray_8, scanline + (k * 2), 1);
                memcpy(&a_8, scanline + (k * 2) + 1, 1);

                r_8 = gray_8;
                g_8 = gray_8;
                b_8 = gray_8;
            }
        }


        if(fmt & (SPNG_FMT_RGBA8 | SPNG_FMT_RGB8))
        {
            if(ctx->ihdr.bit_depth == 16)
            {
                r_8 = r_16 >> 8;
                g_8 = g_16 >> 8;
                b_8 = b_16 >> 8;
                a_8 = a_16 >> 8;
            }

            memcpy(pixel, &r_8, 1);
            memcpy(pixel + 1, &g_8, 1);
            memcpy(pixel + 2, &b_8, 1);

            if(fmt == SPNG_FMT_RGBA8) memcpy(pixel + 3, &a_8, 1);
        }
        else if(fmt == SPNG_FMT_RGBA16)
        {
            if(ctx->ihdr.bit_depth != 16)
            {
                r_16 = r_8;
                g_16 = g_8;
                b_16 = b_8;
                a_16 = a_8;
            }

            memcpy(pixel, &r_16, 2);
            memcpy(pixel + 2, &g_16, 2);
            memcpy(pixel + 4, &b_16, 2);
            memcpy(pixel + 6, &a_16, 2);
        }
    }/* for(k=0; k < width; k++) */

    if(f.apply_trns) trns_row(out, scanline, trns_px, width, fmt, ctx->ihdr.color_type, ctx->ihdr.bit_depth);

    if(f.do_scaling) scale_row(out, width, fmt, processing_depth, sb);

    if(f.apply_gamma) gamma_correct_row(out, width, fmt, gamma_lut);

    /* The previous scanline is always defiltered */
    void *t = ctx->prev_scanline;
    ctx->prev_scanline = ctx->scanline;
    ctx->scanline = t;

    if(ri->scanline_idx == (sub[pass].height - 1)) /* Last scanline */
    {
        if(ri->pass == ctx->last_pass)
        {
            ctx->state = SPNG_STATE_EOI;

            if(ctx->cur_chunk_bytes_left) /* zlib stream ended before an IDAT chunk boundary */
            {/* Discard the rest of the chunk */
                int ret = discard_chunk_bytes(ctx, ctx->cur_chunk_bytes_left);
                if(ret) return decode_err(ctx, ret);
            }

            memcpy(&ctx->last_idat, &ctx->current_chunk, sizeof(struct spng_chunk));

            return SPNG_EOI;
        }

        ri->scanline_idx = 0;
        ri->pass++;

        /* Skip empty passes */
        while( (!sub[ri->pass].width || !sub[ri->pass].height) && (ri->pass < ctx->last_pass)) ri->pass++;
    }
    else
    {
        ri->row_num++;
        ri->scanline_idx++;
    }

    if(f.interlaced) ri->row_num = adam7_y_start[ri->pass] + ri->scanline_idx * adam7_y_delta[ri->pass];

    return 0;
}

int spng_decode_row(spng_ctx *ctx, unsigned char *out, size_t len)
{
    if(ctx == NULL || out == NULL) return 1;
    if(ctx->state >= SPNG_STATE_EOI) return SPNG_EOI;
    if(len < ctx->out_width) return SPNG_EBUFSIZ;

    int ret, pass = ctx->row_info.pass;

    if(!ctx->ihdr.interlace_method || pass == 6) return spng_decode_scanline(ctx, out, len);

    ret = spng_decode_scanline(ctx, ctx->row, ctx->out_width);
    if(ret && ret != SPNG_EOI) return ret;

    uint32_t k;
    unsigned pixel_size = 4; /* RGBA8 */
    if(ctx->fmt == SPNG_FMT_RGBA16) pixel_size = 8;
    else if(ctx->fmt == SPNG_FMT_RGB8) pixel_size = 3;
    else if(ctx->fmt == SPNG_FMT_PNG)
    {
        if(ctx->ihdr.bit_depth < 8)
        {
            const uint8_t samples_per_byte = 8 / ctx->ihdr.bit_depth;
            const uint8_t mask = (uint16_t)(1 << ctx->ihdr.bit_depth) - 1;
            const uint8_t initial_shift = 8 - ctx->ihdr.bit_depth;
            uint8_t shift_amount = initial_shift;
            uint8_t sample;

            for(k=0; k < ctx->subimage[pass].width; k++)
            {
                size_t ioffset = (adam7_x_start[pass] + k * adam7_x_delta[pass]);

                memcpy(&sample, ctx->row + k / samples_per_byte, 1);

                if(shift_amount > 7) shift_amount = initial_shift;

                sample = (sample >> shift_amount) & mask;
                sample = sample << (initial_shift - ioffset * ctx->ihdr.bit_depth % 8);

                ioffset /= samples_per_byte;

                out[ioffset] |= sample;

                shift_amount -= ctx->ihdr.bit_depth;
            }

            return 0;
        }
        else pixel_size = ctx->bytes_per_pixel;
    }

    for(k=0; k < ctx->subimage[pass].width; k++)
    {
        size_t ioffset = (adam7_x_start[pass] + k * adam7_x_delta[pass]) * pixel_size;

        memcpy(out + ioffset, ctx->row + k * pixel_size, pixel_size);
    }

    return 0;
}

int spng_decode_image(spng_ctx *ctx, unsigned char *out, size_t len, int fmt, int flags)
{
    if(ctx == NULL) return 1;
    if(ctx->state >= SPNG_STATE_EOI) return SPNG_EOI;

    int ret = spng_decoded_image_size(ctx, fmt, &ctx->total_out_size);
    if(ret) return decode_err(ctx, ret);

    ret = read_chunks(ctx, 0);
    if(ret) return ret;

    if( !(flags & SPNG_DECODE_PROGRESSIVE) )
    {
        if(out == NULL) return 1;
        if(len < ctx->total_out_size) return SPNG_EBUFSIZ;
    }

    ctx->out_width = ctx->total_out_size / ctx->ihdr.height;

    ret = spng__inflate_init(ctx);
    if(ret) return decode_err(ctx, ret);

    ctx->zstream.avail_in = 0;
    ctx->zstream.next_in = ctx->data;

    ctx->scanline_buf = spng__malloc(ctx, ctx->subimage[ctx->widest_pass].scanline_width);
    ctx->prev_scanline_buf = spng__malloc(ctx, ctx->subimage[ctx->widest_pass].scanline_width);
    ctx->scanline = ctx->scanline_buf;
    ctx->prev_scanline = ctx->prev_scanline_buf;

    struct decode_flags f = {0};

    ctx->fmt = fmt;

    if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_INDEXED) f.indexed = 1;

    unsigned processing_depth = ctx->ihdr.bit_depth;

    if(f.indexed) processing_depth = 8;

    if(ctx->ihdr.interlace_method)
    {
        f.interlaced = 1;
        ctx->row_buf = spng__malloc(ctx, ctx->out_width);
        ctx->row = ctx->row_buf;

        if(ctx->row == NULL) return decode_err(ctx, SPNG_EMEM);
    }

    if(ctx->scanline == NULL || ctx->prev_scanline == NULL)
    {
        return decode_err(ctx, SPNG_EMEM);
    }

    f.do_scaling = 1;
    if(f.indexed) f.do_scaling = 0;

    unsigned depth_target = 8; /* FMT_RGBA8 */
    if(fmt == SPNG_FMT_RGBA16) depth_target = 16;

    if(flags & SPNG_DECODE_TRNS && ctx->stored.trns) f.apply_trns = 1;
    else flags &= ~SPNG_DECODE_TRNS;

    if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_GRAYSCALE_ALPHA ||
       ctx->ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR_ALPHA) flags &= ~SPNG_DECODE_TRNS;

    if(flags & SPNG_DECODE_GAMMA && ctx->stored.gama) f.apply_gamma = 1;
    else flags &= ~SPNG_DECODE_GAMMA;

    if(flags & SPNG_DECODE_USE_SBIT && ctx->stored.sbit) f.use_sbit = 1;
    else flags &= ~SPNG_DECODE_USE_SBIT;

    if(fmt & (SPNG_FMT_RGBA8 | SPNG_FMT_RGBA16))
    {
        if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR_ALPHA &&
           ctx->ihdr.bit_depth == depth_target) f.same_layout = 1;
    }
    else if(fmt == SPNG_FMT_RGB8)
    {
        if(ctx->ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR &&
           ctx->ihdr.bit_depth == depth_target) f.same_layout = 1;

        f.apply_trns = 0; /* not applicable */
    }
    else if(fmt == SPNG_FMT_PNG)
    {
        f.same_layout = 1;
        f.do_scaling = 0;
        f.apply_gamma = 0; /* for now */
        f.apply_trns = 0;
    }

    /*if(f.same_layout && !flags && !f.interlaced) f.zerocopy = 1;*/

    uint16_t *gamma_lut = NULL;

    if(f.apply_gamma)
    {
        float file_gamma = (float)ctx->gama / 100000.0f;
        float max;

        uint32_t lut_entries;

        if(fmt & (SPNG_FMT_RGBA8 | SPNG_FMT_RGB8))
        {
            lut_entries = 256;
            max = 255.0f;

            gamma_lut = ctx->gamma_lut8;
            ctx->gamma_lut = ctx->gamma_lut8;
        }
        else /* SPNG_FMT_RGBA16 */
        {
            lut_entries = 65536;
            max = 65535.0f;

            ctx->gamma_lut16 = spng__malloc(ctx, lut_entries * sizeof(uint16_t));
            if(ctx->gamma_lut16 == NULL) return decode_err(ctx, SPNG_EMEM);

            gamma_lut = ctx->gamma_lut16;
            ctx->gamma_lut = ctx->gamma_lut16;
        }

        float screen_gamma = 2.2f;
        float exponent = file_gamma * screen_gamma;

        if(FP_ZERO == fpclassify(exponent)) return decode_err(ctx, SPNG_EGAMA);

        exponent = 1.0f / exponent;

        int i;
        for(i=0; i < lut_entries; i++)
        {
            float c = pow((float)i / max, exponent) * max;
            c = fmin(c, max);

            gamma_lut[i] = (uint16_t)c;
        }
    }

    struct spng_sbit *sb = &ctx->decode_sb;

    sb->red_bits = processing_depth;
    sb->green_bits = processing_depth;
    sb->blue_bits = processing_depth;
    sb->alpha_bits = processing_depth;
    sb->grayscale_bits = processing_depth;

    if(f.use_sbit)
    {
        if(ctx->ihdr.color_type == 0)
        {
            sb->grayscale_bits = ctx->sbit.grayscale_bits;
            sb->alpha_bits = ctx->ihdr.bit_depth;
        }
        else if(ctx->ihdr.color_type == 2 || ctx->ihdr.color_type == 3)
        {
            sb->red_bits = ctx->sbit.red_bits;
            sb->green_bits = ctx->sbit.green_bits;
            sb->blue_bits = ctx->sbit.blue_bits;
            sb->alpha_bits = ctx->ihdr.bit_depth;
        }
        else if(ctx->ihdr.color_type == 4)
        {
            sb->grayscale_bits = ctx->sbit.grayscale_bits;
            sb->alpha_bits = ctx->sbit.alpha_bits;
        }
        else /* == 6 */
        {
            sb->red_bits = ctx->sbit.red_bits;
            sb->green_bits = ctx->sbit.green_bits;
            sb->blue_bits = ctx->sbit.blue_bits;
            sb->alpha_bits = ctx->sbit.alpha_bits;
        }
    }

    if(ctx->ihdr.bit_depth == 16 && fmt & (SPNG_FMT_RGBA8 | SPNG_FMT_RGB8))
    {/* in this case samples are scaled down by 8 bits */
        sb->red_bits -= 8;
        sb->green_bits -= 8;
        sb->blue_bits -= 8;
        sb->alpha_bits -= 8;
        sb->grayscale_bits -= 8;

        processing_depth = 8;
    }

    /* Prevent infinite loops in sample_to_target() */
    if(!depth_target || depth_target > 16 ||
       !processing_depth || processing_depth > 16 ||
       !sb->grayscale_bits || sb->grayscale_bits > processing_depth ||
       !sb->alpha_bits || sb->alpha_bits > processing_depth ||
       !sb->red_bits || sb->red_bits > processing_depth ||
       !sb->green_bits || sb->green_bits > processing_depth ||
       !sb->blue_bits || sb->blue_bits > processing_depth)
    {
        return decode_err(ctx, SPNG_ESBIT);
    }

    if(sb->red_bits == sb->green_bits &&
       sb->green_bits == sb->blue_bits &&
       sb->blue_bits == sb->alpha_bits &&
       sb->alpha_bits == processing_depth &&
       processing_depth == depth_target) f.do_scaling = 0;

    struct spng_plte_entry16 *plte = ctx->decode_plte;

    /* Pre-process palette entries */
    if(f.indexed)
    {
        int i;
        for(i=0; i < 256; i++)
        {
            if(f.apply_trns && i < ctx->trns.n_type3_entries)
                ctx->plte.entries[i].alpha = ctx->trns.type3_alpha[i];
            else
                ctx->plte.entries[i].alpha = 255;

            plte[i].red = sample_to_target(ctx->plte.entries[i].red, 8, sb->red_bits, depth_target);
            plte[i].green = sample_to_target(ctx->plte.entries[i].green, 8, sb->green_bits, depth_target);
            plte[i].blue = sample_to_target(ctx->plte.entries[i].blue, 8, sb->blue_bits, depth_target);
            plte[i].alpha = sample_to_target(ctx->plte.entries[i].alpha, 8, sb->alpha_bits, depth_target);

            if(f.apply_gamma)
            {
                plte[i].red = gamma_lut[plte[i].red];
                plte[i].green = gamma_lut[plte[i].green];
                plte[i].blue = gamma_lut[plte[i].blue];
            }
        }

        f.apply_trns = 0;
        f.apply_gamma = 0;
    }

    unsigned char *trns_px = ctx->trns_px;

    if(f.apply_trns && ctx->ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR)
    {
        if(ctx->ihdr.bit_depth == 16)
        {
            memcpy(trns_px, &ctx->trns.red, 2);
            memcpy(trns_px + 2, &ctx->trns.green, 2);
            memcpy(trns_px + 4, &ctx->trns.blue, 2);
        }
        else
        {
            trns_px[0] = ctx->trns.red;
            trns_px[1] = ctx->trns.green;
            trns_px[2] = ctx->trns.blue;
        }
    }

    memcpy(&ctx->decode_flags, &f, sizeof(struct decode_flags));

    ctx->state = SPNG_STATE_DECODE_INIT;

    struct spng_row_info *ri = &ctx->row_info;
    struct spng_subimage *sub = ctx->subimage;

    while(!sub[ri->pass].width || !sub[ri->pass].height) ri->pass++;

    if(f.interlaced) ri->row_num = adam7_y_start[ri->pass];

    /* Read the first filter byte, offsetting all reads by 1 byte.
    The scanlines will be aligned with the start of the array with
    the next scanline's filter byte at the end,
    the last scanline will end up being 1 byte "shorter". */
    ret = read_scanline_bytes(ctx, &ri->filter, 1);
    if(ret) return decode_err(ctx, ret);

    if(ri->filter > 4) return decode_err(ctx, SPNG_EFILTER);

    if(flags & SPNG_DECODE_PROGRESSIVE)
    {
        return 0;
    }

    do
    {
        size_t ioffset = ri->row_num * ctx->out_width;

        ret = spng_decode_row(ctx, out + ioffset, ctx->out_width);
    }while(!ret);

    if(ret != SPNG_EOI) return decode_err(ctx, ret);

    return 0;
}

int spng_get_row_info(spng_ctx *ctx, struct spng_row_info *row_info)
{
    if(ctx == NULL || row_info == NULL || ctx->state < SPNG_STATE_DECODE_INIT) return 1;

    if(ctx->state >= SPNG_STATE_EOI) return SPNG_EOI;

    memcpy(row_info, &ctx->row_info, sizeof(struct spng_row_info));

    return 0;
}

spng_ctx *spng_ctx_new(int flags)
{
    struct spng_alloc alloc = {0};

    alloc.malloc_fn = malloc;
    alloc.realloc_fn = realloc;
    alloc.calloc_fn = calloc;
    alloc.free_fn = free;

    return spng_ctx_new2(&alloc, flags);
}

spng_ctx *spng_ctx_new2(struct spng_alloc *alloc, int flags)
{
    if(alloc == NULL) return NULL;
    if(flags != (flags & SPNG_CTX_IGNORE_ADLER32)) return NULL;

    if(alloc->malloc_fn == NULL) return NULL;
    if(alloc->realloc_fn == NULL) return NULL;
    if(alloc->calloc_fn == NULL) return NULL;
    if(alloc->free_fn == NULL) return NULL;

    spng_ctx *ctx = alloc->calloc_fn(1, sizeof(spng_ctx));
    if(ctx == NULL) return NULL;

    memcpy(&ctx->alloc, alloc, sizeof(struct spng_alloc));

    ctx->max_chunk_size = png_u32max;
    ctx->chunk_cache_limit = SIZE_MAX;

    ctx->state = SPNG_STATE_INIT;

    ctx->flags = flags;

    return ctx;
}

void spng_ctx_free(spng_ctx *ctx)
{
    if(ctx == NULL) return;

    if(ctx->streaming && ctx->stream_buf != NULL) spng__free(ctx, ctx->stream_buf);

    if(!ctx->user.exif) spng__free(ctx, ctx->exif.data);

    if(!ctx->user.iccp) spng__free(ctx, ctx->iccp.profile);

    if(ctx->splt_list != NULL && !ctx->user.splt)
    {
        uint32_t i;
        for(i=0; i < ctx->n_splt; i++)
        {
            if(ctx->splt_list[i].entries != NULL) spng__free(ctx, ctx->splt_list[i].entries);
        }
        spng__free(ctx, ctx->splt_list);
    }

    if(ctx->text_list != NULL && !ctx->user.text)
    {
        uint32_t i;
        for(i=0; i< ctx->n_text; i++)
        {
            if(ctx->text_list[i].text != NULL) spng__free(ctx, ctx->text_list[i].text);
            if(ctx->text_list[i].language_tag != NULL) spng__free(ctx, ctx->text_list[i].language_tag);
            if(ctx->text_list[i].translated_keyword != NULL) spng__free(ctx, ctx->text_list[i].translated_keyword);
        }
        spng__free(ctx, ctx->text_list);
    }

    inflateEnd(&ctx->zstream);

    spng__free(ctx, ctx->gamma_lut16);

    spng__free(ctx, ctx->row_buf);
    spng__free(ctx, ctx->scanline_buf);
    spng__free(ctx, ctx->prev_scanline_buf);

    spng_free_fn *free_func = ctx->alloc.free_fn;

    memset(ctx, 0, sizeof(spng_ctx));

    free_func(ctx);
}

static int buffer_read_fn(spng_ctx *ctx, void *user, void *data, size_t n)
{
    if(n > ctx->bytes_left) return SPNG_IO_EOF;

    ctx->data = ctx->data + ctx->last_read_size;

    ctx->last_read_size = n;
    ctx->bytes_left -= n;

    return 0;
}

static int file_read_fn(spng_ctx *ctx, void *user, void *data, size_t n)
{
    FILE *file = user;

    if(fread(data, n, 1, file) != 1)
    {
        if(feof(file)) return SPNG_IO_EOF;
        else return SPNG_IO_ERROR;
    }

    return 0;
}

int spng_set_png_buffer(spng_ctx *ctx, const void *buf, size_t size)
{
    if(ctx == NULL || buf == NULL) return 1;
    if(!ctx->state) return SPNG_EBADSTATE;
    if(ctx->encode_only) return SPNG_ENCODE_ONLY;

    if(ctx->data != NULL) return SPNG_EBUF_SET;

    ctx->data = buf;
    ctx->png_buf = buf;
    ctx->data_size = size;
    ctx->bytes_left = size;

    ctx->read_fn = buffer_read_fn;

    ctx->state = SPNG_STATE_INPUT;

    return 0;
}

int spng_set_png_stream(spng_ctx *ctx, spng_read_fn *read_func, void *user)
{
    if(ctx == NULL || read_func == NULL) return 1;
    if(!ctx->state) return SPNG_EBADSTATE;
    if(ctx->encode_only) return SPNG_ENCODE_ONLY;

    if(ctx->stream_buf != NULL) return SPNG_EBUF_SET;

    ctx->stream_buf = spng__malloc(ctx, SPNG_READ_SIZE);
    if(ctx->stream_buf == NULL) return SPNG_EMEM;

    ctx->data = ctx->stream_buf;
    ctx->data_size = SPNG_READ_SIZE;

    ctx->read_fn = read_func;
    ctx->read_user_ptr = user;

    ctx->streaming = 1;

    ctx->state = SPNG_STATE_INPUT;

    return 0;
}

int spng_set_png_file(spng_ctx *ctx, FILE *file)
{
    if(file == NULL) return 1;

    return spng_set_png_stream(ctx, file_read_fn, file);
}

int spng_set_image_limits(spng_ctx *ctx, uint32_t width, uint32_t height)
{
    if(ctx == NULL) return 1;

    if(width > png_u32max || height > png_u32max) return 1;

    ctx->max_width = width;
    ctx->max_height = height;

    return 0;
}

int spng_get_image_limits(spng_ctx *ctx, uint32_t *width, uint32_t *height)
{
    if(ctx == NULL || width == NULL || height == NULL) return 1;

    *width = ctx->max_width;
    *height = ctx->max_height;

    return 0;
}

int spng_set_chunk_limits(spng_ctx *ctx, size_t chunk_size, size_t cache_limit)
{
    if(ctx == NULL || chunk_size > png_u32max) return 1;

    ctx->max_chunk_size = chunk_size;

    ctx->chunk_cache_limit = cache_limit;

    return 0;
}

int spng_get_chunk_limits(spng_ctx *ctx, size_t *chunk_size, size_t *cache_limit)
{
    if(ctx == NULL || chunk_size == NULL || cache_limit == NULL) return 1;

    *chunk_size = ctx->max_chunk_size;

    *cache_limit = ctx->chunk_cache_limit;

    return 0;
}

int spng_set_crc_action(spng_ctx *ctx, int critical, int ancillary)
{
    if(ctx == NULL) return 1;

    if(critical > 2 || critical < 0) return 1;
    if(ancillary > 2 || ancillary < 0) return 1;

    if(critical == SPNG_CRC_DISCARD) return 1;

    ctx->crc_action_critical = critical;
    ctx->crc_action_ancillary = ancillary;

    return 0;
}

int spng_decoded_image_size(spng_ctx *ctx, int fmt, size_t *len)
{
    if(ctx == NULL || len == NULL) return 1;

    int ret = read_chunks(ctx, 1);
    if(ret) return ret;

    size_t res = ctx->ihdr.width;
    unsigned bytes_per_pixel;

    if(fmt == SPNG_FMT_RGBA8)
    {
        bytes_per_pixel = 4;
    }
    else if(fmt == SPNG_FMT_RGBA16)
    {
        bytes_per_pixel = 8;
    }
    else if(fmt == SPNG_FMT_RGB8)
    {
        bytes_per_pixel = 3;
    }
    else if(fmt == SPNG_FMT_PNG)
    {
        struct spng_subimage img = {0};
        img.width = ctx->ihdr.width;
        img.height = ctx->ihdr.width;

        ret = calculate_scanline_width(ctx, &img);
        if(ret) return ret;

        res = img.scanline_width - 1; /* exclude filter byte */
        bytes_per_pixel = 1;
    }
    else return SPNG_EFMT;

    if(res > SIZE_MAX / bytes_per_pixel) return SPNG_EOVERFLOW;
    res = res * bytes_per_pixel;

    if(res > SIZE_MAX / ctx->ihdr.height) return SPNG_EOVERFLOW;
    res = res * ctx->ihdr.height;

    *len = res;

    return 0;
}

int spng_get_ihdr(spng_ctx *ctx, struct spng_ihdr *ihdr)
{
    if(ctx == NULL || ihdr == NULL) return 1;

    int ret = read_chunks(ctx, 1);
    if(ret) return ret;

    memcpy(ihdr, &ctx->ihdr, sizeof(struct spng_ihdr));

    return 0;
}

int spng_get_plte(spng_ctx *ctx, struct spng_plte *plte)
{
    SPNG_GET_CHUNK_BOILERPLATE(plte);

    if(!ctx->stored.plte) return SPNG_ECHUNKAVAIL;

    memcpy(plte, &ctx->plte, sizeof(struct spng_plte));

    return 0;
}

int spng_get_trns(spng_ctx *ctx, struct spng_trns *trns)
{
    SPNG_GET_CHUNK_BOILERPLATE(trns);

    if(!ctx->stored.trns) return SPNG_ECHUNKAVAIL;

    memcpy(trns, &ctx->trns, sizeof(struct spng_trns));

    return 0;
}

int spng_get_chrm(spng_ctx *ctx, struct spng_chrm *chrm)
{
    SPNG_GET_CHUNK_BOILERPLATE(chrm);

    if(!ctx->stored.chrm) return SPNG_ECHUNKAVAIL;

    chrm->white_point_x = (double)ctx->chrm_int.white_point_x / 100000.0;
    chrm->white_point_y = (double)ctx->chrm_int.white_point_y / 100000.0;
    chrm->red_x = (double)ctx->chrm_int.red_x / 100000.0;
    chrm->red_y = (double)ctx->chrm_int.red_y / 100000.0;
    chrm->blue_y = (double)ctx->chrm_int.blue_y / 100000.0;
    chrm->blue_x = (double)ctx->chrm_int.blue_x / 100000.0;
    chrm->green_x = (double)ctx->chrm_int.green_x / 100000.0;
    chrm->green_y = (double)ctx->chrm_int.green_y / 100000.0;

    return 0;
}

int spng_get_chrm_int(spng_ctx *ctx, struct spng_chrm_int *chrm)
{
    SPNG_GET_CHUNK_BOILERPLATE(chrm);

    if(!ctx->stored.chrm) return SPNG_ECHUNKAVAIL;

    memcpy(chrm, &ctx->chrm_int, sizeof(struct spng_chrm_int));

    return 0;
}

int spng_get_gama(spng_ctx *ctx, double *gamma)
{
    SPNG_GET_CHUNK_BOILERPLATE(gamma);

    if(!ctx->stored.gama) return SPNG_ECHUNKAVAIL;

    *gamma = (double)ctx->gama / 100000.0;

    return 0;
}

int spng_get_iccp(spng_ctx *ctx, struct spng_iccp *iccp)
{
    SPNG_GET_CHUNK_BOILERPLATE(iccp);

    if(!ctx->stored.iccp) return SPNG_ECHUNKAVAIL;

    memcpy(iccp, &ctx->iccp, sizeof(struct spng_iccp));

    return 0;
}

int spng_get_sbit(spng_ctx *ctx, struct spng_sbit *sbit)
{
    SPNG_GET_CHUNK_BOILERPLATE(sbit);

    if(!ctx->stored.sbit) return SPNG_ECHUNKAVAIL;

    memcpy(sbit, &ctx->sbit, sizeof(struct spng_sbit));

    return 0;
}

int spng_get_srgb(spng_ctx *ctx, uint8_t *rendering_intent)
{
    SPNG_GET_CHUNK_BOILERPLATE(rendering_intent);

    if(!ctx->stored.srgb) return SPNG_ECHUNKAVAIL;

    *rendering_intent = ctx->srgb_rendering_intent;

    return 0;
}

int spng_get_text(spng_ctx *ctx, struct spng_text *text, uint32_t *n_text)
{
    if(ctx == NULL || n_text == NULL) return 1;

    if(text == NULL)
    {
        *n_text = ctx->n_text;
        return 0;
    }

    int ret = read_chunks(ctx, 0);
    if(ret) return ret;

    if(*n_text < ctx->n_text) return 1;

    if(!ctx->stored.text) return SPNG_ECHUNKAVAIL;

    memcpy(text, &ctx->text_list, ctx->n_text * sizeof(struct spng_text));

    return ret;
}

int spng_get_bkgd(spng_ctx *ctx, struct spng_bkgd *bkgd)
{
    SPNG_GET_CHUNK_BOILERPLATE(bkgd);

    if(!ctx->stored.bkgd) return SPNG_ECHUNKAVAIL;

    memcpy(bkgd, &ctx->bkgd, sizeof(struct spng_bkgd));

    return 0;
}

int spng_get_hist(spng_ctx *ctx, struct spng_hist *hist)
{
    SPNG_GET_CHUNK_BOILERPLATE(hist);

    if(!ctx->stored.hist) return SPNG_ECHUNKAVAIL;

    memcpy(hist, &ctx->hist, sizeof(struct spng_hist));

    return 0;
}

int spng_get_phys(spng_ctx *ctx, struct spng_phys *phys)
{
    SPNG_GET_CHUNK_BOILERPLATE(phys);

    if(!ctx->stored.phys) return SPNG_ECHUNKAVAIL;

    memcpy(phys, &ctx->phys, sizeof(struct spng_phys));

    return 0;
}

int spng_get_splt(spng_ctx *ctx, struct spng_splt *splt, uint32_t *n_splt)
{
    if(ctx == NULL || n_splt == NULL) return 1;

    if(splt == NULL)
    {
        *n_splt = ctx->n_splt;
        return 0;
    }

    int ret = read_chunks(ctx, 0);
    if(ret) return ret;

    if(*n_splt < ctx->n_splt) return 1;

    if(!ctx->stored.splt) return SPNG_ECHUNKAVAIL;

    memcpy(splt, &ctx->splt_list, ctx->n_splt * sizeof(struct spng_splt));

    return 0;
}

int spng_get_time(spng_ctx *ctx, struct spng_time *time)
{
    SPNG_GET_CHUNK_BOILERPLATE(time);

    if(!ctx->stored.time) return SPNG_ECHUNKAVAIL;

    memcpy(time, &ctx->time, sizeof(struct spng_time));

    return 0;
}

int spng_get_offs(spng_ctx *ctx, struct spng_offs *offs)
{
    SPNG_GET_CHUNK_BOILERPLATE(offs);

    if(!ctx->stored.offs) return SPNG_ECHUNKAVAIL;

    memcpy(offs, &ctx->offs, sizeof(struct spng_offs));

    return 0;
}

int spng_get_exif(spng_ctx *ctx, struct spng_exif *exif)
{
    SPNG_GET_CHUNK_BOILERPLATE(exif);

    if(!ctx->stored.exif) return SPNG_ECHUNKAVAIL;

    memcpy(exif, &ctx->exif, sizeof(struct spng_exif));

    return 0;
}

int spng_set_ihdr(spng_ctx *ctx, struct spng_ihdr *ihdr)
{
    SPNG_SET_CHUNK_BOILERPLATE(ihdr);

    if(ctx->stored.ihdr) return 1;

    ret = check_ihdr(ihdr, ctx->max_width, ctx->max_height);
    if(ret) return ret;

    memcpy(&ctx->ihdr, ihdr, sizeof(struct spng_ihdr));

    ctx->stored.ihdr = 1;
    ctx->user.ihdr = 1;

    return 0;
}

int spng_set_plte(spng_ctx *ctx, struct spng_plte *plte)
{
    SPNG_SET_CHUNK_BOILERPLATE(plte);

    if(!ctx->stored.ihdr) return 1;

    if(check_plte(plte, &ctx->ihdr)) return 1;

    memcpy(&ctx->plte, plte, sizeof(struct spng_plte));

    ctx->stored.plte = 1;
    ctx->user.plte = 1;

    return 0;
}

int spng_set_trns(spng_ctx *ctx, struct spng_trns *trns)
{
    SPNG_SET_CHUNK_BOILERPLATE(trns);

    if(!ctx->stored.ihdr) return 1;

    uint16_t mask = ~0;
    if(ctx->ihdr.bit_depth < 16) mask = (1 << ctx->ihdr.bit_depth) - 1;

    if(ctx->ihdr.color_type == 0)
    {
        trns->gray &= mask;
    }
    else if(ctx->ihdr.color_type == 2)
    {
        trns->red &= mask;
        trns->green &= mask;
        trns->blue &= mask;
    }
    else if(ctx->ihdr.color_type == 3)
    {
        if(!ctx->stored.plte) return SPNG_ETRNS_NO_PLTE;
    }
    else return SPNG_ETRNS_COLOR_TYPE;

    memcpy(&ctx->trns, trns, sizeof(struct spng_trns));

    ctx->stored.trns = 1;
    ctx->user.trns = 1;

    return 0;
}

int spng_set_chrm(spng_ctx *ctx, struct spng_chrm *chrm)
{
    SPNG_SET_CHUNK_BOILERPLATE(chrm);

    struct spng_chrm_int chrm_int;

    chrm_int.white_point_x = (uint32_t)(chrm->white_point_x * 100000.0);
    chrm_int.white_point_y = (uint32_t)(chrm->white_point_y * 100000.0);
    chrm_int.red_x = (uint32_t)(chrm->red_x * 100000.0);
    chrm_int.red_y = (uint32_t)(chrm->red_y * 100000.0);
    chrm_int.green_x = (uint32_t)(chrm->green_x * 100000.0);
    chrm_int.green_y = (uint32_t)(chrm->green_y * 100000.0);
    chrm_int.blue_x = (uint32_t)(chrm->blue_x * 100000.0);
    chrm_int.blue_y = (uint32_t)(chrm->blue_y * 100000.0);

    if(check_chrm_int(&chrm_int)) return SPNG_ECHRM;

    memcpy(&ctx->chrm_int, &chrm_int, sizeof(struct spng_chrm_int));

    ctx->stored.chrm = 1;
    ctx->user.chrm = 1;

    return 0;
}

int spng_set_chrm_int(spng_ctx *ctx, struct spng_chrm_int *chrm_int)
{
    SPNG_SET_CHUNK_BOILERPLATE(chrm_int);

    if(check_chrm_int(chrm_int)) return SPNG_ECHRM;

    memcpy(&ctx->chrm_int, chrm_int, sizeof(struct spng_chrm_int));

    ctx->stored.chrm = 1;
    ctx->user.chrm = 1;

    return 0;
}

int spng_set_gama(spng_ctx *ctx, double gamma)
{
    SPNG_SET_CHUNK_BOILERPLATE(ctx);

    uint32_t gama = gamma * 100000.0;

    if(!gama) return 1;
    if(gama > png_u32max) return 1;

    ctx->gama = gama;

    ctx->stored.gama = 1;
    ctx->user.gama = 1;

    return 0;
}

int spng_set_iccp(spng_ctx *ctx, struct spng_iccp *iccp)
{
    SPNG_SET_CHUNK_BOILERPLATE(iccp);

    if(check_png_keyword(iccp->profile_name)) return SPNG_EICCP_NAME;
    if(!iccp->profile_len) return 1;

    if(ctx->iccp.profile && !ctx->user.iccp) spng__free(ctx, ctx->iccp.profile);

    memcpy(&ctx->iccp, iccp, sizeof(struct spng_iccp));

    ctx->stored.iccp = 1;
    ctx->user.iccp = 1;

    return 0;
}

int spng_set_sbit(spng_ctx *ctx, struct spng_sbit *sbit)
{
    SPNG_SET_CHUNK_BOILERPLATE(sbit);

    if(check_sbit(sbit, &ctx->ihdr)) return 1;

    if(!ctx->stored.ihdr) return 1;

    memcpy(&ctx->sbit, sbit, sizeof(struct spng_sbit));

    ctx->stored.sbit = 1;
    ctx->user.sbit = 1;

    return 0;
}

int spng_set_srgb(spng_ctx *ctx, uint8_t rendering_intent)
{
    SPNG_SET_CHUNK_BOILERPLATE(ctx);

    if(rendering_intent > 3) return 1;

    ctx->srgb_rendering_intent = rendering_intent;

    ctx->stored.srgb = 1;
    ctx->user.srgb = 1;

    return 0;
}

int spng_set_text(spng_ctx *ctx, struct spng_text *text, uint32_t n_text)
{
    if(!n_text) return 1;
    SPNG_SET_CHUNK_BOILERPLATE(text);

    uint32_t i;
    for(i=0; i < n_text; i++)
    {
        if(check_png_keyword(text[i].keyword)) return SPNG_ETEXT_KEYWORD;
        if(!text[i].length) return 1;
        if(text[i].text == NULL) return 1;

        if(text[i].type == SPNG_TEXT)
        {
            if(check_png_text(text[i].text, text[i].length)) return 1;
        }
        else if(text[i].type == SPNG_ZTXT)
        {
            if(check_png_text(text[i].text, text[i].length)) return 1;

            if(text[i].compression_method != 0) return 1;
        }
        else if(text[i].type == SPNG_ITXT)
        {
            if(text[i].compression_flag > 1) return 1;
            if(text[i].compression_method != 0) return 1;
            if(text[i].language_tag == NULL) return SPNG_EITXT_LANG_TAG;
            if(text[i].translated_keyword == NULL) return SPNG_EITXT_TRANSLATED_KEY;

        }
        else return 1;

    }


    if(ctx->text_list != NULL && !ctx->user.text)
    {
        for(i=0; i< ctx->n_text; i++)
        {
            if(ctx->text_list[i].text != NULL) spng__free(ctx, ctx->text_list[i].text);
            if(ctx->text_list[i].language_tag != NULL) spng__free(ctx, ctx->text_list[i].language_tag);
            if(ctx->text_list[i].translated_keyword != NULL) spng__free(ctx, ctx->text_list[i].translated_keyword);
        }
        spng__free(ctx, ctx->text_list);
    }

    ctx->text_list = text;
    ctx->n_text = n_text;

    ctx->stored.text = 1;
    ctx->user.text = 1;

    return 0;
}

int spng_set_bkgd(spng_ctx *ctx, struct spng_bkgd *bkgd)
{
    SPNG_SET_CHUNK_BOILERPLATE(bkgd);

    if(!ctx->stored.ihdr)  return 1;

    uint16_t mask = ~0;

    if(ctx->ihdr.bit_depth < 16) mask = (1 << ctx->ihdr.bit_depth) - 1;

    if(ctx->ihdr.color_type == 0 || ctx->ihdr.color_type == 4)
    {
        bkgd->gray &= mask;
    }
    else if(ctx->ihdr.color_type == 2 || ctx->ihdr.color_type == 6)
    {
        bkgd->red &= mask;
        bkgd->green &= mask;
        bkgd->blue &= mask;
    }
    else if(ctx->ihdr.color_type == 3)
    {
        if(!ctx->stored.bkgd) return SPNG_EBKGD_NO_PLTE;
        if(bkgd->plte_index >= ctx->plte.n_entries) return SPNG_EBKGD_PLTE_IDX;
    }

    memcpy(&ctx->bkgd, bkgd, sizeof(struct spng_bkgd));

    ctx->stored.bkgd = 1;
    ctx->user.bkgd = 1;

    return 0;
}

int spng_set_hist(spng_ctx *ctx, struct spng_hist *hist)
{
    SPNG_SET_CHUNK_BOILERPLATE(hist);

    if(!ctx->stored.plte) return SPNG_EHIST_NO_PLTE;

    memcpy(&ctx->hist, hist, sizeof(struct spng_hist));

    ctx->stored.hist = 1;
    ctx->user.hist = 1;

    return 0;
}

int spng_set_phys(spng_ctx *ctx, struct spng_phys *phys)
{
    SPNG_SET_CHUNK_BOILERPLATE(phys);

    if(check_phys(phys)) return SPNG_EPHYS;

    memcpy(&ctx->phys, phys, sizeof(struct spng_phys));

    ctx->stored.phys = 1;
    ctx->user.phys = 1;

    return 0;
}

int spng_set_splt(spng_ctx *ctx, struct spng_splt *splt, uint32_t n_splt)
{
    if(!n_splt) return 1;
    SPNG_SET_CHUNK_BOILERPLATE(splt);

    uint32_t i;
    for(i=0; i < n_splt; i++)
    {
        if(check_png_keyword(splt[i].name)) return SPNG_ESPLT_NAME;
        if( !(splt[i].sample_depth == 8 || splt[i].sample_depth == 16) ) return SPNG_ESPLT_DEPTH;
    }

    if(ctx->stored.splt && !ctx->user.splt)
    {
        for(i=0; i < ctx->n_splt; i++)
        {
            if(ctx->splt_list[i].entries != NULL) spng__free(ctx, ctx->splt_list[i].entries);
        }
        spng__free(ctx, ctx->splt_list);
    }

    ctx->splt_list = splt;
    ctx->n_splt = n_splt;

    ctx->stored.splt = 1;
    ctx->user.splt = 1;

    return 0;
}

int spng_set_time(spng_ctx *ctx, struct spng_time *time)
{
    SPNG_SET_CHUNK_BOILERPLATE(time);

    if(check_time(time)) return SPNG_ETIME;

    memcpy(&ctx->time, time, sizeof(struct spng_time));

    ctx->stored.time = 1;
    ctx->user.time = 1;

    return 0;
}

int spng_set_offs(spng_ctx *ctx, struct spng_offs *offs)
{
    SPNG_SET_CHUNK_BOILERPLATE(offs);

    if(check_offs(offs)) return SPNG_EOFFS;

    memcpy(&ctx->offs, offs, sizeof(struct spng_offs));

    ctx->stored.offs = 1;
    ctx->user.offs = 1;

    return 0;
}

int spng_set_exif(spng_ctx *ctx, struct spng_exif *exif)
{
    SPNG_SET_CHUNK_BOILERPLATE(exif);

    if(check_exif(exif)) return SPNG_EEXIF;

    if(ctx->exif.data != NULL && !ctx->user.exif) spng__free(ctx, ctx->exif.data);

    memcpy(&ctx->exif, exif, sizeof(struct spng_exif));

    ctx->stored.exif = 1;
    ctx->user.exif = 1;

    return 0;
}

const char *spng_strerror(int err)
{
    switch(err)
    {
        case SPNG_IO_EOF: return "end of stream";
        case SPNG_IO_ERROR: return "stream error";
        case SPNG_OK: return "success";
        case SPNG_EINVAL: return "invalid argument";
        case SPNG_EMEM: return "out of memory";
        case SPNG_EOVERFLOW: return "arithmetic overflow";
        case SPNG_ESIGNATURE: return "invalid signature";
        case SPNG_EWIDTH: return "invalid image width";
        case SPNG_EHEIGHT: return "invalid image height";
        case SPNG_EUSER_WIDTH: return "image width exceeds user limit";
        case SPNG_EUSER_HEIGHT: return "image height exceeds user limit";
        case SPNG_EBIT_DEPTH: return "invalid bit depth";
        case SPNG_ECOLOR_TYPE: return "invalid color type";
        case SPNG_ECOMPRESSION_METHOD: return "invalid compression method";
        case SPNG_EFILTER_METHOD: return "invalid filter method";
        case SPNG_EINTERLACE_METHOD: return "invalid interlace method";
        case SPNG_EIHDR_SIZE: return "invalid IHDR chunk size";
        case SPNG_ENOIHDR: return "missing IHDR chunk";
        case SPNG_ECHUNK_POS: return "invalid chunk position";
        case SPNG_ECHUNK_SIZE: return "invalid chunk length";
        case SPNG_ECHUNK_CRC: return "invalid chunk checksum";
        case SPNG_ECHUNK_TYPE: return "invalid chunk type";
        case SPNG_ECHUNK_UNKNOWN_CRITICAL: return "unknown critical chunk";
        case SPNG_EDUP_PLTE: return "duplicate PLTE chunk";
        case SPNG_EDUP_CHRM: return "duplicate cHRM chunk";
        case SPNG_EDUP_GAMA: return "duplicate gAMA chunk";
        case SPNG_EDUP_ICCP: return "duplicate iCCP chunk";
        case SPNG_EDUP_SBIT: return "duplicate sBIT chunk";
        case SPNG_EDUP_SRGB: return "duplicate sRGB chunk";
        case SPNG_EDUP_BKGD: return "duplicate bKGD chunk";
        case SPNG_EDUP_HIST: return "duplicate hIST chunk";
        case SPNG_EDUP_TRNS: return "duplicate tRNS chunk";
        case SPNG_EDUP_PHYS: return "duplicate pHYs chunk";
        case SPNG_EDUP_TIME: return "duplicate tIME chunk";
        case SPNG_EDUP_OFFS: return "duplicate oFFs chunk";
        case SPNG_EDUP_EXIF: return "duplicate eXIf chunk";
        case SPNG_ECHRM: return "invalid cHRM chunk";
        case SPNG_EPLTE_IDX: return "invalid palette (PLTE) index";
        case SPNG_ETRNS_COLOR_TYPE: return "tRNS chunk with incompatible color type";
        case SPNG_ETRNS_NO_PLTE: return "missing palette (PLTE) for tRNS chunk";
        case SPNG_EGAMA: return "invalid gAMA chunk";
        case SPNG_EICCP_NAME: return "invalid iCCP profile name";
        case SPNG_EICCP_COMPRESSION_METHOD: return "invalid iCCP compression method";
        case SPNG_ESBIT: return "invalid sBIT chunk";
        case SPNG_ESRGB: return "invalid sRGB chunk";
        case SPNG_ETEXT: return "invalid tEXt chunk";
        case SPNG_ETEXT_KEYWORD: return "invalid tEXt keyword";
        case SPNG_EZTXT: return "invalid zTXt chunk";
        case SPNG_EZTXT_COMPRESSION_METHOD: return "invalid zTXt compression method";
        case SPNG_EITXT: return "invalid iTXt chunk";
        case SPNG_EITXT_COMPRESSION_FLAG: return "invalid iTXt compression flag";
        case SPNG_EITXT_COMPRESSION_METHOD: return "invalid iTXt compression method";
        case SPNG_EITXT_LANG_TAG: return "invalid iTXt language tag";
        case SPNG_EITXT_TRANSLATED_KEY: return "invalid iTXt translated key";
        case SPNG_EBKGD_NO_PLTE: return "missing palette for bKGD chunk";
        case SPNG_EBKGD_PLTE_IDX: return "invalid palette index for bKGD chunk";
        case SPNG_EHIST_NO_PLTE: return "missing palette for hIST chunk";
        case SPNG_EPHYS: return "invalid pHYs chunk";
        case SPNG_ESPLT_NAME: return "invalid suggested palette name";
        case SPNG_ESPLT_DUP_NAME: return "duplicate suggested palette (sPLT) name";
        case SPNG_ESPLT_DEPTH: return "invalid suggested palette (sPLT) sample depth";
        case SPNG_ETIME: return "invalid tIME chunk";
        case SPNG_EOFFS: return "invalid oFFs chunk";
        case SPNG_EEXIF: return "invalid eXIf chunk";
        case SPNG_EIDAT_TOO_SHORT: return "IDAT stream too short";
        case SPNG_EIDAT_STREAM: return "IDAT stream error";
        case SPNG_EZLIB: return "zlib error";
        case SPNG_EFILTER: return "invalid scanline filter";
        case SPNG_EBUFSIZ: return "output buffer too small";
        case SPNG_EIO: return "i/o error";
        case SPNG_EOF: return "end of file";
        case SPNG_EBUF_SET: return "buffer already set";
        case SPNG_EBADSTATE: return "non-recoverable state";
        case SPNG_EFMT: return "invalid format";
        case SPNG_EFLAGS: return "invalid flags";
        case SPNG_ECHUNKAVAIL: return "chunk not available";
        case SPNG_ENCODE_ONLY: return "encode only context";
        case SPNG_EOI: return "reached end-of-image state";
        case SPNG_ENOPLTE: return "missing PLTE for indexed image";
        default: return "unknown error";
    }
}

const char *spng_version_string(void)
{
    return SPNG_VERSION_STRING "-rc1";
}

#if defined(_MSC_VER)
    #pragma warning(pop)
#endif

/* filter_sse2_intrinsics.c - SSE2 optimized filter functions
 *
 * Copyright (c) 2018 Cosmin Truta
 * Copyright (c) 2016-2017 Glenn Randers-Pehrson
 * Written by Mike Klein and Matt Sarett
 * Derived from arm/filter_neon_intrinsics.c
 *
 * This code is released under the libpng license.
 * For conditions of distribution and use, see the disclaimer
 * and license in png.h
 */

#if defined(SPNG_X86)

#ifndef SPNG_SSE
    #define SPNG_SSE 1
#endif

#if defined(__GNUC__) && !defined(__clang__)
   #pragma GCC target("sse2")

    #if SPNG_SSE == 3
        #pragma GCC target("ssse3")
    #endif
#endif

#include <immintrin.h>
#include <inttypes.h>
#include <string.h>

/* Functions in this file look at most 3 pixels (a,b,c) to predict the 4th (d).
 * They're positioned like this:
 *    prev:  c b
 *    row:   a d
 * The Sub filter predicts d=a, Avg d=(a+b)/2, and Paeth predicts d to be
 * whichever of a, b, or c is closest to p=a+b-c.
 */

static __m128i load4(const void* p)
{
   int tmp;
   memcpy(&tmp, p, sizeof(tmp));
   return _mm_cvtsi32_si128(tmp);
}

static void store4(void* p, __m128i v)
{
   int tmp = _mm_cvtsi128_si32(v);
   memcpy(p, &tmp, sizeof(int));
}

static __m128i load3(const void* p)
{
   uint32_t tmp = 0;
   memcpy(&tmp, p, 3);
   return _mm_cvtsi32_si128(tmp);
}

static void store3(void* p, __m128i v)
{
   int tmp = _mm_cvtsi128_si32(v);
   memcpy(p, &tmp, 3);
}

static void defilter_sub3(size_t rowbytes, unsigned char *row)
{
   /* The Sub filter predicts each pixel as the previous pixel, a.
    * There is no pixel to the left of the first pixel.  It's encoded directly.
    * That works with our main loop if we just say that left pixel was zero.
    */
   size_t rb = rowbytes;

   __m128i a, d = _mm_setzero_si128();

   while (rb >= 4) {
      a = d; d = load4(row);
      d = _mm_add_epi8(d, a);
      store3(row, d);

      row += 3;
      rb  -= 3;
   }
   if (rb > 0) {
      a = d; d = load3(row);
      d = _mm_add_epi8(d, a);
      store3(row, d);
   }
}

static void defilter_sub4(size_t rowbytes, unsigned char *row)
{
   /* The Sub filter predicts each pixel as the previous pixel, a.
    * There is no pixel to the left of the first pixel.  It's encoded directly.
    * That works with our main loop if we just say that left pixel was zero.
    */
   size_t rb = rowbytes+4;

   __m128i a, d = _mm_setzero_si128();

   while (rb > 4) {
      a = d; d = load4(row);
      d = _mm_add_epi8(d, a);
      store4(row, d);

      row += 4;
      rb  -= 4;
   }
}

static void defilter_avg3(size_t rowbytes, unsigned char *row, const unsigned char *prev)
{
   /* The Avg filter predicts each pixel as the (truncated) average of a and b.
    * There's no pixel to the left of the first pixel.  Luckily, it's
    * predicted to be half of the pixel above it.  So again, this works
    * perfectly with our loop if we make sure a starts at zero.
    */

   size_t rb = rowbytes;

   const __m128i zero = _mm_setzero_si128();

   __m128i    b;
   __m128i a, d = zero;

   while (rb >= 4)
   {
      __m128i avg;
             b = load4(prev);
      a = d; d = load4(row );

      /* PNG requires a truncating average, so we can't just use _mm_avg_epu8 */
      avg = _mm_avg_epu8(a,b);
      /* ...but we can fix it up by subtracting off 1 if it rounded up. */
      avg = _mm_sub_epi8(avg, _mm_and_si128(_mm_xor_si128(a, b),
                                            _mm_set1_epi8(1)));
      d = _mm_add_epi8(d, avg);
      store3(row, d);

      prev += 3;
      row  += 3;
      rb   -= 3;
   }

   if (rb > 0)
   {
      __m128i avg;
             b = load3(prev);
      a = d; d = load3(row );

      /* PNG requires a truncating average, so we can't just use _mm_avg_epu8 */
      avg = _mm_avg_epu8(a, b);
      /* ...but we can fix it up by subtracting off 1 if it rounded up. */
      avg = _mm_sub_epi8(avg, _mm_and_si128(_mm_xor_si128(a, b),
                                            _mm_set1_epi8(1)));

      d = _mm_add_epi8(d, avg);
      store3(row, d);
   }
}

static void defilter_avg4(size_t rowbytes, unsigned char *row, const unsigned char *prev)
{
   /* The Avg filter predicts each pixel as the (truncated) average of a and b.
    * There's no pixel to the left of the first pixel.  Luckily, it's
    * predicted to be half of the pixel above it.  So again, this works
    * perfectly with our loop if we make sure a starts at zero.
    */
   size_t rb = rowbytes+4;

   const __m128i zero = _mm_setzero_si128();
   __m128i    b;
   __m128i a, d = zero;

   while (rb > 4)
   {
      __m128i avg;
             b = load4(prev);
      a = d; d = load4(row );

      /* PNG requires a truncating average, so we can't just use _mm_avg_epu8 */
      avg = _mm_avg_epu8(a,b);
      /* ...but we can fix it up by subtracting off 1 if it rounded up. */
      avg = _mm_sub_epi8(avg, _mm_and_si128(_mm_xor_si128(a, b),
                                            _mm_set1_epi8(1)));

      d = _mm_add_epi8(d, avg);
      store4(row, d);

      prev += 4;
      row  += 4;
      rb   -= 4;
   }
}

/* Returns |x| for 16-bit lanes. */
#if (SPNG_SSE == 3) && !defined(_MSC_VER)
__attribute__((target("ssse3")))
#endif
static __m128i abs_i16(__m128i x)
{
#if SPNG_SSE >= 2
   return _mm_abs_epi16(x);
#else
   /* Read this all as, return x<0 ? -x : x.
   * To negate two's complement, you flip all the bits then add 1.
    */
   __m128i is_negative = _mm_cmplt_epi16(x, _mm_setzero_si128());

   /* Flip negative lanes. */
   x = _mm_xor_si128(x, is_negative);

   /* +1 to negative lanes, else +0. */
   x = _mm_sub_epi16(x, is_negative);
   return x;
#endif
}

/* Bytewise c ? t : e. */
static __m128i if_then_else(__m128i c, __m128i t, __m128i e)
{
#if SPNG_SSE > 3
   return _mm_blendv_epi8(e, t, c);
#else
   return _mm_or_si128(_mm_and_si128(c, t), _mm_andnot_si128(c, e));
#endif
}

static void defilter_paeth3(size_t rowbytes, unsigned char *row, const unsigned char *prev)
{
   /* Paeth tries to predict pixel d using the pixel to the left of it, a,
    * and two pixels from the previous row, b and c:
    *   prev: c b
    *   row:  a d
    * The Paeth function predicts d to be whichever of a, b, or c is nearest to
    * p=a+b-c.
    *
    * The first pixel has no left context, and so uses an Up filter, p = b.
    * This works naturally with our main loop's p = a+b-c if we force a and c
    * to zero.
    * Here we zero b and d, which become c and a respectively at the start of
    * the loop.
    */
   size_t rb = rowbytes;
   const __m128i zero = _mm_setzero_si128();
   __m128i c, b = zero,
           a, d = zero;

   while (rb >= 4)
   {
      /* It's easiest to do this math (particularly, deal with pc) with 16-bit
       * intermediates.
       */
      __m128i pa,pb,pc,smallest,nearest;
      c = b; b = _mm_unpacklo_epi8(load4(prev), zero);
      a = d; d = _mm_unpacklo_epi8(load4(row ), zero);

      /* (p-a) == (a+b-c - a) == (b-c) */

      pa = _mm_sub_epi16(b, c);

      /* (p-b) == (a+b-c - b) == (a-c) */
      pb = _mm_sub_epi16(a, c);

      /* (p-c) == (a+b-c - c) == (a+b-c-c) == (b-c)+(a-c) */
      pc = _mm_add_epi16(pa, pb);

      pa = abs_i16(pa);  /* |p-a| */
      pb = abs_i16(pb);  /* |p-b| */
      pc = abs_i16(pc);  /* |p-c| */

      smallest = _mm_min_epi16(pc, _mm_min_epi16(pa, pb));

      /* Paeth breaks ties favoring a over b over c. */
      nearest  = if_then_else(_mm_cmpeq_epi16(smallest, pa), a,
                         if_then_else(_mm_cmpeq_epi16(smallest, pb), b, c));

      /* Note `_epi8`: we need addition to wrap modulo 255. */
      d = _mm_add_epi8(d, nearest);
      store3(row, _mm_packus_epi16(d, d));

      prev += 3;
      row  += 3;
      rb   -= 3;
   }

   if (rb > 0)
   {
      /* It's easiest to do this math (particularly, deal with pc) with 16-bit
       * intermediates.
       */
      __m128i pa,pb,pc,smallest,nearest;
      c = b; b = _mm_unpacklo_epi8(load3(prev), zero);
      a = d; d = _mm_unpacklo_epi8(load3(row ), zero);

      /* (p-a) == (a+b-c - a) == (b-c) */
      pa = _mm_sub_epi16(b, c);

      /* (p-b) == (a+b-c - b) == (a-c) */
      pb = _mm_sub_epi16(a, c);

      /* (p-c) == (a+b-c - c) == (a+b-c-c) == (b-c)+(a-c) */
      pc = _mm_add_epi16(pa, pb);

      pa = abs_i16(pa);  /* |p-a| */
      pb = abs_i16(pb);  /* |p-b| */
      pc = abs_i16(pc);  /* |p-c| */

      smallest = _mm_min_epi16(pc, _mm_min_epi16(pa, pb));

      /* Paeth breaks ties favoring a over b over c. */
      nearest  = if_then_else(_mm_cmpeq_epi16(smallest, pa), a,
                         if_then_else(_mm_cmpeq_epi16(smallest, pb), b, c));

      /* Note `_epi8`: we need addition to wrap modulo 255. */
      d = _mm_add_epi8(d, nearest);
      store3(row, _mm_packus_epi16(d, d));
   }
}

static void defilter_paeth4(size_t rowbytes, unsigned char *row, const unsigned char *prev)
{
   /* Paeth tries to predict pixel d using the pixel to the left of it, a,
    * and two pixels from the previous row, b and c:
    *   prev: c b
    *   row:  a d
    * The Paeth function predicts d to be whichever of a, b, or c is nearest to
    * p=a+b-c.
    *
    * The first pixel has no left context, and so uses an Up filter, p = b.
    * This works naturally with our main loop's p = a+b-c if we force a and c
    * to zero.
    * Here we zero b and d, which become c and a respectively at the start of
    * the loop.
    */
   size_t rb = rowbytes+4;

   const __m128i zero = _mm_setzero_si128();
   __m128i pa,pb,pc,smallest,nearest;
   __m128i c, b = zero,
           a, d = zero;

   while (rb > 4)
   {
      /* It's easiest to do this math (particularly, deal with pc) with 16-bit
       * intermediates.
       */
      c = b; b = _mm_unpacklo_epi8(load4(prev), zero);
      a = d; d = _mm_unpacklo_epi8(load4(row ), zero);

      /* (p-a) == (a+b-c - a) == (b-c) */
      pa = _mm_sub_epi16(b, c);

      /* (p-b) == (a+b-c - b) == (a-c) */
      pb = _mm_sub_epi16(a, c);

      /* (p-c) == (a+b-c - c) == (a+b-c-c) == (b-c)+(a-c) */
      pc = _mm_add_epi16(pa, pb);

      pa = abs_i16(pa);  /* |p-a| */
      pb = abs_i16(pb);  /* |p-b| */
      pc = abs_i16(pc);  /* |p-c| */

      smallest = _mm_min_epi16(pc, _mm_min_epi16(pa, pb));

      /* Paeth breaks ties favoring a over b over c. */
      nearest  = if_then_else(_mm_cmpeq_epi16(smallest, pa), a,
                         if_then_else(_mm_cmpeq_epi16(smallest, pb), b, c));

      /* Note `_epi8`: we need addition to wrap modulo 255. */
      d = _mm_add_epi8(d, nearest);
      store4(row, _mm_packus_epi16(d, d));

      prev += 4;
      row  += 4;
      rb   -= 4;
   }
}

#endif /* SPNG_X86 */


/* filter_neon_intrinsics.c - NEON optimised filter functions
 *
 * Copyright (c) 2018 Cosmin Truta
 * Copyright (c) 2014,2016 Glenn Randers-Pehrson
 * Written by James Yu <james.yu at linaro.org>, October 2013.
 * Based on filter_neon.S, written by Mans Rullgard, 2011.
 *
 * This code is released under the libpng license.
 * For conditions of distribution and use, see the disclaimer
 * and license in png.h
 */


#if defined(SPNG_ARM)

#define png_aligncast(type, value) ((void*)(value))
#define png_aligncastconst(type, value) ((const void*)(value))

/* libpng row pointers are not necessarily aligned to any particular boundary,
 * however this code will only work with appropriate alignment. mips/mips_init.c
 * checks for this (and will not compile unless it is done). This code uses
 * variants of png_aligncast to avoid compiler warnings.
 */
#define png_ptr(type,pointer) png_aligncast(type *,pointer)
#define png_ptrc(type,pointer) png_aligncastconst(const type *,pointer)

/* The following relies on a variable 'temp_pointer' being declared with type
 * 'type'.  This is written this way just to hide the GCC strict aliasing
 * warning; note that the code is safe because there never is an alias between
 * the input and output pointers.
 */
#define png_ldr(type,pointer)\
   (temp_pointer = png_ptr(type,pointer), *temp_pointer)


#if defined(_MSC_VER) && !defined(__clang__) && defined(_M_ARM64)
    #include <arm64_neon.h>
#else
    #include <arm_neon.h>
#endif

static void defilter_sub3(size_t rowbytes, unsigned char *row)
{
   unsigned char *rp = row;
   unsigned char *rp_stop = row + rowbytes;

   uint8x16_t vtmp = vld1q_u8(rp);
   uint8x8x2_t *vrpt = png_ptr(uint8x8x2_t, &vtmp);
   uint8x8x2_t vrp = *vrpt;

   uint8x8x4_t vdest;
   vdest.val[3] = vdup_n_u8(0);

   for (; rp < rp_stop;)
   {
      uint8x8_t vtmp1, vtmp2;
      uint32x2_t *temp_pointer;

      vtmp1 = vext_u8(vrp.val[0], vrp.val[1], 3);
      vdest.val[0] = vadd_u8(vdest.val[3], vrp.val[0]);
      vtmp2 = vext_u8(vrp.val[0], vrp.val[1], 6);
      vdest.val[1] = vadd_u8(vdest.val[0], vtmp1);

      vtmp1 = vext_u8(vrp.val[1], vrp.val[1], 1);
      vdest.val[2] = vadd_u8(vdest.val[1], vtmp2);
      vdest.val[3] = vadd_u8(vdest.val[2], vtmp1);

      vtmp = vld1q_u8(rp + 12);
      vrpt = png_ptr(uint8x8x2_t, &vtmp);
      vrp = *vrpt;

      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[0]), 0);
      rp += 3;
      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[1]), 0);
      rp += 3;
      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[2]), 0);
      rp += 3;
      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[3]), 0);
      rp += 3;
   }
}

static void defilter_sub4(size_t rowbytes, unsigned char *row)
{
   unsigned char *rp = row;
   unsigned char *rp_stop = row + rowbytes;

   uint8x8x4_t vdest;
   vdest.val[3] = vdup_n_u8(0);

   for (; rp < rp_stop; rp += 16)
   {
      uint32x2x4_t vtmp = vld4_u32(png_ptr(uint32_t,rp));
      uint8x8x4_t *vrpt = png_ptr(uint8x8x4_t,&vtmp);
      uint8x8x4_t vrp = *vrpt;
      uint32x2x4_t *temp_pointer;
      uint32x2x4_t vdest_val;

      vdest.val[0] = vadd_u8(vdest.val[3], vrp.val[0]);
      vdest.val[1] = vadd_u8(vdest.val[0], vrp.val[1]);
      vdest.val[2] = vadd_u8(vdest.val[1], vrp.val[2]);
      vdest.val[3] = vadd_u8(vdest.val[2], vrp.val[3]);

      vdest_val = png_ldr(uint32x2x4_t, &vdest);
      vst4_lane_u32(png_ptr(uint32_t,rp), vdest_val, 0);
   }
}

static void defilter_avg3(size_t rowbytes, unsigned char *row, const unsigned char *prev_row)
{
   unsigned char *rp = row;
   const unsigned char *pp = prev_row;
   unsigned char *rp_stop = row + rowbytes;

   uint8x16_t vtmp;
   uint8x8x2_t *vrpt;
   uint8x8x2_t vrp;
   uint8x8x4_t vdest;
   vdest.val[3] = vdup_n_u8(0);

   vtmp = vld1q_u8(rp);
   vrpt = png_ptr(uint8x8x2_t,&vtmp);
   vrp = *vrpt;

   for (; rp < rp_stop; pp += 12)
   {
      uint8x8_t vtmp1, vtmp2, vtmp3;

      uint8x8x2_t *vppt;
      uint8x8x2_t vpp;

      uint32x2_t *temp_pointer;

      vtmp = vld1q_u8(pp);
      vppt = png_ptr(uint8x8x2_t,&vtmp);
      vpp = *vppt;

      vtmp1 = vext_u8(vrp.val[0], vrp.val[1], 3);
      vdest.val[0] = vhadd_u8(vdest.val[3], vpp.val[0]);
      vdest.val[0] = vadd_u8(vdest.val[0], vrp.val[0]);

      vtmp2 = vext_u8(vpp.val[0], vpp.val[1], 3);
      vtmp3 = vext_u8(vrp.val[0], vrp.val[1], 6);
      vdest.val[1] = vhadd_u8(vdest.val[0], vtmp2);
      vdest.val[1] = vadd_u8(vdest.val[1], vtmp1);

      vtmp2 = vext_u8(vpp.val[0], vpp.val[1], 6);
      vtmp1 = vext_u8(vrp.val[1], vrp.val[1], 1);

      vtmp = vld1q_u8(rp + 12);
      vrpt = png_ptr(uint8x8x2_t,&vtmp);
      vrp = *vrpt;

      vdest.val[2] = vhadd_u8(vdest.val[1], vtmp2);
      vdest.val[2] = vadd_u8(vdest.val[2], vtmp3);

      vtmp2 = vext_u8(vpp.val[1], vpp.val[1], 1);

      vdest.val[3] = vhadd_u8(vdest.val[2], vtmp2);
      vdest.val[3] = vadd_u8(vdest.val[3], vtmp1);

      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[0]), 0);
      rp += 3;
      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[1]), 0);
      rp += 3;
      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[2]), 0);
      rp += 3;
      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[3]), 0);
      rp += 3;
   }
}

static void defilter_avg4(size_t rowbytes, unsigned char *row, const unsigned char *prev_row)
{
   unsigned char *rp = row;
   unsigned char *rp_stop = row + rowbytes;
   const unsigned char *pp = prev_row;

   uint8x8x4_t vdest;
   vdest.val[3] = vdup_n_u8(0);

   for (; rp < rp_stop; rp += 16, pp += 16)
   {
      uint32x2x4_t vtmp;
      uint8x8x4_t *vrpt, *vppt;
      uint8x8x4_t vrp, vpp;
      uint32x2x4_t *temp_pointer;
      uint32x2x4_t vdest_val;

      vtmp = vld4_u32(png_ptr(uint32_t,rp));
      vrpt = png_ptr(uint8x8x4_t,&vtmp);
      vrp = *vrpt;
      vtmp = vld4_u32(png_ptrc(uint32_t,pp));
      vppt = png_ptr(uint8x8x4_t,&vtmp);
      vpp = *vppt;

      vdest.val[0] = vhadd_u8(vdest.val[3], vpp.val[0]);
      vdest.val[0] = vadd_u8(vdest.val[0], vrp.val[0]);
      vdest.val[1] = vhadd_u8(vdest.val[0], vpp.val[1]);
      vdest.val[1] = vadd_u8(vdest.val[1], vrp.val[1]);
      vdest.val[2] = vhadd_u8(vdest.val[1], vpp.val[2]);
      vdest.val[2] = vadd_u8(vdest.val[2], vrp.val[2]);
      vdest.val[3] = vhadd_u8(vdest.val[2], vpp.val[3]);
      vdest.val[3] = vadd_u8(vdest.val[3], vrp.val[3]);

      vdest_val = png_ldr(uint32x2x4_t, &vdest);
      vst4_lane_u32(png_ptr(uint32_t,rp), vdest_val, 0);
   }
}

static uint8x8_t paeth_arm(uint8x8_t a, uint8x8_t b, uint8x8_t c)
{
   uint8x8_t d, e;
   uint16x8_t p1, pa, pb, pc;

   p1 = vaddl_u8(a, b); /* a + b */
   pc = vaddl_u8(c, c); /* c * 2 */
   pa = vabdl_u8(b, c); /* pa */
   pb = vabdl_u8(a, c); /* pb */
   pc = vabdq_u16(p1, pc); /* pc */

   p1 = vcleq_u16(pa, pb); /* pa <= pb */
   pa = vcleq_u16(pa, pc); /* pa <= pc */
   pb = vcleq_u16(pb, pc); /* pb <= pc */

   p1 = vandq_u16(p1, pa); /* pa <= pb && pa <= pc */

   d = vmovn_u16(pb);
   e = vmovn_u16(p1);

   d = vbsl_u8(d, b, c);
   e = vbsl_u8(e, a, d);

   return e;
}

static void defilter_paeth3(size_t rowbytes, unsigned char *row, const unsigned char *prev_row)
{
   unsigned char *rp = row;
   const unsigned char *pp = prev_row;
   unsigned char *rp_stop = row + rowbytes;

   uint8x16_t vtmp;
   uint8x8x2_t *vrpt;
   uint8x8x2_t vrp;
   uint8x8_t vlast = vdup_n_u8(0);
   uint8x8x4_t vdest;
   vdest.val[3] = vdup_n_u8(0);

   vtmp = vld1q_u8(rp);
   vrpt = png_ptr(uint8x8x2_t,&vtmp);
   vrp = *vrpt;

   for (; rp < rp_stop; pp += 12)
   {
      uint8x8x2_t *vppt;
      uint8x8x2_t vpp;
      uint8x8_t vtmp1, vtmp2, vtmp3;
      uint32x2_t *temp_pointer;

      vtmp = vld1q_u8(pp);
      vppt = png_ptr(uint8x8x2_t,&vtmp);
      vpp = *vppt;

      vdest.val[0] = paeth_arm(vdest.val[3], vpp.val[0], vlast);
      vdest.val[0] = vadd_u8(vdest.val[0], vrp.val[0]);

      vtmp1 = vext_u8(vrp.val[0], vrp.val[1], 3);
      vtmp2 = vext_u8(vpp.val[0], vpp.val[1], 3);
      vdest.val[1] = paeth_arm(vdest.val[0], vtmp2, vpp.val[0]);
      vdest.val[1] = vadd_u8(vdest.val[1], vtmp1);

      vtmp1 = vext_u8(vrp.val[0], vrp.val[1], 6);
      vtmp3 = vext_u8(vpp.val[0], vpp.val[1], 6);
      vdest.val[2] = paeth_arm(vdest.val[1], vtmp3, vtmp2);
      vdest.val[2] = vadd_u8(vdest.val[2], vtmp1);

      vtmp1 = vext_u8(vrp.val[1], vrp.val[1], 1);
      vtmp2 = vext_u8(vpp.val[1], vpp.val[1], 1);

      vtmp = vld1q_u8(rp + 12);
      vrpt = png_ptr(uint8x8x2_t,&vtmp);
      vrp = *vrpt;

      vdest.val[3] = paeth_arm(vdest.val[2], vtmp2, vtmp3);
      vdest.val[3] = vadd_u8(vdest.val[3], vtmp1);

      vlast = vtmp2;

      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[0]), 0);
      rp += 3;
      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[1]), 0);
      rp += 3;
      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[2]), 0);
      rp += 3;
      vst1_lane_u32(png_ptr(uint32_t,rp), png_ldr(uint32x2_t,&vdest.val[3]), 0);
      rp += 3;
   }
}

static void defilter_paeth4(size_t rowbytes, unsigned char *row, const unsigned char *prev_row)
{
   unsigned char *rp = row;
   unsigned char *rp_stop = row + rowbytes;
   const unsigned char *pp = prev_row;

   uint8x8_t vlast = vdup_n_u8(0);
   uint8x8x4_t vdest;
   vdest.val[3] = vdup_n_u8(0);

   for (; rp < rp_stop; rp += 16, pp += 16)
   {
      uint32x2x4_t vtmp;
      uint8x8x4_t *vrpt, *vppt;
      uint8x8x4_t vrp, vpp;
      uint32x2x4_t *temp_pointer;
      uint32x2x4_t vdest_val;

      vtmp = vld4_u32(png_ptr(uint32_t,rp));
      vrpt = png_ptr(uint8x8x4_t,&vtmp);
      vrp = *vrpt;
      vtmp = vld4_u32(png_ptrc(uint32_t,pp));
      vppt = png_ptr(uint8x8x4_t,&vtmp);
      vpp = *vppt;

      vdest.val[0] = paeth_arm(vdest.val[3], vpp.val[0], vlast);
      vdest.val[0] = vadd_u8(vdest.val[0], vrp.val[0]);
      vdest.val[1] = paeth_arm(vdest.val[0], vpp.val[1], vpp.val[0]);
      vdest.val[1] = vadd_u8(vdest.val[1], vrp.val[1]);
      vdest.val[2] = paeth_arm(vdest.val[1], vpp.val[2], vpp.val[1]);
      vdest.val[2] = vadd_u8(vdest.val[2], vrp.val[2]);
      vdest.val[3] = paeth_arm(vdest.val[2], vpp.val[3], vpp.val[2]);
      vdest.val[3] = vadd_u8(vdest.val[3], vrp.val[3]);

      vlast = vpp.val[3];

      vdest_val = png_ldr(uint32x2x4_t, &vdest);
      vst4_lane_u32(png_ptr(uint32_t,rp), vdest_val, 0);
   }
}

#endif /* SPNG_ARM */
