/**************************************************************************
 * Copyright (C) 2022-2023  Junlon2006
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 **************************************************************************/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "aws_s3_sdk.h"
#include "webclient.h"

#define TAG "oss_aws"

#define HOST_BUFFER_SIZE       (128)
#define URI_BUFFER_SIZE        (HOST_BUFFER_SIZE << 1)
#define UUID_BUFFER_SIZE       (36 + 1)
#define REGION_BUFFER_SIZE     (64)
#define MD5SUM_SIZE            (16)
#define AUTH_BUFFER_SIZE       (512)

// AWS_GLOBAL is a pseudo region that can be used to tell SDK to use the service global endpoint if there is any.
// You can specify this region to corresponding environment variable, config file item and in your code.
// For services without global region, the request will be directed to us-east-1
#define AWS_GLOBAL      "aws-global"
#define US_EAST_1       "us-east-1" // US East (N. Virginia)
#define US_EAST_2       "us-east-2" // US East (Ohio)
#define US_WEST_1       "us-west-1" // US West (N. California)
#define US_WEST_2       "us-west-2" // US West (Oregon)
#define EU_WEST_1       "eu-west-1" // EU (Ireland)
#define EU_WEST_2       "eu-west-2" // EU (London)
#define EU_WEST_3       "eu-west-3" // EU (Paris)
#define EU_CENTRAL_1    "eu-central-1" // "EU (Frankfurt)
#define EU_NORTH_1      "eu-north-1" // EU (Stockholm)
#define EU_SOUTH_1      "eu-south-1" // EU (Milan)
#define AP_EAST_1       "ap-east-1" // Asia Pacific (Hong Kong)
#define AP_SOUTH_1      "ap-south-1" // Asia Pacific (Mumbai)
#define AP_SOUTHEAST_1  "ap-southeast-1" // Asia Pacific (Singapore)
#define AP_SOUTHEAST_2  "ap-southeast-2" // Asia Pacific (Sydney)
#define AP_NORTHEAST_1  "ap-northeast-1" // Asia Pacific (Tokyo)
#define AP_NORTHEAST_2  "ap-northeast-2" // Asia Pacific (Seoul)
#define AP_NORTHEAST_3  "ap-northeast-3" // Asia Pacific (Osaka)
#define SA_EAST_1       "sa-east-1" // South America (Sao Paulo
#define CN_NORTH_1      "cn-north-1" // China (Beijing)
#define CN_NORTHWEST_1  "cn-northwest-1" // China (Ningxia)
#define CA_CENTRAL_1    "ca-central-1" // Canada (Central)
#define ME_SOUTH_1      "me-south-1" // Middle East (Bahrain)
#define AF_SOUTH_1      "af-south-1" // Africa (Cape Town)
#define US_GOV_WEST_1   "us-gov-west-1" // AWS GovCloud (US-West)
#define US_GOV_EAST_1   "us-gov-east-1" // AWS GovCloud (US-East)
#define US_ISO_EAST_1   "us-iso-east-1"  // US ISO East
#define US_ISOB_EAST_1  "us-isob-east-1" // US ISOB East (Ohio)
#define US_ISO_WEST_1   "us-iso-west-1" // US ISO West

#define REGION_CMP(r1, r2) (0 == strcmp(r1, r2))
static void __compute_signer_region(char region[REGION_BUFFER_SIZE], const char *region_orgin)
{
  if (REGION_CMP(region_orgin, AWS_GLOBAL)) {
    snprintf(region, REGION_BUFFER_SIZE, "%s", US_EAST_1);
  } else if (REGION_CMP(region_orgin, "fips-aws-global")) {
    snprintf(region, REGION_BUFFER_SIZE, "%s", US_EAST_1);
  } else if (REGION_CMP(region_orgin, "s3-external-1")) {
    snprintf(region, REGION_BUFFER_SIZE, "%s", US_EAST_1);
  } else if (strlen(region_orgin) >= 5 && strncmp(region_orgin, "fips-", 5) == 0) {
    snprintf(region, REGION_BUFFER_SIZE, "%s", region_orgin + 5);
  } else if (strlen(region_orgin) >= 5 && strncmp(region_orgin + strlen(region_orgin) - 5, "-fips", 5) == 0) {
    snprintf(region, REGION_BUFFER_SIZE, "%s", region_orgin);
    region[strlen(region) - 5] = '\0';
  } else {
    snprintf(region, REGION_BUFFER_SIZE, "%s", region_orgin);
  }
}

static void __get_x_amz_date(char *date_time, int date_time_len,
                             char *date, int date_len)
{
  time_t rawtime;
  struct tm *tm;

  /* step1. get gmt */
  time(&rawtime);
  tm = gmtime(&rawtime);

  /* step2. format datetime */
  snprintf(date_time, date_time_len, "%.4d%.2d%.2dT%.2d%.2d%.2dZ",
           1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
  snprintf(date, date_len, "%.4d%.2d%.2d", 1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday);
}

typedef struct {
  uint64_t size;        // Size of input in bytes
  uint32_t buffer[4];   // Current accumulation of hash
  uint8_t input[64];    // Input to be used in the next step
  uint8_t digest[16];   // Result of algorithm
} md5_context_t;
/*
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
 * and modified slightly to be functionally identical but condensed into control structures.
 */

/*
 * Constants defined by the MD5 algorithm
 */
#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476

static uint32_t S[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static uint32_t K[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                       0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                       0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                       0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                       0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                       0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                       0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                       0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                       0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                       0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                       0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                       0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                       0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                       0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                       0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                       0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
/*
 * Bit-manipulation functions defined by the MD5 algorithm
 */
#define F(X, Y, Z) ((X & Y) | (~X & Z))
#define G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | ~Z))

/*
 * Padding used to make the size (in bits) of the input congruent to 448 mod 512
 */
static uint8_t PADDING[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
/*
 * Initialize a context
 */
static void __md5_init(md5_context_t *ctx)
{
  ctx->size = (uint64_t)0;

  ctx->buffer[0] = (uint32_t)A;
  ctx->buffer[1] = (uint32_t)B;
  ctx->buffer[2] = (uint32_t)C;
  ctx->buffer[3] = (uint32_t)D;
}

/*
 * Rotates a 32-bit word left by n bits
 */
static uint32_t __rotate_left(uint32_t x, uint32_t n)
{
  return (x << n) | (x >> (32 - n));
}

/*
 * Step on 512 bits of input with the main MD5 algorithm.
 */
static void __md5_step(uint32_t *buffer, uint32_t *input)
{
  uint32_t AA = buffer[0];
  uint32_t BB = buffer[1];
  uint32_t CC = buffer[2];
  uint32_t DD = buffer[3];
  uint32_t E;
  unsigned int j;

  for (int i = 0; i < 64; ++i) {
    switch (i / 16) {
      case 0:
        E = F(BB, CC, DD);
        j = i;
        break;
      case 1:
        E = G(BB, CC, DD);
        j = ((i * 5) + 1) % 16;
        break;
      case 2:
        E = H(BB, CC, DD);
        j = ((i * 3) + 5) % 16;
        break;
      default:
        E = I(BB, CC, DD);
        j = (i * 7) % 16;
        break;
    }

    uint32_t temp = DD;
    DD = CC;
    CC = BB;
    BB = BB + __rotate_left(AA + E + K[i] + input[j], S[i]);
    AA = temp;
  }

  buffer[0] += AA;
  buffer[1] += BB;
  buffer[2] += CC;
  buffer[3] += DD;
}

/*
 * Add some amount of input to the context
 *
 * If the input fills out a block of 512 bits, apply the algorithm (__md5_step)
 * and save the result in the buffer. Also updates the overall size.
 */
static void __md5_update(md5_context_t *ctx, uint8_t *input_buffer, size_t input_len)
{
  uint32_t input[16];
  unsigned int offset = ctx->size % 64;
  ctx->size += (uint64_t)input_len;

  // Copy each byte in input_buffer into the next space in our context input
  for (unsigned int i = 0; i < input_len; ++i) {
    ctx->input[offset++] = (uint8_t)*(input_buffer + i);

    // If we've filled our context input, copy it into our local array input
    // then reset the offset to 0 and fill in a new buffer.
    // Every time we fill out a chunk, we run it through the algorithm
    // to enable some back and forth between cpu and i/o
    if (offset % 64 == 0) {
      for (unsigned int j = 0; j < 16; ++j) {
        // Convert to little-endian
        // The local variable `input` our 512-bit chunk separated into 32-bit words
        // we can use in calculations
        input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
          (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
          (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
          (uint32_t)(ctx->input[(j * 4)]);
      }
      __md5_step(ctx->buffer, input);
      offset = 0;
    }
  }
}

/*
 * Pad the current input to get to 448 bytes, append the size in bits to the very end,
 * and save the result of the final iteration into digest.
 */
static void __md5_finalize(md5_context_t *ctx)
{
  uint32_t input[16];
  unsigned int offset = ctx->size % 64;
  unsigned int padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;

  // Fill in the padding andndo the changes to size that resulted from the update
  __md5_update(ctx, PADDING, padding_length);
  ctx->size -= (uint64_t)padding_length;

  // Do a final update (internal to this function)
  // Last two 32-bit words are the two halves of the size (converted from bytes to bits)
  for (unsigned int j = 0; j < 14; ++j) {
    input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
      (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
      (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
      (uint32_t)(ctx->input[(j * 4)]);
  }
  input[14] = (uint32_t)(ctx->size * 8);
  input[15] = (uint32_t)((ctx->size * 8) >> 32);

  __md5_step(ctx->buffer, input);

  // Move the result into digest (convert from little-endian)
  for (unsigned int i = 0; i < 4; ++i) {
    ctx->digest[(i * 4) + 0] = (uint8_t)((ctx->buffer[i] & 0x000000FF));
    ctx->digest[(i * 4) + 1] = (uint8_t)((ctx->buffer[i] & 0x0000FF00) >>  8);
    ctx->digest[(i * 4) + 2] = (uint8_t)((ctx->buffer[i] & 0x00FF0000) >> 16);
    ctx->digest[(i * 4) + 3] = (uint8_t)((ctx->buffer[i] & 0xFF000000) >> 24);
  }
}

/*
 * Functions that will return a pointer to the hash of the provided input
 */
static void __md5_sum(uint8_t *input, int len, uint8_t sum[MD5SUM_SIZE])
{
  md5_context_t ctx;
  __md5_init(&ctx);
  __md5_update(&ctx, input, len);
  __md5_finalize(&ctx);
  memcpy(sum, ctx.digest, MD5SUM_SIZE);
}

static int32_t __base64_encode(const uint8_t *src, int32_t src_len, char *encoded)
{
  const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  int i;
  char *p = encoded;
  for (i = 0; i < src_len - 2; i += 3) {
    *p++ = basis_64[(src[i] >> 2) & 0x3F];
    *p++ = basis_64[((src[i] & 0x3) << 4) |
      ((src[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((src[i + 1] & 0xF) << 2) |
      ((src[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[src[i + 2] & 0x3F];
  }

  if (i < src_len) {
    *p++ = basis_64[(src[i] >> 2) & 0x3F];
    if (i == (src_len - 1)) {
      *p++ = basis_64[((src[i] & 0x3) << 4)];
      *p++ = '=';
    } else {
      *p++ = basis_64[((src[i] & 0x3) << 4) |
        ((src[i + 1] & 0xF0) >> 4)];
      *p++ = basis_64[((src[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
  }

  *p++ = '\0';
  return (p - encoded);
}

#define SHA256_SIZE_BYTES       32
#define FN_                     static inline __attribute__((const))

typedef struct {
  uint8_t  buf[64];
  uint32_t hash[8];
  uint32_t bits[2];
  uint32_t len;
  uint32_t rfu__;
  uint32_t W[64];
} sha256_context;

static const uint32_t KK[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

FN_ uint8_t _shb(uint32_t x, uint32_t n)
{
  return ((x >> (n & 31)) & 0xff);
}

FN_ uint32_t _shw(uint32_t x, uint32_t n)
{
  return ((x << (n & 31)) & 0xffffffff);
}

FN_ uint32_t _r(uint32_t x, uint8_t n)
{
  return ((x >> n) | _shw(x, 32 - n));
}

FN_ uint32_t _Ch(uint32_t x, uint32_t y, uint32_t z)
{
  return ((x & y) ^ ((~x) & z));
}

FN_ uint32_t _Ma(uint32_t x, uint32_t y, uint32_t z)
{
  return ((x & y) ^ (x & z) ^ (y & z));
}

FN_ uint32_t _S0(uint32_t x)
{
  return (_r(x, 2) ^ _r(x, 13) ^ _r(x, 22));
}

FN_ uint32_t _S1(uint32_t x)
{
  return (_r(x, 6) ^ _r(x, 11) ^ _r(x, 25));
}

FN_ uint32_t _G0(uint32_t x)
{
  return (_r(x, 7) ^ _r(x, 18) ^ (x >> 3));
}

FN_ uint32_t _G1(uint32_t x)
{
  return (_r(x, 17) ^ _r(x, 19) ^ (x >> 10));
}

FN_ uint32_t _word(uint8_t *c)
{
  return (_shw(c[0], 24) | _shw(c[1], 16) | _shw(c[2], 8) | (c[3]));
}

static void _addbits(sha256_context *ctx, uint32_t n)
{
  if (ctx->bits[0] > (0xffffffff - n)) {
    ctx->bits[1] = (ctx->bits[1] + 1) & 0xFFFFFFFF;
  }
  ctx->bits[0] = (ctx->bits[0] + n) & 0xFFFFFFFF;
}

static void _hash(sha256_context *ctx)
{
  register uint32_t a, b, c, d, e, f, g, h;
  uint32_t t[2];

  a = ctx->hash[0];
  b = ctx->hash[1];
  c = ctx->hash[2];
  d = ctx->hash[3];
  e = ctx->hash[4];
  f = ctx->hash[5];
  g = ctx->hash[6];
  h = ctx->hash[7];

  for (uint32_t i = 0; i < 64; i++) {
    if (i < 16) {
      ctx->W[i] = _word(&ctx->buf[_shw(i, 2)]);
    } else {
      ctx->W[i] = _G1(ctx->W[i - 2])  + ctx->W[i - 7] +
        _G0(ctx->W[i - 15]) + ctx->W[i - 16];
    }

    t[0] = h + _S1(e) + _Ch(e, f, g) + KK[i] + ctx->W[i];
    t[1] = _S0(a) + _Ma(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t[0];
    d = c;
    c = b;
    b = a;
    a = t[0] + t[1];
  }

  ctx->hash[0] += a;
  ctx->hash[1] += b;
  ctx->hash[2] += c;
  ctx->hash[3] += d;
  ctx->hash[4] += e;
  ctx->hash[5] += f;
  ctx->hash[6] += g;
  ctx->hash[7] += h;
}

static void __sha256_init(sha256_context *ctx)
{
  if (ctx != NULL) {
    ctx->bits[0] = ctx->bits[1] = ctx->len = 0;
    ctx->hash[0] = 0x6a09e667;
    ctx->hash[1] = 0xbb67ae85;
    ctx->hash[2] = 0x3c6ef372;
    ctx->hash[3] = 0xa54ff53a;
    ctx->hash[4] = 0x510e527f;
    ctx->hash[5] = 0x9b05688c;
    ctx->hash[6] = 0x1f83d9ab;
    ctx->hash[7] = 0x5be0cd19;
  }
}

static void __sha256_hash(sha256_context *ctx, const void *data, size_t len)
{
  const uint8_t *bytes = (const uint8_t *)data;

  if ((ctx != NULL) && (bytes != NULL) && (ctx->len < sizeof(ctx->buf))) {
    for (size_t i = 0; i < len; i++) {
      ctx->buf[ctx->len++] = bytes[i];
      if (ctx->len == sizeof(ctx->buf)) {
        _hash(ctx);
        _addbits(ctx, sizeof(ctx->buf) * 8);
        ctx->len = 0;
      }
    }
  }
}

static void __sha256_done(sha256_context *ctx, uint8_t *hash)
{
  register uint32_t i, j;

  if (ctx != NULL) {
    j = ctx->len % sizeof(ctx->buf);
    ctx->buf[j] = 0x80;
    for (i = j + 1; i < sizeof(ctx->buf); i++) {
      ctx->buf[i] = 0x00;
    }

    if (ctx->len > 55) {
      _hash(ctx);
      for (j = 0; j < sizeof(ctx->buf); j++) {
        ctx->buf[j] = 0x00;
      }
    }

    _addbits(ctx, ctx->len * 8);
    ctx->buf[63] = _shb(ctx->bits[0],  0);
    ctx->buf[62] = _shb(ctx->bits[0],  8);
    ctx->buf[61] = _shb(ctx->bits[0], 16);
    ctx->buf[60] = _shb(ctx->bits[0], 24);
    ctx->buf[59] = _shb(ctx->bits[1],  0);
    ctx->buf[58] = _shb(ctx->bits[1],  8);
    ctx->buf[57] = _shb(ctx->bits[1], 16);
    ctx->buf[56] = _shb(ctx->bits[1], 24);
    _hash(ctx);

    if (hash != NULL) {
      for (i = 0, j = 24; i < 4; i++, j -= 8) {
        hash[i +  0] = _shb(ctx->hash[0], j);
        hash[i +  4] = _shb(ctx->hash[1], j);
        hash[i +  8] = _shb(ctx->hash[2], j);
        hash[i + 12] = _shb(ctx->hash[3], j);
        hash[i + 16] = _shb(ctx->hash[4], j);
        hash[i + 20] = _shb(ctx->hash[5], j);
        hash[i + 24] = _shb(ctx->hash[6], j);
        hash[i + 28] = _shb(ctx->hash[7], j);
      }
    }
  }
}

#define HMAC_SHA256_DIGEST_SIZE 32
#define SHA256_DIGEST_SIZE      32
#define BB                      64
#define L                       SHA256_DIGEST_SIZE
#define I_PAD                   0x36
#define O_PAD                   0x5C
static void __hmac_sha256(uint8_t out[HMAC_SHA256_DIGEST_SIZE],
                          const uint8_t *data, size_t data_len,
                          const uint8_t *key, size_t key_len)
{
  sha256_context ss;
  uint8_t kh[SHA256_DIGEST_SIZE];

  /*
   * If the key length is bigger than the buffer size B, apply the hash
   * function to it first and use the result instead.
   */
  if (key_len > BB) {
    __sha256_init(&ss);
    __sha256_hash(&ss, key, key_len);
    __sha256_done(&ss, kh);
    key_len = SHA256_DIGEST_SIZE;
    key = kh;
  }

  /*
   * (1) append zeros to the end of K to create a B byte string
   *     (e.g., if K is of length 20 bytes and B=64, then K will be
   *     appended with 44 zero bytes 0x00)
   * (2) XOR (bitwise exclusive-OR) the B byte string computed in step
   *     (1) with ipad
   */
  uint8_t kx[BB];
  for (size_t i = 0; i < key_len; i++) kx[i] = I_PAD ^ key[i];
  for (size_t i = key_len; i < BB; i++) kx[i] = I_PAD ^ 0;

  /*
   * (3) append the stream of data 'text' to the B byte string resulting
   *     from step (2)
   * (4) apply H to the stream generated in step (3)
   */
  __sha256_init(&ss);
  __sha256_hash(&ss, kx, BB);
  __sha256_hash(&ss, data, data_len);
  __sha256_done(&ss, out);

  /*
   * (5) XOR (bitwise exclusive-OR) the B byte string computed in
   *     step (1) with opad
   *
   * NOTE: The "kx" variable is reused.
   */
  for (size_t i = 0; i < key_len; i++) kx[i] = O_PAD ^ key[i];
  for (size_t i = key_len; i < BB; i++) kx[i] = O_PAD ^ 0;

  /*
   * (6) append the H result from step (4) to the B byte string
   *     resulting from step (5)
   * (7) apply H to the stream generated in step (6) and output
   *     the result
   */
  __sha256_init(&ss);
  __sha256_hash(&ss, kx, BB);
  __sha256_hash(&ss, out, SHA256_DIGEST_SIZE);
  __sha256_done(&ss, out);
}

static void __sha256(const void *data, size_t len, uint8_t *hash)
{
  sha256_context ctx;
  __sha256_init(&ctx);
  __sha256_hash(&ctx, data, len);
  __sha256_done(&ctx, hash);
}

static void __sha256_string(uint8_t *hash, char* hash_string, int len)
{
  for (int i = 0; i < SHA256_SIZE_BYTES; i++) {
    snprintf(hash_string + (i << 1), len - (i << 1), "%02x", hash[i]);
  }
}

static void __get_hmac_sha256_sign_key(const char* date,
                                       const char* region,
                                       const char* service,
                                       const char* secret,
                                       uint8_t hash_out[HMAC_SHA256_DIGEST_SIZE])
{
  uint8_t hash[HMAC_SHA256_DIGEST_SIZE];
  uint8_t *aws4;
  int len;

  len = strlen(secret) + 4 + 1;//"AWS4""<secret>"
  aws4 = (uint8_t *)malloc(len);
  assert(aws4);

  snprintf((char *)aws4, len, "AWS4%s", secret);

  __hmac_sha256(hash,
                (uint8_t *)date, strlen(date),
                (uint8_t *)aws4, len - 1);

  __hmac_sha256(hash_out,
                (uint8_t *)region, strlen(region),
                hash, HMAC_SHA256_DIGEST_SIZE);

  __hmac_sha256(hash,
                (uint8_t *)service, strlen(service),
                hash_out, HMAC_SHA256_DIGEST_SIZE);

  __hmac_sha256(hash_out,
                (uint8_t *)"aws4_request", 12,
                hash, HMAC_SHA256_DIGEST_SIZE);

  free(aws4);
}

static void __sign_str_sha256(uint8_t hash_out[SHA256_SIZE_BYTES],
                              const char *object_name,
                              const char *uuid, int content_len, const char *content_md5,
                              const char *host, const char *content_sha256, const char *x_amz_date, const char *token)
{
  char *sig_str = (char *)malloc(2048);
  assert(sig_str);

  snprintf(sig_str, 2048,
           "PUT\n"
           "/%s\n"
           "\n"
           "amz-sdk-invocation-id:%s\n"
           "amz-sdk-request:attempt=1\n"
           "content-length:%d\n"
           "content-md5:%s\n"
           "content-type:binary/octet-stream\n"
           "host:%s\n"
           "x-amz-content-sha256:%s\n"
           "x-amz-date:%s\n"
           "x-amz-security-token:%s\n"
           "\n"
           "amz-sdk-invocation-id;amz-sdk-request;content-length;content-md5;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token\n"
           "%s", object_name, uuid, content_len, content_md5, host, content_sha256, x_amz_date, token, content_sha256);

  __sha256(sig_str, strlen(sig_str), hash_out);
  free(sig_str);
}

static void __sign(uint8_t hash_out[HMAC_SHA256_DIGEST_SIZE],
                   uint8_t canonical_request_sha256[SHA256_SIZE_BYTES],
                   uint8_t hmac_sha256_sign_key[HMAC_SHA256_DIGEST_SIZE],
                   const char *date, const char *date_time, const char *region, const char *service)
{
  char *sig_str = (char *)malloc(512);
  assert(sig_str);

  char hash_string[(HMAC_SHA256_DIGEST_SIZE << 1) + 1];
  __sha256_string(canonical_request_sha256, hash_string, sizeof(hash_string));

  snprintf(sig_str, 512,
           "AWS4-HMAC-SHA256\n"
           "%s\n"
           "%s/%s/%s/aws4_request\n"
           "%s", date_time, date, region, service, hash_string);

  __sha256_string(hmac_sha256_sign_key, hash_string, sizeof hash_string);
  __hmac_sha256(hash_out, (uint8_t *)sig_str, strlen(sig_str), hmac_sha256_sign_key, HMAC_SHA256_DIGEST_SIZE);

  free(sig_str);
}

static void __uuid(char uuid[UUID_BUFFER_SIZE])
{
  strcpy(uuid, "A2B9EDCE-0DC1-4DF3-9CEC-14799009FEDF");//mock, donnot need actual uuid
}

static void __get_authorization(char authorization[AUTH_BUFFER_SIZE],
                                const char *id, const char *date,
                                const char *region, const char *service,
                                const char *sign_string)
{
  snprintf(authorization, AUTH_BUFFER_SIZE,
           "AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, "
           "SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;"
           "content-length;content-md5;content-type;host;"
           "x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=%s",
           id, date, region, service, sign_string);
}

static void __get_host(char host[HOST_BUFFER_SIZE], const char *bucket_name, const char *service, const char *region)
{
  if (REGION_CMP(region, CN_NORTH_1) || REGION_CMP(region, CN_NORTHWEST_1)) {
    snprintf(host, HOST_BUFFER_SIZE, "%s.%s.%s.amazonaws.com.cn", bucket_name, service, region);
  } else if (REGION_CMP(region, US_ISO_EAST_1) || REGION_CMP(region, US_ISO_WEST_1)) {
    snprintf(host, HOST_BUFFER_SIZE, "%s.%s.%s.c2s.ic.gov", bucket_name, service, region);
  } else if (REGION_CMP(region, US_ISOB_EAST_1)) {
    snprintf(host, HOST_BUFFER_SIZE, "%s.%s.%s.sc2s.sgov.gov", bucket_name, service, region);
  } else {
    snprintf(host, HOST_BUFFER_SIZE, "%s.%s.%s.amazonaws.com", bucket_name, service, region);
  }
}

static int __http_put(const char *data, int len, const char *object_name,
                      const char *id, const char *secret, const char *token,
                      const char *service, const char *region_orgin, const char *bucket_name)
{
  webclient_session *session = NULL;
  char host[HOST_BUFFER_SIZE];
  char uri[URI_BUFFER_SIZE];
  char date_time[64];
  char date[32];
  uint8_t content_md5_sum[MD5SUM_SIZE];
  char content_base64_result[MD5SUM_SIZE << 2];
  uint8_t content_sha256_hash[SHA256_SIZE_BYTES];
  char content_sha256_string[(SHA256_SIZE_BYTES << 1) + 1];
  uint8_t hmac_sha256_sign_key[HMAC_SHA256_DIGEST_SIZE];
  uint8_t canonical_request_sha256[SHA256_SIZE_BYTES];
  char uuid_str[UUID_BUFFER_SIZE];
  uint8_t sign[HMAC_SHA256_DIGEST_SIZE];
  char sign_string[(HMAC_SHA256_DIGEST_SIZE << 1) + 1];
  char authorization[AUTH_BUFFER_SIZE];
  char region[REGION_BUFFER_SIZE];

  __uuid(uuid_str);
  __compute_signer_region(region, region_orgin);
  __get_host(host, bucket_name, service, region);
  __get_x_amz_date(date_time, sizeof(date_time), date, sizeof(date));
  __md5_sum((uint8_t *)data, len, content_md5_sum);
  __base64_encode(content_md5_sum, sizeof(content_md5_sum), content_base64_result);
  __sha256(data, len, content_sha256_hash);
  __sha256_string(content_sha256_hash, content_sha256_string, sizeof(content_sha256_string));
  __get_hmac_sha256_sign_key(date, region, service, secret, hmac_sha256_sign_key);
  __sign_str_sha256(canonical_request_sha256, object_name, uuid_str, len, content_base64_result, host, content_sha256_string, date_time, token);
  __sign(sign, canonical_request_sha256, hmac_sha256_sign_key, date, date_time, region, service);
  __sha256_string(sign, sign_string, sizeof(sign_string));
  __get_authorization(authorization, id, date, region, service, sign_string);

  /* step1. create webclient session */
  session = webclient_session_create(2048, "cert", 4);
  assert(session);

  /* step2. fill http header */
  webclient_header_fields_add(session, "Host: %s\r\n", host);
  webclient_header_fields_add(session, "Accept: */*\r\n");
  webclient_header_fields_add(session, "amz-sdk-invocation-id: %s\r\n", uuid_str);
  webclient_header_fields_add(session, "amz-sdk-request: attempt=1\r\n");
  webclient_header_fields_add(session, "authorization: %s\r\n", authorization);
  webclient_header_fields_add(session, "content-length: %d\r\n", len);
  webclient_header_fields_add(session, "content-md5: %s\r\n", content_base64_result);
  webclient_header_fields_add(session, "content-type: binary/octet-stream\r\n");
  webclient_header_fields_add(session, "x-amz-content-sha256: %s\r\n", content_sha256_string);
  webclient_header_fields_add(session, "x-amz-date: %s\r\n", date_time);
  webclient_header_fields_add(session, "x-amz-security-token: %s\r\n", token);

  /* step3. URI generate */
  snprintf(uri, sizeof(uri), "http://%s/%s", host, object_name);

  /* step4. http put request */
  int err = webclient_put(session, uri, data, len);

  /* step5. destroy webclient */
  webclient_close(session);
  return err;
}

int aws_s3_push(const char *data, int len, const char *object_name,
                const char *id, const char *secret, const char *token,
                const char *service, const char *region, const char *bucket_name)
{
  int err = __http_put(data, len, object_name, id, secret, token, service, region, bucket_name);
  return err == 200 ? 0 : -1;
}