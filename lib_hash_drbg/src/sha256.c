/* Copyright (c) 2015, Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* +FHDR-----------------------------------------------------------------------
 * ----------------------------------------------------------------------------
 * AUTHOR :     Based on Brad Conte's public domain SHA256 code
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2014-01-23   T. Tkacik   Initial version
 * 0.0.2     2014-01-28   T. Tkacik   Code cleanup
 * 0.0.3     2014-01-28   T. Tkacik   Comment cleanup
 * ----------------------------------------------------------------------------
 * KEYWORDS : hash, sha256
 * ----------------------------------------------------------------------------
 * PURPOSE: Provide an API to the sha256 hash function
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "sha256.h"

/*
 * Maximum size of a hex string
 *  Most of the code expects data in big endian byte arrays
 *  Most of the test data is in the form of hex strings
 *  As such, local buffers are used to convert the hex strings to byte arrays,
 *   and those local buffers will typically be MAX_SIZE bytes long.
 */
#define MAX_SIZE  100000

/*
 * SHA256 Functions -- FIPS180-4, Sec. 4.2.1 (pg. 10)
 */
#define ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define SHR(a,b)  ((a) >> (b))

#define CH(x,y,z)     (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)        (ROTR(x, 2)  ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)        (ROTR(x, 6)  ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x)       (ROTR(x, 7)  ^ ROTR(x, 18) ^ SHR(x, 3))
#define SIG1(x)       (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/*
 * SHA256 Constants -- FIPS180-4 Sec. 4.2.2 (pg. 11)
 */
static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};


/*
 * A SHA256 hash of data can be calculated in two ways
 * 1) Calling the routines sha256_init(), sha256_update() (or sha_256_update_hex(),
 *    and sha256_finalize().  In this case, sha256_init() must be called first
 *    to initialize the hash context, followed by one or more calls to
 *    sha256_update() (or sha256_update_hex()) to hash the actual data,
 *    followed by a call to sha256_finalize() to convert the hash state to output;
 * 2) Calling sha256() (or sha256_hex()) with all of the data. In this case,
 *    all of the data is given in a single call, and the result will be returned.
 *
 * Sha256() and sha256_update() take the data as an unsigned byte array, in big endian
 *  format.
 * The returned hash value is also an unsigned byte array.
 *
 * Sha256_hex() and sha256_update_hex() take the data as a string of hex characters.
 *  There must be two hex characters per byte, and hence a leading '0' is required if
 *  the first byte is less then 16.
 * The returned hash value will be a character string of hex characters,
 *  and will include a trailing '\0'.
 * Therefore, the output buffer will need to be 65 bytes long.
 * Sha256_update_hex() has an input length restriction.
 *  If more than MAX_SIZE bytes of data are given to the routine, an error will result
 *  Break the data into multiple chuncks, each less than MAX_SIZE bytes in length.
 */

/*
 * Initialize the sha256 context buffer
 *  FIPS180-4, Sec. 5.3.3 (pg. 15)
 *
 * Parameters:
 * SHA256_CTX* context - structure holding the sha256 context
 */
void
sha256_init(SHA256_CTX* context)
{
    context->datalen = 0;
    context->bitlen  = 0;
    context->H[0] = 0x6a09e667;
    context->H[1] = 0xbb67ae85;
    context->H[2] = 0x3c6ef372;
    context->H[3] = 0xa54ff53a;
    context->H[4] = 0x510e527f;
    context->H[5] = 0x9b05688c;
    context->H[6] = 0x1f83d9ab;
    context->H[7] = 0x5be0cd19;
}


/*
 * Transform the sha256 hash state (H) using the 64 bytes in the data array
 *  FIPS180-4, Sec. 6.2.2 (pg. 22)
 *
 * Parameters:
 * SHA256_CTX* context - structure holding the sha256 context
 */
void
sha256_transform(SHA256_CTX* context)
{
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t i;
    uint32_t T1, T2, W[64];

    /*
     * Prepare the message schedule
     *  First reading in the data
     */
    for (i = 0; i < 16; i += 1) {
        W[i] = (context->data[4*i]     << 24) | (context->data[4*i + 1] << 16) |
               (context->data[4*i + 2] <<  8) | (context->data[4*i + 3]);
    }
    /*
     * Then mixing the existing data
     */
    for (i = 16; i < 64; i += 1) {
        W[i] = SIG1(W[i - 2]) + W[i - 7] + SIG0(W[i - 15]) + W[i - 16];
    }

    /*
     * Initialize the eight working variables
     */
    a = context->H[0];
    b = context->H[1];
    c = context->H[2];
    d = context->H[3];
    e = context->H[4];
    f = context->H[5];
    g = context->H[6];
    h = context->H[7];

    /*
     * Loop 64 times, mixing the working variables
     */
    for (i = 0; i < 64; i += 1) {
        T1 = h + EP1(e) + CH(e,f,g) + k[i] + W[i];
        T2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    /*
     * Finally, add the working variables back to the context
     */
    context->H[0] += a;
    context->H[1] += b;
    context->H[2] += c;
    context->H[3] += d;
    context->H[4] += e;
    context->H[5] += f;
    context->H[6] += g;
    context->H[7] += h;
}


/*
 * Update the sha256 context with the input data as a byte array
 *  Read data one byte at a time, and store it into an internal buffer
 *  in the Context.  When 64 bytes (512 bits) are stored, call sha256_transform
 *  to consume the bytes, and clear the buffer. The buffer may be left partially
 *  full when the last of the input data has been consumed.
 *  Update the message length as input data is read.
 *
 * Parameters:
 * SHA256_CTX* context - structure holding the sha256 context
 * uint8_t* data       - input data buffer to be hashed
 * uint32_t length     - size of input data buffer
 */
void
sha256_update(SHA256_CTX* context, const uint8_t* data, uint32_t length)
{
    uint32_t i;

    /*
     * Copy the input data to the internal context buffer
     */
    for (i = 0; i < length; i += 1) {
        context->data[context->datalen++] = data[i];
        /*
         * Update the bit length, for each byte processed
         */
        context->bitlen += 8;
        /*
         * And when the context buffer is full, call sha256_transform
         */
        if (context->datalen == 64) {
            sha256_transform(context);
            context->datalen = 0;
        }
    }
}


/*
 * Update the sha256 context with the input data as a hex string
 *  Convert the input hex string to a byte array and call sha256_update.
 *
 *  A maximum of MAX_SIZE bytes (2*MAX_SIZE hex characters) may be hashed with a single call
 *  although multiples calls may be made
 *
 *  Note that while sha256_update() always completes its operation, and has no return value
 *   while sha256_update_hex() may return with an error (if the input is too large).
 *
 * Parameters:
 * SHA256_CTX* context - structure holding the sha256 context
 * uint8_t* hex        - input hex data buffer to be hashed
 * uint32_t length     - size of input data buffer, which may be longer than the hex string inside
 *
 * Return code:
 * -1 - hexstring is too long
 *  1 - Ok
 */
int
sha256_update_hex(SHA256_CTX* context, const char* hex, uint32_t length)
{

    uint8_t data[MAX_SIZE];  /* at most 100,000 bytes mat be contained in the hex buffer */
    int    datalen;  /* amount of data in hex string */

    /*
     * Convert input hex string to a byte array
     *  If the input hex string is too long, return an error
     */
    datalen = hex_to_bytes(hex, length, data, MAX_SIZE);
    if (datalen == -1) {
        return -1;
    }
    sha256_update(context, data, datalen);

    return 1;
}


/*
 * Finalize the sha256 context and return the hash result
 *  FIPS180-4, Sec. 5.1.1 (pg. 13)
 *
 * Parameters:
 * SHA256_CTX* context - structure holding the sha256 context
 * uint8_t* hash_bytes - 32 byte output buffer to hold the hash result
 */
void
sha256_finalize(SHA256_CTX* context, uint8_t* hash_bytes)
{
    uint32_t i;

    /*
     * Pad the remaining data in the context data buffer
     *  and call sha256_transform on the padded data
     * The pad is a '1' bit, followed by enough '0' bits
     *  to fill out to byte 56, (the last eight bytes
     *  will be the length of the messsage).
     *
     * If the buffer is currently too full to contain the padding
     *  plus message length, two calls to sha256_transform will be required
     */

    context->data[context->datalen++] = 0x80;
    while (context->datalen != 56) {
        if (context->datalen == 64) {
            sha256_transform(context);
            context->datalen = 0;
        }
        context->data[context->datalen++] = 0x00;
    }

    /*
     * Add the bit length to the message
     */
    for (i = 0; i < 8; i += 1) {
        context->data[56+i] =  (context->bitlen >> (56-i*8)) & 0xff;
    }

    /*
     * Perform the last transform on the padded data
     */
    sha256_transform(context);

    /*
     * Copy the eight hash context registers to hash_output
     */
    for (i = 0; i < 8; i += 1) {
        *hash_bytes++ = (context->H[i] >> 24) & 0xff;
        *hash_bytes++ = (context->H[i] >> 16) & 0xff;
        *hash_bytes++ = (context->H[i] >>  8) & 0xff;
        *hash_bytes++ =  context->H[i]        & 0xff;
    }
}


/*
 * Hash a byte array using SHA256, as a single function call
 *
 * Parameters:
 * uint8_t* data        - byte array holding the message
 * uint32_t length      - length of input byte array
 * uint8_t* hash_output - 32 byte output buffer to hold the hash result
 */
void
sha256(const uint8_t* in, uint32_t in_len, uint8_t* hash_bytes)
{
    SHA256_CTX context;

    sha256_init    (&context);
    sha256_update  (&context, in, in_len);
    sha256_finalize(&context, hash_bytes);
}


/*
 * Hash a hex string using SHA256, as a single function call
 *  Similar to sha256(), but takes a hex string as input rather than a byte array
 *
 *  Note that while sha256() always completes its operation, and has no return value
 *   while sha256_hex() may return with an error (if the input is too large).
 *
 * Parameters:
 * uint8_t* hex      - input hex data buffer to be hashed
 * uint32_t length   - size of input data buffer, which may be longer than the hex string inside
 * char* hash_string - 65 byte output buffer to hold the hash result in hex
 *
 * Return code:
 * -1 - hexstring is too long
 *  1 - Ok
 */
int
sha256_hex(const char* hex, uint32_t length, char* hash_string)
{
    SHA256_CTX context;
    uint8_t    hash_bytes[32];
    int        result;

    sha256_init(&context);

    /*
     * Too much input data will result in an error
     */
    result = sha256_update_hex(&context, hex, length);
    if (result != -1) {
        sha256_finalize(&context, hash_bytes);
    }
    bytes_to_hex (hash_bytes, 32, hash_string, 65);
    return result;
}


/*
 * Convert a hex string to a byte array
 *  Read two hex characters, convert them to a single byte and copy the value
 *   to the output buffer.
 *  If the hex string is an odd number of hex characters long, or would result in
 *   copying more to the output buffer than there is room, return an error.
 *
 * Parameters:
 * char* in        - hex string with two hex characters per ascii character
 * uint32_t inlen  - maximum length of input hex string, at most inlen characters will be used
 * uint8_t* out    - byte array without terminating '\0' ('\0' is a valid byte within the array)
 * uint32_t outlen - length of output byte array
 *
 * Return code:
 * -1  - Error
 * >=0 - length of output byte array
 */
int
hex_to_bytes(const char* in, uint32_t inlen, uint8_t* out, uint32_t outlen)
{

    uint32_t h_len;  /* length of hex string */
    uint32_t i;      /* index into the input buffer */
    uint8_t  c1, c2; /* two hex characters which will make up one byte */

    /*
     * Find the actual length of the input string
     */
    h_len = strnlen(in, inlen);
    if (((h_len & 0x01) == 1) || ((inlen < h_len) && (inlen & 0x01) == 1)) {
        /*
         * There are an odd number of hex characters,
         *  which do not fully fill a byte array, and is not supported
         */
        return -1;
    }
    if ((h_len / 2) > outlen) {
        /*
         * There are more input characters than there is room for in the output buffer
         */
        return -1;
    }

    /*
     * Copy the hex input characters to the output buffer
     */
    for (i = 0; ((i < h_len) && (i < inlen)); i += 2) {
        /*
         * C1 is the first hex character of a byte
         */
        c1 = in[i];
        if (!isxdigit(c1)) {
            return -1;
        }
        if (isdigit(c1)) {
            c1 -= '0';
        } else {
            c1 = tolower(c1) - 'a' + 10;
        }

        /* C2 is the second hex character of a byte
         */
        c2 = in[i+1];
        if (!isxdigit(c2)) {
            return -1;
        }
        if (isdigit(c2)) {
            c2 -= '0';
        } else {
            c2 = tolower(c2) - 'a' + 10;
        }

        /*
         * Combine c1 and c2 to form a full byte
         */
        *out++ = (c1 << 4) + c2;
    }

    return (h_len / 2); /* All is well */
}


/*
 * Convert a byte array to a hex string
 *  Read each byte, and convert it to two hex characters.
 *  Copy the hex characters to the output buffer.
 *  Add a trailing '\0' to the buffer, to make it a valide C string.
 *
 *  If the output buffer is not long enough to hold the entire string,
 *   return an error.
 *
 * Parameters:
 * uint8_t* in     - byte array
 * uint32_t inlen  - length of byte array
 * uint8_t* out    - hex string with terminating '\0'
 * uint32_t outlen - length of output string buffer
 *
 * Return code:
 * 0 - Error if output buffer is not at least 2*x+1 as long as the input byte array
 * 1 - Ok
 */
int
bytes_to_hex(const uint8_t* in, uint32_t inlen, char* out, uint32_t outlen)
{
    uint32_t i;
    const char hex[17] = "0123456789abcdef";

    /*
     * Verify output buffer is long enough to hold all of the data
     */
    if ((2*inlen+1) > outlen) {
        return 0;
    }

    /*
     * Convert each byte into two hex characters,
     *  and append them to the output string
     */
    for (i = 0; i < inlen; i += 1) {
        *out++ = hex[in[i] >> 4];
        *out++ = hex[in[i] & 0x0f];
    }

    /*
     * Tack on a '\0' at the end to make it a valid C string
     */
    *out = '\0';

    return 1;  /* All is well */
}
