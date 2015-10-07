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
 * FILE NAME :  hash_drbg.h
 * DEPARTMENT : Security Technology Center (STC), NCSG
 * AUTHOR :     Tom Tkacik (rp0624)
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2014-01-23   T. Tkacik   Initial version
 * 0.0.2     2014-01-28   T. Tkacik   Code cleanup
 * 0.0.3     2014-04-28   T. Tkacik  Added entropy and nonce max lengths
 * ----------------------------------------------------------------------------
 * KEYWORDS : hash, sha256, random number generation
 * ----------------------------------------------------------------------------
 * PURPOSE: Provide an API to a SHA256 based Hash_DRBG
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#ifndef _HASH_DRBG_H_
#define _HASH_DRBG_H_

#include "sha256.h"

/*
 * Status returned by hash_drbg functions
 */
#define UNINSTANTIATED          0
#define INSTANTIATED            1
#define SUCCESS                 0
#define ERROR_FLAG              2
#define CATASTROPHIC_ERROR_FLAG 3

/*
 * Seed length in bits; length of V and C working registers
 */
#define SEED_LENGTH             440

/*
 * No hardware RNG, so reseed infrequently
 */
#ifndef RESEED_MAX_LONG
#define RESEED_MAX_LONG         10000
#endif

/*
 * There is a hardware RNG, so reseed always
 */
#ifndef RESEED_MAX_SHORT
#define RESEED_MAX_SHORT        1
#endif

#define PERS_STR_MAX_LEN        1000
#define ADD_INPUT_MAX_LEN       1000
#define ENTROPY_MAX_LEN         1000
#define NONCE_MAX_LEN           1000

/*
 * Maximum size of a single DRNBG data request
 */
#define REQUEST_MAX             1000000

/*
 * The context for a SHA-256 based Hash-DRBG instance
 */
typedef struct {
    uint32_t reseed_interval;  /* Number of generates before an automatic reseed */
    uint32_t reseed_count;
    uint8_t  V[SEED_LENGTH / 8];
    uint8_t  C[SEED_LENGTH / 8];
    uint8_t  comp[32];         /* implements the continous compare function */
    uint32_t reseeds;          /* number of reseeds since instantiation */
    uint32_t generates;        /* number of generate requests since instantiation */
    uint32_t state;            /* instantiated = 1; uninstantiated = 0; error = 2; */
} HASH_DRBG_CTX;

/*
 * Function declarations
 */

int is_hash_drbg_instantiated();
int is_hash_drbg_uninstantiated();
int hash_drbg_instantiate     (const uint8_t*  pers_str,
                               uint32_t  pers_str_len,
                               int       tpm_required);
int hash_drbg_instantiate_alg (const uint8_t*  pers_str, uint32_t  pers_str_len,
                               uint8_t*  entropy, uint32_t  entropy_len,
                               uint8_t*  nonce, uint32_t  nonce_len,
                               uint32_t  reseed_max);
int hash_drbg_reseed          (const uint8_t*  add_input, uint32_t  add_input_len);
int hash_drbg_reseed_alg      (const uint8_t*  add_input, uint32_t  add_input_len,
                               uint8_t*  entropy, uint32_t  entropy_len);
int hash_drbg_generate        (const uint8_t*  add_input, uint32_t  add_input_len,
                               uint8_t*  out, uint32_t  out_len,
                               uint32_t  pred_res_req);
int hash_drbg_generate_alg    (const uint8_t*  add_input, uint32_t  add_input_len,
                               uint8_t*  output, uint32_t  out_len);
int hash_drbg_uninstantiate(int verbosity);
int hash_drbg_selftest();

/*
 * Utility functions
 */
int  hash_df (const uint8_t* in,  uint32_t in_len,
              uint8_t* out, uint32_t out_len);
int  hash_gen(uint8_t* out, uint32_t out_len);
void byte_add(uint8_t* X,   uint32_t x_len,
              const uint8_t* Y,   uint32_t y_len);

/*
 * Self-test functions and declarations
 */
typedef struct hash_drbg_test {
    uint32_t count;
    const char* entropy1;
    const char* nonce;
    const char* pers_str;
    const char* add_input1;
    const char* entropy2;
    const char* add_input2;
    const char* entropy3;
    const char* expected_bytes;
} hash_drbg_test;

extern const hash_drbg_test hash_drbg[];
extern const int hash_drbg_count;

int hash_drbg_selftest();

#endif  /* _HASH_DRBG_H_ */

