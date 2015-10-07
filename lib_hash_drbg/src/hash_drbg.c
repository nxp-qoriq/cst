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
 * FILE NAME :  hash_drbg.c
 * DEPARTMENT : Security Technology Center (STC), NCSG
 * AUTHOR :     Tom Tkacik (rp0624)
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2014-01-23   T. Tkacik   Initial version
 * 0.0.2     2014-01-28   T. Tkacik   Code cleanup
 * 0.0.3     2014-02-03   T. Tkacik   Comment cleanup
 * 0.0.4     2014-04-10   T. Tkacik   Added input length checks
 * 0.0.5     2015-09-17   T. Tkacik   Code cleanup
 * ----------------------------------------------------------------------------
 * KEYWORDS : drbg, sha256
 * ----------------------------------------------------------------------------
 * PURPOSE: Provide an API to the hash_drbg function
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
#include "hash_drbg.h"
#include "entropy.h"

/*
 * Set default values for Makefile parameters
 */
#ifndef SEVERITY
#define SEVERITY 1
#endif

#ifndef VERBOSITY
#define VERBOSITY 1
#endif

#ifndef TPM_REQUIRED
#define TPM_REQUIRED 1
#endif

#ifndef PRED_RES
#define PRED_RES 0
#endif

/*
 * Implement SHA256 based Hash_DRBG specified in SP800-90A, Sec. 10.1
 *  Prediction resistance is always supported, and can be requested
 *  Personalization String and Additional Input of length <1000 bytes are supported
 *
 * If a TPM is required to provide entropy, a tpm_required input to the Instantiate function
 *  will cause that function to return an ERROR if a HW random number generator is not
 *  available.
 * If a HW random number generator is available to generate entropy at a high rate,
 *  then the reseed interval will be set to a small number (perhaps 1).
 *  Otherwise, the reseed interval will be set to a high number (perhaps 10000).
 *
 * All data is passed as arrays of bytes, and the generated random data is passed back as
 *  and array of bytes.  It is expected that the output byte arrays are large enough to
 *  hold all of the required data.
 *
 * The continous random number generator test specified in FIPS140-2, 4.9.2 is implemented,
 *  and the Hash_DRBG_Generate function will return an error
 *  if two consecutive generated blocks are the same.
 */

/*
 * Hash DRBG instance state information is only available to the functions in this file
 *  This data is not available to the consuming applications
 */
static HASH_DRBG_CTX instance = { 0, 0, {0}, {0}, {0}, 0, 0, UNINSTANTIATED };

/*
 * Is the SHA256-based hash drbg instantiated?
 *
 * Return code:
 * 0 - Not in the instantiated state
 * 1 - In the instantiated state
 */
int
is_hash_drbg_instantiated()
{
    return (instance.state == INSTANTIATED);
}

/*
 * Is the SHA256-based hash drbg uninstantiated?
 *
 * Return code:
 * 0 - Not in the uninstantiated state
 * 1 - In the uninstantiated state
 */
int
is_hash_drbg_uninstantiated()
{
    return (instance.state == UNINSTANTIATED);
}

/*
 * Instantiate a SHA256-based hash drbg instance according to
 *  the Instantiate Process defined in SP800-90A, Sec. 9.1 (pg. 27)
 *
 *  Security strength is always 256 bits
 *  Prediction resistance is always supported
 *
 * Run the SHA256_ShortMsg, SHA256_LongMsg, SHA256_Monte and Hash_DRBG CAVP tests
 * before instantiating the DRBG in production mode. If any test fails, return an ERROR
 *
 * Parameters:
 * uint8_t* pers_string  - an optional personalization string byte array
 * uint32_t pers_str_len - length of personalization string byte array
 * int      tpm_required - 0: do not require hw rng; 1: require hw rng 
 *
 * Return code:
 * 0 - SUCCESS
 * 2 - ERROR
 * 3 - CATASTROPHIC ERROR
 */
int
hash_drbg_instantiate(const uint8_t* pers_str, uint32_t pers_str_len, int tpm_required)
{
    uint8_t  entropy[64];  /* buffer to hold 512 bits of entropy */
    int      ret_code;
    uint32_t reseed_interval;

    /*
     * Check that it is not already instantiated
     */
    if (instance.state == INSTANTIATED) {
        return ERROR_FLAG;
    }

    /*
     * Perform a self-test of the SHA256 and Hash_DRBG algorithms
     *  before using them for the first time
     */
    if ((sha256_ShortMsg() + sha256_LongMsg() + sha256_Monte() + hash_drbg_selftest()) > 0) {
        if ((VERBOSITY > 0) || (SEVERITY > 0)) {
            fprintf(stderr, "Failed SHA256/Hash_DRBG CAVP testing\n");
        }
        if (SEVERITY > 0) {
            exit(1);
        }
        return ERROR_FLAG;
    } else if (VERBOSITY > 0) {
        fprintf(stderr, "SHA256/Hash_DRBG CAVP self-testing passed\n");
    }

    /*
     * Check that the personalization string is not too long
     */
    if (pers_str_len > PERS_STR_MAX_LEN) {
        return ERROR_FLAG;
    }

    /*
     * If a TPM is not activated, set the reseed interval to a large value
     * If a TPM is not activated, but is required, generate an error
     * If a TPM is activated, set the reseed interval to a small value
     */
    if (is_hw_rng_supported() == 0) {
        reseed_interval = RESEED_MAX_LONG;
        if (tpm_required == 1) {
            if ((VERBOSITY > 0) || (SEVERITY > 0)) {
                fprintf(stderr, "TPM not found, but is required. No random data will be generated\n");
            }
            if (SEVERITY > 0) {
                fprintf(stderr, "Enable the TPM in the BIOS, and activate it in the OS\n"
                                 " Then run /sbin/rngd, the RNG daemon to get the TPM "
                                 "to feed entropy to /dev/random\n"
                                 " /sbin/rngd must be running in the background before "
                                 "this program will work\n");
                exit(1);
            }
            return ERROR_FLAG;
        }
    } else {
        reseed_interval = RESEED_MAX_SHORT;
    }

    /*
     * Get enough entropy for 256-bits of entropy, plus 256-bits of nonce
     */
    ret_code = get_entropy(entropy, 64);
    if (ret_code == SUCCESS) {
        /*
         * Now that we have entropy and nonce, call the instantiate algorithm
         */
        ret_code = hash_drbg_instantiate_alg(pers_str,   pers_str_len,
                                             entropy,    32,
                                             entropy+32, 32,
                                             reseed_interval);
    }

    if ((VERBOSITY > 1) && (ret_code == SUCCESS)) {
        fprintf(stderr, "Hash_DRBG has been instantiated\n");
    }
    return ret_code;
}


/*
 * Instantiate a SHA256-based hash drbg instance according to
 *  the Instantiate Algorithm defined in SP800-90A, Sec. 10.1.1.2 (pg. 40)
 *
 *  In a test instance, the entropy, nonce and reseed interval
 *     cab be passed as inputs to the function
 *
 *  Security strength is always 256 bits
 *  Prediction resistance is always supported
 *
 * Parameters:
 * uint8_t* pers_string     - an optional personalization string byte array
 * uint32_t pers_str_len    - length of personalization string byte array
 * uint8_t* entropy         - user specified entropy byte array
 * uint32_t entropy_len     - length of entropy byte array (in bytes)
 * uint8_t* nonce           - user specified nonce byte array
 * uint32_t nonce_len       - length of nonce byte array (in bytes)
 * uint32_t reseed_interval - reseed interval
 *
 * Return code:
 * 0 - SUCCESS
 * 1 - ERROR
 * 2 - CATASTROPHIC ERROR
 */
int
hash_drbg_instantiate_alg(const uint8_t* pers_str, uint32_t pers_str_len,
                          uint8_t* entropy,  uint32_t entropy_len,
                          uint8_t* nonce,    uint32_t nonce_len,
                          uint32_t reseed_interval)
{
    uint8_t  tmp[3000];    /* a temporary byte array buffer, larger than needed */
    int      ret_code;
    uint32_t seedlen;
    uint32_t i;

    /*
     * Temporarily set the instance state to ERROR, in case we find an error
     */
    instance.state = ERROR_FLAG;

    /*
     * Initialize the reseed counter and reseed interval
     */
    instance.reseed_interval = reseed_interval;
    instance.reseed_count = 1;

    /*
     * Seedlen is simply a constant,
     *  the number of bytes in the V and C working registers
     */
    seedlen = SEED_LENGTH / 8;

    /*
     * Check that the personalization string, entropy and nonce are not too long
     */
    if ((pers_str_len > PERS_STR_MAX_LEN) ||
       (entropy_len  > ENTROPY_MAX_LEN)  ||
       (nonce_len    > NONCE_MAX_LEN)) {
        return ERROR_FLAG;
    }

    /*
     * Tmp is a byte buffer holding all of the seed material
     */
    memcpy(tmp,                       entropy,  entropy_len);
    memcpy(tmp+entropy_len,           nonce,    nonce_len);
    memcpy(tmp+entropy_len+nonce_len, pers_str, pers_str_len);

    /*
     * Calculate the initial value of V
     */
    ret_code = hash_df(tmp, entropy_len+nonce_len+pers_str_len, instance.V, seedlen);
    if (ret_code == SUCCESS) {
        /*
         * If calculating V succeeded, then also calculate the initial value of C
         */
        tmp[0] = 0x00;
        memcpy(tmp+1, instance.V, seedlen);
        ret_code = hash_df(tmp, 1 + seedlen, instance.C, seedlen);
    }

    /*
     * Clear the buffers holding secret seed material
     *  This includes the inputs entropy and nonce,
     *  so that they cannot be reused for any other purpose
     *  Personalization String is not secret, so it does not need to be cleared
     */
    for (i = 0; i < 1000; i += 1) {
        tmp[i] = 0;
    }
    for (i = 0; i < entropy_len; i += 1) {
        entropy[i] = 0;
    }
    for (i = 0; i < nonce_len; i += 1) {
        nonce[i] = 0;
    }

    /*
     * Initialize the RNG block comparison register
     */
    for (i = 0; i < 32; i += 1) {
        instance.comp[i] = 0;
    }

    /*
     * Initialize rest of the instance data structure
     */
    instance.reseeds = 0;           /* Used for gathering statistics */
    instance.generates = 0;         /* Used for gathering statistics */
    instance.state = INSTANTIATED;  /* Instance has been successfully instantiated */
    return ret_code;
}


/*
 * Reseed a SHA256-based hash drbg instance according to
 *  the Reseed Process defined in SP800-90A, Sec. 9.2 (pg. 30)
 *
 *  Security strength is always 256 bits
 *  Prediction resistance is always supported
 *
 * Parameters:
 * uint8_t* add_input      - user specified optional input byte array
 * uint32_t add_input_len  - number of bytes of additional input
 *
 * Return code:
 * 0 - SUCCESS
 * 1 - ERROR
 * 2 - CATASTROPHIC ERROR
 */
int
hash_drbg_reseed(const uint8_t* add_input, uint32_t add_input_len)
{

    uint8_t  entropy[32];  /* buffer to hold 256 bits of entropy */
    int      ret_code;

    /*
     * Do not reseed an instance that is not instantiated
     */
    if (instance.state != INSTANTIATED) {
        return ERROR_FLAG;
    }

    /*
     * Check that the additional input is not too long
     */
    if (add_input_len > ADD_INPUT_MAX_LEN) {
        return ERROR_FLAG;
    }

    /*
     * Get enough entropy for 256-bits of entropy
     */
    ret_code = get_entropy(entropy, 32);
    if (ret_code == SUCCESS) {
        /*
         * Now that we have entropy, call the reseed algorithm
         */
        ret_code = hash_drbg_reseed_alg(add_input, add_input_len,
                                        entropy,   32);
    }

    if ((VERBOSITY > 2) && (ret_code == SUCCESS)) {
        fprintf(stderr, "Hash_DRBG has been reseeded\n");
    }
    return ret_code;
}


/*
 * Reseed a SHA256-based hash drbg instance according to
 *  the Reseed Algorithm defined in SP800-90A, Sec. 10.1.1.3 (pg. 41)
 *
 *  In a test instance, the entropy can be passed as an input to the function
 *
 *  Security strength is always 256 bits
 *  Prediction resistance is always supported
 *
 * Parameters:
 * uint8_t* add_input       - user specified optional input byte array
 * uint32_t add_input_len   - number of bytes of additional input
 * uint8_t* entropy         - user specified entropy byte array
 * uint32_t entropy_len     - length of entropy byte array (in bytes)
 *
 * Return code:
 * 0 - SUCCESS
 * 1 - ERROR
 * 2 - CATASTROPHIC ERROR
 */
int
hash_drbg_reseed_alg(const uint8_t* add_input, uint32_t add_input_len,
                     uint8_t* entropy,   uint32_t entropy_len)
{

    uint8_t  tmp[3000];    /* a temporary byte array buffer, larger than needed */
    int      ret_code;
    uint32_t seedlen;
    uint32_t i;

    /*
     * Do not reseed an instance that is not instantiated
     */
    if (instance.state != INSTANTIATED) {
        return ERROR_FLAG;
    }

    /*
     * Seedlen is simply a constant,
     *  the number of bytes in the V and C working registers
     */
    seedlen = SEED_LENGTH / 8;

    /*
     * Check that the additional input and entropy are not too long
     */
    if ((add_input_len > ADD_INPUT_MAX_LEN) ||
       (entropy_len   > ENTROPY_MAX_LEN)) {
        return ERROR_FLAG;
    }

    /*
     * Calculate new value of V, using tmp to hold the seed material
     */
    tmp[0] = 0x01;
    memcpy(tmp+1,                     instance.V, seedlen);
    memcpy(tmp+1+seedlen,             entropy,    entropy_len);
    memcpy(tmp+1+seedlen+entropy_len, add_input,  add_input_len);
    ret_code = hash_df(tmp, 1 + seedlen+entropy_len+add_input_len, instance.V, seedlen);

    if (ret_code == SUCCESS) {
        /*
         * If calculating V succeeded, then also calculate the new value of C
         */
        tmp[0] = 0x00;
        memcpy(tmp+1, instance.V, seedlen);
        ret_code = hash_df(tmp, 1 + seedlen, instance.C, seedlen);
    }

    /*
     * Reset the reseed counter, and update the reseeds statistics counter
     */
    instance.reseed_count = 1;
    instance.reseeds += 1;

    /*
     * Clear the buffers holding secret reseed material
     *  Additional Input is not secret, and does not need to be cleared
     */
    for (i = 0; i < 1000; i += 1) {
        tmp[i] = 0;
    }
    for (i = 0; i < entropy_len; i += 1) {
        entropy[i] = 0;
    }
    return ret_code;
}


/*
 * Generate Random Data using a SHA256-based hash drbg instance according to
 *  the Generate Process defined in SP800-90A, Sec. 9.3 (pg. 32)
 *
 *  Security strength is always 256 bits
 *  Prediction resistance is always supported
 *
 * Parameters:
 * uint8_t* add_input     - user specified optional input byte array
 * uint32_t add_input_len - number of bytes of additional input
 * uint8_t* out           - user specified output byte array
 * uint32_t out_len       - number of bytes to store in output byte array
 * uint32_t pred_res_req  - request prediction resistance; reseed immediately if 1
 *
 * Return code:
 * 0 - SUCCESS
 * 1 - ERROR
 * 2 - CATASTROPHIC ERROR
 */
int
hash_drbg_generate(const uint8_t* add_input, uint32_t add_input_len,
                   uint8_t* out,       uint32_t out_len,
                   uint32_t pred_res_req)
{
    int      ret_code;

    /*
     * Do not generate random data from an instance that is not instantiated
     */
    if (instance.state != INSTANTIATED) {
        return ERROR_FLAG;
    }

    /*
     * Check that not too much data is requested in a single request
     */
    if (out_len > REQUEST_MAX) {
        return ERROR_FLAG;
    }

    /*
     * Check that the Additional Input is not too long
     */
    if (add_input_len > ADD_INPUT_MAX_LEN) {
        return ERROR_FLAG;
    }

    /*
     * A reseed may be required, before generating random data,
     *  if the the number of generate requests has hit the reseed interval
     *  since the last reseed, or if Prediction Resistance has been requested
     *
     * Note that SP800-90A, Sec. 9.3 appears to assume that hash_drbg_generate()
     *  does not have access to the internal state of the instance, and must call
     *  hash_drbg_generate_alg() to determine if a reseed is necessary.
     *  This makes the code somewhat convoluted.
     * Here, we simply check the instance reseed_count directly.
     *  This is much simpler, but accomplishes the same function as specified.
     */
    if ((instance.reseed_count > instance.reseed_interval) || (pred_res_req == 1)) {
        ret_code = hash_drbg_reseed(add_input, add_input_len);
        if(ret_code != SUCCESS) {
            return ret_code;
        }

        /*
         * Additional Input is used for either reseed or generate, but not both
         *  Any additional input was used during reseed should not be also used
         *  during random data generation
         */
        add_input_len = 0;
    }

    /*
     * Finally, generate the requested random data bytes
     */
    ret_code = hash_drbg_generate_alg(add_input, add_input_len, out, out_len);
    return ret_code;
}


/*
 * Generate Random Data using a SHA256-based hash drbg instance according to
 *  the Generate Algorithm defined in SP800-90A, Sec. 10.1.1.4 (pg. 42)
 *
 *  Security strength is always 256 bits
 *  Prediction resistance is always supported
 *
 * Parameters:
 * uint8_t* add_input     - user specified optional input byte array
 * uint32_t add_input_len - number of bytes of additional input
 * uint8_t* out           - user specified output byte array
 * uint32_t out_len       - number of bytes to store in output byte array
 *
 * Return code:
 * 0 - SUCCESS
 * 1 - ERROR
 * 2 - CATASTROPHIC ERROR
 */
int
hash_drbg_generate_alg(const uint8_t* add_input, uint32_t add_input_len,
                       uint8_t* out,       uint32_t out_len)
{

    uint8_t  tmp[1000]; /* A temporary byte array buffer, larger than needed */
    int      ret_code;
    uint32_t seedlen;
    uint8_t  w[32];     /* Used when there is additional input */
    uint8_t  H[32];     /* Used to update V */
    uint8_t  R[4];      /* Used to update V, value of reseed_count as a byte array */

    /*
     * Seedlen is simply a constant,
     *  the number of bytes in the V and C working registers
     */
    seedlen = SEED_LENGTH / 8;

    /*
     * Do not generate random data from an instance that is not instantiated
     */
    if (instance.state != INSTANTIATED) {
        return ERROR_FLAG;
    }

    /*
     * Check that not too much data is requested in a single request
     */
    if (out_len > REQUEST_MAX) {
        return ERROR_FLAG;
    }

    /*
     * Check that the Additional Input is not too long
     */
    if (add_input_len > ADD_INPUT_MAX_LEN) {
        return ERROR_FLAG;
    }

    /*
     * If there is Additional Input, it gets processed first to generate a new V
     *   V = [ V + sha256( 0x02 || V || add_input ) ] mod 2^SEED_LENGTH
     */
    if (add_input_len > 0) {
        /*
         * Calculate new value of V
         */
        tmp[0] = 0x02;
        memcpy(tmp+1,         instance.V, seedlen);
        memcpy(tmp+1+seedlen, add_input,  add_input_len);
        sha256(tmp, 1+seedlen+add_input_len, w);

        /*
         * Add w to V mod 2^SEED_LENGTH
         */
        byte_add(instance.V, seedlen, w, 32);
    }

    /*
     * Generate the requested random data
     */
    ret_code = hash_gen(out, out_len);
    if (ret_code == SUCCESS) {
        /*
         * If generating the requested random data succeeded,
         *  then update the DRBG internal working state V
         *  C is not updated during the generate function
         *
         * H = sha256( 0x03 || V )
         * V = (V + C + H + reseed_counter) mod 2^SEED_LENGTH
         */

        /*
         * The reseed_count is used as part of the seed material for generating the new V
         *  so put the value of reseed_count (which is 32-bits) into a four byte array
         *  in big endian format
         */
        R[0] = (instance.reseed_count >> 24) & 0xff;
        R[1] = (instance.reseed_count >> 16) & 0xff;
        R[2] = (instance.reseed_count >>  8) & 0xff;
        R[3] =  instance.reseed_count        & 0xff;

        /*
         * Calculate H
         */
        tmp[0] = 0x03;
        memcpy(tmp+1, instance.V, seedlen);
        sha256(tmp, 1+seedlen, H);

        /*
         * Calculate new V
         */
        byte_add(instance.V, seedlen, instance.C, seedlen);
        byte_add(instance.V, seedlen, H, 32);
        byte_add(instance.V, seedlen, R, 4);

        instance.reseed_count += 1;
    }

    instance.generates += 1;
    return ret_code;
}


/*
 * Uninstantiate the SHA256-based Hash DRBG instance according to
 *  the Uninstantiate Process defined in SP800-90A, Sec. 9.4 (pg. 36)
 *
 * Parameters:
 * int verbosity - if 1, then print hash_drbg statistics
 *
 * Return code:
 * 0 - SUCCESS
 * 1 - ERROR: Already not instantiated
 */
int
hash_drbg_uninstantiate(int verbosity)
{
    int i;

    /*
     * Do no Uninstantiate an instance that is not instantiated
     */
    if (instance.state == UNINSTANTIATED) {
        return ERROR_FLAG;
    }

    /*
     * Clear the working state for the instance, as it is secret seed material
     */
    for (i = 0; i < (SEED_LENGTH / 8); i += 1) {
        instance.V[i] = 0;
        instance.C[i] = 0;
    }
    instance.state = UNINSTANTIATED;

    if (verbosity > 0) {
        fprintf(stderr, "Hash_DRBG has been uninstantiated\n"
                        " There have been %u reseeds, and %u generates since instantiation\n"
                        " The reseed interval was set to %u\n",
                        instance.reseeds, instance.generates, instance.reseed_interval);
    }
    return SUCCESS;
}

/*
 * Generate bits from the Hash_df function
 *  SP800-90A, Sec. 10.4.1 (pg. 67)
 *
 *  Always returns full bytes
 *
 * Parameters:
 * uint8_t* in        - byte array to hash to generate the requested bits
 * uint32_t in_len    - length of input byte array
 * uint8_t* out       - must be large enough to hold all returned bytes
 * uint32_t out_len   - length of output byte array, out_len <= 255 * 32 (<=8160) bytes
 *
 * Return code:
 * 0 - SUCCESS
 * 1 - ERROR: requests too many bytes
 */
int
hash_df(const uint8_t* in,  uint32_t in_len,
        uint8_t* out, uint32_t out_len)
{

    uint8_t counter;
    int len;
    uint8_t num_bytes[4];    /* out_len as a byte array */
    uint8_t hash_bytes[32];  /* temporary buffer to store hash output */

    /*
     * Check that no too many bytes are requested
     *  Only 255 calls to sha256() are allowed, according to the spec
     */
    if (out_len > (255*32)) {
        return ERROR_FLAG;
    }

    /*
     * Round up the number of hash calls we need to make
     */
    len = (out_len + 31) / 32;

    /*
     * Number of bytes requested is used as input to the hash function,
     *  so it needs to be converted from a 32-bit number to a four byte array,
     *  in big endian format
     */
    num_bytes[0] = ((out_len*8) >> 24) & 0xff;
    num_bytes[1] = ((out_len*8) >> 16) & 0xff;
    num_bytes[2] = ((out_len*8) >>  8) & 0xff;
    num_bytes[3] =  (out_len*8)        & 0xff;

    /*
     * Generate the requested bytes
     */
    for (counter = 1; (counter <= len) && (counter != 0); counter += 1) {
        SHA256_CTX context;
        /*
         * Hash the data
         */
        sha256_init(&context);
        sha256_update(&context, &counter,  1);
        sha256_update(&context, num_bytes, 4);
        sha256_update(&context, in,        in_len);
        sha256_finalize(&context, hash_bytes);

        /*
         * Copy the hash result to the output buffer
         *  but make sure that the last block only copies
         *  the amount needed, so that we do not overflow the buffer
         */
        if ((counter != len) || ((out_len % 32) == 0)) {
            memcpy(out, hash_bytes, 32);
            out += 32;
        } else {
            memcpy(out, hash_bytes, out_len % 32);
        }
    }

    return SUCCESS;
}


/*
 * Generate bits from the Hash_gen function
 *  Hash instance.V, and increment until enough data is produced.
 *  SP800-90A, Sec. 10.1.1.4 (pg. 43)
 *
 * Parameters:
 * uint8_t* out       - must be large enough to hold all returned bytes
 * uint32_t out_len   - length of output byte array, out_len <= 255 * 32 (<=8160) bytes
 *
 * Return code:
 * 0 - SUCCESS
 * 1 - ERROR: requests too many bytes
 */
int
hash_gen(uint8_t* out, uint32_t out_len)
{

    uint32_t counter;
    uint32_t len;
    uint8_t  hash_bytes[32];  /* Temporary buffer to store hash output */
    int      seedlen;
    uint8_t  data[SEED_LENGTH / 8];
    uint8_t  one = 1;         /* Used to increment data */

    /*
     * Check that no too many bytes are requested
     */
    if (out_len > REQUEST_MAX) {
        return ERROR_FLAG;
    }

    /*
     * Seedlen is simply a constant,
     *  the number of bytes in the V and C working registers
     */
    seedlen = SEED_LENGTH / 8;

    /*
     * Data is a local copy of V, so that it can be incremented
     *  without modifying the actual value of V
     */
    memcpy(data, instance.V, seedlen);

    /*
     * Round up the number of hash calls we need to make
     */
    len = (out_len + 31) / 32;

    /*
     * Generate the requested bytes
     */
    for (counter = 1; counter <= len; counter += 1) {
        sha256(data, seedlen, hash_bytes );

        /*
         * Implement the Continous Random Number Test from FIPS140-2 sec 4.9.2
         *  Compare this generated block with the previous block
         */
        if (memcmp(hash_bytes, instance.comp, 32) == 0) {
            if ((VERBOSITY > 0) || (SEVERITY > 0)) {
                fprintf(stderr, "Continuous RNG test failed\n");
            }
            if (SEVERITY > 0) {
                exit(1);
            }
            return ERROR_FLAG;
        } else {
            /*
             * Make the new value the old value
             */
            memcpy(instance.comp, hash_bytes, 32);
        }

        /*
         * Copy the hash output to the output buffer,
         *  making sure not to overflow the output buffer
         *  after the last hash operation
         */
        if ((counter != len) || ((out_len % 32) == 0)) {
            memcpy(out, hash_bytes, 32);
            out += 32;
        } else {
            memcpy(out, hash_bytes, out_len % 32);
        }

        /*
         * Increment data = data + 1 mod 2^seedlen
         */
        byte_add(data, seedlen, &one, 1);
    }

    return SUCCESS;
}


/*
 * Add two byte arrays, both in big endian format
 *  X = (X + Y) mod 2^(x_len*8)
 *  X may be larger than Y
 *  Y may be a single byte, (used to increment X)
 *  If Y is longer than X, the upper bytes of Y will be ignored
 *
 * Parameters:
 * uint8_t* X       - X byte array of length x_len
 * uint32_t x_len   - Length of X byte array
 * uint8_t* Y       - Y byte array of length y_len
 * uint32_t y_len   - Length of Y byte array
 */
void
byte_add(uint8_t* X, uint32_t x_len, const uint8_t* Y, uint32_t y_len)
{
    int i, y_offset;
    int c;
    int sum;

    /*
     * Because the numbers in the byte arrays are big endian
     *  if they are not the same length, a different byte from each array
     *  will be added.  Y_offset is the delta between the two
     */
    y_offset = x_len - y_len;

    /*
     * C is the carry from one byte add to the next
     */
    c = 0;

    /*
     * Add each corresponding byte of X and Y,
     *  taking care of overflow (a carry into the next add),
     *  and when the Y array runs out of bytes to add
     */
    for (i = (x_len-1); i >= 0; i -= 1) {
        if ((i - y_offset) >= 0) {
            sum = X[i] + Y[i - y_offset] + c;
        } else {
            sum = X[i] + c;
        }
        if(sum > 255) {
            c = 1;
            sum &= 0xff;
        } else {
            c = 0;
        }

        /*
         * Copy the sum back to the input X byte array
         */
        X[i] = sum;
    }
}




