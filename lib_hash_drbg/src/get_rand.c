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
 * FILE NAME :  get_rand.c
 * DEPARTMENT : Security Technology Center (STC), DN
 * AUTHOR :     Tom Tkacik (rp0624)
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2015-04-29   T. Tkacik   Initial version
 * 0.0.2     2015-09-17   T. Tkacik   Code cleanup
 * ----------------------------------------------------------------------------
 * KEYWORDS : RNG
 * ----------------------------------------------------------------------------
 * PURPOSE: API to get random bytes from the DRBG
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "hash_drbg.h"
#include "get_rand.h"

/*
 * Set default values for Makefile parameters
 */
#ifndef SEVERITY
#define SEVERITY 0
#endif

#ifndef VERBOSITY
#define VERBOSITY 0
#endif

#ifndef TPM_REQUIRED
#define TPM_REQUIRED 0
#endif

#ifndef PRED_RES
#define PRED_RES 0
#endif

/*
 * Is a TPM required to generate entropy?
 *  For some customers, this will be a manufacturing requirement
 *  In this case, no TPM is considered as a catastrophic error,
 *  and no random data will be generated
 *
 * For test purposes, and for not critical customers, no TPM will
 *  simply cause reseeds to occur less frequently,
 *  but random data may still be generated
 */
static int tpm_required = TPM_REQUIRED;

/*
 * pre_res_req = 0;  prediction resistance is not require
 * pre_res_req = 1;  prediction resistance is required, reseed before every request
 */
static int pre_res_req  = PRED_RES;   /* prediction resistance request not required */


/*
 * Generate random bits from the hash_drbg
 *
 * Parameters:
 * uint8_t* rand_bits - 256 byte buffer to hold the random code word
 *                        One bit per uint8_t
 * int bit_len        - number of random bits to generate
 *
 * Return code:
 *  0 - All is well
 * >0 - Error occurred somewhere
 */
int
get_rand_bits(uint8_t* bits, int bit_len)
{
    int ret_code;
    int byte_len;

    /*
     * Get random data as a byte array
     */
    byte_len = (bit_len+7) / 8;   /* round up to next byte */
    ret_code = get_rand_bytes(bits, byte_len);

    if (ret_code == SUCCESS) {
        /*
         * In place convert the byte data to bits
         */
        bytes_to_bits(bits, bits, bit_len);
    }
    return ret_code;
}


/*
 * Generate random bytes, and stuff them into the bytes buffer
 *
 * If the Hash_DRBG has not already been instantiated,
 *  it will be instantiated before data is generated.
 *
 * Parameters:
 * uint8_t* bytes  - byte buffer large enough to hold the requested random date
 * int    byte_len - number of random bytes to generate
 *
 * Return code:
 *  0 - All is well
 * >0 - Error occurred somewhere
 */
int
get_rand_bytes(uint8_t* bytes, int byte_len)
{
    int ret_code;

    /*
     * If this is the first time this routine is called,
     *  then the hash_drbg will not already be instantiated.
     * Therefore, before generating data, instantiate the hash_drbg
     */
    if (is_hash_drbg_uninstantiated()) {
        if (VERBOSITY > 1) {
            fprintf(stderr, "Instantiating the Hash_DRBG\n");
        }

        /*
         * Instantiate the hash_drbg
         */
        ret_code = hash_drbg_instantiate((uint8_t*)"OPTMK_STRING", 12, tpm_required);
        if (ret_code != SUCCESS) {
            if(VERBOSITY > 0) {
                fprintf(stderr, "Hash_DRBG Instantiate failed - Cannot generate OTPMK keys\n");
            }
            return ret_code;
        }
    }

    /*
     * If the Hash_DRBG is still not instantiated, something must have gone wrong,
     *  it must be in the error state, and we will not generate any random data
     */
    if (!is_hash_drbg_instantiated()) {
            if ((VERBOSITY > 0) || (SEVERITY > 0)) {
                fprintf(stderr, "Hash DRBG is in an Error state, and cannot be used\n");
            }
            if (SEVERITY > 0) {
                exit(1);
            }
        return ERROR_FLAG;
    }

    /*
     * Generate a random 256-bit value, as 32 bytes
     */
    ret_code = hash_drbg_generate(0, 0, bytes, byte_len, pre_res_req);
    if (ret_code != SUCCESS) {
        if ((VERBOSITY > 0) || (SEVERITY > 0)) {
            fprintf(stderr, "Hash_DRBG Generate failed\n");
        }
        if (SEVERITY > 0) {
            exit(1);
        }
        return ret_code;
    }

    return ret_code;
}

/*
 * Convert bytes of data to bits
 *
 * For this conversion, the input bytes are treated as an array,
 *  with byte 0 containing bits 7 - 0.
 * The input buffer can also be the output buffer
 *
 * Parameters:
 * uint8_t* otpmk       - byte array holding the input value
 * uint8_t* otpmk_bits  - buffer to hold the output
 *                        One bit per uint8_t
 * int      bit_len     - number of bits to convert
 */
void
bytes_to_bits(uint8_t* bytes, uint8_t* bits, int bit_len)
{
    /*
     * Copy the byte array to the output bit array
     *  one bit at a time, starting at the end
     *  to allow overwriting the input buffer
     */
    int byte_len, excess;
    int i, j;

    byte_len = (bit_len+7) / 8;   /* round up to next byte */
    excess = bit_len - ((byte_len-1) * 8); /* number of bits in the last byte */

    for (i = byte_len - 1; i >= 0; i -= 1) {
       for (j = excess; j >= 0; j -= 1) {
           bits[(i*8)+j] = ((bytes[i] >> j) & 0x1);
        }
        excess = 8;
    }
}
