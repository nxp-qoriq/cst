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
 * FILE NAME :  hash_drbg_selftest.c
 * DEPARTMENT : Security Technology Center (STC), NCSG
 * AUTHOR :     Tom Tkacik (rp0624)
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2014-01-23   T. Tkacik   Initial version
 * 0.0.2     2014-01-28   T. Tkacik   Code cleanup
 * 0.0.3     2014-02-04   T. Tkacik   Put CAVP test data into a separate file
 * 0.0.4     2015-09-17   T. Tkacik   Code cleanup
 * ----------------------------------------------------------------------------
 * KEYWORDS : hash, drbg, sha256, self-test
 * ----------------------------------------------------------------------------
 * PURPOSE: Run a SHA256 Hash DRBG CAVP test
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "hash_drbg.h"


/*
 * Maximum size of a local hex string buffer
 */
#define MAX_SIZE  1000

/*
 * Set default values for Makefile parameters
 */
#ifndef VERBOSITY
#define VERBOSITY 1
#endif


/*
 * Perform a SHA256 Hash DRBG CAVP test
 *
 * Return code:
 *  0 - All is well
 * >0 - Number of failures
 */
int
hash_drbg_selftest()
{
    int      i;
    int      fails;
    uint8_t  entropy[MAX_SIZE];    /* at most MAX_SIZE bytes may be contained in each hex buffer */
    uint8_t  nonce[MAX_SIZE];
    uint8_t  pers_str[MAX_SIZE];
    uint8_t  add_input[MAX_SIZE];
    uint8_t  data[MAX_SIZE];
    char     data_str[MAX_SIZE];
    uint32_t entropy_len;
    uint32_t nonce_len;
    uint32_t add_input_len;
    uint32_t pers_str_len;

    fails = 0;

    /*
     * Determine the number of tests to run
     */
    if (VERBOSITY > 1) {
        fprintf(stderr, "Running %u Hash_DRBG tests\n", hash_drbg_count);
    }

    /*
     * Test the functions hash_drbg_instantiate_alg
     *  hash_drbg_reseed_alg, and hash_drbg_generate_alg()
     */
    for (i = 0; i < hash_drbg_count; i += 1) {
        /* Instantiate with the given data */
        entropy_len  = hex_to_bytes(hash_drbg[i].entropy1, strlen(hash_drbg[i].entropy1),
                                    entropy, 1000);
        nonce_len    = hex_to_bytes(hash_drbg[i].nonce,    strlen(hash_drbg[i].nonce),
                                    nonce,   1000);
        pers_str_len = hex_to_bytes(hash_drbg[i].pers_str, strlen(hash_drbg[i].pers_str),
                                    pers_str, 1000);
        hash_drbg_instantiate_alg(pers_str, pers_str_len,
                                  entropy,  entropy_len,
                                  nonce,    nonce_len,  10000);

        /*
         * The first generate with prediction resistance
         *  Perform the reseed manually as it is hash_drbg_generate() that checks
         *  for prediction resistance, but we are not testing hash_drbg_generate(),
         *  we are testing hash_drbg_generate_alg()
         *
         * I do not understand how the CAVP can test hash_drbg_generate(),
         *  when hash_drbg_generate() calls hash_drbg_reseed(), and hash_drbg_reseed
         *  explicity states that entropy shall not be provided by the consuming
         *  application.  Therefore, the CAVP test cannot call hash_drbg_reseed(),
         *  and hence cannot test hash_drbg_generate().
         *
         * So, we are left testing hash_drbg_generate_alg(), which does not perform
         *  the actual prediction resistance check,
         *  and so the reseed must be done manually. :-(
         */
        entropy_len   = hex_to_bytes(hash_drbg[i].entropy2, strlen(hash_drbg[i].entropy2),
                                     entropy, 1000);
        add_input_len = hex_to_bytes(hash_drbg[i].add_input1, strlen(hash_drbg[i].add_input1),
                                     add_input,   1000);
        hash_drbg_reseed_alg(add_input, add_input_len, entropy, entropy_len);

        hash_drbg_generate_alg(0, 0, data, 1024 / 8);

        /*
         * The second generate with prediction resistance
         *  Perform the reseed manually (same comment as above)
         */
        entropy_len   = hex_to_bytes(hash_drbg[i].entropy3, strlen(hash_drbg[i].entropy3),
                                     entropy, 1000);
        add_input_len = hex_to_bytes(hash_drbg[i].add_input2, strlen(hash_drbg[i].add_input2),
                                     add_input,   1000);
        hash_drbg_reseed_alg(add_input, add_input_len, entropy, entropy_len);

        hash_drbg_generate_alg(0, 0, data, 1024 / 8);

        /*
         * Compare the results to expected values
         */
        bytes_to_hex(data, 1024 / 8, data_str, 1000);
        if(strncmp(data_str, hash_drbg[i].expected_bytes, 1000) != 0) {
            if(VERBOSITY > 0) {
                fprintf(stderr, "Bad Instantiation %d\n", i);
            }
            fails += 1;
        }

        hash_drbg_uninstantiate(0);
    }
    return fails;
}
