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
 * FILE NAME :  sha256_cavp_selftest.c
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
 * ----------------------------------------------------------------------------
 * KEYWORDS : hash, sha256, self-test
 * ----------------------------------------------------------------------------
 * PURPOSE: Run a SHA256 CAVP test (ShortMsg, LongMsg and Monte Carlo tests)
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "sha256.h"

/*
 * Maximum size of a hex string
 *  This needs to be large, for this Long Message test includes messages
 *  up to 51200 bits long (>12000 hex character strings)
 */
#define MAX_SIZE  100000

/*
 * Perform a SHA256 Long or Short Message CAVP test
 *  This is defined in Sec. 6.2.2 (pg. 5) of
 *   The Secure Hash Algorithm Validation System (SHAVS)
 *
 *  This tests both sha256() and sha256_hex()
 *
 * Parameters:
 * const sha_msg_test* sha_tests - CAVP test data
 * int   count                   - Number of tests
 *
 * Return code:
 *  0 - All is well
 * >0 - Number of failures
 */
int
sha256_testMsg(const sha_msg_test* sha_tests, int count)
{
    int i;
    char     hash_string[65];
    uint8_t  hash_bytes[32];
    int      datalen;
    int      result;
    int      fails;
    uint8_t  data[MAX_SIZE];  /* At most MAX_SIZE bytes mat be contained in the hex buffer */

    fails = 0;


    /*
     * Test the function sha256_hex()
     */
    for (i = 0; i < count; i += 1) {
        int j;

        /*
         * Initialize hash_string to a known non-hex string
         *  This is just to verify that the output is indeed being set
         */
        for (j = 0; j < 64; j += 1) hash_string[j] = 'z';
        hash_string[64] = 0;

        /*
         * Hash the test string
         */
        result = sha256_hex(sha_tests[i].Msg, sha_tests[i].Bitlen / 4, hash_string);

        /*
         * Check that the result is correct
         */
        if (result == -1) {
            fails += 1;
            printf("Test %u failed; bad message:\n Len = %u\n MSG = \"%s\"\n MD  = \"%s\"\n\n",
                   i, sha_tests[i].Bitlen, sha_tests[i].Msg, sha_tests[i].MD);
        } else {
            if (strcmp(hash_string, sha_tests[i].MD) != 0) {
                /*
                 * Error if strings do not match
                 *  Print data for this test
                 */
                fails += 1;
                printf("SHA256_hex test %u failed; wrong hash:\n Len = %u\n MSG = \"%s\"\n MD  = \"%s\"\n SHA = \"%s\"\n\n",
                       i, sha_tests[i].Bitlen, sha_tests[i].Msg, sha_tests[i].MD, hash_string);
            }
        }
    }

    /*
     * Now, run the test again, but fur the sha256()
     */
    for (i = 0; i < count; i += 1) {
        int j;

        /*
         * Initialize hash_string to a known non-hex string
         *  This is just to verify that the output is indeed being set
         */
        for (j = 0; j < 64; j += 1) hash_string[j] = 'z';
        hash_string[64] = 0;

        /*
         * Convert the hex string to a byte array for hashing
         */
        datalen = hex_to_bytes(sha_tests[i].Msg, sha_tests[i].Bitlen / 4, data, MAX_SIZE);

        /*
         * Check that the conversion succeeded
         */
        if (datalen == -1) {
            fails += 1;
            printf("Test %u failed; bad message:\n Len = %u\n MSG = \"%s\"\n MD  = \"%s\"\n\n",
                   i, sha_tests[i].Bitlen, sha_tests[i].Msg, sha_tests[i].MD);
        } else {
            /*
             * Hash the byte array data
             */
            sha256(data, datalen, hash_bytes);

            /*
             * Convert the hash result from a byte array to a hex string,
             *  and compare it to the expected result
             */
            result = bytes_to_hex(hash_bytes, 32, hash_string, 65);
            if (strcmp(hash_string, sha_tests[i].MD) != 0) {
                /* Error if strings do not match */
                /* Print data for this test */
                fails += 1;
                printf("SHA256 test %u failed; wrong hash:\n Len = %u\n MSG = \"%s\"\n MD  = \"%s\"\n SHA = \"%s\"\n\n",
                       i, sha_tests[i].Bitlen, sha_tests[i].Msg, sha_tests[i].MD, hash_string);
            }
        }
    }

    return fails;
}

/*
 * Run the CAVP SHA Short Msg test
 */
int sha256_ShortMsg()
{
    return sha256_testMsg(sha_short, sha_short_count);
}

/*
 * Run the CAVP SHA Long Msg test
 */
int sha256_LongMsg()
{
    return sha256_testMsg(sha_long, sha_long_count);
}


/*
 * Perform a SHA256 Monte Carlo CAVP test
 *  This is defined in Sec. 6.4 (pg. 8) of
 *   The Secure Hash Algorithm Validation System (SHAVS)
 *
 *  This tests sha256_init() and sha256_update_hex() and sha256_finalize()
 *
 * Return code:
 *  0 - All is well
 * >0 - Number of failures
 */
int
sha256_Monte()
{
    char* MD0;      /* pointers to the last three message digests */
    char* MD1;
    char* MD2;
    char* temp;

    char buf0[65];  /* buffers to hold hex strings of the last three message digests */
    char buf1[65];
    char buf2[65];
    uint8_t hash_bytes[32]; /* buffer to hold hash output byte array */

    int inner;    /* inner loop counter */
    int outer;    /* outer loop counter */

    int r0, r1, r2; /* hash return codes */

    int fails;

    /*
     * No failures to start with
     */
    fails = 0;

    /*
     * Copy initial seeds to the buffers
     *  Hash the past three hash values
     */
    strncpy(buf0, sha_monte_seed, 65);
    strncpy(buf1, sha_monte_seed, 65);
    strncpy(buf2, sha_monte_seed, 65);
    MD0 = buf0;
    MD1 = buf1;
    MD2 = buf2;

    /*
     * The outer loop runs for each result hex string in sha_monte[]
     *  and then checks the result, and prepares for the next loop
     */
    for (outer = 0; outer < sha_monte_count; outer += 1) {

        /*
         * The inner loop runs 1000 times
         *  hashing the previous three hash values
         *  and then shifting them for the next iteration
         */
        for (inner = 0; inner < 1000; inner += 1) {
            /*
             * The message to hash is the concatenation of MD0, MD1 and MD2
             */
            SHA256_CTX context;
            sha256_init(&context);
            r0 = sha256_update_hex(&context, MD0, 65);
            r1 = sha256_update_hex(&context, MD1, 65);
            r2 = sha256_update_hex(&context, MD2, 65);
            if ((r0 == -1) || (r1 == -1) || (r2 == -1)) {
                printf("Error in loop %d, %d,    %d, %d, %d\n", outer, inner, r0, r1, r2);
            }
            sha256_finalize(&context, hash_bytes);

            /*
             * Convert the final hash byte array to a hex string, for comparison
             */
            bytes_to_hex(hash_bytes, 32, MD0, 65);

            /*
             * Rotate message digests around
             */
            temp = MD0;
            MD0 = MD1;
            MD1 = MD2;
            MD2 = temp;
        }

        /* MD2 now holds the final message digest of the inner loop */
        /*  compare it to the expected result */
        if (strcmp(MD2, sha_monte[outer]) != 0) {
            printf("Bad hash in loop %d\n \"%s\"\n \"%s\"\n", outer, MD2, sha_monte[outer]);
            fails += 1;
        }

        /* Set new seeds */
        strncpy(MD0, MD2, 65);
        strncpy(MD1, MD2, 65);
    }
    return fails;
}


