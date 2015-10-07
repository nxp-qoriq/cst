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
 * FILE NAME :  drvr.c
 * DEPARTMENT : Security Technology Center (STC), NCSG
 * AUTHOR :     Tom Tkacik
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.2     2015-09-17   T. Tkacik   Code cleanup
 * ----------------------------------------------------------------------------
 * KEYWORDS : DRVR, random code word
 * ----------------------------------------------------------------------------
 * PURPOSE: Provide an API to collect DRVR fuse values
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
#include "drvr.h"



/*
 * Generate a 64-bit random drvr value,  as 64 bits
 *
 * Parameters:
 * uint8_t* drvr_bits - 64 byte buffer to hold the random code word
 *                       One bit per uint8_t
 * int with_1e        - 0: all bits random
 *                      1: four bits are forced to 1s
 *
 * Return code:
 *  0 - All is well
 * >0 - Error occurred somewhere
 */
int
drvr_b_get_rand_bits_64(uint8_t* drvr_bits, int with_1e)
{
    int ret_code;
    uint8_t drvr[8];

    /*
     * Get the 64-bit otpmk code word as a byte array
     */
    ret_code = drvr_b_get_rand_64(drvr, with_1e);
    if (ret_code == SUCCESS) {
        bytes_to_bits(drvr, drvr_bits, 64);
    }
    return ret_code;
}


/*
 * Generate a 64-bit random code word, as 8 bytes
 *  This is a random value which has been turned into a code word
 *
 * Parameters:
 * uint8_t* drvr - 8 byte buffer to hold the random code word
 * int with_1e   - 0: all bits random
 *                 1: four bits are forced to 1s in the high byte
 *
 * Return code:
 *  0 - All is well
 * >0 - Error occurred somewhere
 */
int
drvr_b_get_rand_64(uint8_t* drvr, int with_1e)
{
    int ret_code;

    /*
     * Get 8 bytes of random data
     */
    ret_code = get_rand_bytes(drvr, 8);

    if (with_1e == 1) {
        drvr[60/8] |= (1 << (60%8));
        drvr[59/8] |= (1 << (59%8));
        drvr[58/8] |= (1 << (58%8));
        drvr[57/8] |= (1 << (57%8));
    }
    /*
     * Convert the random bytes to a DRVR code word
     */
    if (ret_code == SUCCESS) {
        drvr_b_make_code_word_64(drvr);
    }
    return ret_code;
}


/*
 * Check that a 64-bit random value (8 bytes) is a DRVR code word
 *
 * For this check, the 8 bytes are treated as an array, with byte 0
 *  containing bits 7 - 0, and byte 7 containing bits 63 - 56.
 *
 * Parameters:
 * uint8_t* otpmk - 8 byte array holding the random value (both input and output)
 *
 * Return code:
 *  0 - All is well
 * >0 - The intpu is not a code word
 */
int
drvr_b_check_code_word_64(uint8_t* drvr)
{
    int i;
    int j;
    uint8_t parity_bit;     /* Parity bit of drvr when */
    uint8_t cbit1;
    uint8_t cbit2;
    uint8_t cbit3;
    uint8_t cbit4;
    uint8_t cbit5;
    uint8_t cbit6;

    /*
     * Generate the hamming code for the code word
     */

    parity_bit = 0;
    cbit1 = 0;
    cbit2 = 0;
    cbit3 = 0;
    cbit4 = 0;
    cbit5 = 0;
    cbit6 = 0;

    for (i = 0; i < 64; i += 2) {
        if((drvr[i/8] & (1 << (i%8))) != 0) {
            cbit1  ^= 1;
        }
    }

    for (i = 1; i <= 62; i += 4) {
      for (j = 0; j < 2; j += 1) {
        if ((drvr[(j+i)/8] & (1 << ((j+i)%8))) != 0) {
            cbit2  ^= 1;
	}
      }
    }

    for (i = 3; i <= 62; i += 8) {
      for (j = 0; j < 4; j += 1) {
        if ((drvr[(j+i)/8] & (1 << ((j+i)%8))) != 0) {
            cbit3  ^= 1;
	}
      }
    }

    for (i = 7; i <= 62; i += 16) {
      for (j = 0; j < 8; j += 1) {
        if ((drvr[(j+i)/8] & (1 << ((j+i)%8))) != 0) {
            cbit4  ^= 1;
	}
      }
    }

    for (i = 15; i <= 62; i += 32) {
      for (j = 0; j < 16; j += 1) {
        if ((drvr[(j+i)/8] & (1 << ((j+i)%8))) != 0) {
            cbit5  ^= 1;
	}
      }
    }

    for (i = 31; i <= 62; i += 64) {
      for (j = 0; j < 32; j += 1) {
        if ((drvr[(j+i)/8] & (1 << ((j+i)%8))) != 0) {
            cbit6  ^= 1;
	}
      }
    }


    for (i = 0; i < 64; i += 1) {
        if ((drvr[i/8] & (1 << (i%8))) != 0) {
            parity_bit  ^= 1;
        }
    }

    parity_bit ^= (cbit1 << 1);
    parity_bit ^= (cbit2 << 2);
    parity_bit ^= (cbit3 << 3);
    parity_bit ^= (cbit4 << 4);
    parity_bit ^= (cbit5 << 5);
    parity_bit ^= (cbit6 << 6);

    return(parity_bit);
}


/*
 * Turn a 64-bit random value (8 bytes) into an DRVR code word
 *  modifying the input data array in place
 * Note that there is an off-by-1 issue in the definition of
 *  a DRVR code word, so you will see (code_bit = code_bit-1) below
 *  and bit 63 is the parity bit, rather than bit 0.
 *
 * Parameters:
 * uint8_t* drvr - 8 byte array holding the random value (both input and output)
 */
void
drvr_b_make_code_word_64(uint8_t* drvr)
{
    int i;
    uint8_t parity_bit;     /* Parity bit of drvr when */
    uint8_t code_bit;       /* Bit, which if changed, will make the drvr a code word */

    /*
     * Generate the hamming code for the code word
     */
    parity_bit = 0;
    code_bit = 0;
    for (i = 0; i < 64; i += 1) {
        if ((drvr[i/8] & (1 << (i%8))) != 0) {
            parity_bit ^= 1;
            code_bit   ^= (i+1) & 0x3f;
        }
    }

    /*
     * Inverting drvr[code_bit-1] will cause the drvr
     *  to become a valid code word (except for overall parity)
     */
    if (code_bit < 32) {
        code_bit = (code_bit - 1) & 0x3f;
        drvr[code_bit/8] ^= (1 << (code_bit%8));
        parity_bit  ^= 1;  /* account for flipping a bit changing the parity */
    } else {
        /*
         * Avoid modifying the high bits, so modify two low bits instead
         */
        code_bit = (code_bit - 1) & 0x3f;
        drvr[(code_bit^32)/8] ^= (1 << ((code_bit^32)%8));
        drvr[31/8] ^= (1 << (31%8));
    }

    /*
     * Finally, adjust the overall parity of the otpmk
     */
    drvr[7] ^= (parity_bit<<7);  /* drvr bit 0 */

}

