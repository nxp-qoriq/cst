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
 * FILE NAME :  otpmk.c
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
 * 0.0.4     2014-04-08   T. Tkacik   Rewrote otpmk_make_code_word()
 * 0.0.6     2015-09-17   T. Tkacik   Code cleanup
 * ----------------------------------------------------------------------------
 * KEYWORDS : OTPMK, random code word
 * ----------------------------------------------------------------------------
 * PURPOSE: Provide an API to collect OTPMK fuse values
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#include "hash_drbg.h"
#include "get_rand.h"
#include "otpmk.h"

/*
 * Selects either from /dev/urandom or /dev/random to get entropy.
 */
extern uint8_t urandom;

/*
 * Generate a 256-bit formatted, random otpmk value,  as 256 bits
 *
 * Parameters:
 * uint8_t* otpmk_bits - 256 byte buffer to hold the random code word
 *                       One bit per uint8_t
 * int with_f          - 0: all bits are random
 *                       1: four bits are forced to 1
 * uint8_t uran   - use /dev/urandom or /dev/random for entropy
 *
 * Return code:
 *  0 - All is well
 * >0 - Error occurred somewhere
 */
int
otpmk_get_rand_bits_256(uint8_t* otpmk_bits, int with_f, uint8_t uran)
{
    int ret_code;
    uint8_t otpmk[32];

    /*
     * Get the 256-bit otpmk code word as a byte array
     */
    ret_code = otpmk_get_rand_256(otpmk, with_f, uran);
    if (ret_code == SUCCESS) {
        bytes_to_bits(otpmk, otpmk_bits, 256);
    }
    return ret_code;
}


/*
 * Generate a 256-bit random code word, as 32 bytes
 *  This is a random value which has been turned into a code word
 *
 * Parameters:
 * uint8_t* otpmk - 32 byte buffer to hold the random code word
 * int with_f     - 0: all bits are random
 *                  1: four bits are forced to 1
 * uint8_t uran   - use /dev/urandom or /dev/random for entropy
 *
 * Return code:
 *  0 - All is well
 * >0 - Error occurred somewhere
 */
int
otpmk_get_rand_256(uint8_t* otpmk, int with_f, uint8_t uran)
{
    int ret_code;

    urandom = uran;

    /*
     * Get 32 bytes of random data
     */
    ret_code = get_rand_bytes(otpmk, 32);

    /*
     * Force bits 252, 253, 254 and 255 to 1
     *  This is because these fuses may have already been blown
     *  and the OTPMK cannot force them back to 0
     */
    if (with_f == 1) {
        otpmk[252/8] |= (1 << (252%8));
        otpmk[253/8] |= (1 << (253%8));
        otpmk[254/8] |= (1 << (254%8));
        otpmk[255/8] |= (1 << (255%8));
    }
    /*
     * Convert the random bytes to an OTPMK code word
     */
    if (ret_code == SUCCESS) {
        otpmk_make_code_word_256(otpmk);
    }
    return ret_code;
}


/*
 * Turn a 256-bit random value (32 bytes) into an OTPMK code word
 *  modifying the input data array in place
 *
 * For this conversion, the 32 bytes are treated as an array, with byte 0
 *  containing bits 7 - 0, and byte 31 containing bits 255 - 248.
 * It does not really matter which endian is used, as the code word will be
 *  valid either way. It's just that it will match how other current software
 *  does it, making checking the results easier.
 *
 * Parameters:
 * uint8_t* otpmk - 32 byte array holding the random value (both input and output)
 */
void
otpmk_make_code_word_256(uint8_t* otpmk)
{
    int i;
    uint8_t parity_bit;     /* Parity bit of otpmk when */
    uint8_t code_bit;       /* Bit, which if changed, will make the otpmk a code word */

    /*
     * Generate the hamming code for the code word
     */
    parity_bit = 0;
    code_bit = 0;
    for (i = 0; i < 256; i += 1) {
        if ((otpmk[i/8] & (1 << (i%8))) != 0) {
            parity_bit ^= 1;
            code_bit   ^= i;
        }
    }

    /*
     * Inverting otpmk[code_bit] will cause the otpmk
     *  to become a valid code word (except for overall parity)
     */
    if (code_bit < 128) {
        otpmk[code_bit/8] ^= (1 << (code_bit%8));
        parity_bit  ^= 1;  /* account for flipping a bit changing the parity */
    } else {
        /*
         * Invert two bits:  (code_bit - 128) and 128
         *  Because we invert two bits, no need to touch the parity bit
         */
        otpmk[(code_bit-128)/8] ^= (1 << ((code_bit-128)%8));
        otpmk[128/8] ^= (1 << (128%8));
    }

    /*
     * Finally, adjust the overall parity of the otpmk
     */
    otpmk[0] ^= parity_bit;  /* otpmk bit 0 */
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
 * >0 - The input is not a code word
 */
int
otpmk_check_code_word_256(uint8_t* otpmk)
{
    int i;
    uint8_t parity_bit;     /* Parity bit of otpmk when */
    uint8_t code_bit;       /* Bit, which if changed, will make the otpmk a code word */

    /*
     * Generate the hamming code for the code word
     */
    parity_bit = 0;
    code_bit = 0;
    for (i = 0; i < 256; i += 1) {
        if ((otpmk[i/8] & (1 << (i%8))) != 0) {
            parity_bit ^= 1;
            code_bit   ^= i;
        }
    }

    return ((int)code_bit | ((int)parity_bit << 8));
}
