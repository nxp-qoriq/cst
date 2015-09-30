/* +FHDR-----------------------------------------------------------------------
 * Copyright (c) 2014, Freescale Semiconductor, Inc.
 * Freescale Semiconductor Confidential Proprietary
 * ----------------------------------------------------------------------------
 * FILE NAME :  get_rand.h
 * DEPARTMENT : Security Technology Center (STC), NCSG
 * AUTHOR :     Tom Tkacik (rp0624)
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2015-04-29   T. Tkacik   Initial version
 * ----------------------------------------------------------------------------
 * KEYWORDS :  RNG
 * ----------------------------------------------------------------------------
 * PURPOSE: API to get random bytes from the DRBG
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#ifndef _GET_RAND_H_
#define _GET_RAND_H_

#define uint8_t  unsigned char

int  get_rand_bits(uint8_t* bits, int bit_len);
int  get_rand_bytes(uint8_t* bytes, int byte_len);
void bytes_to_bits(uint8_t* bytes, uint8_t* bits, int bit_len);

#endif  /* _GET_RAND_H_ */
