/* +FHDR-----------------------------------------------------------------------
 * Copyright (c) 2014, Freescale Semiconductor, Inc.
 * Freescale Semiconductor Confidential Proprietary
 * ----------------------------------------------------------------------------
 * FILE NAME :  drvr.h
 * DEPARTMENT : Security Technology Center (STC), NCSG
 * AUTHOR :     Tom Tkacik (rp0624)
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2014-01-23   T. Tkacik   Initial version
 * ----------------------------------------------------------------------------
 * KEYWORDS : random code word
 * ----------------------------------------------------------------------------
 * PURPOSE: Provide an API to collect entropy
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#ifndef _DRVR_H_
#define _DRVR_H_

#define uint8_t  unsigned char

int  drvr_a_get_rand_bits_64(uint8_t* drvr_bits, int with_f);
int  drvr_a_get_rand_64(uint8_t* drvr, int with_f);
void drvr_a_make_code_word_64(uint8_t* drvr);
int  drvr_a_check_code_word_64(uint8_t* drvr);

int  drvr_b_get_rand_bits_64(uint8_t* drvr_bits, int with_1e);
int  drvr_b_get_rand_64(uint8_t* drvr, int with_1e);
void drvr_b_make_code_word_64(uint8_t* drvr);
int  drvr_b_check_code_word_64(uint8_t* drvr);

#endif  /* _DVDR_H_ */
