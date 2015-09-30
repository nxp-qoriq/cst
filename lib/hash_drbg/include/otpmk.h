/* +FHDR-----------------------------------------------------------------------
 * Copyright (c) 2014, Freescale Semiconductor, Inc.
 * Freescale Semiconductor Confidential Proprietary
 * ----------------------------------------------------------------------------
 * FILE NAME :  otpmk.h
 * DEPARTMENT : Security Technology Center (STC), NCSG
 * AUTHOR :     Tom Tkacik (rp0624)
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2014-01-23   T. Tkacik   Initial version
 * ----------------------------------------------------------------------------
 * KEYWORDS : OTPMK, random code word
 * ----------------------------------------------------------------------------
 * PURPOSE: Provide an API to collect entropy
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#ifndef _OTPMK_H_
#define _OTPMK_H_

#define uint8_t  unsigned char

int  otpmk_get_rand_bits_256(uint8_t* otpmk_bits, int with_f);
int  otpmk_get_rand_256(uint8_t* otpmk, int with_f);
void otpmk_make_code_word_256(uint8_t* otpmk);
int  otpmk_check_code_word_256(uint8_t* otpmk);

#endif  /* _OTPMK_H_ */
