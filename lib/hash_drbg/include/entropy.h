/* +FHDR-----------------------------------------------------------------------
 * Copyright (c) 2014, Freescale Semiconductor, Inc.
 * Freescale Semiconductor Confidential Proprietary
 * ----------------------------------------------------------------------------
 * FILE NAME :  entropy.h
 * DEPARTMENT : Security Technology Center (STC), NCSG
 * AUTHOR :     Tom Tkacik (rp0624)
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2014-01-23   T. Tkacik   Initial version
 * ----------------------------------------------------------------------------
 * KEYWORDS : entropy, random number generation
 * ----------------------------------------------------------------------------
 * PURPOSE: Provide an API to collect entropy
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

#ifndef _ENTROPY_H_
#define _ENTROPY_H_

int get_entropy(uint8_t* entropy, uint32_t entropy_len);

int is_hw_rng_supported();  /* Is a TPM feeding /dev/random? */

#endif  /* _ENTROPY_H_ */
