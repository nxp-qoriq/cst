/* +FHDR-----------------------------------------------------------------------
 * Copyright (c) 2014, Freescale Semiconductor, Inc.
 * Freescale Semiconductor Confidential Proprietary
 * ----------------------------------------------------------------------------
 * FILE NAME :  entropy.c
 * DEPARTMENT : Security Technology Center (STC), NCSG
 * AUTHOR :     Tom Tkacik (rp0624)
 * ----------------------------------------------------------------------------
 * REVIEW(S) :
 * ----------------------------------------------------------------------------
 * RELEASE HISTORY
 * VERSION   DATE         AUTHOR      DESCRIPTION
 * 0.0.1     2014-01-23   T. Tkacik   Initial version
 * 0.0.2     2014-01-28   T. Tkacik   Code cleanup
 * 0.0.3     2015-09-17   T. Tkacik   Code cleanup
 * ----------------------------------------------------------------------------
 * KEYWORDS : entropy, random number generation
 * ----------------------------------------------------------------------------
 * PURPOSE: Provide an API to collect entropy
 * ----------------------------------------------------------------------------
 * REUSE ISSUES
 *
 * -FHDR-----------------------------------------------------------------------
 */

/*
 * define integer types
 */
typedef unsigned long long uint64_t;
typedef unsigned int       uint32_t;
typedef unsigned char      uint8_t;

#include <stdio.h>
#include <stdlib.h>
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
 * Initialize an unopened file descriptor
 */
static FILE* fp = 0;

/*
 * Get entropy by reading /dev/random
 * Parameters:
 * uint8_t* entropy     - byte buffer to store entropy
 * uint32_t entropy_len - number of bytes of entropy to return
 *
 * Return code:
 * 0 - All is well
 * 3 - Error opening, or reading entropy file
 */
int
get_entropy(uint8_t* entropy, uint32_t entropy_len)
{
#ifdef USE_URANDOM
    const char* filename = "/dev/urandom";
#else
    const char* filename = "/dev/random";
#endif
    uint32_t i;
    int c;

    /*
     * If /dev/random is not open, then open it for reading
     */
    if (fp == 0) {
        fp = fopen(filename, "r");
        if (fp == 0) {
            if ((VERBOSITY > 0) || (SEVERITY > 0)) {
                fprintf(stderr, "Could not open %s\n", filename);
            }
            if (SEVERITY > 0) {
                exit(1);
            } else {
                return 3;
            }
        }
    }

    /*
     * Read entropy data from /dev/random
     */
    for (i = 0; i < entropy_len; i += 1) {
        c = getc(fp);
        if (c == EOF) {
            return 3;
        }
        *entropy++ = c;
    }
    return 0;
}


/*
 * Is a TPM feeding /dev/random?
 *  Rngd is a Random Number Generator Daemon, which reads data from a HW RNG
 *   and enters it into the Linux entropy pool, /dev/random.
 *  Rngd might be running if a TPM is not present, assuming that some other
 *   HW RNG was present in the system.  This is not likely in the cases of interest,
 *   so rngd running should be a proper test that a TPM is present and activated.
 * 
 * Parameters:
 *  None
 *
 * Return code:
 * 0 - No HW RNG was found
 * 1 - A HW RNG is feeding /dev/random
 */
int
is_hw_rng_supported()
{
    /*
     * Search for /sbin/rngb, and see that it is running.
     */
    if (system("ps -e | grep -q rngd") == 0) {
        return 1;
    } else {
        return 0;
    }
}

