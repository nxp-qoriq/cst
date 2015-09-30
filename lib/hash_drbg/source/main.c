
/*
 * An example test program
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include "hash_drbg.h"
#include "entropy.h"
#include "otpmk.h"
#include "drvr.h"

void billion_Bs_test();         /* hash 1 billion Bs */
void generate_1000000_otpmk();  /* generate 1000000 otpmks, output to file for statistical testing */


int
main(int argc, char* argv[]) {
    int i;
    char* str;
    int n;

    int ret_code;
    uint8_t otpmk[32];
    uint8_t drvr[8];
    char hex[65];

    /*
     * If a number is given on the comman line, use it as the number of OTPMK values
     *  to generate. Otherwise default to 20
     */
    if (argc == 2) {
        str = argv[1];
        n = atoi(str);
    } else {
        n = 20;
    }

#if 0
    billion_Bs_test();        /* hash a billion Bs */
    generate_1000000_otpmk(); /* generate 1000000 otpmks for statistical testing */

    /*
     * Just perform a quick check if a TPM is activated,
     *  so that we can print a message, verifying that the routing works
     */
    if (is_hw_rng_supported() == 1) {
        fprintf(stderr, "Found TPM feeding /dev/random\n");
    } else {
        fprintf(stderr, "No TPM Found\n");
    }
#endif

    /*
     * Test get_otpmk_rand_256
     */
    for (i = 0; i < n; i += 1) {
        ret_code = otpmk_get_rand_256(otpmk, 1);
        if (ret_code != 0) {
            fprintf (stderr, "Error generating bits\n");
            break;
	} else {
            int x;
            ret_code = bytes_to_hex(otpmk, 32, hex, 65);
            if (ret_code == 0) {
                fprintf(stderr, "Error copying bits\n");
                break;
            } else {
                printf("0x%s\n", hex);
            }
            x = otpmk_check_code_word_256(otpmk);
            if (x != 0) {
                fprintf (stderr, "  Not a valid codeword:  0x%02x\n", x);
            }
            if ((otpmk[31] & 0xf0) != 0xf0) {
                fprintf (stderr, "Flipped high bits of OTPMK\n");
            }
        }
    }

    /*
     * Test get_drvr_rand_64
     */
    for (i = 0; i < n; i += 1) {
        ret_code = drvr_b_get_rand_64(drvr, 1);
        if (ret_code != 0) {
            fprintf (stderr, "Error generating bits\n");
            break;
        } else {
            int x;
            ret_code = bytes_to_hex(drvr, 8, hex, 17);
            if (ret_code == 0) {
                fprintf(stderr, "Error copying bits\n");
                break;
            } else {
                printf("0x%s\n", hex);
            }
            x = drvr_b_check_code_word_64(drvr);
            if (x != 0) {
                fprintf (stderr, "  Not a valid codeword:  0x%02x\n", x);
            }
            if ((drvr[7] & 0x1e) != 0x1e) {
                 fprintf (stderr, "  Flipped high bits of DRVR\n");
            }
        }
    }

    /*
     * Call hash_drbg_uninstantiate() just to print
     *  some statistics about reseeds and generates
     * Otherwise, it is not really necessary at the end of the program
     */
    ret_code = hash_drbg_uninstantiate(1);

    return ret_code;
}

void
billion_Bs_test() {
    int i;
    const char B[119] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    SHA256_CTX ctx;
    uint8_t hash_bytes[32];
    const char result[65] = "c23ce8a7895f4b21ec0daf37920ac0a262a220045a03eb2dfed48ef9b05aabea";
    char    hash_string[65];


    /*
     * Hash a block of 1610612798 bytes of 'B's
     *  (Note that 1610612798 = 118 * 13649261)
     */
    sha256_init(&ctx);
    for (i = 0; i < 13649261; i += 1) {
        sha256_update(&ctx, (const uint8_t*)B, strlen(B));
    }
    sha256_finalize(&ctx, hash_bytes);
    bytes_to_hex(hash_bytes, 32, hash_string, 65);
    if (strncmp(hash_string, result, 65) != 0) {
        fprintf(stderr, "Billion Bs test failed:\n"
                        "expected %s\n"
                        "actual   %s\n", result, hash_string);
    } else {
        fprintf(stderr, "Billion Bs test passed\n");
    }

}

void
generate_1000000_otpmk() {
    int i;
    int ret_code;
    uint8_t otpmk[32];

    const char* filename = "otpmk_1000000";
    FILE* fp;

    fp = fopen(filename, "w");
    if (fp == 0) {
        fprintf(stderr, "Error opening file %s\n", filename);
        return;
    }

    for (i = 0; i < 1000000; i += 1) {
        int j;
        ret_code = otpmk_get_rand_256(otpmk, 0);
        if (ret_code != 0) {
            fprintf (stderr, "Error generating bits\n");
        }
        for (j = 0; j < 32; j += 1) {
            fprintf(fp, "%c", otpmk[j]);
        }
    }
}
