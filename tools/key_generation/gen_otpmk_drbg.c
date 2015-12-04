/* This code generates the OTPMK Key with the hamming code embedded in
 * the key.
 * The Hamming algorithm as per the reference manual has been implemented.
 */

/* Copyright (c) 2012, Freescale Semiconductor, Inc.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <otpmk.h>

#define OTPMK_SIZE_BITS 256
#define OTPMK_SIZE_BYTES (OTPMK_SIZE_BITS/8)
#define OTPMK_REG_NO (OTPMK_SIZE_BITS/32)

typedef unsigned char u8;

u8 otpmk_hex[OTPMK_SIZE_BYTES];
int bit_ordering_type;

/* There is a change in SFP word ordering from Trust 1.x to Trust 2.0
 * In Trust 2.0 devices the key is 255-0, and OTPMK 0 holds bits 255-224,
 * rather than 31-0, while in Trust 1.x devices OTPMK 0 holds bits 31-0.
 * */

/* Generate the Hamming code bits for the 256 bits stored in number.
 * The values at the locations of the code bits are ignored and is
 * overwritten with the generated values.
 */
void print_otpmk_bit_order1()
{
	int i;
	printf("\n NAME    |     BITS     |    VALUE  ");
	printf("\n_________|______________|____________");

	for (i = OTPMK_SIZE_BYTES - 4; i >= 0; i = i - 4) {
		printf("\nOTPMKR %d | %3d-%3d\t|   %.2x%.2x%.2x%.2x ",
		       OTPMK_REG_NO - 1 - i / 4,
		       OTPMK_SIZE_BYTES - 1 + (OTPMK_REG_NO - 1 -
					       i / 4) * OTPMK_SIZE_BYTES,
		       (OTPMK_REG_NO - 1 - i / 4) * OTPMK_SIZE_BYTES,
		       otpmk_hex[i], otpmk_hex[i + 1], otpmk_hex[i + 2],
		       otpmk_hex[i + 3]);
	}

}

/* Generate the Hamming code bits for the 256 bits stored in number.
 * The values at the locations of the code bits are ignored and is
 * overwritten with the generated values.
 */
void print_otpmk_bit_order2()
{
	int i;
	int j = 0;
	printf("\n NAME    |     BITS     |    VALUE  ");
	printf("\n_________|______________|____________");

	for (i = OTPMK_REG_NO - 1; i >= 0; i--) {
		printf("\nOTPMKR %d | %3d-%3d\t|   %.2x%.2x%.2x%.2x ",
		       OTPMK_REG_NO - i - 1,
		       ((i + 1) * OTPMK_SIZE_BYTES) - 1,
		       i * OTPMK_SIZE_BYTES,
		       otpmk_hex[j], otpmk_hex[j + 1], otpmk_hex[j + 2],
		       otpmk_hex[j + 3]);
		j = j + 4;
	}

}

int check_string(char *str)
{
	while (*str) {
		if ((*(str) >= 48 && *(str) <= 57)
		    || (*(str) >= 65 && *(str) <= 70) || (*(str) >= 97
							  && *(str) <= 102)) {

		} else {
			return -1;
		}

		str++;
	}

	return 0;

}

void usage()
{
	printf("\n");
	printf("Usage : ./gen_otpmk_drbg <bit_order> [string]\n");
	printf("<bit_order> : (1 or 2) OTPMK Bit Ordering Scheme in SFP\n");
	printf("\t1 : BSC913x, P1010, P3, P4, P5, C29x\n");
	printf("\t2 : T1, T2, T4, B4, LSx\n");
	printf("<string> : 32 byte string\n");
	printf("\ne.g. gen_otpmk_drbg 1 11111111222222223333333344444444"
			"55555555666666667777777788888888\n");
}

int main(int argc, char *argv[])
{
	char otpmk_in[2];
	int i, l, ret;

	printf("\n\t#----------------------------------------------------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#------- CST (Code Signing Tool) Version 2.0  -------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#----------------------------------------------------#");
	printf("\n");

	if (argc == 3 &&
	    (strlen(argv[1]) == 1 && (*argv[1] == '1' || *argv[1] == '2'))) {
		bit_ordering_type = atoi(argv[1]);
		/*check length of hexadecimal string*/
		if (strlen(argv[2]) == 2 * OTPMK_SIZE_BYTES) {
			/*check if string is valid hexadecimal string*/
			ret = check_string(argv[2]);
			if (ret == -1) {
				printf("\nError: Input key is not having"
					"valid hexadecimal character\n");
				return -1;
			}
			for (i = 0; i < 2 * OTPMK_SIZE_BYTES; i += 2) {
				otpmk_in[0] = argv[2][i + 0];
				otpmk_in[1] = argv[2][i + 1];
				l = i / 2;
				otpmk_hex[l] = strtoul(otpmk_in, NULL, 16);

				/* Create the OTPMK Key using hash_drbg lib */
				otpmk_make_code_word_256(otpmk_hex);
			}
		} else {
			printf("\nError: Invalid Input key Length\n");
			usage();
			exit(1);
		}
	} else if (argc == 2) {
		if ((strcmp(argv[1], "--help") == 0)
			|| (strcmp(argv[1], "-h") == 0)) {
			usage();
			exit(0);
		} else if (strlen(argv[1]) == 1 &&
			   (*argv[1] == '1' || *argv[1] == '2')) {
			printf("\nInput string not provided");
			printf("\nGenerating a random string");
			printf("\n-------------------------------------------");
			printf("\n* Hash_DRBG library invoked");
			printf("\n* Seed being taken from /dev/random");
			printf("\n-------------------------------------------");
			bit_ordering_type = *argv[1] - 48;

			/* Generate Random OTPMK using hash_drbg lib */
			ret = otpmk_get_rand_256(otpmk_hex, 0);
			if (ret != 0) {
				printf("\nRandom bytes generation failed\n");
				exit(1);
			}
		} else {
			printf("\nError: Wrong Usage\n");
			usage();
			exit(1);
		}
	} else {
		printf("\nError: Wrong Usage\n");
		usage();
		exit(1);
	}


	printf("\nOTPMK[255:0] is:\n");
	for (i = 0; i < OTPMK_SIZE_BYTES; i++)
		printf("%.2x", otpmk_hex[i]);

	printf("\n");

	if (bit_ordering_type == 1)
		print_otpmk_bit_order1();

	if (bit_ordering_type == 2)
		print_otpmk_bit_order2();

	printf("\n");
	return 0;
}
