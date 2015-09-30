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
#include <time.h>

#define OTPMK_SIZE_BITS 256
#define OTPMK_SIZE_BYTES (OTPMK_SIZE_BITS/8)
#define OTPMK_REG_NO (OTPMK_SIZE_BITS/32)

typedef unsigned char u8;

u8 otpmk_hex[OTPMK_SIZE_BYTES];
int trust_arch;

/* There is a change in SFP word ordering from Trust 1.x to Trust 2.0
 * In Trust 2.0 devices the key is 255-0, and OTPMK 0 holds bits 255-224,
 * rather than 31-0, while in Trust 1.x devices OTPMK 0 holds bits 31-0.
 * */

/* Generate the Hamming code bits for the 256 bits stored in number.
 * The values at the locations of the code bits are ignored and is
 * overwritten with the generated values.
 */
void print_otpmk_trust1()
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
void print_otpmk_trust2()
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

void generate_code_bits(bool number[])
{
	int i, j;
	char k[9];
/* Calculate each code bit in turn */
	for (i = 1; i <= OTPMK_SIZE_BITS / 2; i = (i << 1)) {
/* Examine each data bit
 * Only bits greater than i need to be checked as no
 * bit less than i will ever be XORed into i
 * J starts at i so that number[i] is initialized to 0
 */
		for (j = i; j <= OTPMK_SIZE_BITS - 1; j = j + 1) {
			if ((i & j) != 0)
				number[i] = number[i] ^ number[j];
		}
	}
/* Calculate the overall parity
 * J starts at 0 so that number[0] is initialized to 0
 * number[0] contains the even parity of all of the bits
 */
	for (j = 0; j <= OTPMK_SIZE_BITS - 1; j = j + 1)
		number[0] = number[0] ^ number[j];
#ifdef DEBUG
	printf("\nHamming code -\n");
	for (i = 0; i < OTPMK_SIZE_BITS; i++)
		printf("%d", number[i]);
#endif
	for (i = 0; i < OTPMK_SIZE_BYTES; i++) {
		for (j = 0; j < 8; j++) {
			k[j] =
			    (number[(OTPMK_SIZE_BYTES - i) * 8 - (j + 1)]) + 48;
		}
		k[8] = '\0';
		otpmk_hex[i] = (u8)strtoul(k, NULL, 2);
	}

	if (trust_arch == 1)
		print_otpmk_trust1();

	if (trust_arch == 2)
		print_otpmk_trust2();
}

void gen_rand_string()
{
	unsigned int iseed = (unsigned int)time(NULL);
	int i, l, index1, index2;
	char hex_digits[] = "0123456789abcdef";
	char rand_string[3] = {'\0'};

	/*providing seed for random number generation*/
	srand(iseed);

	for (i = 0; i < 2 * OTPMK_SIZE_BYTES; i = i + 2) {
		/*generate first random nibble of the byte*/
		index1 = rand() % strlen(hex_digits);
		rand_string[0] = hex_digits[index1];

		/*generate second random nibble of the byte*/
		index2 = rand() % strlen(hex_digits);
		rand_string[1] = hex_digits[index2];

		l = i / 2;
		otpmk_hex[l] = (u8)strtoul(rand_string, NULL, 16);
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
	printf("\nUsage: ./gen_otpmk <trust_arch> [string]\n");
	printf("string : 32 byte string\n");
	printf("e.g. gen_otpmk 1 11111111222222223333333344444444"
			"55555555666666667777777788888888\n");
}

int main(int argc, char *argv[])
{
	bool num[OTPMK_SIZE_BITS];
	char otpmk_in[2];
	int i, j, l, ret;
	if (argc == 3 &&
	    (strlen(argv[1]) == 1 && (*argv[1] == '1' || *argv[1] == '2'))) {
		trust_arch = atoi(argv[1]);
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
				otpmk_hex[l] = (u8)strtoul(otpmk_in, NULL, 16);
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
			printf("\nGenerating random key as input "
				"string not provided\n");
			trust_arch = *argv[1] - 48;
			gen_rand_string();
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

	/*Create array of bits to be used as an input*/
	for (i = 0; i < OTPMK_SIZE_BYTES; i++) {

		l = 0x80;
		for (j = 0; j < 8; j++) {
			num[OTPMK_SIZE_BYTES * 8 - i * 8 - 1 - j] =
			    (otpmk_hex[i]) & (l);
			l = l >> 1;
		}
	}

#ifdef DEBUG
	for (i = 0; i < OTPMK_SIZE_BITS; i++)
		printf("%d", num[i]);
#endif
	/*generate Hamming code and replace bits in OTPMK key*/
	generate_code_bits(num);

	printf("\n");
	return 0;
}
