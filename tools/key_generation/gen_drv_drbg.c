/* This code generates the DRV value with the hamming code embedded in it.
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
#include <get_rand.h>

#define DRV_SIZE_BITS 64
#define DRV_SIZE_BYTES (DRV_SIZE_BITS/8)
#define DRV_REG_NO (DRV_SIZE_BITS/32)
#define DRV_REG_BITS 32

typedef unsigned char u8;

u8 drv_hex[DRV_SIZE_BYTES];

/* Generate the Hamming code bits for the 256 bits stored in number.
 * The values at the locations of the code bits are ignored and is
 * overwritten with the generated values.
 */

void print_drv_a1_b()
{
	printf("\n NAME    |     BITS     |    VALUE  ");
	printf("\n_________|______________|____________");
	printf("\nDRV 0    |    31 - 0    | %.2x%.2x%.2x%.2x ",
		drv_hex[4], drv_hex[5], drv_hex[6], drv_hex[7]);
	printf("\nDRV 1    |    63 - 32   | %.2x%.2x%.2x%.2x ",
		drv_hex[0], drv_hex[1], drv_hex[2], drv_hex[3]);

}

void print_drv_a2()
{
	printf("\n NAME    |     BITS     |    VALUE  ");
	printf("\n_________|______________|____________");
	printf("\nDRV 0    |    63 - 32   | %.2x%.2x%.2x%.2x ",
		drv_hex[0], drv_hex[1], drv_hex[2], drv_hex[3]);
	printf("\nDRV 1    |    31 - 0    | %.2x%.2x%.2x%.2x ",
		drv_hex[4], drv_hex[5], drv_hex[6], drv_hex[7]);

}

/* Generate the Hamming code bits for the 64 bits stored in number*/
/* according to sfp's ECC algorithm. */
void generate_code_bits_hamming_B(bool number[])
{
	int i, j;
	char k[9];
	u8 parity;

/* response must be masked out the hamming coding bits first */
	for (i = 0; i < 64; i = (2*(i+1) - 1))
		number[i] = 0;

/* Calculate each code bit in turn */
	for (i = 0; i < 32; i = (2*(i+1) - 1)) {
		parity = number[i];

		for (j = i+1; j < 64; j++) {
			if (((i+1) & (j+1)) != 0)
				parity ^= number[j];

		number[i] = (number[i] & 0) | parity;
		}
	}

/* Calculate the overall parity */
		parity = 0;
		for (j = 0; j < 64; j++)
			parity ^= number[j];

		number[63] = number[63] | parity;
#ifdef DEBUG
	printf("\nHamming code -\n");
	for (i = 0; i < DRV_SIZE_BITS; i++)
		printf("%d", number[i]);
#endif
	for (i = 0; i < DRV_SIZE_BYTES; i++) {
		for (j = 0; j < 8; j++) {
			k[j] =
			    (number[(DRV_SIZE_BYTES - i) * 8 - (j + 1)]) + 48;
		}
		k[8] = '\0';
		drv_hex[i] = (u8)strtoul(k, NULL, 2);
	}

}

void generate_code_bits_hamming_A(bool number[])
{
	int i, j;
	char k[9];
/* Calculate each code bit in turn */
	for (i = 1; i <= DRV_SIZE_BITS / 2; i = (i << 1)) {
/* Examine each data bit
 * Only bits greater than i need to be checked as no
 * bit less than i will ever be XORed into i
 * J starts at i so that number[i] is initialized to 0
 */
		for (j = i; j <= DRV_SIZE_BITS - 1; j = j + 1) {
			if ((i & j) != 0)
				number[i] = number[i] ^ number[j];
		}
	}
/* Calculate the overall parity
 * J starts at 0 so that number[0] is initialized to 0
 * number[0] contains the even parity of all of the bits
 */
	for (j = 0; j <= DRV_SIZE_BITS - 1; j = j + 1)
		number[0] = number[0] ^ number[j];
#ifdef DEBUG
	printf("\nHamming code -\n");
	for (i = 0; i < DRV_SIZE_BITS; i++)
		printf("%d", number[i]);
#endif
	for (i = 0; i < DRV_SIZE_BYTES; i++) {
		for (j = 0; j < 8; j++) {
			k[j] =
			    (number[(DRV_SIZE_BYTES - i) * 8 - (j + 1)]) + 48;
		}
		k[8] = '\0';
		drv_hex[i] = (u8)strtoul(k, NULL, 2);
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
	printf("\nUsage: ./gen_drv_drbg <Hamming_algo> [string]\n");
	printf("Hamming_algo : Platforms\n");
	printf("A1           : T10xx, T20xx, T4xxx, P4080rev1, B4xxx\n");
	printf("A2           : LSx\n");
	printf("B            : P10xx, P20xx, P30xx, P4080rev2, P4080rev3,"
				" P50xx, BSC913x, C29x\n");
	printf("string : 8 byte string\n");
}

enum algorithm {
	HAMMING_A1 = 0,
	HAMMING_A2,
	HAMMING_B
};

int main(int argc, char *argv[])
{
	bool num[DRV_SIZE_BITS];
	char drv_in[2];
	int i, j, l, ret;
	enum algorithm hamming_algo;

	printf("\n\t#----------------------------------------------------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#------- CST (Code Signing Tool) Version 2.0  -------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#----------------------------------------------------#");
	printf("\n");

	if (argc < 2) {
		printf("\nError: Wrong Usage\n");
		usage();
		return -1;
	}

	/* Parse the Arguments */
	if ((argc == 2) || (argc == 3)) {
		if (strcmp(argv[1], "A1") == 0)
			hamming_algo = HAMMING_A1;
		else if (strcmp(argv[1], "A2") == 0)
			hamming_algo = HAMMING_A2;
		else if (strcmp(argv[1], "B") == 0)
			hamming_algo = HAMMING_B;
		else {
			if ((strcmp(argv[1], "-h") == 0 )||
			    (strcmp(argv[1], "--help") == 0)
			) {
				usage();
				return 0;
			} else {
				printf("\nError: Check Hamming Algorithm\n");
				usage();
				return -1;
			}
		}

		if (argc == 2) {
			printf("\nInput string not provided");
			printf("\nGenerating a random string");
			printf("\n-------------------------------------------");
			printf("\n* Hash_DRBG library invoked");
			printf("\n* Seed being taken from /dev/random");
			printf("\n-------------------------------------------");
			/* Generate Random bytes using hash_debg */
			ret = get_rand_bytes(drv_hex, DRV_SIZE_BYTES);
			if (ret != 0) {
				printf("\nRandom bytes generation failed\n");
				exit(1);
			}
			printf("\nRandom Key Genearted is:\n");
			for (i = 0; i < DRV_SIZE_BYTES; i++)
				printf("%.2x", drv_hex[i]);
		} else {
		if (strlen(argv[2]) == 2 * DRV_SIZE_BYTES) {
			/*check if string is valid hexadecimal string*/
			ret = check_string(argv[2]);
			if (ret == -1) {
				printf
				    ("\nError: Input string is not having "
					"valid hexadecimal character\n");
				return -1;
			}
			for (i = 0; i < 2 * DRV_SIZE_BYTES; i = i + 2) {
				drv_in[0] = argv[2][i + 0];
				drv_in[1] = argv[2][i + 1];
				l = i / 2;
				drv_hex[l] = (u8)strtoul(drv_in, NULL, 16);
			}
		} else {
			printf("\nError: Invalid Input string Length\n");
			usage();
			return -1;

		}
		}
	} else {
		printf("\nError: Wrong Usage\n");
		usage();
		return -1;
	}

	/*Create array of bits to be used as an input*/
	/*Also reversing the bytes provided as input*/
	for (i = 0; i < DRV_SIZE_BYTES; i++) {

		l = 0x80;
		for (j = 0; j < 8; j++) {
			num[DRV_SIZE_BYTES * 8 - i * 8 - 1 - j] =
			    (drv_hex[i]) & (l);
			l = l >> 1;
		}
	}

#ifdef DEBUG
	for (i = 0; i < DRV_SIZE_BITS; i++)
		printf("%d", num[i]);
#endif
	/*generate Hamming code and replace bits in DRV key*/
	if (hamming_algo == HAMMING_B)
		generate_code_bits_hamming_B(num);
	else
		generate_code_bits_hamming_A(num);

	printf("\nDRV[63:0] after Hamming Code is:\n");
	for (i = 0; i < DRV_SIZE_BYTES; i++)
		printf("%.2x", drv_hex[i]);

	/* Print the DRV bits
	 * SFP version 1.0 - SFP version 3.2.2:
	 * Hamming Algo B or A1
	 * DRVR0: 31:0
	 * DRVR1: 63:32
	 *
	 * SFP version 3.3 - SFP version 3.5 (i.e. all layerscape products):
	 * Hamming Algo A2
	 * DRVR0: 63:32
	 * DRVR1: 31:0
	 */
	if (hamming_algo == HAMMING_A2)
		print_drv_a2();
	else
		print_drv_a1_b();

	printf("\n");
	return 0;
}
