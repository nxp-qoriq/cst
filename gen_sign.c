/* This code generates signature on hash using key provided through input.
 */

/* Copyright (c) 2011-2012 Freescale Semiconductor, Inc.
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
/*
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 */
/*
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 */

#define OPENSSL_NO_KRB5

#include <stdio.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <getopt.h>
#include "common.h"

#define SIGN_FILE	"sign.out"
#define KEY_SIZE_BYTES	1024

static void usage_gen_sign(void)
{
	printf("\n./gen_sign [option] HASH_FILE PRIV_KEY_FILE \n\n"
	       "--sign_file SIGN_FILE\tProvide file name for signature"
	       " to be generated as operand.\n\t\t\t");
	printf("SIGN_FILE is generated containing signature calculated\n\t\t\t"
	       "over hash provided through HASH_FILE using private\n\t\t\t"
	       "key provided through PRIV_KEY_FILE. With this\n\t\t\t"
	       "option HASH_FILE and PRIV_KEY_FILE are compulsory\n\t\t\t"
	       "while SIGN_FILE is optional. SIGN_FILE default value\n\t\t\t"
	       "is sign.out\n\n");

	printf("HASH_FILE: name of hash file containing hash over signature"
	       " needs to be calculated.\n");
	printf("PRIV_KEY_FILE: name of key file containing private key.\n\n");

	printf("--help\t\t\t");
	printf("Show this help message and exit.\n");
	exit(1);
}

void hash_sign(char *hash_file, char *priv_file, char *sign_file)
{
	FILE *fhash;
	FILE *fsign;
	FILE *pri_file;
	RSA *pri_key;
	unsigned char sign[KEY_SIZE_BYTES];
	unsigned char hash_val[SHA256_DIGEST_LENGTH];
	u32 fsize, sign_size;

	fhash = fopen(hash_file, "rb");
	if (fhash == NULL) {
		fprintf(stderr, "Error in opening the"
			" file: %s\n", hash_file);
		exit(1);
	}
	fseek(fhash, 0, SEEK_END);
	fsize = ftell(fhash);

	if (fsize != SHA256_DIGEST_LENGTH) {
		printf("Error. Hash size should be 256 bytes.\n");
		exit(1);
	}

	/* Reading hash from hash file*/
	fseek(fhash, 0, SEEK_SET);
	fread((unsigned char *)hash_val, 1, fsize, fhash);

	/* Opening and reading private key from priv file*/
	pri_file = fopen(priv_file, "r");
	if (pri_file == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", priv_file);
		exit(1);
	}

	pri_key = PEM_read_RSAPrivateKey(pri_file, NULL, NULL, NULL);
	if (pri_key == NULL) {
		fprintf(stderr, "Error in reading key from : %s\n", priv_file);
		fclose(pri_file);
		exit(1);
	}

	/* Calculating hash over signature*/
	if (RSA_sign(NID_sha256, hash_val, SHA256_DIGEST_LENGTH, sign,
		     &sign_size, pri_key) != 1) {
		printf("Error in generating signature\n");
		exit(1);
	}

	/* Dumping signature to sign.out file*/
	fsign = fopen(sign_file, "wb");
	if (fsign == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", sign_file);
		exit(1);
	}
	fwrite((unsigned char *)sign, 1, sign_size, fsign);

	fclose(fhash);
	fclose(pri_file);
	fclose(fsign);
	RSA_free(pri_key);
	printf("HEADER file %s created\n", sign_file);
	exit(1);

}

int main(int argc, char **argv)
{
	int c;
	int sign_file_flag;
	static int help_flag;
	char *sign_file = SIGN_FILE;

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, &help_flag, 1},
			{"sign_file", required_argument, 0, 's'},
			{0, 0, 0, 0}
		};
		int option_index = 0;

		c = getopt_long(argc, argv, "s:",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		if (c == 's') {
			sign_file_flag = 1;
			sign_file = optarg;
		}
	}

	/* check if help is called*/
	if (help_flag == 1)
		usage_gen_sign();

	/* Error checking for required input file*/
	if ((sign_file_flag != 1 && argc != 3) ||
	    (sign_file_flag == 1 && argc != 5)) {
		printf("Error.Inavlid Usage. With ./gen_sign"
			" only hash file and private key is required\n");
		usage_gen_sign();
	} else {
		hash_sign(argv[optind], argv[optind + 1], sign_file);
	}

	exit(1);
}
