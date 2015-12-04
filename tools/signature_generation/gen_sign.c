/* Copyright (c) 2015 Freescale Semiconductor, Inc.
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
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <global.h>
#include <crypto_utils.h>

static void usage_gen_sign(void)
{
	printf("\n./gen_sign [option] <HASH_FILE> <PRIV_KEY_FILE> \n\n"
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

/***************************************************************************
 * Function	:	main
 * Arguments	:	argc - Argument Count
 *			argv - Argumnet List
 * Return	:	SUCCESS or FAILURE
 * Description	:	Main function where execution starts
 ***************************************************************************/
int main(int argc, char **argv)
{
	int ret, c = 0;
	int sign_file_flag = 0;
	static int help_flag;
	char *sign_file = DEFAULT_SIGN_FILE_NAME;
	char *hash_file, *priv_key;
	uint32_t len;
	FILE *fsign, *fhash;
	uint8_t img_hash[SHA256_DIGEST_LENGTH];
	uint8_t rsa_sign[KEY_SIZE_BYTES];

	printf("\n\t#----------------------------------------------------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#------- CST (Code Signing Tool) Version 2.0  -------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#----------------------------------------------------#");
	printf("\n");

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
	if (help_flag == 1) {
		usage_gen_sign();
		return 0;
	}

	/* Error checking for required input file*/
	if ((sign_file_flag != 1 && argc != 3) ||
	    (sign_file_flag == 1 && argc != 5)) {
		printf("Error.Inavlid Usage. With ./gen_sign"
			" only hash file and private key is required\n");
		usage_gen_sign();
		return 1;
	}

	hash_file = argv[optind];
	priv_key = argv[optind + 1];

	/* Read the Value of Image Hash from the file */
	fhash = fopen(hash_file, "rb");
	if (fhash == NULL) {
		printf("Error in opening the file: %s\n", hash_file);
		return FAILURE;
	}
	ret = fread(img_hash, 1, SHA256_DIGEST_LENGTH, fhash);
	fclose(fhash);
	if (ret == 0) {
		printf("Error in Reading from file %s\n", hash_file);
		return FAILURE;
	}

	ret = crypto_rsa_sign(img_hash, SHA256_DIGEST_LENGTH,
			rsa_sign, &len, priv_key);
	if (ret != SUCCESS) {
		printf("Error in Signing\n");
		return FAILURE;
	}

	/* Store the RSA Signature in RSA_SIGN_FILENAME */
	fsign = fopen(sign_file, "wb");
	if (fsign == NULL) {
		printf("Error in opening the file: %s\n", sign_file);
		return FAILURE;
	}

	ret = fwrite(rsa_sign, 1, len, fsign);
	fclose(fsign);
	if (ret == 0) {
		printf("Error in Writing to file\n");
		return FAILURE;
	}

	printf("Signature Length = %x\n", len);
	printf("Hash in %s is signed with %s\n", hash_file, priv_key);
	printf("Signature is stored in file : %s\n", sign_file);

	return 0;
}
