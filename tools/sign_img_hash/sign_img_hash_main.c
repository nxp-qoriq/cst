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
/*
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 */
/*
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>

#include <global.h>
#include <parse_utils.h>
#include <crypto_utils.h>

struct g_data_t gd;
/***************************************************************************
 * Function	:	main
 * Arguments	:	argc - Argument Count
 *			argv - Argumnet List
 * Return	:	SUCCESS or FAILURE
 * Description	:	Main function where execution starts
 ***************************************************************************/
int main(int argc, char **argv)
{
	int ret;
	uint32_t len;
	FILE *fp, *fpriv, *fsign, *fhash;
	RSA *priv_key;

	/* Initialization of Structures to 0 */
	memset(&gd, 0, sizeof(struct g_data_t));

	/* Check the command line argument */
	if (argc != 2) {
		/* Incorrect Usage */
		printf("\nIncorrect Usage");
		printf("\nCorrect Usage: %s <input_file>\n", argv[0]);
		return 1;
	} else if ((strcmp(argv[1], "--help") == 0) ||
		   (strcmp(argv[1], "-h") == 0)) {
		/* Command Help */
		printf("\nCorrect Usage: %s <input_file>\n", argv[0]);
		return 0;
	} else {
		/* Input File passed as Argument */
		gd.input_file = argv[1];
	}

	/* Open The Input File and get the names of following:
	 * PRI_KEY
	 * RSA_SIGN_FILENAME
	 * IMAGE_HASH_FILENAME
	 */
	fp = fopen(gd.input_file, "r");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", gd.input_file);
		return FAILURE;
	}

	ret = fill_gd_input_file("PRI_KEY", fp);
	ret |= fill_gd_input_file("IMAGE_HASH_FILENAME", fp);
	ret |= fill_gd_input_file("RSA_SIGN_FILENAME", fp);
	fclose(fp);

	if (ret)
		return ret;

	/* Read the Value of Image Hash from the file */
	fhash = fopen(gd.img_hash_file_name, "rb");
	if (fhash == NULL) {
		printf("Error in opening the file: %s\n",
			gd.img_hash_file_name);
		return FAILURE;
	}
	ret = fread(gd.img_hash, 1, SHA256_DIGEST_LENGTH, fhash);
	fclose(fhash);
	if (ret == 0) {
		printf("Error in Reading from file");
		return FAILURE;
	}

	/* Open the private Key */
	fpriv = fopen(gd.priv_key_name, "r");
	if (fpriv == NULL) {
		printf("Error in file opening %s:\n", gd.priv_key_name);
		return FAILURE;
	}

	priv_key = PEM_read_RSAPrivateKey(fpriv, NULL, NULL, NULL);
	fclose(fpriv);
	if (priv_key == NULL) {
		printf("Error in key reading %s:\n", gd.priv_key_name);
		return FAILURE;
	}

	/* Sign the Image Hash with Private Key */
	len = RSA_size(priv_key);
	ret = RSA_sign(NID_sha256, gd.img_hash, SHA256_DIGEST_LENGTH,
			gd.rsa_sign, &len,
			priv_key);
	if (ret != 1) {
		printf("Error in Signing\n");
		return FAILURE;
	}

	/* Store the RSA Signature in RSA_SIGN_FILENAME */
	fsign = fopen(gd.rsa_sign_file_name, "wb");
	if (fsign == NULL) {
		printf("Error in opening the file: %s\n",
			gd.rsa_sign_file_name);
		return FAILURE;
	}

	ret = fwrite(gd.rsa_sign, 1, len, fsign);
	fclose(fsign);
	if (ret == 0) {
		printf("Error in Writing to file\n");
		return FAILURE;
	}

	printf("Signature Length = %x\n", len);
	printf("Hash in %s is signed with %s\n",
			gd.img_hash_file_name, gd.priv_key_name);
	printf("Signature is stored in file : %s\n",
			gd.rsa_sign_file_name);
	return 0;
}
