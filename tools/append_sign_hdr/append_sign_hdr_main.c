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

#include <global.h>
#include <parse_utils.h>

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
	char ch;
	int ret, i;
	uint32_t len;
	FILE *fp, *fhdr, *fsign;
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
	 * OUTPUT_HDR_FILENAME
	 * RSA_SIGN_FILENAME
	 */
	fp = fopen(gd.input_file, "r");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", gd.input_file);
		return FAILURE;
	}

	ret = fill_gd_input_file("OUTPUT_HDR_FILENAME", fp);
	ret = fill_gd_input_file("RSA_SIGN_FILENAME", fp);
	fclose(fp);
	if (ret)
		return ret;

	/* Open the OUTPUT_HDR_FILENAME in 'Append Binary' Mode */
	fhdr = fopen(gd.hdr_file_name, "ab");
	if (fhdr == NULL) {
		printf("Error in opening the file: %s\n",
			gd.hdr_file_name);
		return FAILURE;
	}

	len = get_file_size(gd.rsa_sign_file_name);
	/* Open the RSA_SIGN_FILENAME in 'Read Binary' Mode */
	fsign = fopen(gd.rsa_sign_file_name, "rb");
	if (fsign == NULL) {
		printf("Error in opening the file: %s\n",
			gd.rsa_sign_file_name);
		return FAILURE;
	}

	/* Append the contents of RSA_SIGN_FILENAME to end of
	 * OUTPUT_HDR_FILENAME
	 */
	for (i = 0; i < len; i++) {
		ch = fgetc(fsign);
		if (feof(fsign))
			break;
		fputc(ch, fhdr);
	}

	fclose(fhdr);
	fclose(fsign);

	printf("\n%s is appended with file %s (0x%x)\n\n",
			gd.hdr_file_name, gd.rsa_sign_file_name, len);
	return 0;
}
