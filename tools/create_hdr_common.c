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
#include <taal.h>
#include <parse_utils.h>
#include <crypto_utils.h>

extern struct g_data_t gd;
/***************************************************************************
 * Function	:	create_hdr
 * Arguments	:	argc - Argument Count
 *			argv - Argumnet List
 * Return	:	SUCCESS or FAILURE
 * Description	:	Main function where execution starts
 ***************************************************************************/
int create_hdr(int argc, char **argv)
{
	enum cfg_taal cfg_taal;
	int ret, i;

	/* Initialization of Global Structure to 0 */
	memset(&gd, 0, sizeof(struct g_data_t));

	/* Print the Attribution */
	print_attribution();

	/* Check the command line argument */
	if (argc != 2) {
		/* Incorrect Usage */
		printf("\nIncorrect Usage");
		printf("\nCorrect Usage: %s <input_file>\n", argv[0]);
		return FAILURE;
	} else if ((strcmp(argv[1], "--help") == 0) ||
		   (strcmp(argv[1], "-h") == 0)) {
		/* Command Help */
		printf("\nCorrect Usage: %s <input_file>\n", argv[0]);
		return SUCCESS;
	} else {
		/* Input File passed as Argument */
		gd.input_file = argv[1];
		printf("\nInput File is %s\n", gd.input_file);
	}

	/* Get the Trust Arch Version from Input File */
	cfg_taal = get_ta_from_file(gd.input_file);

	if (cfg_taal == TA_UNKNOWN_MAX) {
		/* Invalid Platform Name in Input File */
		printf("\n Unknown/Missing Platform name in Input file\n");
		return FAILURE;
	}

	/* TAAL: Parse the Input File and Populate the Global Structure */
	ret = taal_parse_input_file(cfg_taal);
	if (ret != SUCCESS)
		return ret;

	/* TAAL: Fill the Structures (CSF Header, SRK, SG Table) */
	ret = taal_fill_structures(cfg_taal);
	if (ret != SUCCESS)
		return ret;

	/* TAAL: Combine Structures to create the Output Header */
	ret = taal_create_hdr(cfg_taal);
	if (ret != SUCCESS)
		return ret;

	/* TAAL: Calculate Image Hash Required for Signature */
	ret = taal_calc_img_hash(cfg_taal);
	if (ret != SUCCESS)
		return ret;

	/* TAAL: Calculate Public Key / SRK Hash */
	ret = taal_calc_srk_hash(cfg_taal);
	if (ret != SUCCESS)
		return ret;

	/* TAAL: Dump the header fields */
	if (gd.verbose_flag == 1) {
		ret = taal_dump_header(cfg_taal);
		if (ret != SUCCESS)
			return ret;
		printf("\nImage Hash (To Be signed using Private Key):\n");
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02x", gd.img_hash[i]);
	}

	/* Output to user and exit */
	printf("\n\nImage Hash Stored in File: %s", gd.img_hash_file_name);
	printf("\n\nHeader File Created: %s", gd.hdr_file_name);
	printf("\n\nSRK (Public Key) Hash:\n");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", gd.srk_hash[i]);

	printf("\n");
	return SUCCESS;
}
