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
#include <string.h>
#include <unistd.h>

#include <global.h>
#include <taal.h>
#include <parse_utils.h>
#include <crypto_utils.h>

extern struct g_data_t gd;

void print_usage(char *tool)
{
	printf("\nCorrect Usage of Tool is:\n");
	printf("\t%s <input_file>             -- Create Header and Sign\n",
		tool);
	printf("\t%s --hash <input_file>      -- Print SRK Hash Only\n",
		tool);
	printf("\t%s --img_hash <input_file>  -- Create Header w/o Sign\n",
		tool);
}

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
	crypto_print_attribution();

	/* Check the command line argument */
	if ((argc < 2) || (argc > 3)) {
		/* Incorrect Usage */
		printf("\nIncorrect Usage");
		print_usage(argv[0]);
		return FAILURE;
	}
	if ((strcmp(argv[1], "--help") == 0) ||
	   (strcmp(argv[1], "-h") == 0)) {
		print_usage(argv[0]);
		return SUCCESS;
	} else if (strcmp(argv[1], "--hash") == 0) {
		gd.option_srk_hash = 1;
		gd.input_file = argv[2];
	} else if (strcmp(argv[1], "--img_hash") == 0) {
		gd.option_img_hash = 1;
		gd.input_file = argv[2];
	} else if (argc == 3) {
		printf("\nIncorrect Usage");
		print_usage(argv[0]);
		return FAILURE;
	} else {
		gd.input_file = argv[1];
	}

	if (gd.input_file == NULL) {
		/* Incorrect Usage */
		printf("\nIncorrect Usage");
		print_usage(argv[0]);
		return FAILURE;
	}

	printf("\nInput File is %s\n", gd.input_file);

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

	/* TAAL: Create and Calculate Public Key / SRK Hash */
	ret = taal_calc_srk_hash(cfg_taal);
	if (ret != SUCCESS)
		return ret;

	/* If SRK Hash Option is Selected, Skip remaining part of Tool */
	if (gd.option_srk_hash == 0) {
		/* TAAL: Fill the Structures (CSF Header, SG Table) */
		ret = taal_fill_structures(cfg_taal);
		if (ret != SUCCESS)
		return ret;

		/* TAAL: Calculate Image Hash Required for Signature */
		ret = taal_calc_img_hash(cfg_taal);
		if (ret != SUCCESS)
			return ret;

		/* TAAL: Combine Structures to create the Output Header */
		ret = taal_create_hdr(cfg_taal);
		if (ret != SUCCESS)
			return ret;

		/* TAAL: Dump the header fields */
		if (gd.verbose_flag == 1) {
			ret = taal_dump_header(cfg_taal);
			if (ret != SUCCESS)
				return ret;

			printf("\nImage Hash:\n");
			for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
				printf("%02x", gd.img_hash[i]);
		}

		/* Output to user and exit */
		if (gd.option_img_hash == 1) {
			printf("\n\nImage Hash Stored in File: %s",
				gd.img_hash_file_name);
			printf("\nHeader File is w/o Signature appended");
		} else {
			printf("\nHeader File is with Signature appended");
		}
		printf("\nHeader File Created: %s", gd.hdr_file_name);
	}

	printf("\n\nSRK (Public Key) Hash:\n");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", gd.srk_hash[i]);

	printf("\n\n");
	return SUCCESS;
}
