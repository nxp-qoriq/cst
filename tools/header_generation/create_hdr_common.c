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
#include <getopt.h>

#include <global.h>
#include <taal.h>
#include <parse_utils.h>
#include <crypto_utils.h>

extern struct g_data_t gd;

static struct option long_options[] = {
	{"verbose", no_argument, &gd.verbose_flag, 1},
	{"hash", no_argument, &gd.option_srk_hash, 1},
	{"img_hash", no_argument, &gd.option_img_hash, 1},
	{"help", no_argument, &gd.help_flag, 1},
	{0, 0, 0, 0}
};

void print_usage(char *tool)
{
	printf("\nCorrect Usage of Tool is:\n");
	printf("\n%s [options] <input_file>\n", tool);
	printf("\t--verbose    Display header Info after Creation\n");
	printf("\t--hash       Print the SRK(Public key) hash.\n");
	printf("\t--img_hash   Header is generated without Signature.\n");
	printf("\t             Image Hash is stored in a separate file.\n");
	printf("\t--help       Show the Help for Tool Usage.\n");
	printf("\n<input_file>   Contains all information required by tool");
	printf("\n\n");
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
	int ret, i, c;
	int option_index;
	uint32_t *srk;

	printf("\n\t#----------------------------------------------------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#------- CST (Code Signing Tool) Version 2.0  -------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#----------------------------------------------------#");
	printf("\n");

	/* Initialization of Global Structure to 0 */
	memset(&gd, 0, sizeof(struct g_data_t));

	/* Check the command line argument */
	c = 0;
	option_index = 0;
	while (c != -1)
		c = getopt_long(argc, argv, "", long_options, &option_index);

	if (gd.help_flag == 1) {
		print_usage(argv[0]);
		return SUCCESS;
	}
		
	if (optind != argc - 1) {
		printf("\nError!! Input File is not Specified");
		print_usage(argv[0]);
		return FAILURE;
	}

	/* Print the Attribution */
	crypto_print_attribution();

	gd.input_file = argv[optind];
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
		if (gd.verbose_flag) {
			ret = taal_dump_header(cfg_taal);
			if (ret != SUCCESS)
				return ret;

			printf("\nImage Hash:\n");
			for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
				printf("%02x", gd.img_hash[i]);
		}

		printf("\n\n************************************************");
		/* Check if option for img_has is selected */
		if (gd.option_img_hash == 1) {
			ret = create_img_hash_file();
			if (ret != SUCCESS)
				return ret;
			printf("\n* Image Hash Stored in File: %s",
				gd.img_hash_file_name);
			printf("\n* Header File is w/o Signature appended");
		} else {
			/* Calculate the Signature over Image Hash */
			ret = calculate_signature();
			if (ret != SUCCESS)
				return ret;

			/* Append Signature to Header File */
			ret = append_signature();
			if (ret != SUCCESS)
				return ret;
			printf("\n* Header File is with Signature appended");
		}
		printf("\n************************************************\n");
		printf("\nHeader File Created: %s", gd.hdr_file_name);
	}

	if (gd.srk_hash_flag == 1) {
		printf("\n\nSRK (Public Key) Hash:\n");
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02x", gd.srk_hash[i]);

		srk = (uint32_t *)gd.srk_hash;
		for (i = 0; i < SHA256_DIGEST_LENGTH / sizeof(uint32_t); i++)
			printf("\n\t SFP SRKHR%i = %08x", i, htonl(srk[i]));
	} else {
		printf("\nSRK (Public Key) Hash Not Available");
	}

	printf("\n\n");
	return SUCCESS;
}

/***************************************************************************
 * Function	:	create_srk_calc_hash
 * Arguments	:	max_keys - Maximum Number of entries in SRK Table
 * Return	:	SUCCESS or FAILURE
 * Description	:	Creates the SRK Table and calculate the hash
 ***************************************************************************/
int create_srk_calc_hash(uint32_t max_keys)
{
	int i, ret;
	uint32_t key_len;
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];

	/* Check if Num of Entries and Key Select is Correct */
	ret = FAILURE;

	if (gd.srk_flag == 0)
		max_keys = 1;

	if ((gd.num_srk_entries > max_keys) ||
	(gd.num_srk_entries == 0)) {
		printf("Invalid Number of Keys\n");
		return FAILURE;
	}

	if ((gd.srk_sel > gd.num_srk_entries) ||
	    (gd.srk_sel == 0)) {
		printf("Invalid Key Select\n");
		return FAILURE;
	}

	if (gd.option_img_hash == 0) {
		if (gd.num_srk_entries != gd.num_pri_key) {
			printf("Public and Private Key Count Mismatch\n");
			return FAILURE;
		}
	}

	/* Read all the public Keys and Store in SRK Table */
	for (i = 0; i < gd.num_srk_entries; i++) {
		key_len = 0;
		ret = crypto_extract_pub_key(gd.pub_fname[i],
					&key_len,
					gd.key_table[i].pkey);
		if (gd.hton_flag == 0)
			gd.key_table[i].key_len = key_len;
		else
			gd.key_table[i].key_len = htonl(key_len);
		if (ret != SUCCESS)
			break;
	}

	/* Update the size of SRK Table */
	gd.srk_size = gd.num_srk_entries * sizeof(struct srk_table_t);

	/* Calculate the Hash if SRK/ Public Key */
	crypto_hash_init(ctx);

	if (gd.srk_flag == 1)
		crypto_hash_update(ctx, gd.key_table, gd.srk_size);
	else {
		gd.pkey = gd.key_table[0].pkey;

		if (gd.hton_flag == 0)
			gd.key_len = gd.key_table[0].key_len;
		else
			gd.key_len = htonl(gd.key_table[0].key_len);

		crypto_hash_update(ctx, gd.pkey, gd.key_len);
	}

	crypto_hash_final(gd.srk_hash, ctx);
	gd.srk_hash_flag = 1;

	return ret;
}

/***************************************************************************
 * Function	:	parse_input_file
 * Arguments	:	list - Pointer to array of field names
 *			num_list - Number of elements in list
 * Return	:	SUCCESS or FAILURE
 * Description	:	Parses all the fields in the list and fills the info
 *			in Global Structure
 ***************************************************************************/
int parse_input_file(char **list, uint32_t num_list)
{
	int i, ret = 0;
	FILE *fp;
	fp = fopen(gd.input_file, "r");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", gd.input_file);
		return FAILURE;
	}

	for (i = 0; i < num_list; i++) {
		ret = fill_gd_input_file(list[i], fp);
		if (ret != SUCCESS)
			break;
	}

	fclose(fp);
	return ret;
}

/***************************************************************************
 * Function	:	calculate_signature
 * Arguments	:	NONE
 * Return	:	SUCCESS or FAILURE
 * Description	:	Calculate Signature over Image Hash
 ***************************************************************************/
int calculate_signature(void)
{
	int ret;
	ret = crypto_rsa_sign(gd.img_hash, SHA256_DIGEST_LENGTH,
		gd.rsa_sign, &gd.rsa_size, gd.pri_fname[gd.srk_sel - 1]);
	if (ret != SUCCESS)
		printf("Error in Signing\n");

	return ret;
}

/***************************************************************************
 * Function	:	append_signature
 * Arguments	:	NONE
 * Return	:	SUCCESS or FAILURE
 * Description	:	Appends Signature to end of HDR
 ***************************************************************************/
int append_signature(void)
{
	int i;
	FILE *fhdr;
	char ch;

	/* Open the OUTPUT_HDR_FILENAME in 'Append Binary' Mode */
	fhdr = fopen(gd.hdr_file_name, "ab");
	if (fhdr == NULL) {
		printf("Error in opening the file: %s\n",
			gd.hdr_file_name);
		return FAILURE;
	}

	for (i = 0; i < gd.rsa_size; i++) {
		ch = gd.rsa_sign[i];
		fputc(ch, fhdr);
	}

	fclose(fhdr);

	return SUCCESS;
}

/***************************************************************************
 * Function	:	create_img_hash_file
 * Arguments	:	NONE
 * Return	:	SUCCESS or FAILURE
 * Description	:	Writes Image Hash to a file
 ***************************************************************************/
int create_img_hash_file(void)
{
	int ret;
	FILE *fp;

	fp = fopen(gd.img_hash_file_name, "wb");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n",
			gd.img_hash_file_name);
		return FAILURE;
	}
	ret = fwrite(gd.img_hash, 1, SHA256_DIGEST_LENGTH, fp);
	fclose(fp);

	if (ret == 0) {
		printf("Error in Writing to file");
		return FAILURE;
	}
	return SUCCESS;
}

/*****************************************************************************
 * Error For Unsupported Platforms
 *****************************************************************************/
int error_unsupported(void)
{
	printf("\nError !!! ");
	printf("This tool is not applicable for the Platform specified\n");
	return FAILURE;
}
