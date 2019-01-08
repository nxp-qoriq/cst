/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright 2016-2019 NXP
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

#include <taal.h>
#include <parse_utils.h>
#include <ta_1_x.h>
#include <ta_2_x.h>
#include <ta_3_x.h>

extern struct input_field file_field;

static ta_struct_t ta_table[] = {
	{ "P4080", TA_1_X_PBL },
	{ "4080", TA_1_X_PBL },
	{ "P3041", TA_1_X_PBL },
	{ "3041", TA_1_X_PBL },
	{ "P2041", TA_1_X_PBL },
	{ "2041", TA_1_X_PBL },
	{ "P5040", TA_1_X_PBL },
	{ "5040", TA_1_X_PBL },
	{ "P5020", TA_1_X_PBL },
	{ "5020", TA_1_X_PBL },

	{ "P1010", TA_1_X_NONPBL },
	{ "1010", TA_1_X_NONPBL },
	{ "BSC9132", TA_1_X_NONPBL },
	{ "9132", TA_1_X_NONPBL },
	{ "9131", TA_1_X_NONPBL },

	{ "T4240", TA_2_0_PBL },
	{ "4240", TA_2_0_PBL },
	{ "T2080", TA_2_0_PBL },
	{ "2080", TA_2_0_PBL },
	{ "T1040", TA_2_0_PBL },
	{ "1040", TA_2_0_PBL },
	{ "T1023", TA_2_0_PBL },
	{ "1023", TA_2_0_PBL },
	{ "B4860", TA_2_0_PBL },
	{ "4860", TA_2_0_PBL },

	{ "C290", TA_2_0_NONPBL },

	{ "LS1020", TA_2_1_ARM7 },
	{ "LS1", TA_2_1_ARM7 },

	{ "LS1043", TA_2_1_ARM8 },
	{ "LS1012", TA_2_1_ARM8 },
	{ "LS1046", TA_2_1_ARM8 },

	{ "LS2080", TA_3_0 },
	{ "LS2085", TA_3_0 },

	{ "LS2088", TA_3_1 },
	{ "LS1088", TA_3_1 },

	{ "LX2160", TA_3_2 },
	{ "LS1028", TA_3_2 },
};

#define NUM_TA_TABLE (sizeof(ta_table) / sizeof(ta_struct_t))

/***************************************************************************
 * Global Arry of Function Pointer Structure
 ***************************************************************************/
static struct taal_t taal[] = {
	/* TA_1_X_PBL */
	{
		parse_input_file_ta_1_x_pbl,
		fill_structure_ta_1_x_pbl,
		create_header_ta_1_x_pbl,
		calc_img_hash_ta_1_x_pbl,
		calc_srk_hash_ta_1_x_pbl,
		dump_hdr_ta_1_x_pbl,
	},
	/* TA_1_X_NONPBL */
	{
		parse_input_file_ta_1_x_nonpbl,
		fill_structure_ta_1_x_nonpbl,
		create_header_ta_1_x_nonpbl,
		calc_img_hash_ta_1_x_nonpbl,
		calc_srk_hash_ta_1_x_nonpbl,
		dump_hdr_ta_1_x_nonpbl,
	},
	/* TA_2_0_PBL */
	{
		parse_input_file_ta_2_0_pbl,
		fill_structure_ta_2_0_pbl,
		create_header_ta_2_0_pbl,
		calc_img_hash_ta_2_0_pbl,
		calc_srk_hash_ta_2_0_pbl,
		dump_hdr_ta_2_0_pbl,
	},
	/* TA_2_0_NONPBL */
	{
		parse_input_file_ta_2_0_nonpbl,
		fill_structure_ta_2_0_nonpbl,
		create_header_ta_2_0_nonpbl,
		calc_img_hash_ta_2_0_nonpbl,
		calc_srk_hash_ta_2_0_nonpbl,
		dump_hdr_ta_2_0_nonpbl,
	},
	/* TA_2_1_ARM7 */
	{
		parse_input_file_ta_2_1_arm7,
		fill_structure_ta_2_1_arm7,
		create_header_ta_2_1_arm7,
		calc_img_hash_ta_2_1_arm7,
		calc_srk_hash_ta_2_1_arm7,
		dump_hdr_ta_2_1_arm7,
	},
	/* TA_2_1_ARM8 */
	{
		parse_input_file_ta_2_1_arm8,
		fill_structure_ta_2_1_arm8,
		create_header_ta_2_1_arm8,
		calc_img_hash_ta_2_1_arm8,
		calc_srk_hash_ta_2_1_arm8,
		dump_hdr_ta_2_1_arm8,
	},
	/* TA_3_0 */
	{
		parse_input_file_ta_3_0,
		fill_structure_ta_3_0,
		create_header_ta_3_0,
		calc_img_hash_ta_3_0,
		calc_srk_hash_ta_3_0,
		dump_hdr_ta_3_0,
	},
	/* TA_3_1 */
	{
		parse_input_file_ta_3_1,
		fill_structure_ta_3_1,
		create_header_ta_3_1,
		calc_img_hash_ta_3_1,
		calc_srk_hash_ta_3_1,
		dump_hdr_ta_3_1,
	},
	/* TA_3_2 */
	{
		parse_input_file_ta_3_1,
		fill_structure_ta_3_1,
		create_header_ta_3_1,
		calc_img_hash_ta_3_1,
		calc_srk_hash_ta_3_1,
		dump_hdr_ta_3_1,
	},
	/* TA_UNKNOWN_MAX */
	{
		NULL, NULL, NULL, NULL, NULL, NULL
	}
};
	
/***************************************************************************
 * Function	:	taal_parse_input_file
 * Arguments	:	ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Parse the Input File and Populate the Global Structure
 ***************************************************************************/
int taal_parse_input_file(enum cfg_taal ta)
{
	if (taal[ta].parse_input_file)
		return (*taal[ta].parse_input_file)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	taal_fill_structures
 * Arguments	:	ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Fill the Structures (CSF Header, SRK, SG Table)
 ***************************************************************************/
int taal_fill_structures(enum cfg_taal ta)
{
	if (taal[ta].fill_structure)
		return (*taal[ta].fill_structure)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	taal_create_hdr
 * Arguments	:	ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Combine Structures to create the Output Header
 ***************************************************************************/
int taal_create_hdr(enum cfg_taal ta)
{
	if (taal[ta].create_header)
		return (*taal[ta].create_header)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	taal_calc_img_hash
 * Arguments	:	ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Calculate Image Hash Required for Signature
 ***************************************************************************/
int taal_calc_img_hash(enum cfg_taal ta)
{
	if (taal[ta].calc_img_hash)
		return (*taal[ta].calc_img_hash)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	taal_calc_srk_hash
 * Arguments	:	ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Calculate Public Key / SRK Hash
 ***************************************************************************/
int taal_calc_srk_hash(enum cfg_taal ta)
{
	if (taal[ta].calc_srk_hash)
		return (*taal[ta].calc_srk_hash)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	taal_dump_header
 * Arguments	:	ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Dump the header fields
 ***************************************************************************/
int taal_dump_header(enum cfg_taal ta)
{
	if (taal[ta].dump_hdr)
		return (*taal[ta].dump_hdr)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	get_ta_from_file
 * Arguments	:	file_name - Input File Name
 * Return	:	TA Type
 * Description	:	Parse PLATFORM from input file and return TA_TYPE
 ***************************************************************************/
enum cfg_taal get_ta_from_file(char *file_name)
{
	int i = 0;
	char *plat_name;

	FILE *fp;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", file_name);
		exit(EXIT_FAILURE);
	}

	/* Parse Platform from input file */
	find_value_from_file("PLATFORM", fp);
	if (file_field.count == 1) {
		plat_name = file_field.value[0];
		for (i = 0; i < NUM_TA_TABLE; i++) {
			if (strcmp(ta_table[i].plat_name, plat_name) == 0) {
				fclose(fp);
				return ta_table[i].ta_type;
			}
		}
	} else {
		fprintf(stderr, "Unable to Get PLATFORM from %s\n", file_name);
		fclose(fp);
		exit(EXIT_FAILURE);
	}

	fclose(fp);
	return TA_UNKNOWN_MAX;
}
