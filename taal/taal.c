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

#include <taal.h>
#include <parse_utils.h>
#include <ta_3_x.h>

extern struct input_field file_field;

static ta_struct_t ta_table[] = {
	{ "LS2085", TA_3_0 },
	{ "LS2088", TA_3_1 },
	{ "LS1088", TA_3_1 },
};

#define NUM_TA_TABLE (sizeof(ta_table) / sizeof(ta_struct_t))

/***************************************************************************
 * Function	:	taal_init
 * Arguments	:	taal - TAAL struct
 * Return	:	void
 * Description	:	Sets the function pointers for all API's for various
 *			TA's
 ***************************************************************************/
void taal_init(struct taal_t *taal)
{
	taal[TA_3_0].parse_input_file		= TA_3_0_PARSE;
	taal[TA_3_0].fill_structure		= TA_3_0_FILL;
	taal[TA_3_0].create_header		= TA_3_0_CREATE;
	taal[TA_3_0].calc_img_hash		= TA_3_0_IMG_HASH;
	taal[TA_3_0].calc_srk_hash		= TA_3_0_SRK_HASH;
	taal[TA_3_0].dump_hdr			= TA_3_0_DUMP;

	taal[TA_3_1].parse_input_file		= TA_3_1_PARSE;
	taal[TA_3_1].fill_structure		= TA_3_1_FILL;
	taal[TA_3_1].create_header		= TA_3_1_CREATE;
	taal[TA_3_1].calc_img_hash		= TA_3_1_IMG_HASH;
	taal[TA_3_1].calc_srk_hash		= TA_3_1_SRK_HASH;
	taal[TA_3_1].dump_hdr			= TA_3_1_DUMP;
}

/***************************************************************************
 * Function	:	taal_parse_input_file
 * Arguments	:	taal - TAAL struct
 *			ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Parse the Input File and Populate the Global Structure
 ***************************************************************************/
int taal_parse_input_file(struct taal_t *taal, enum cfg_taal ta)
{
	if (taal[ta].parse_input_file)
		return (*taal[ta].parse_input_file)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	taal_fill_structures
 * Arguments	:	taal - TAAL struct
 *			ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Fill the Structures (CSF Header, SRK, SG Table)
 ***************************************************************************/
int taal_fill_structures(struct taal_t *taal, enum cfg_taal ta)
{
	if (taal[ta].fill_structure)
		return (*taal[ta].fill_structure)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	taal_create_hdr
 * Arguments	:	taal - TAAL struct
 *			ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Combine Structures to create the Output Header
 ***************************************************************************/
int taal_create_hdr(struct taal_t *taal, enum cfg_taal ta)
{
	if (taal[ta].create_header)
		return (*taal[ta].create_header)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	taal_calc_img_hash
 * Arguments	:	taal - TAAL struct
 *			ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Calculate Image Hash Required for Signature
 ***************************************************************************/
int taal_calc_img_hash(struct taal_t *taal, enum cfg_taal ta)
{
	if (taal[ta].calc_img_hash)
		return (*taal[ta].calc_img_hash)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	taal_calc_srk_hash
 * Arguments	:	taal - TAAL struct
 *			ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Calculate Public Key / SRK Hash
 ***************************************************************************/
int taal_calc_srk_hash(struct taal_t *taal, enum cfg_taal ta)
{
	if (taal[ta].calc_srk_hash)
		return (*taal[ta].calc_srk_hash)();

	printf("\n TA Abstraction Layer Error.. Missing Function Definition");
	return FAILURE;
}

/***************************************************************************
 * Function	:	taal_dump_header
 * Arguments	:	taal - TAAL struct
 *			ta - Trust ARCH Type enum
 * Return	:	ERROR or SUCCESS
 * Description	:	Dump the header fields
 ***************************************************************************/
int taal_dump_header(struct taal_t *taal, enum cfg_taal ta)
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
