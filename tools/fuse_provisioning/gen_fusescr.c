/*
 * Copyright 2018 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the above-listed copyright holders nor the
 *     names of any contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
#include <gen_fusescr.h>

struct g_data_t gd;
static uint8_t barker[] = {0x68, 0x39, 0x27, 0x81};
struct fuse_hdr_t fuse_hdr;

/****************************************************************************
 * API's for PARSING INPUT FILES
 ****************************************************************************/
static char *parse_list[] = {
	"POVDD_GPIO",
	"OTPMK_FLAGS",
	"OTPMK_0",
	"OTPMK_1",
	"OTPMK_2",
	"OTPMK_3",
	"OTPMK_4",
	"OTPMK_5",
	"OTPMK_6",
	"OTPMK_7",
	"SRKH_0",
	"SRKH_1",
	"SRKH_2",
	"SRKH_3",
	"SRKH_4",
	"SRKH_5",
	"SRKH_6",
	"SRKH_7",
	"OEM_UID_0",
	"OEM_UID_1",
	"OEM_UID_2",
	"OEM_UID_3",
	"OEM_UID_4",
	"DCV_0",
	"DCV_1",
	"DRV_0",
	"DRV_1",
	"MC_ERA",
	"DBG_LVL",
	"WP",
	"ITS",
	"NSEC",
	"ZD",
	"K0",
	"K1",
	"K2",
	"K3",
	"K4",
	"K5",
	"K6",
	"FR0",
	"FR1",
	"OUTPUT_FUSE_FILENAME",
	"VERBOSE"
};

#define NUM_PARSE_LIST (sizeof(parse_list) / sizeof(char *))

static struct option long_options[] = {
	{"verbose", no_argument, &gd.verbose_flag, 1},
	{"help", no_argument, &gd.help_flag, 1},
	{0, 0, 0, 0}
};

static void print_usage(char *tool)
{
	printf("\nCorrect Usage of Tool is:\n");
	printf("\n%s [options] <input_file>\n", tool);
	printf("\t--verbose    Display Script Info after Creation\n");
	printf("\t--help       Show the Help for Tool Usage.\n");
	printf("\n<input_file>   Contains all information required by tool");
	printf("\n\n");
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

int fill_fuse_structure(void)
{
	uint8_t otpmk_flags = 0;

	otpmk_flags = (gd.flags >> FLAG_OTPMK_SHIFT) & FLAG_OTPMK_MASK;

	memset(&fuse_hdr, 0, sizeof(struct fuse_hdr_t));

	/* Pouplate the fields in Header */
	fuse_hdr.barker[0] = barker[0];
	fuse_hdr.barker[1] = barker[1];
	fuse_hdr.barker[2] = barker[2];
	fuse_hdr.barker[3] = barker[3];

	/* Fill flags field */
	fuse_hdr.flags = gd.flags;

	if (gd.povdd_gpio > 0)
		fuse_hdr.povdd_gpio = gd.povdd_gpio;

	/* OTPMK flags = 0x2 or 0x6 means user supplied inputs */
	if ((otpmk_flags == 0x2) || (otpmk_flags == 0x6))
		memcpy(fuse_hdr.otpmk, gd.otpmk, sizeof(fuse_hdr.otpmk));

	memcpy(fuse_hdr.srkh, gd.srkh, sizeof(fuse_hdr.srkh));
	memcpy(fuse_hdr.oem_uid, gd.oemuid, sizeof(fuse_hdr.oem_uid));

	fuse_hdr.dcv[0] = gd.dcv[0];
	fuse_hdr.dcv[1] = gd.dcv[1];
	fuse_hdr.drv[0] = gd.drv[0];
	fuse_hdr.drv[1] = gd.drv[1];

	/* Populate OSPR1 and OSPR0 (System configuration) fields */
	fuse_hdr.ospr1 = (((uint32_t)gd.mc_era) << 16) | (uint32_t)gd.dbg_lvl;
	fuse_hdr.sc = gd.scb;

	return SUCCESS;
}

/****************************************************************************
 * API for Creating FUSE FILE
 ****************************************************************************/
int create_fuse_file(void)
{
	int ret;
	FILE *fp;
	uint32_t hdrlen = sizeof(struct fuse_hdr_t);

	/* Create the header file */
	fp = fopen(gd.fuse_op_fname, "wb");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", gd.fuse_op_fname);
		ret = FAILURE;
		goto exit;
	}
	ret = fwrite(&fuse_hdr, 1, hdrlen, fp);
	fclose(fp);

	if (ret == 0) {
		printf("Error in Writing to file");
		ret = FAILURE;
		goto exit;
	}

	ret = SUCCESS;
exit:
	return ret;
}

int main(int argc, char **argv)
{
	enum cfg_taal cfg_taal;
	int ret, c;
	int option_index;

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

	/* Parse input file and populate gd structure */
	gd.hton_flag = 1;
	ret = parse_input_file(parse_list, NUM_PARSE_LIST);
	if (ret != SUCCESS)
		return ret;

	/* Fill fuse header structure */
	ret = fill_fuse_structure();
	if (ret != SUCCESS)
		return ret;

	/* Create fuse file */
	ret = create_fuse_file();
	if (ret != SUCCESS)
		return ret;

	return ret;
}
