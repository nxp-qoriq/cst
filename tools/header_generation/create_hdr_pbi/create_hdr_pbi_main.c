/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright 2018 NXP
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

struct g_data_t gd;

static struct option long_options[] = {
	{"verbose", no_argument, &gd.verbose_flag, 1},
	{"hash", no_argument, &gd.option_srk_hash, 1},
	{"img_hash", no_argument, &gd.option_img_hash, 1},
	{"out", required_argument, 0, 'h'},
	{"in", required_argument, 0, 'i'},
	{"sben", no_argument, &gd.option_sb_en, 1},
	{"help", no_argument, &gd.help_flag, 1},
	{0, 0, 0, 0}
};
static void print_usage(char *tool)
{
	printf("\nCorrect Usage of Tool is:\n");
	printf("\n%s [options] <input_file>\n", tool);
	printf("\t--verbose    Display header Info after Creation. This option is invalid for TA2 platform\n");
	printf("\t--out <file> Output file name\n");
	printf("\t--in <file>  Input RCW file.\n");
	printf("\t--sben       Enable SB_EN in the RCW.\n");
	printf("\t--hash       Print the SRK(Public key) hash. This option is invalid for TA2 platform\n");
	printf("\t--img_hash   Header is generated without Signature.\n");
	printf("\t             Image Hash is stored in a separate file. This option is invalid for TA2 platform\n");
	printf("\t--help       Show the Help for Tool Usage.\n");
	printf("\n<input_file>   Contains all information required by tool");
	printf("\n\n");
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
	enum cfg_taal cfg_taal;
	int ret = 0, c;
	int option_index;
	/* Initialization of Global Structure to 0 */
	memset(&gd, 0, sizeof(struct g_data_t));

	/* Check the command line argument */
	c = 0;
	option_index = 0;
	while (c != -1) {
		c = getopt_long(argc, argv, "", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'h':
				printf("file name is %s\n", optarg);
				strcpy(gd.rcw_op_fname, optarg);
				gd.rcw_opfile_flag = 1;
				break;
			case 'i':
				printf("file name is %s\n", optarg);
				strcpy(gd.rcw_fname, optarg);
				gd.rcw_file_flag = 1;
				break;
			default:
				break;
		}
	}

	if (gd.help_flag == 1) {
		printf("\n\t#----------------------------------------------------#");
		printf("\n\t#-------         --------     --------        -------#");
		printf("\n\t#------- CST (Code Signing Tool) Version 2.0  -------#");
		printf("\n\t#-------         --------     --------        -------#");
		printf("\n\t#----------------------------------------------------#");
		printf("\n");

		print_usage(argv[0]);
		return SUCCESS;
	}

	if (optind != argc - 1) {
		printf("\nError!! Input File is not Specified");
		print_usage(argv[0]);
		return FAILURE;
	}

	if (optind != argc - 1) {
		printf("\nError!! Input File is not Specified");
		return FAILURE;
	}
	gd.input_file = argv[optind];
	/* Get the Trust Arch Version from Input File */
	cfg_taal = get_ta_from_file(argv[optind]);
	/*initialize optind to 1 for futuree parsing using getopt_long()*/
	optind = 1;
	if (cfg_taal == TA_UNKNOWN_MAX) {
		/* Invalid Platform Name in Input File */
		printf("\n Unknown/Missing Platform name in Input file\n");
		return FAILURE;
	}
	switch (cfg_taal) {
	case TA_2_0_PBL:
	case TA_2_1_ARM8:
	case TA_2_1_ARM7:
		ret = create_pbi_ta2(argc, argv);
		break;
	default:
		ret = create_hdr(argc, argv);
		break;
	}

	if (ret != SUCCESS)
		return ret;

	return 0;
}
