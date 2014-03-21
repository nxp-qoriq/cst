/** @file
 * common.h
 */

/* Copyright (c) 2011,2012 Freescale Semiconductor, Inc.
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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <ctype.h>

#define BOOT_SIG		0x424f4f54      /*offset 0x40-43 */
#define BARKER_LEN		0x4
#define SHA256_DIGEST_LENGTH	32
#define NID_sha256		672

#define PRI_KEY_FILE		"srk.pri"
#define PUB_KEY_FILE		"srk.pub"
#define MAX_NUM_KEYS		4
#define MAX_LINE_SIZE		256
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

char *tar[][2] = { {"NOR_8B", "b"},
{"NOR_16B", "f"},
{"NAND_8B_512", "8"},
{"NAND_8B_2K", "9"},
{"NAND_8B_4K", "a"},
{"NAND_16B_512", "c"},
{"NAND_16B_2K", "d"},
{"NAND_16B_4K", "e"},
{"MMC", "7"},
{"SD", "7"},
{"SDHC", "7"},
{"SPI", "6"},
{"LAST", "0"}
};

struct input_field {
	char *value[4];
	int count;
};


struct input_field file_field;	
char line_data[MAX_LINE_SIZE];

int cal_line_size(FILE *fp)
{
	u32 ctr = 0;
	char ch = 'a';
	while (ch != EOF) {

		if ((ch == '\n') && (ctr != 1))
			return ctr;

		ch = fgetc(fp);
		ctr++;
	}
return 0;
}


void get_field_from_file(char *line, char *field_name)
{

	int i = 0;
	char delims[] = ",;=";
	char *result = NULL;

	result = strtok(line, delims);
	while (result != NULL) {
		if (i == 5) {

			printf
			    ("Error. Invalid no. of entries found in input "
				"file for %s. Refer usage\n", field_name);
			exit(1);
		}
		result = strtok(NULL, delims);
		file_field.value[i] = result;
		i++;
	}
	file_field.count = i - 1;

}


void remove_whitespace(char *line)
{

	char *p1 = line;
	char *p2 = line;
	p1 = line;
	while (*p1 != 0) {
		if (*p1 == '{' || *p1 == '}' || *p1 == '[' || *p1 == ']' ||
		    isspace(*p1) || *p1 == '(' || *p1 == ')') {
			++p1;
		} else
			*p2++ = *p1++;
	}
	*p2 = 0;
}


void find_value_from_file(char *field_name, FILE * fp)
{
	int line_size = 0, i = 0;

	file_field.value[0] = NULL;
	file_field.value[1] = NULL;
	file_field.value[2] = NULL;
	file_field.value[3] = NULL;
	file_field.count = 0;

	fseek(fp, 0, SEEK_SET);
	line_size = cal_line_size(fp);
	fseek(fp, -line_size, SEEK_CUR);

	while (fread(line_data, 1, line_size, fp)) {
		i = 0;
		*(line_data + line_size) = '\0';
		remove_whitespace(line_data);
		if ((strstr(line_data, field_name)) && (*line_data != '#')) {
			get_field_from_file(line_data, field_name);
			goto exit1;
		}
		line_size = cal_line_size(fp);

		fseek(fp, -line_size, SEEK_CUR);
	}
	file_field.count = -1;
exit1:
	if (((strcmp(field_name, "PLATFORM") == 0) ||
	     (strcmp(field_name, "ESBC") == 0) ||
	     (strcmp(field_name, "KEY_SELECT") == 0) ||
	     (strcmp(field_name, "ENTRY_POINT") == 0) ||
	     (strcmp(field_name, "IMAGE_TARGET") == 0) ||
	     (strcmp(field_name, "OEM_UID") == 0) ||
	     (strcmp(field_name, "FSL_UID") == 0) ||
	     (strcmp(field_name, "OUTPUT_HDR_FILENAME") == 0) ||
	     (strcmp(field_name, "SG_TABLE_ADDR") == 0) ||
	     (strcmp(field_name, "HK_AREA_POINTER") == 0) ||
	     (strcmp(field_name, "HK_AREA_SIZE") == 0) ||
	     (strcmp(field_name, "SFP_WP") == 0) ||
	     (strcmp(field_name, "SEC_IMAGE") == 0) ||
	     (strcmp(field_name, "ESBC_HDRADDR") == 0) ||
	     (strcmp(field_name, "ESBC_HDRADDR_SEC_IMAGE") == 0) ||
	     (strcmp(field_name, "VERBOSE") == 0)
	    ) && (file_field.count > 1)) {
		printf("Error. Invalid usage. Only one field required in "
			"input file for %s. Refer usage\n", field_name);
		exit(1);
	}

}

int check_target(char *target_name, uint32_t *targetid)
{
	int i = 0;
	while (strcmp(tar[i][0], "LAST")) {
		if (strcmp(tar[i][0], target_name) == 0) {
			*targetid = strtoul(tar[i][1], 0, 16);
			return 0;
		}
		i++;
	}
	return -1;
}

#endif
