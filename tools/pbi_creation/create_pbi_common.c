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
#include <crypto_utils.h>

static char *parse_list[] = {
	"SB_EN",
	"BOOT_HO",
	"RCW_PBI_FILENAME",
	"OUTPUT_RCW_PBI_FILENAME",
	"BOOT1_PTR",
	"BOOT_SRC",
};

#define MAX_PBI_DATA_LEN_WORD	16
#define CRC_STOP_CMD_ARM	0x08610040
#define CRC_STOP_CMD_POWERPC	0x08138040

#define BYTE_SWAP_32(word)	((((word) & 0xff000000) >> 24) | \
		(((word) & 0x00ff0000) >>  8) | \
		(((word) & 0x0000ff00) <<  8) | \
		(((word) & 0x000000ff) << 24))

extern struct g_data_t gd;
extern char line_data[];
struct input_field file_field;

#define NUM_PARSE_LIST (sizeof(parse_list) / sizeof(char *))

/***************************************************************************
 * Function	:	ta2_parse_input_file
 * Arguments	:	list - Pointer to array of field names
 *			num_list - Number of elements in list
 * Return	:	SUCCESS or FAILURE
 * Description	:	Parses all the fields in the list and fills the info
 *			in Global Structure
 ***************************************************************************/
int ta2_parse_input_file(char **list, uint32_t num_list)
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
 * Function	:	rcw_sben_boot_ho
 * Arguments	:	fp_rcw_pbi_ip,FILE - Pointer to input file
 *			fp_rcw_pbi_op -  Pointer to input file
 * Return	:	SUCCESS or FAILURE
 * Description	:	modify output file based on the value of sben and bootho
 ***************************************************************************/
int rcw_sben_boot_ho(FILE *fp_rcw_pbi_ip, FILE *fp_rcw_pbi_op)
{
#define NUM_RCW_WORD	18
#define SB_EN_BOOT_HO_WORD	8
#define SB_EN_MASK	0x00200000
#define BOOT_HO_MASK	0x00400000
	int ret, i;
	uint32_t file_len, word;
	/* Get file size */
	fseek(fp_rcw_pbi_ip, 0L, SEEK_END);
	file_len = ftell(fp_rcw_pbi_ip);
	fseek(fp_rcw_pbi_ip, 0L, SEEK_SET);
	if (gd.sben_flag != 1) {
		printf("\nError: SB_EN field not found in input file\nUsage: SB_EN = <0/1>\n");
		exit(1);
	}
	if (gd.bootho_flag != 1) {
		printf("\nError: BOOT_HO field not found in input file\nUsage: BOOT_HO = <0/1>\n");
		exit(1);
	}
	if (file_len < NUM_RCW_WORD * sizeof(uint32_t)) {
		printf("Invalid RCW File. Does not have the RCW words");
		return FAILURE;
	}

	/* Modify RCW Words read from rcw_pbi_ip_file
	* and write in rcw_pbi_op_file */
	for (i = 0; i < NUM_RCW_WORD; i++) {
		ret = fread(&word, sizeof(word), 1, fp_rcw_pbi_ip);
		if (ret == 0) {
			printf("Error in Reading RCW Words\n");
			return FAILURE;
		}
		if (i == SB_EN_BOOT_HO_WORD) {
			word = BYTE_SWAP_32(word);
			if (gd.option_sb_en == 1)
				word = word | SB_EN_MASK;
			if (gd.boot_ho == 1)
				word = word | BOOT_HO_MASK;
			word = BYTE_SWAP_32(word);
		}
		ret = fwrite(&word, sizeof(word), 1, fp_rcw_pbi_op);
		if (ret == 0) {
			printf("Error in Writing RCW Words\n");
			return FAILURE;
		}
	}
	printf("\nSB_EN = %x\n", gd.option_sb_en);
	printf("\nBOOT_HO = %x\n", gd.boot_ho);
	return SUCCESS;
}

/***************************************************************************
 * Function	:	get_bootptr
 * Arguments	:	fp_rcw_pbi_op - Pointer to output file
 * Return	:	SUCCESS or FAILURE
 * Description	:	Add bootptr pbi command to output file
 ***************************************************************************/
int get_bootptr(FILE *fp_rcw_pbi_op)
{
	#define BOOTPTR_ADDR 0x09ee0200
	uint32_t bootptr_addr = BYTE_SWAP_32(BOOTPTR_ADDR);
	int ret = 0;
	ret = fwrite(&bootptr_addr, sizeof(bootptr_addr),
		     1, fp_rcw_pbi_op);
	if (ret == 0) {
		printf("Error in Writing PBI Words\n");
		return FAILURE;
	}
	gd.boot1_ptr = BYTE_SWAP_32(gd.boot1_ptr);
	if (gd.boot1_ptr != 0) {
		ret = fwrite(&gd.boot1_ptr, sizeof(gd.boot1_ptr),
			     1, fp_rcw_pbi_op);
	} else {
		printf("\nError: Boot location pointer (BOOT1_PTR) field not found in input file\n"
			"Usage: BOOT1_PTR = <ADDR>\n\n");
		exit(1);
	}
	if (ret == 0) {
		printf("Error in Writing PBI Words\n");
		return FAILURE;
	}
	printf("\nBOOT1_PTR = %x\n", BYTE_SWAP_32(gd.boot1_ptr));
	return SUCCESS;
}

/***************************************************************************
 * Function	:	add_pbi_stop_cmd
 * Arguments	:	fp_rcw_pbi_op - output rcw_pbi file pointer
 * Return	:	SUCCESS or FAILURE
 * Description	:	This function insert pbi stop command.
 ***************************************************************************/
int add_pbi_stop_cmd(FILE *fp_rcw_pbi_op)
{
#define PBI_CRC_POLYNOMIAL	0x04c11db7
	int ret;
	int32_t pbi_stop_cmd = BYTE_SWAP_32(gd.stop_cmd);
	uint32_t pbi_crc = 0xffffffff, i, j, c;
	uint32_t crc_table[256];
	uint8_t data;
	ret = fwrite(&pbi_stop_cmd, sizeof(pbi_stop_cmd),
	1, fp_rcw_pbi_op);
	if (ret == 0) {
		printf("Error in Writing PBI STOP CMD\n");
		return FAILURE;
	}

	for (i = 0; i < 256; i++) {
		c = i << 24;
		for (j = 0; j < 8; j++)
			c = c & 0x80000000 ?
			PBI_CRC_POLYNOMIAL ^ (c << 1) : c << 1;
		crc_table[i] = c;
	}

	fseek(fp_rcw_pbi_op, 0L, SEEK_SET);

	while ((ret = fread(&data, 1, 1, fp_rcw_pbi_op)))
		pbi_crc =
		crc_table[((pbi_crc >> 24) ^ (data)) & 0xff] ^ (pbi_crc << 8);

	pbi_crc = BYTE_SWAP_32(pbi_crc);

	ret = fwrite(&pbi_crc, sizeof(pbi_crc), 1, fp_rcw_pbi_op);
	if (ret == 0) {
		printf("Error in Writing PBI PBI CRC\n");
		return FAILURE;
	}
	return SUCCESS;
}

/***************************************************************************
 * Function	:	get_copy_cmd
 * Arguments	:	file_name - Name of input file
 * Return	:	SUCCESS or FAILURE
 * Description	:	Fill global data structure corresponding
 *			to acs write commands
 ***************************************************************************/
int get_copy_cmd(char *file_name)
{
	int i, line_size = 0;
	int ret;
	char *field_name = "COPY_CMD";
	FILE *fp;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", file_name);
		return FAILURE;
	}
	file_field.value[0] = NULL;
	file_field.value[1] = NULL;
	file_field.value[2] = NULL;
	file_field.count = 0;

	fseek(fp, 0, SEEK_SET);
	line_size = cal_line_size(fp);
	ret = fseek(fp, -line_size, SEEK_CUR);
	if (ret != 0)
		printf("Error in reading the file\n");
	while ((ret = fread(line_data, 1, line_size, fp))) {
		*(line_data + line_size) = '\0';
		remove_whitespace(line_data);
		if ((strstr(line_data, field_name)) && (*line_data != '#')) {
			get_field_from_file(line_data, field_name);
			if (file_field.count == 3) {
				gd.cp_cmd[gd.cp_cmd_count].src_off =
				STR_TO_UL(file_field.value[0], 16);
				gd.cp_cmd[gd.cp_cmd_count].dst =
				STR_TO_UL(file_field.value[1], 16);
				strcpy(gd.cp_cmd[gd.cp_cmd_count].img_name,
				       file_field.value[2]);
				gd.cp_cmd_count++;
				if (gd.cp_cmd_count >= MAX_CP_CMD) {
					printf("Error:Only %d COPY CMD Pairs "
					       "Allowed\n", MAX_CP_CMD);
					fclose(fp);
					return FAILURE;
				}
			} else {
				printf("Error:Wrong Format in Input File\n"
				"Usage: COPY_CMD = (SRC, DEST, SIZE)\n");
				fclose(fp);
				return FAILURE;
			}
		}
		line_size = cal_line_size(fp);
		ret = fseek(fp, -line_size, SEEK_CUR);
		if (ret != 0)
			printf("Error in reading the file\n");
	}
	for (i = 0; i < gd.cp_cmd_count; i++) {
		printf("\nACS Write COMMAND : offset %x and image name %s",
		       gd.cp_cmd[i].dst, gd.cp_cmd[i].img_name);
	}
	fclose(fp);
	return SUCCESS;
}

/***************************************************************************
 * Function	:	add_cpy_cmd
 * Arguments	:	fp_rcw_pbi_op - pointer to output file
 * Return	:	SUCCESS or FAILURE
 * Description	:	Add pbi commands for acs write in output file
 ***************************************************************************/
int add_cpy_cmd(FILE *fp_rcw_pbi_op)
{
#define OFFSET_MASK	0x00ffffff
	uint32_t WRITE_CMD_BASE = 0x81000000;
	uint32_t MAX_PBI_DATA_LEN_BYTE = 64;
	uint32_t ALTCBAR_ADDRESS = BYTE_SWAP_32(0x09570158);
	uint32_t WAIT_CMD_WRITE_ADDRESS = BYTE_SWAP_32(0x096100c0);
	uint32_t WAIT_CMD = BYTE_SWAP_32(0x000FFFFF);
	int ret, size, i;
	uint32_t j, file_size;
	uint32_t pbi_cmd, altcbar;
	uint8_t pbi_data[MAX_PBI_DATA_LEN_BYTE];
	uint32_t dst_offset;

	FILE *fp_img;
	for (i = 0; i < gd.cp_cmd_count; i++) {
		MAX_PBI_DATA_LEN_BYTE = 64;
		altcbar = gd.cp_cmd[i].dst;
		dst_offset = gd.cp_cmd[i].dst;
		fp_img = fopen(gd.cp_cmd[i].img_name, "rb");
		if (fp_img == NULL) {
			printf("Error in opening the file: %s\n",
			       gd.cp_cmd[i].img_name);
			return FAILURE;
		}
		file_size = get_file_size(gd.cp_cmd[i].img_name);
		altcbar = 0xfff00000 & altcbar;
		altcbar = BYTE_SWAP_32(altcbar >> 16);
		ret = fwrite(&ALTCBAR_ADDRESS, sizeof(ALTCBAR_ADDRESS),
		1, fp_rcw_pbi_op);
		ret = fwrite(&altcbar, sizeof(altcbar), 1, fp_rcw_pbi_op);
		ret = fwrite(&WAIT_CMD_WRITE_ADDRESS,
		sizeof(WAIT_CMD_WRITE_ADDRESS), 1, fp_rcw_pbi_op);
		ret = fwrite(&WAIT_CMD, sizeof(WAIT_CMD), 1, fp_rcw_pbi_op);

		do {
			if (file_size == 0)
				break;
			if (file_size < 64) {
				for (j = 32 ; j >= 1; j /= 2) {
					if (file_size >= j) {
						MAX_PBI_DATA_LEN_BYTE = j;
						 break;
					}
				}
			}
			memset(pbi_data, 0, MAX_PBI_DATA_LEN_BYTE);
			size = fread(&pbi_data, MAX_PBI_DATA_LEN_BYTE,
				     1, fp_img);

			switch (MAX_PBI_DATA_LEN_BYTE) {
			case 32:
				WRITE_CMD_BASE = 0xC1000000;
				break;
			case 16:
				WRITE_CMD_BASE = 0xA1000000;
				break;
			case 8:
				WRITE_CMD_BASE = 0x91000000;
				break;
			case 4:
				WRITE_CMD_BASE = 0x89000000;
				break;
			case 2:
				WRITE_CMD_BASE = 0x85000000;
				break;
			case 1:
				WRITE_CMD_BASE = 0x82000000;
				break;
			default:
				WRITE_CMD_BASE = 0x81000000;
			}
			dst_offset &= OFFSET_MASK;
			pbi_cmd = WRITE_CMD_BASE | dst_offset;
			pbi_cmd = BYTE_SWAP_32(pbi_cmd);
			ret = fwrite(&pbi_cmd, sizeof(pbi_cmd), 1,
				     fp_rcw_pbi_op);
			if (ret == 0) {
				printf("Error in Writing PBI ACS CMD\n");
				fclose(fp_img);
				return FAILURE;
			}
			ret = fwrite(&pbi_data,  MAX_PBI_DATA_LEN_BYTE, 1,
				     fp_rcw_pbi_op);
			if (ret == 0) {
				printf("Error in Writing PBI ACS Data\n");
				fclose(fp_img);
				return FAILURE;
			}
			dst_offset += MAX_PBI_DATA_LEN_BYTE;
			file_size -= MAX_PBI_DATA_LEN_BYTE;
		} while (size);

	fclose(fp_img);
	}
	return SUCCESS;
}

/***************************************************************************
 * Function	:	get_ap_img
 * Arguments	:	file_name - name of the input file
 * Return		SUCCESS or FAILURE$
 * Description	:	fill global data structure with data
 *			of images to be appended$
 ***************************************************************************/
int get_ap_img(char *file_name)
{
	int line_size = 0;
	int ret, ret_val;
	char *field_name = "APPEND_IMAGES";
	FILE *fp;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", file_name);
		return FAILURE;
	}
	file_field.value[0] = NULL;
	file_field.value[1] = NULL;
	file_field.value[2] = NULL;
	file_field.count = 0;
	fseek(fp, 0, SEEK_SET);
	line_size = cal_line_size(fp);
	ret_val = fseek(fp, -line_size, SEEK_CUR);
	if (ret_val != 0)
		printf("Error in reading the file\n");
	while ((ret = fread(line_data, 1, line_size, fp))) {
		*(line_data + line_size) = '\0';
		remove_whitespace(line_data);
		if ((strstr(line_data, field_name)) && (*line_data != '#')) {
			get_field_from_file(line_data, field_name);
			if (file_field.count == 2) {
				strcpy(gd.ap_file[gd.ap_count].name,
				       file_field.value[0]);
				gd.ap_file[gd.ap_count].offset =
				STR_TO_UL(file_field.value[1], 16);
				gd.ap_count++;
				if (gd.ap_count >= MAX_AP_FILE) {
					printf("Error:Only %d APPEND IMG  Pairs\n"
					"Allowed\n", MAX_AP_FILE);
					fclose(fp);
					return FAILURE;
				}
			} else {
				printf("Error:Wrong Format in Input File\n"
				"Usage: APPEND_IMG = (FILE_NAME, OFFSET\n");
				fclose(fp);
				return FAILURE;
			}
		}
		line_size = cal_line_size(fp);
		ret_val = fseek(fp, -line_size, SEEK_CUR);
		if (ret_val != 0)
			printf("Error in reading the file\n");
	}

	fclose(fp);
	return SUCCESS;
}

/***************************************************************************
 * Function	:	add_ap_img
 * Arguments	:	fp_rcw_pbi_op - pointer to putput file
 * Return	:	SUCCESS or FAILURE
 * Description	:	append images to the output file
 ***************************************************************************/
int add_ap_img(FILE *fp_rcw_pbi_op)
{
#define BUFFER_SIZE             1024
#define APPEND_IMAGE_PAD        0xff
/* Since image is appended to rcw, which is loaded at 8th
sector in SD, the images have to be appended to rcw at
1000 bytes less than the actual offset*/
#define APND_IMG_OFF		0x1000

	int i, j, size, ret;
	uint32_t image_offset, file_len;
	char *image_name;
	uint8_t data_buffer[BUFFER_SIZE], padding[BUFFER_SIZE];
	FILE *fp_img;
	if (gd.ap_count != 0)
		printf("\n\nImages to be appended\n");
	memset(padding, APPEND_IMAGE_PAD, BUFFER_SIZE);

	for (i = 0; i < gd.ap_count; i++) {
		printf("Image Offset: %08x, Image Name: %s\n",
		       gd.ap_file[i].offset,  gd.ap_file[i].name);
		if (strncmp(gd.boot_src, "SD_BOOT", 6) == 0)
			image_offset = (gd.ap_file[i].offset - APND_IMG_OFF);
		else
			image_offset = gd.ap_file[i].offset;
		image_name = gd.ap_file[i].name;

		/* Get file size */
		fseek(fp_rcw_pbi_op, 0L, SEEK_END);
		file_len = ftell(fp_rcw_pbi_op);

		if (image_offset < file_len) {
			printf("Error Image offset: %08x less than "
			       "file length: %08x\n", image_offset, file_len);
			return FAILURE;
		}

		/* Append padding */
		for (j = (image_offset - file_len); j > 0; j -= BUFFER_SIZE) {
			ret = fwrite(&padding, ((j >= BUFFER_SIZE) ?
				BUFFER_SIZE : j), 1, fp_rcw_pbi_op);
			if (ret == 0) {
				printf("Error in Appending Padding\n");
				return FAILURE;
			}
		}
		fp_img = fopen(image_name, "rb");
		if (fp_img == NULL) {
			printf("Error in opening the file: %s\n", image_name);
			return FAILURE;
		}

		while ((size = fread(&data_buffer, 1, BUFFER_SIZE, fp_img))) {
			ret = fwrite(&data_buffer, 1, size, fp_rcw_pbi_op);
			if (ret == 0) {
				printf("Error in Appending Image\n");
				fclose(fp_img);
				return FAILURE;
			}
		}

		fclose(fp_img);
	}

	return SUCCESS;
}


/***************************************************************************
 * Function	:	create_pbi_ta2
 * Arguments	:	argc - Argument Count
 *			argv - Argumnet List
 * Return	:	SUCCESS or FAILURE
 * Description	:	Main function where execution starts
 ***************************************************************************/
int create_pbi_ta2(int argc, char **argv)
{
	int ret;
	FILE *fp_rcw_pbi_ip, *fp_rcw_pbi_op;
	uint32_t word;
	enum cfg_taal cfg_taal;
	printf("\n\t#----------------------------------------------------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#------- CST (Code Signing Tool) Version 2.0  -------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#----------------------------------------------------#");
	printf("\n");


	/* Initialization of Global Structure to 0 */
	/* Check the command line argument */
	ret = ta2_parse_input_file(parse_list, NUM_PARSE_LIST);
	printf("Input File Name : %s\n", gd.rcw_fname);

	fp_rcw_pbi_ip = fopen(gd.rcw_fname, "rb");
	if (fp_rcw_pbi_ip == NULL) {
		printf("Error in opening the file: %s\n", gd.rcw_fname);
		return FAILURE;
	}

	printf("Output File Name : %s\n", gd.rcw_op_fname);

	fp_rcw_pbi_op = fopen(gd.rcw_op_fname, "wb+");
	if (fp_rcw_pbi_op == NULL) {
		printf("Error in opening the file: %s\n", gd.rcw_op_fname);
		fclose(fp_rcw_pbi_ip);
		return FAILURE;
	}

	printf("\nInput File is %s\n", gd.input_file);
	
	cfg_taal = get_ta_from_file(gd.input_file);
	switch (cfg_taal)  {
	case TA_2_0_PBL:
		gd.stop_cmd = CRC_STOP_CMD_POWERPC;
		break;
	default :	
		gd.stop_cmd = CRC_STOP_CMD_ARM;
		break;
	}

	/* modify rcw field based on sben and boot_ho */
	ret = rcw_sben_boot_ho(fp_rcw_pbi_ip, fp_rcw_pbi_op);
	ret = fread(&word, sizeof(word), 1, fp_rcw_pbi_ip);
	while (BYTE_SWAP_32(word) != gd.stop_cmd) {
		ret = fwrite(&word, sizeof(word), 1, fp_rcw_pbi_op);
		if (ret == 0) {
			printf("Error in Writing PBI Words\n");
                        ret = FAILURE;
                        goto exit;
		}
		ret = fread(&word, sizeof(word), 1, fp_rcw_pbi_ip);
		if (ret == 0) {
			printf("Error in Reading PBI Words\n");
                        ret = FAILURE;
                        goto exit;
		}
	}

	/* Add command to set boot_loc ptr */
	ret = get_bootptr(fp_rcw_pbi_op);
	if (ret != SUCCESS)
		goto exit;
	/* Get acs write command and fill global data structure */
	ret = get_copy_cmd(gd.input_file);
	if (ret != SUCCESS)
		goto exit;
	/* Write acs write commands to output file */
	ret = add_cpy_cmd(fp_rcw_pbi_op);
	if (ret != SUCCESS)
		goto exit;
	/* Add stop command after adding pbi commands */
	ret = add_pbi_stop_cmd(fp_rcw_pbi_op);
	if (ret != SUCCESS)
		goto exit;
	/* get data for images to be appended and fill data struct */
	ret = get_ap_img(gd.input_file);
	if (ret != SUCCESS)
		goto exit;
	/* append images to the output file */
	ret = add_ap_img(fp_rcw_pbi_op);
	if (ret != SUCCESS)
		goto exit;

	printf("\n\n");
	ret = SUCCESS;
exit:
	fclose(fp_rcw_pbi_op);
	fclose(fp_rcw_pbi_ip);
	return ret;
}

