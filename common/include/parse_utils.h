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
#ifndef _PARSE_UTILS_H
#define _PARSE_UTILS_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <netinet/in.h>

#include <global.h>

#define MAX_LINE_SIZE		1024
#define MAX_U32			0xFFFFFFFF

struct input_field {
	char *value[64];
	int count;
};

unsigned long STR_TO_UL(char *str, int base);
unsigned long long STR_TO_ULL(char *str, int base);
int cal_line_size(FILE *fp);
void get_field_from_file(char *line, char *field_name);
void remove_whitespace(char *line);
void find_value_from_file(char *field_name, FILE *fp);
int find_cfw_from_file(char *file_name);
int fill_gd_input_file(char *field_name, FILE *fp);
int get_file_size(const char *file_name);

enum input_field_t {
	FIELD_PLATFORM = 0,
	FIELD_ENTRY_POINT,
	FIELD_PUB_KEY,
	FIELD_BOOT_SRC,
	FIELD_KEY_SELECT,
	FIELD_BOOT_HO,
	FIELD_SB_EN,
	FIELD_IMAGE_1,
	FIELD_IMAGE_2,
	FIELD_IMAGE_3,
	FIELD_IMAGE_4,
	FIELD_IMAGE_5,
	FIELD_IMAGE_6,
	FIELD_IMAGE_7,
	FIELD_IMAGE_8,
	FIELD_FSL_UID_0,
	FIELD_FSL_UID_1,
	FIELD_OEM_UID_0,
	FIELD_OEM_UID_1,
	FIELD_OEM_UID_2,
	FIELD_OEM_UID_3,
	FIELD_OEM_UID_4,
	FIELD_OUTPUT_HDR_FILENAME,
	FIELD_MP_FLAG,
	FIELD_ISS_FLAG,
	FIELD_LW_FLAG,
	FIELD_VERBOSE,
	FIELD_PRI_KEY,
	FIELD_IMAGE_HASH_FILENAME,
	FIELD_RSA_SIGN_FILENAME,
	FIELD_RCW_PBI_FILENAME,
	FIELD_OUTPUT_RCW_PBI_FILENAME,
	FIELD_BOOT1_PTR,
	FIELD_SEC_IMAGE,
	FIELD_WP_FLAG,
	FIELD_HK_AREA_POINTER,
	FIELD_HK_AREA_SIZE,
	FIELD_IMAGE_TARGET,
	FIELD_OUTPUT_SG_BIN,
	FIELD_SG_TABLE_ADDR,
	FIELD_ESBC_HDRADDR,
	FIELD_ESBC_HDRADDR_SEC_IMAGE,
	FIELD_IE_KEY_SEL,
	FIELD_IE_KEY,
	FIELD_IE_REVOC,
	FIELD_IE_TABLE_ADDR,
	FIELD_POVDD_GPIO,
	FIELD_OTPMK_FLAGS,
	FIELD_OTPMK_0,
	FIELD_OTPMK_1,
	FIELD_OTPMK_2,
	FIELD_OTPMK_3,
	FIELD_OTPMK_4,
	FIELD_OTPMK_5,
	FIELD_OTPMK_6,
	FIELD_OTPMK_7,
	FIELD_SRKH_0,
	FIELD_SRKH_1,
	FIELD_SRKH_2,
	FIELD_SRKH_3,
	FIELD_SRKH_4,
	FIELD_SRKH_5,
	FIELD_SRKH_6,
	FIELD_SRKH_7,
	FIELD_DCV_0,
	FIELD_DCV_1,
	FIELD_DRV_0,
	FIELD_DRV_1,
	FIELD_MC_ERA,
	FIELD_DBG_LVL,
	FIELD_WP,
	FIELD_ITS,
	FIELD_NSEC,
	FIELD_ZD,
	FIELD_K0,
	FIELD_K1,
	FIELD_K2,
	FIELD_K3,
	FIELD_K4,
	FIELD_K5,
	FIELD_K6,
	FIELD_FR0,
	FIELD_FR1,
	FIELD_OUTPUT_FUSE_FILENAME,
	FIELD_UNKNOWN_MAX
};

typedef struct {
	char *field_name;
	enum input_field_t index;
} parse_struct_t;

typedef union {
	uint64_t whole;
	struct {
		uint32_t low;
		uint32_t high;
	} m_halfs;
} DWord;

#endif
