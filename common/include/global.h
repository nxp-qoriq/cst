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

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#include <stdio.h>
#include <stdint.h>

int create_hdr(int argc, char **argv);
int create_srk_calc_hash(uint32_t max_keys);
int parse_input_file(char **list, uint32_t num_list);
int calculate_signature(void);
int create_img_hash_file(void);
int append_signature(void);
int error_unsupported(void);
int create_ie_file(char *file_name);
int read_file_in_buffer(uint8_t *ptr, char *file_name);

#define SUCCESS			0
#define FAILURE			-1

#define BARKER_LEN		4
#define IOBLOCK			128
#define MAX_FNAME_LEN		0x64
#define SHA256_DIGEST_LENGTH	32

#define MAX_NUM_KEY		8
#define MAX_NUM_IEKEY		32
#define MAX_NUM_SG_ENTRY	8

#define KEY_SIZE_BYTES		1024
#define MAX_CF_WORD		1024

#define MAX_HDR_SIZE		0x1000

#define MAX_NUM_FSL_UID		2
#define MAX_NUM_OEM_UID		5

#define ADDR_ALIGN_MASK		0x000001FF
#define ADDR_ALIGN_OFFSET	0x00000200
#define OFFSET_ALIGN(x)		((x) & ADDR_ALIGN_MASK ? \
			(((x) & (~ADDR_ALIGN_MASK)) + ADDR_ALIGN_OFFSET) :\
			(x))

#define DEFAULT_HDR_FILE_NAME	"hdr.out"
#define DEFAULT_HASH_FILE_NAME	"hash.out"
#define DEFAULT_SIGN_FILE_NAME	"sign.out"
#define DEFAULT_SG_FILE_NAME	"sg_table.out"
#define DEFAULT_IE_FILE_NAME	"ie_table.out"

struct srk_table_t {
	uint32_t key_len;
	uint8_t pkey[KEY_SIZE_BYTES];
};

struct ie_table_t {
	uint32_t key_revok;
	uint32_t num_keys;
	struct srk_table_t srk_table[MAX_NUM_IEKEY];
};

struct sg_table_t {
	uint32_t len;
	uint32_t target;
	uint32_t src_addr_low;
	union {
		uint32_t src_addr_high;
		uint32_t dst_addr;
	};
};

struct sg_table_ptr_t {
	uint32_t len;
	uint32_t src_addr;
};

struct sg_input {
	char name[MAX_FNAME_LEN];
	uint32_t addr_low;
	uint32_t addr_high;
	uint32_t dst_addr;
};

struct cf_word_t {
	uint32_t addr;
	uint32_t data;
};

struct g_data_t {
	char *input_file;

	uint32_t srk_sel;
	uint32_t iek_sel;
	uint32_t num_srk_entries;
	uint32_t num_pri_key;
	uint32_t num_ie_key;
	uint8_t srk_flag;
	uint8_t srk_hash_flag;
	char pub_fname[MAX_NUM_KEY][MAX_FNAME_LEN];
	char pri_fname[MAX_NUM_KEY][MAX_FNAME_LEN];
	char iek_fname[MAX_NUM_IEKEY][MAX_FNAME_LEN];
	uint32_t iek_revok[MAX_NUM_IEKEY];
	uint32_t num_iek_revok;
	uint8_t *pkey;
	uint32_t key_len;

	char rcw_fname[MAX_FNAME_LEN];

	uint32_t entry_addr_low;
	uint32_t entry_addr_high;
	uint32_t num_entries;
	struct sg_input entries[MAX_NUM_SG_ENTRY];

	uint32_t fsluid[MAX_NUM_FSL_UID];
	uint32_t oemuid[MAX_NUM_OEM_UID];
	uint8_t fsluid_flag[MAX_NUM_FSL_UID];
	uint8_t oemuid_flag[MAX_NUM_OEM_UID];

	char hdr_file_name[MAX_FNAME_LEN];
	char img_hash_file_name[MAX_FNAME_LEN];
	char rsa_sign_file_name[MAX_FNAME_LEN];
	char sg_file_name[MAX_FNAME_LEN];

	uint8_t hton_flag;
	uint8_t mp_flag;
	uint8_t iss_flag;
	uint8_t lw_flag;
	uint8_t wp_flag;
	uint8_t sec_image_flag;
	uint8_t sg_flag;
	uint8_t iek_flag;

	uint8_t srk_hash[SHA256_DIGEST_LENGTH];
	uint8_t img_hash[SHA256_DIGEST_LENGTH];
	uint8_t rsa_sign[KEY_SIZE_BYTES];

	struct srk_table_t key_table[MAX_NUM_KEY];
	struct ie_table_t ie_table;
	uint32_t ie_table_flag;
	struct sg_table_t sg_table[MAX_NUM_SG_ENTRY];
	struct sg_table_ptr_t sg_table_ptr[MAX_NUM_SG_ENTRY];
	uint32_t img_target;
	uint8_t hdr_struct[MAX_HDR_SIZE];
	uint32_t hdr_size;
	uint32_t num_pbi_words;
	uint32_t pbi_len;

	uint32_t hkarea;
	uint32_t hksize;

	uint32_t boot1_ptr;

	uint32_t srk_offset;
	uint32_t srk_size;
	uint32_t ie_table_size;
	uint32_t ie_table_offset;
	uint32_t ie_table_addr;
	uint32_t sg_offset;
	uint32_t sg_size;
	uint32_t sg_addr;
	uint32_t rsa_offset;
	uint32_t rsa_size;

	struct cf_word_t cf_word[MAX_CF_WORD];
	uint32_t cf_count;

	uint32_t hdr_addr;
	uint32_t hdr_addr_sec;

	int option_srk_hash;
	int option_img_hash;
	int verbose_flag;
	int help_flag;
};

#endif
