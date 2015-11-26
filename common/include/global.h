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

#ifndef _BOOT1_SIGN_H_
#define _BOOT1_SIGN_H_

#include <stdio.h>
#include <stdint.h>

int create_hdr(int argc, char **argv);
int create_srk(uint32_t max_keys);
int parse_input_file(char **list, uint32_t num_list);
int calculate_signature(void);
int append_signature(void);

#define SUCCESS			0
#define FAILURE			-1

#define BARKER_LEN		4
#define IOBLOCK			128
#define MAX_FNAME_LEN		0x64
#define SHA256_DIGEST_LENGTH	32

#define MAX_NUM_KEY		8
#define MAX_NUM_SG_ENTRY	8

#define KEY_SIZE_BYTES		1024
#define MAX_HDR_SIZE		0x1000

#define ADDR_ALIGN_MASK		0x000001FF
#define ADDR_ALIGN_OFFSET	0x00000200
#define OFFSET_ALIGN(x)		((x) & ADDR_ALIGN_MASK ? \
			(((x) & (~ADDR_ALIGN_MASK)) + ADDR_ALIGN_OFFSET) :\
			(x))

#define DEFAULT_HDR_FILE_NAME	"hdr.out"
#define DEFAULT_HASH_FILE_NAME	"hash.out"
#define DEFAULT_SIGN_FILE_NAME	"sign.out"

struct srk_table_t {
	uint32_t key_len;
	uint8_t pkey[KEY_SIZE_BYTES];
};

struct sg_table_t {
	uint32_t len;
	uint32_t reserved;
	uint32_t src_addr_low;
	union {
		uint32_t src_addr_high;
		uint32_t dst_addr;
	};
};


struct sg_input {
	char name[MAX_FNAME_LEN];
	uint32_t addr_low;
	uint32_t addr_high;
	uint32_t dst_addr;
};

struct g_data_t {
	char *input_file;

	uint32_t srk_sel;
	uint32_t num_srk_entries;
	uint32_t num_pri_key;
	char pub_fname[MAX_NUM_KEY][MAX_FNAME_LEN];
	char pri_fname[MAX_NUM_KEY][MAX_FNAME_LEN];

	char rcw_fname[MAX_FNAME_LEN];

	uint32_t entry_addr_low;
	uint32_t entry_addr_high;
	uint32_t num_entries;
	struct sg_input entries[MAX_NUM_SG_ENTRY];

	uint32_t fsluid[2];
	uint32_t oemuid[5];
	uint8_t fsluid_flag[2];
	uint8_t oemuid_flag[5];

	char hdr_file_name[MAX_FNAME_LEN];
	char img_hash_file_name[MAX_FNAME_LEN];
	char rsa_sign_file_name[MAX_FNAME_LEN];

	uint8_t mp_flag;
	uint8_t iss_flag;
	uint8_t lw_flag;

	uint8_t srk_hash[SHA256_DIGEST_LENGTH];
	uint8_t img_hash[SHA256_DIGEST_LENGTH];
	uint8_t rsa_sign[KEY_SIZE_BYTES];

	struct srk_table_t key_table[MAX_NUM_KEY];
	struct sg_table_t sg_table[MAX_NUM_SG_ENTRY];
	uint8_t hdr_struct[MAX_HDR_SIZE];
	uint32_t hdr_size;
	uint32_t num_pbi_words;
	uint32_t pbi_len;

	uint32_t boot1_ptr;

	uint32_t srk_offset;
	uint32_t srk_size;
	uint32_t sg_offset;
	uint32_t sg_size;
	uint32_t rsa_offset;
	uint32_t rsa_size;

	int option_srk_hash;
	int option_img_hash;
	int verbose_flag;
	int help_flag;
};

#endif
