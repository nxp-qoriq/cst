/** @file
 * uni_sign.h
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

#ifndef __UNI_SIGN_H__
#define __UNI_SIGN_H__

#ifndef ARM
#define BYTE_ORDER_L(x)	htonl(x)
#define BYTE_ORDER_S(x)	htons(x)
#else
#define BYTE_ORDER_L(x)	(x)
#define BYTE_ORDER_S(x)	(x)
#endif

#define HDR_FILE		"hdr.out"
#define PBI_LEN_MASK		0xFFF00000
#define PBI_LEN_SHIFT		20
#define SB_EN_MASK		0x00000400
/* I/O block size used for hashing operations */
#define IOBLOCK			128
#define KEY_SIZE_BYTES		1024

enum blocks_order {
	CSF_HDR_LS = 0,
	SRK_TABLE,
	SIGNATURE,
	BLOCK_END,
};


struct srk_table {
	u32 key_len;
	u8 pkey[KEY_SIZE_BYTES];
};

struct img_hdr_ls2 {
	u8 barker[BARKER_LEN];		/* 0x00 Barker code */
	u32 srk_table_offset;		/* 0x04 SRK Table Offset */

	u8 num_keys;			/* 0x08 No. of keys */
	u8 key_num_verify;		/* 0x09 Key no. to be used*/
	u8 reserve;			/* 0x0a Reserved */
	u8 misc_flags;			/* 0x0b Misc. Flags*/

	u8 res[3];			/* 0x0c 0x0d 0x0e */
	u8 uid_flags;			/* 0x0f UID Flags */

	u32 psign;			/* 0x10 signature offset */
	u32 sign_len;			/* 0x14 length of signature */
	u32 sg_table_addr;		/* 0x18 ptr to SG table */
	u32 sg_entries;			/* 0x1c no. of entries in SG */
	u32 entry_point;		/* 0x20 ESBC entry point */

	u32 fsl_uid[2];			/* 0x24-0x28 Freescale unique id's*/
	u32 oem_uid[5];			/* 0x2c-0x3c OEM unique id's*/

	u32 reserved[4];		/* 0x40 - 0x4f */
};

struct combined_hdr {
	void *blk_ptr;
	uint32_t blk_size;
	uint32_t blk_offset;
};


struct rcw_pbi {
	#define NO_RCW_WORD	35
	u32 rcw_words[NO_RCW_WORD];
	u32 load_sec_hdr_cmd;
	struct img_hdr_ls2 pbi_sec_hdr;
	u32 pbi_words[0x400];
};

struct global {
	/* Variables used across functions */
	struct rcw_pbi pbi_sec;
	FILE *fsrk[MAX_NUM_KEYS];
	RSA * srk[MAX_NUM_KEYS];
	FILE *fie_key[MAX_IE_KEYS];
	RSA * ie_key[MAX_IE_KEYS];
	struct combined_hdr *cmbhdrptr[BLOCK_END];
	/* Options flags*/
	int file_flag;
	int verbose_flag;
	int help_flag;
	int hash_flag;
	/* These entries are filled by parsing the arguments */
	uint32_t boot1_ptr;
	uint32_t boot1_flag;
	char *pub_fname[MAX_NUM_KEYS];
	char *priv_fname[MAX_NUM_KEYS];
	uint32_t pub_fname_count;
	uint32_t priv_fname_count;
	char *hdrfile;
	char *rcwfile;
	char *sign_file;
	uint32_t oemuid_flag[5];
	uint32_t fsluid_flag[2];
	uint32_t oemuid[5];
	uint32_t fsluid[2];
	uint32_t sign_size;
	uint32_t srk_sel;
	uint32_t srk_table_flag;
	uint32_t no_key_flag;
	uint32_t hdrfile_flag;
	uint32_t rcwfile_flag;
	uint32_t target_flag;
	uint32_t key_check_flag;
	struct srk_table key_table[MAX_NUM_KEYS];
	uint32_t num_srk_entries;
	uint32_t ie_flag;
	uint32_t mp_flag;
	uint32_t iss_flag;
	uint32_t b01_flag;
	uint32_t lw_flag;
	int no_pbi_words;
};


#endif
