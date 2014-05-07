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

#define CSF_HDR_OFFSET		0x0
#define SRK_TABLE_OFFSET	0x200
#define SG_TABLE_OFFSET		0x1400
#define IE_TABLE_OFFSET		0x1500

#define OUID_FUID_BOTH		0x1
#define OUID_ONLY		0x2
#define FUID_ONLY		0x4
#define NO_UID			0x0

#define TBL_FILE		"sg_table.out"
#define HDR_FILE		"hdr.out"
#define HASH_FILE		"img_hash.out"
#define DESTINATION_ADDR	0xFFFFFFFF
#define SIGNATURE_MASK		0x0000000F
#define SIGNATURE_OFFSET	0x00000010


/* I/O block size used for hashing operations */
#define IOBLOCK			128
#define NUM_SG_ENTRIES		8
#define KEY_SIZE_BYTES		1024
#define NUM_BLOCKS		8

char *group[][2] = { {"3041", "1"},
{"4080", "1"},
{"5020", "1"},
{"5040", "1"},
{"1010", "2"},
{"9131", "2"},
{"9132", "2"},
{"4860", "3"},
{"4240", "3"},
{"1040", "4"},
{"C290", "4"},
{"LS1", "5"},
{"LS2", "6"},
{"LAST", "0"}
};

enum blocks_order {
	CSF_HDR_LS = 0,
	CSF_HDR,
	EXTENDED_HDR,
	EXT_ESBC_HDR,
	SRK_TABLE,
	SG_TABLE,
	IE_TABLE,
	SIGNATURE,
	BLOCK_END
};


struct sg_table {
	u32 len;		/* length of the segment */
	u32 pdata;		/* ptr to the data segment */
};

struct sg_table_offset {
	u32 len;		/* length of the segment */
	u32 target_id;
	u32 source;		/* ptr to the data segment */
	u32 destination;	/* ptr to the data segment */
};

struct srk_table {
	u32 key_len;
	u8 pkey[KEY_SIZE_BYTES];
};

struct ie_key_table {
	u32 key_len;
	u8 pkey[KEY_SIZE_BYTES];
};

struct hk {
	u32 hkptr;		/* House keeping area starting address */
	u32 hksize;		/* House keeping area size */
};

struct sg_input {
	char *name;
	uint32_t addr;
	uint32_t d_addr;
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

struct img_hdr {
	u8 barker[BARKER_LEN];	/* barker code */
	union {
		u32 pkey;	/* public key offset */
		u32 srk_table_offset;
	};
	union {
		u32 key_len;	/* pub key length */
		struct {
			u32 srk_table_flag:8;
			u32 srk_sel:8;
			u32 num_srk_entries:16;
		}len_kr;	
	};
	u32 psign;		/* sign ptr */
	u32 sign_len;		/* length of the signature */
	union {
		u32 psgtable;	/* prt to SG table */
		u32 pimg;	/* img offset */
	};
	union {
		u32 sg_entries;	/* no of entries in SG table */
		u32 img_size;	/* img_size length */
	};
	u32 img_start;		/* start ptr */
	union {
		u32 sg_flag;
		struct {
			u32 mp_flag:16;	/* Mfg Protection flag */
			u32 sg_flag:16;	/* Scatter gather flag */
		}mp_n_sg_flag;
	};
	union {
		u32 uid_flag;	/* Flag to indicate uid is present or not */
		struct {
			u8 sfp_wp:8;
			u8 sec_image_flag:8;
			u32 uid_flag:16;
		}uid_n_wp;
	};
	u32 fsl_uid;		/* Freescale unique id */
	u32 oem_uid;		/* OEM unique id */
};

/* Extended image header used for group 3,4,5 */
struct ext_img_hdr {
	u32 hkptr;		/* House keeping area starting address */
	u32 hksize;		/* House keeping area size */
	u32 fsl_uid_1;		/* Freescale unique id 1*/
	u32 oem_uid_1;		/* OEM unique id 1*/
};

/* Extended image header of IE Key usage for ESBC*/
struct ext_esbc_ie_hdr {
	uint32_t ie_flag;	/* IE flag*/
	uint32_t ie_sel;	/* IE key select*/
};

/* Generic structure for linking all individual headers and tables */
struct combined_hdr {
	void *blk_ptr;
	uint32_t blk_size;
	uint32_t blk_offset;
};

struct global {
	/* Variables used across functions */
	FILE *fsrk[MAX_NUM_KEYS];
	RSA * srk[MAX_NUM_KEYS];
	FILE *fie_key[MAX_NUM_KEYS];
	RSA * ie_key[MAX_NUM_KEYS];
	struct sg_table hsgtbl[NUM_SG_ENTRIES];	/* SG table */
	struct combined_hdr *cmbhdrptr[NUM_BLOCKS];
	/* Options flags*/
	int file_flag;
	int verbose_flag;
	int key_ext_flag;
	int hash_flag;
	int img_hash_flag;
	int sign_app_flag;
	int help_flag;
	/* These entries are filled by parsing the arguments */
	int group;
	int sg_flag;
	int entry_flag;
	int num_entries;
	char *pub_fname[MAX_NUM_KEYS];
	char *priv_fname[MAX_NUM_KEYS];
	char *ie_key_fname[MAX_NUM_KEYS];
	uint32_t pub_fname_count;
	uint32_t priv_fname_count;
	uint32_t ie_key_fname_count;
	char *hdrfile;
	char *hash_file;
	char *sign_file;
	char *sgfile;
	uint32_t oemuid_flag[5];
	uint32_t fsluid_flag[2];
	uint32_t oemuid[5];
	uint32_t fsluid[2];
	uint32_t sg_addr;
	uint32_t img_addr;
	uint32_t entry_addr;
	struct sg_input entries[NUM_SG_ENTRIES];
	uint32_t targetid;
	char *target_name;
	uint32_t hkptr;
	uint32_t hksize;
	uint32_t sign_size;
	uint32_t srk_sel;
	uint32_t srk_table_flag;
	uint32_t no_key_flag;
	int sfp_wp;
	uint32_t sec_image_flag;
	uint32_t hkptr_flag;
	uint32_t hksize_flag;
	uint32_t hdrfile_flag;
	uint32_t sgfile_flag;
	uint32_t target_flag;
	uint32_t key_check_flag;
	struct srk_table key_table[MAX_NUM_KEYS];
	struct ie_key_table ie_key_entry[MAX_NUM_KEYS];
	uint32_t num_srk_entries;
	uint32_t num_ie_keys;
	int esbc_flag;
	int sec_image;
	uint32_t mp_flag;
	uint32_t iss_flag;
	uint32_t b01_flag;
	uint32_t lw_flag;
	uint32_t sdhc_flag;
	uint32_t sdhc_bsize;
	uint32_t esbc_hdr;
	uint32_t ie_key_revoc;
	uint32_t ie_flag;
	uint32_t ie_key_sel;
};


#endif
