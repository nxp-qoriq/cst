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

#define OUID_FUID_BOTH 0x1
#define OUID_ONLY 0x2
#define FUID_ONLY 0x4
#define NO_UID	0x0

#define TBL_FILE "sg_table.out"
#define HDR_FILE "hdr.out"

#define IOBLOCK 128		/* I/O block size used for hashing operations */
#define NUM_SG_ENTRIES	8

char *group[][2] = { {"3041", "1"},
{"4080", "1"},
{"5020", "1"},
{"5040", "1"},
{"3041", "1"},
{"1010", "2"},
{"9131", "2"},
{"9132", "2"},
{"4860", "3"},
{"4240", "3"},
{"1040", "4"},
{"C290", "4"},
{"LS1", "5"},
{"LAST", "0"}
};

/* Header Format */
struct size_format {
	u32 header;
	u32 padd1;
	u32 key_table;
	u32 padd2;
	u32 sign_len;
	u32 padd3;
	u32 sg_table;
};


struct sg_table {
	u32 len;		/* length of the segment */
	u32 pdata;		/* ptr to the data segment */
};

struct srk_table {
	u32 key_len;
	u8 pkey[1024];
};

struct sg_table_offset {
	u32 len;		/* length of the segment */
	u32 target_id;
	u32 source;		/* ptr to the data segment */
	u32 destination;	/* ptr to the data segment */
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
	u32 hkptr;		/* House keeping area starting address */
	u32 hksize;		/* House keeping area size */
	u32 fsl_uid_1;		/* Freescale unique id 1*/
	u32 oem_uid_1;		/* OEM unique id 1*/
};

struct sg_input {
	char *name;
	uint32_t addr;
	uint32_t d_addr;
};

struct hk {
	u32 hkptr;		/* House keeping area starting address */
	u32 hksize;		/* House keeping area size */
};

struct global {
	/* Variables used across functions */
	FILE * fsrk_pri[MAX_NUM_KEYS];
	RSA * srk[MAX_NUM_KEYS];
	struct sg_table hsgtbl[NUM_SG_ENTRIES];	/* SG table */
	struct sg_table_offset osgtbl[NUM_SG_ENTRIES];	/* offset SG table */
	struct img_hdr himg;
	/* These entries are filled by parsing the arguments */
	int group;
	int sg_flag;
	int entry_flag;
	int hash_flag;
	int num_entries;
	char *pub_fname[MAX_NUM_KEYS];
	char *priv_fname[MAX_NUM_KEYS];
	char *hdrfile;
	char *sgfile;
	uint32_t oemuid_flag;
	uint32_t fsluid_flag;
	uint32_t oemuid_1_flag;
	uint32_t fsluid_1_flag;
	uint32_t fslid;
	uint32_t oemid;
	uint32_t fslid_1;
	uint32_t oemid_1;
	uint32_t sg_addr;
	uint32_t img_addr;
	uint32_t entry_addr;
	int verbose_flag;
	struct sg_input entries[NUM_SG_ENTRIES];
	uint32_t targetid;
	char *target_name;
	uint32_t hkptr;
	uint32_t hksize;
	uint32_t srk_sel;
	uint32_t srk_table_flag;
	int sfp_wp;
	uint32_t sec_image_flag;
	uint32_t hkptr_flag;
	uint32_t hksize_flag;
	uint32_t hdrfile_flag;
	uint32_t sgfile_flag;
	uint32_t target_flag;
	struct srk_table key_table[MAX_NUM_KEYS];
	uint32_t num_srk_entries;
	int esbc_flag;
	int file_flag;
	int sec_image;
	uint32_t mp_flag;
	uint32_t sdhc_flag;
	uint32_t sdhc_bsize;
	uint32_t help_flag;
};


#endif
