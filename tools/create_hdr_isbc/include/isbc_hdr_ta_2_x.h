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

#ifndef _ISBC_HDR_TA_2_X_H_
#define _ISBC_HDR_TA_2_X_H_

/**********************************************************
 * HEADER Structures
 **********************************************************/
#define MAX_SG_TA_2_X		8
#define MAX_SRK_TA_2_X		4

struct isbc_hdr_ta_2_0 {
	uint8_t barker[BARKER_LEN];	/* 0x00 Barker code */
	union {
		uint32_t srk_table_offset;	/* SRK Table Offset */
		uint32_t pkey;			/* Public Key */
	};				/* 0x04 */

	union {
		uint32_t key_len;
		struct {
			uint32_t srk_table_flag:8;
			uint32_t key_num_verify:8;
			uint32_t num_keys:16;
		}len_kr;	
	};				/* 0x08 */

	uint32_t psign;			/* 0x0c signature offset */
	uint32_t sign_len;		/* 0x10 length of signature */

	uint32_t sg_table_addr;		/* 0x14 ptr to SG table */
	uint32_t sg_entries;		/* 0x18 no. of entries in SG */
	uint32_t entry_point;		/* 0x1c ESBC entry point */

	union {
		uint32_t sg_flag;
		struct {
			uint32_t mp_flag:16;	/* Mfg Protection flag */
			uint32_t sg_flag:16;	/* Scatter gather flag */
		}mp_n_sg_flag;
	};				/* 0x20 */

	union {
		uint32_t uid_flag;	/* Flag to indicate uid */
		struct {
			uint32_t sfp_wp:8;
			uint32_t sec_image_flag:8;
			uint32_t uid_flag:16;
		}uid_n_wp;
	};				/* 0x24 */
	uint32_t fsl_uid_0;		/* 0x28 Freescale unique id */
	uint32_t oem_uid_0;		/* 0x2c OEM unique id */

	uint32_t hkarea;		/* 0x30 HK Area */
	uint32_t hksize;		/* 0x34 HK Area */
	uint32_t res2[2];		/* 0x38 - 0x3c */
};

struct isbc_hdr_ta_2_1 {
	uint8_t barker[BARKER_LEN];	/* 0x00 Barker code */
	union {
		uint32_t srk_table_offset;	/* SRK Table Offset */
		uint32_t pkey;			/* Public Key */
	};				/* 0x04 */

	union {
		uint32_t key_len;
		struct {
			uint32_t srk_table_flag:8;
			uint32_t key_num_verify:8;
			uint32_t num_keys:16;
		}len_kr;	
	};				/* 0x08 */

	uint32_t psign;			/* 0x0c signature offset */
	uint32_t sign_len;		/* 0x10 length of signature */

	uint32_t sg_table_addr;		/* 0x14 ptr to SG table */
	uint32_t sg_entries;		/* 0x18 no. of entries in SG */
	uint32_t entry_point;		/* 0x1c ESBC entry point */

	union {
		uint32_t sg_flag;
		struct {
			uint32_t mp_flag:16;	/* Mfg Protection flag */
			uint32_t sg_flag:16;	/* Scatter gather flag */
		}mp_n_sg_flag;
	};				/* 0x20 MP Flag */

	union {
		uint32_t uid_flag;	/* Flag to indicate uid */
		struct {
			uint32_t sfp_wp:8;
			uint32_t sec_image_flag:8;
			uint32_t uid_flag:16;
		}uid_n_wp;
	};				/* 0x24 */
	uint32_t fsl_uid_0;		/* 0x28 Freescale unique id */
	uint32_t oem_uid_0;		/* 0x2c OEM unique id */

	uint32_t res2[2];		/* 0x30 - 0x34 */
	uint32_t fsl_uid_1;		/* 0x38 Freescale unique id */
	uint32_t oem_uid_1;		/* 0x3c OEM unique id */
};

#endif
