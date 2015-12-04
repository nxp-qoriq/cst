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

#ifndef _ESBC_HDR_TA_1_X_2_X_H_
#define _ESBC_HDR_TA_1_X_2_X_H_

/**********************************************************
 * HEADER Structures
 **********************************************************/
#define MAX_SRK_ESBC_X		4

struct esbc_hdr_ta_1_ta_2_ppc {
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

	uint32_t pimg;			/* 0x14 ptr to Image */
	uint32_t img_size;		/* 0x18 Size of Image */
	uint32_t res1[2];		/* 0x1c, 0x20 Reserved */

	uint32_t uid_flag;		/* 0x24 Flag to indicate uid */

	uint32_t fsl_uid_0;		/* 0x28 Freescale unique id */
	uint32_t oem_uid_0;		/* 0x2c OEM unique id */

	uint32_t res2[6];		/* 0x30 - 0x48 */
	uint32_t ie_flag;		/* 0x48 IE Flag */
	uint32_t ie_key_select;		/* 0x4c IE Key Select */
};

struct esbc_hdr_ta_2_1_arm7 {
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

	uint32_t pimg;			/* 0x14 ptr to Image */
	uint32_t img_size;		/* 0x18 Size of Image */
	uint32_t res1[2];		/* 0x1c, 0x20 Reserved */

	uint32_t uid_flag;		/* 0x24 Flag to indicate uid */

	uint32_t fsl_uid_0;		/* 0x28 Freescale unique id */
	uint32_t oem_uid_0;		/* 0x2c OEM unique id */

	uint32_t res2[2];		/* 0x30, 0x34 */

	uint32_t fsl_uid_1;		/* 0x38 Freescale unique id */
	uint32_t oem_uid_1;		/* 0x3c OEM unique id */

	uint32_t res3[2];		/* 0x40, 0x44 */

	uint32_t ie_flag;		/* 0x48 IE Flag */
	uint32_t ie_key_select;		/* 0x4c IE Key Select */
};

struct esbc_hdr_ta_2_1_arm8 {
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

	uint32_t reserved;		/* 0x14 Reserved*/
	uint32_t img_size;		/* 0x18 Size of Image */
	uint32_t res1[2];		/* 0x1c, 0x20 Reserved */

	uint32_t uid_flag;		/* 0x24 Flag to indicate uid */

	uint32_t fsl_uid_0;		/* 0x28 Freescale unique id */
	uint32_t oem_uid_0;		/* 0x2c OEM unique id */

	uint32_t res2[2];		/* 0x30, 0x34 */

	uint32_t fsl_uid_1;		/* 0x38 Freescale unique id */
	uint32_t oem_uid_1;		/* 0x3c OEM unique id */

	uint32_t pimg_low;		/* 0x40 ptr to Image */
	uint32_t pimg_high;		/* 0x44 ptr to Image */

	uint32_t ie_flag;		/* 0x48 IE Flag */
	uint32_t ie_key_select;		/* 0x4c IE Key Select */
};



#endif
