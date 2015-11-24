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

#ifndef _ISBC_HDR_TA_3_X_H_
#define _ISBC_HDR_TA_3_X_H_

/**********************************************************
 * HEADER Structures
 **********************************************************/
#define LW_FLAG_MASK		0x80
#define B01_FLAG_MASK		0x40
#define ISS_FLAG_MASK		0x20
#define MP_FLAG_MASK		0x10
#define IE_FLAG_MASK		0x01

#define FID_MASK		0x80
#define OID_0_MASK		0x40
#define OID_1_MASK		0x20
#define OID_2_MASK		0x10
#define OID_3_MASK		0x08
#define OID_4_MASK		0x04

#define MAX_SG_TA_3_X		8
#define MAX_SRK_TA_3_X		8

struct isbc_hdr_ta_3_1 {
	uint8_t barker[BARKER_LEN];	/* 0x00 Barker code */
	uint32_t srk_table_offset;	/* 0x04 SRK Table Offset */

	uint8_t num_keys;		/* 0x08 No. of keys */
	uint8_t key_num_verify;		/* 0x09 Key no. to be used*/
	uint8_t reserve;		/* 0x0a Reserved */
	uint8_t misc_flags;		/* 0x0b Misc. Flags*/

	uint8_t res[3];			/* 0x0c 0x0d 0x0e */
	uint8_t uid_flags;		/* 0x0f UID Flags */

	uint32_t psign;			/* 0x10 signature offset */
	uint32_t sign_len;		/* 0x14 length of signature */
	uint32_t sg_table_addr;		/* 0x18 ptr to SG table */
	uint32_t sg_entries;		/* 0x1c no. of entries in SG */
	uint32_t entry_point_l;		/* 0x20 ESBC entry point */
	uint32_t entry_point_h;		/* 0x24 ESBC entry point */

	uint32_t fsl_uid[2];		/* 0x28-0x30 Freescale unique id's*/
	uint32_t oem_uid[5];		/* 0x30-0x44 OEM unique id's*/

	uint32_t reserved[3];		/* 0x44 - 0x4f */
};


struct isbc_hdr_ta_3_0 {
	uint8_t barker[BARKER_LEN];	/* 0x00 Barker code */
	uint32_t srk_table_offset;	/* 0x04 SRK Table Offset */

	uint8_t num_keys;		/* 0x08 No. of keys */
	uint8_t key_num_verify;		/* 0x09 Key no. to be used*/
	uint8_t reserve;		/* 0x0a Reserved */
	uint8_t misc_flags;		/* 0x0b Misc. Flags*/

	uint8_t res[3];			/* 0x0c 0x0d 0x0e */
	uint8_t uid_flags;		/* 0x0f UID Flags */

	uint32_t psign;			/* 0x10 signature offset */
	uint32_t sign_len;		/* 0x14 length of signature */
	uint32_t sg_table_addr;		/* 0x18 ptr to SG table */
	uint32_t sg_entries;		/* 0x1c no. of entries in SG */
	uint32_t entry_point;		/* 0x20 ESBC entry point */

	uint32_t fsl_uid[2];		/* 0x24-0x28 Freescale unique id's*/
	uint32_t oem_uid[5];		/* 0x2c-0x3c OEM unique id's*/

	uint32_t reserved[4];		/* 0x40 - 0x4f */
};
#endif
