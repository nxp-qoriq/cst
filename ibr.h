/** @file
 * ibr.h
 */

/* Copyright (c) 2011, Freescale Semiconductor, Inc.
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
#ifndef __IBR_H__
#define __IBR_H__

struct cf_hdr_legacy {
	u32 boot_sig;		/*0x40*/
	u32 res5;		/*0x44-0x47*/
	u32 code_len;		/*0x48-0x4B*/
	u32 res7;		/*0x4C-0x4F*/
	u32 src_addr;		/*0x50-0x53*/
	u32 res9;		/*0x54-0x57*/
	u32 dst_addr;		/*0x58-0x5B*/
	u32 res11;		/*0x5C-0x5F*/
	u32 entry_point;	/*0x60-0x63*/
	u32 res13;		/*0x64-0x67*/
	u32 no_conf_pairs;	/*0x68-0x6B*/
	u8 res14[20];		/*0x6C-0x7F*/
};

struct cf_hdr_secure {
	u32 ehdrloc;
	u32 esbc_target_id;	/*0xB4-0xB7*/
	u32 pkey_off; 		/*0xB8-0xBB*/	/* public key offset */
	u32 key_len;  		/*0xBC-0xBF*/	/* pub key length */
	u32 psign_off;  	/*0xC0-0xC3*/	/* sign ptr */
	u32 sign_len; 		/*0xC4-0xC7*/	/* length of the signature */
};

/**
\brief          ESBC header structure.

\details        contain the following fields
		barker code
		public key offset
		pub key length
		signature offset
		length of the signature
		ptr to SG table
		no of entries in SG table
		esbc ptr
		size of esbc
		esbc entry point
		Scatter gather flag
		UID flag
		FSL UID
		OEM UID

\note		pub key is modulus concatenated with exponent 
		of equal length 
*/
struct esbc_hdr {
	u8 barker[ESBC_BARKER_LEN];	/* barker code */
	u32 pkey;		/* public key offset */
	u32 key_len;		/* pub key length in bytes */
	u32 psign;		/* signature offset */
	u32 sign_len;		/* length of the signature in bytes */
	u32 sg_table_addr;	/* ptr to SG table */
	u32 sg_entries;	/* no of entries in SG table */
	u32 entry_point;		/* ESBC entry point */
	u32 sg_flag;		/* Scatter gather flag */
	u32 uid_flag;		/* Flag to indicate uid is present or not */
	u32 fsl_uid;		/* Freescale unique id */
	u32 oem_uid;		/* OEM unique id */
};

struct sg_table {
	u32 len;
	u32 trgt_id;
	u32 src_addr;
	u32 dst_addr;
};
#endif
