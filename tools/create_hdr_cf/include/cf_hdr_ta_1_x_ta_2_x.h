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

#ifndef _CF_HDR_TA_1_X_2_X_H_
#define _CF_HDR_TA_1_X_2_X_H_

/**********************************************************
 * HEADER Structures
 **********************************************************/
#define MAX_SRK_ESBC_X		4
#define BOOT_SIGNATURE		0x424F4F54

struct cf_hdr_legacy {
	uint32_t boot_sig;		/*0x40*/
	uint32_t res1;			/*0x44-0x47*/
	uint32_t code_len;		/*0x48-0x4B*/
	uint32_t res2;			/*0x4C-0x4F*/
	uint32_t src_addr;		/*0x50-0x53*/
	uint32_t res3;			/*0x54-0x57*/
	uint32_t dst_addr;		/*0x58-0x5B*/
	uint32_t res4;			/*0x5C-0x5F*/
	uint32_t entry_point;		/*0x60-0x63*/
	uint32_t res5;			/*0x64-0x67*/
	uint32_t no_conf_pairs;		/*0x68-0x6B*/
	uint8_t res6[20];		/*0x6C-0x7F*/
};

struct cf_hdr_secure {
	uint32_t ehdrloc;
	uint32_t esbc_target_id;
	union {
		uint32_t pkey_off;		/* public key offset */
		uint32_t srk_table_offset;
	};	
	union {
		uint32_t key_len;		/* pub key length */
		struct {
			uint32_t srk_sel:16;
			uint32_t num_srk_entries:16;	
		}len_kr;	
	};
	uint32_t psign_off;			/* sign ptr */
	uint32_t sign_len;			/* length of the signature */
	uint32_t ehdrloc_simg;
};

#define SIZE_HDR_LEGACY		(sizeof(struct cf_hdr_legacy))
#define SIZE_HDR_SECURE_TA_2	(sizeof(struct cf_hdr_secure))
#define SIZE_HDR_SECURE_TA_1	(SIZE_HDR_SECURE_TA_2 - sizeof(uint32_t))
#define SIZE_CF_WORD		(sizeof(struct cf_word_t) * gd.cf_count)
#define SIZE_RESERVED		0x40

#endif
