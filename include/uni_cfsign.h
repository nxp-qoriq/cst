/** @file
 * uni_cfsign.h
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

#ifndef __UNI_CFSIGN_H__
#define __UNI_CFSIGN_H__


#define HDR_FILE "cf_hdr.out"
#define MAKE_WORD(ADDR, DATA)\
	words[word_count++] = htonl(ADDR);\
	words[word_count++] = htonl(DATA);


char *group[][2] = { {"1010", "1"},
{"9131", "1"},
{"9132", "1"},
{"1040", "2"},
{"C290", "2"},
{"c290", "2"},
{"LAST", "0"}
};

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
	u32 esbc_target_id;
	union {
		u32 pkey_off;		/* public key offset */
		u32 srk_table_offset;
	};	
	union {
		u32 key_len;		/* pub key length */
		struct {
			u32 srk_table_flag:4;
			u32 srk_sel:12;
			u32 num_srk_entries:16;	
		}len_kr;	
	};
	u32 psign_off;			/* sign ptr */
	u32 sign_len;			/* length of the signature */
	u32 ehdrloc_simg;
};

struct size_format {
	u32 hdr_legacy;
	u32 cfw;
	u32 hdr_secure;
	u32 padd1;
	u32 key_table;
	u32 padd2;
	u32 sign_len;
};

struct srk_table {
	u32 key_len;
	u8 pkey[1024];
};


struct global {
	FILE * fsrk_pri[MAX_NUM_KEYS];
	RSA * srk[MAX_NUM_KEYS];
	int group;
	char *priv_fname[MAX_NUM_KEYS];
	struct srk_table key_table[MAX_NUM_KEYS];
	uint32_t num_srk_entries;
	uint32_t srk_sel;
	uint32_t srk_table_flag;
	char *hdrfile;
};

#endif
