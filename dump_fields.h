/** @file
 * dump_fields.h
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

#ifndef __DUMP_FIELDS_H__
#define __DUMP_FIELDS_H__

#include "common.h"
#include "uni_sign.h"

static void dump_sg_table1(struct sg_table *t, int num_entries)
{
	int i;
	printf("no of entries  %d\n", num_entries);
	for (i = 0; i < num_entries; i++)
		printf("entry %d  len %d ptr %x\n",
		       i, BYTE_ORDER_L((t + i)->len),
		       BYTE_ORDER_L((t + i)->pdata));
}

static void dump_sg_table2(struct sg_table_offset *t, int num_entries, int group)
{
	int i;
	printf("no of entries  %d\n", num_entries);
	for (i = 0; i < num_entries; i++) {
		printf("entry %d  len %d ptr %x",
		       i, BYTE_ORDER_L((t + i)->len),
		       BYTE_ORDER_L((t + i)->source));
		if ((group == 2 || group == 4)) {
			printf(" target_id %x destination %x ",
			       (t + i)->target_id, (t + i)->destination);
		}
		printf("\n");
	}
}

static void printkeyhash(u8 *addr, uint32_t key_len,
			 uint32_t srk_table_flag, uint32_t num_srk_entries)
{
	SHA256_CTX key_ctx;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int i;

	SHA256_Init(&key_ctx);
	if (srk_table_flag == 0) {
		SHA256_Update(&key_ctx, addr, key_len);
	} else {
		SHA256_Update(&key_ctx, addr,
			      num_srk_entries * sizeof(struct srk_table));
	}

	SHA256_Final(hash, &key_ctx);
	printf("\n");
	printf("Key Hash :\n");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", hash[i]);
	printf("\n\n");
}

static void printonlyhash(uint32_t srk_table_flag,
			  char *pub_fname[MAX_NUM_KEYS],
			  uint32_t pub_fname_count)
{
	int i, n;
	SHA256_CTX key_ctx;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	FILE * fsrk_pub[MAX_NUM_KEYS];
	RSA * srk_pub[MAX_NUM_KEYS];
	unsigned char *key;
	u8 key_store[1024];
	unsigned char *key_len_ptr;
	u32 key_len = 0, total_key_len;
	n = 0;
	if (pub_fname_count > 1)
		srk_table_flag = 1;

	SHA256_Init(&key_ctx);
	/* open SRK public key file and get the key */
	while (n != pub_fname_count) {
		fsrk_pub[n] = fopen(pub_fname[n], "r");
		if (fsrk_pub[n] == NULL) {
			fprintf(stderr, "Error in opening the file: %s\n",
				pub_fname[n]);
			return;
		}

		srk_pub[n] =
		    PEM_read_RSAPublicKey(fsrk_pub[n], NULL, NULL, NULL);
		if (srk_pub[n] == NULL) {
			fprintf(stderr, "Error in reading key from : %s\n",
				pub_fname[n]);
			fclose(fsrk_pub[n]);
			return;
		}

		key_len = RSA_size(srk_pub[n]);
		memset(key_store, 0, 1024);

		/* Copy N component and E component*/
		key = key_store;
		extract_key(key, key_len, n, srk_pub);

		if (srk_table_flag == 1) {
			total_key_len = BYTE_ORDER_L(2 * key_len);
			key_len_ptr = (u8 *)&total_key_len;
#ifdef DEBUG
		int ctr;
			for (ctr = 0; ctr < 4; ctr++)
				printf("0x%0.2x ", *(key_len_ptr + ctr));
#endif
			SHA256_Update(&key_ctx, key_len_ptr, 4);
			key_len = 512;
		}
#ifdef DEBUG
		for (ctr = 0; ctr < 2 * key_len; ctr++)
			printf("0x%0.2x ", *(key_store + ctr));
#endif
		SHA256_Update(&key_ctx, (u8 *)key_store, 2 * key_len);
		n++;
	}
	SHA256_Final(hash, &key_ctx);
	printf("\n");
	printf("Key Hash :\n");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", hash[i]);
	printf("\n\n");
	n = 0;
	while (n != pub_fname_count) {
		fclose(fsrk_pub[n]);
		RSA_free(srk_pub[n]);
		n++;
	}
}

static void dump_img_hdr1(struct global *gd)
{
	int i;
	struct img_hdr *h = (struct img_hdr *)gd->cmbhdrptr[CSF_HDR]->blk_ptr;
	struct ext_img_hdr *ext_h = (struct ext_img_hdr *)
				    gd->cmbhdrptr[EXTENDED_HDR]->blk_ptr;

	printf("barker:0x");
	for (i = 0; i < BARKER_LEN; i++)
		printf("%.2x",
		       (unsigned)(unsigned char)((BYTE_ORDER_L(h->barker[i])) >> 24));
	printf("\n");
	if (gd->srk_table_flag) {
		printf("srk_table_offset %x\n",
		       BYTE_ORDER_L(h->srk_table_offset));
		printf("srk_table_flag(8) : %x\nsrk_sel(8) : %x\nnum_srk_entries(16) : %x\n",
		       (h->len_kr.srk_table_flag),
		       (h->len_kr.srk_sel),
		       BYTE_ORDER_S((uint16_t)h->len_kr.num_srk_entries));
	} else {
		printf("pkey %x, key length %d\n", BYTE_ORDER_L(h->pkey),
		       BYTE_ORDER_L(h->key_len));
	}
	printf("psign %x, length %d\n", BYTE_ORDER_L(h->psign),
	       BYTE_ORDER_L(h->sign_len));
	printf("uid_flag %x\n", BYTE_ORDER_L(h->uid_flag));
	printf("sfp_wp(8) : %x\nsec_image_flag(8) : %x\nuid_flag(16) : %x\n",
	       (h->uid_n_wp.sfp_wp),
	       (h->uid_n_wp.sec_image_flag),
	       BYTE_ORDER_S((uint16_t)h->uid_n_wp.uid_flag));
	if (BYTE_ORDER_L(h->sg_flag) || ((gd->esbc_flag == 0) &&
					 (gd->group != 1))) {
		printf("psgtable  %x num_entries %d\n",
		       BYTE_ORDER_L(h->psgtable), BYTE_ORDER_L(h->sg_entries));
	} else if (gd->group == 1 || gd->esbc_flag == 1)
		printf("pimg %x len %d\n", BYTE_ORDER_L(h->pimg),
		       BYTE_ORDER_L(h->img_size));

	printf("img start %x\n", BYTE_ORDER_L(h->img_start));
	printf("FSL UID %x\n", BYTE_ORDER_L(h->fsl_uid));
	printf("OEM UID %x\n", BYTE_ORDER_L(h->oem_uid));
	if ((gd->group == 5) && (gd->esbc_flag == 0)) {
		printf("FSL UID 1%x\n", BYTE_ORDER_L(ext_h->fsl_uid_1));
		printf("OEM UID 1%x\n", BYTE_ORDER_L(ext_h->oem_uid_1));
		printf("Manufacturing Protection Flag %x\n",
		       BYTE_ORDER_S((uint16_t)h->mp_n_sg_flag.mp_flag));
		printf("sg_flag %d\n", BYTE_ORDER_S((uint16_t)h->mp_n_sg_flag.sg_flag));
	} else {
		printf("sg_flag %d\n", BYTE_ORDER_L(h->sg_flag));
	}
	if ((gd->hkptr_flag == 1) && (gd->esbc_flag == 0)) {
		printf("hkptr %x\n", BYTE_ORDER_L(ext_h->hkptr));
		printf("hksize %x\n", BYTE_ORDER_L(ext_h->hksize));
	}
}

#ifdef DEBUG
static void dump_gd(struct global *gd)
{
	int i = 0;
	printf("group		: %d\n", gd->group);
	printf("file_flag	: %d\n", gd->file_flag);
	printf("esbc_flag	: %d\n", gd->esbc_flag);
	printf("sg_flag		: %d\n", gd->sg_flag);
	printf("entry_flag	: %d\n", gd->entry_flag);
	printf("hash_flag	: %d\n", gd->hash_flag);
	printf("num_entries	: %d\n", gd->num_entries);
	printf("num_srk_entries	: %d\n", gd->num_srk_entries);
	for (i = 0; i < gd->num_srk_entries; i++) {
		printf("pub_fname %d	: %s\n", i + 1, gd->pub_fname[i]);
		printf("priv_fname %d	: %s\n", i + 1, gd->priv_fname[i]);
	}
	printf("fslid		: %x\n", gd->fsluid[0]);
	printf("oemid		: %x\n", gd->oemuid[0]);
	printf("sg_addr		: %x\n", gd->sg_addr);
	printf("entry_addr	: %x\n", gd->entry_addr);
	printf("img_addr	: %x\n", gd->img_addr);
	for (i = 0; i < gd->num_entries; i++) {
		printf("binary name %s .. addr %x\n",
		       gd->entries[i].name, gd.entries[i].addr);
	}
	if ((gd->group == 3 || gd->group == 4) && (gd->esbc_flag == 0)) {
		printf("hkptr		: %x\n", gd->hkptr);
		printf("hksize		: %x\n", gd->hksize);
	} else if (gd->group == 5) {
		printf("fslid_1		: %x\n", gd->fsluid[1]);
		printf("oemid_1		: %x\n", gd->oemuid[1]);
		printf("mp_flag		: %x\n", gd->mp_flag);
	}
	if (gd->group == 3 || gd->group == 4 || gd->group == 5) {
		printf("srk_sel		: %x\n", gd->srk_sel);
		printf("srk_table_flag	: %x\n", gd->srk_table_flag);
		printf("sfp_wp		: %x\n", gd->sfp_wp);
	}

	if ((gd->group == 2 || gd->group == 4) && (gd->esbc_flag == 0))
		printf("target_id	: %x\n", gd->targetid);
	/* Variables used across functions */
	/* These entries are filled by parsing the arguments */
}
#endif

static void usage(void)
{
		printf("\nThis script signs the files and generates the header"
		       " as understood by ");
		printf("ISBC/ESBC with signature embedded in it.\n");
		printf("For format of header generated refer to the "
			"User Document.\n");
		printf("\nUsage :\n");
		printf("./uni_sign [options] INPUT_FILE\n");

		printf("--verbose \t");
		printf("Generate output header alongwith displays the"
		       " headerinfo. Dumps signature in sign.out file.\n");

		printf("--key_ext \t");
		printf("Generate ISBC/ESBC output header with IE_KEY"
		       " usage feature.\n");

		printf("--hash \t\t");
		printf("Print the hash of public key(srk table) as specified"
		       " in input file.\n");

		printf("--img_hash \t");
		printf("Dump the complete SHA256 hash in a separate file("
		       "Default filename: hash.out). Header file is generated"
		       " without\n\t\tsignature embedded in it.\n");

		printf("--sign_app_verify\n\t\t");
		printf("Generates the header based on input file provided."
		       " Verifies the SHA256hash value with the HASH FILE. The"
		       " signature\n\t\tprovided as input in SIGN FILE is appended"
		       " in the output header file.\n\t\tHASH FILE and SIGN"
		       " FILE name should be defined in input file passed.\n");

		printf("INPUT_FILE\tRefer Default input_file and provide all"
		       " the input in the file for header generation .\n");

		printf("--help\t\t");
		printf("Show this help message and exit.\n");
}
#endif
