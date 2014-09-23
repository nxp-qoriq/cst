/* This code generates and puts  header, public key and signature
 * on top of the image / data to be validated.
 */

/* Copyright (c) 2011-2012 Freescale Semiconductor, Inc.
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
/*
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 */
/*
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 */

#define OPENSSL_NO_KRB5
#define BLOCK_SIZE 512

#include <stdio.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <getopt.h>
#include "common.h"
#include "uni_sign.h"
#include "dump_fields.h"

struct global gd;
extern struct input_field file_field;	/* Required for parsing input file */

/* Creates new node for combined header*/
static struct combined_hdr *new_node()
{
	struct combined_hdr *cmbhdr;
	cmbhdr = (struct combined_hdr *)malloc(sizeof(struct combined_hdr));

	cmbhdr->blk_ptr = NULL;
	cmbhdr->blk_size = 0;
	cmbhdr->blk_offset = 0;
	return cmbhdr;
}

/* Initialise all the blocks and forms a complete header*/
static void initialise_nodes()
{
	/* Initialise img_hdr node*/
	gd.cmbhdrptr[CSF_HDR_LS] = new_node();
	gd.cmbhdrptr[CSF_HDR] = new_node();
	if (gd.group == 6) {
		gd.cmbhdrptr[CSF_HDR_LS]->blk_ptr = (struct img_hdr_ls2 *)
					calloc(1, sizeof(struct img_hdr_ls2));
		gd.cmbhdrptr[CSF_HDR_LS]->blk_size = sizeof(struct img_hdr_ls2);
	} else {
		gd.cmbhdrptr[CSF_HDR]->blk_ptr = (struct img_hdr *)
					calloc(1, sizeof(struct img_hdr));
		gd.cmbhdrptr[CSF_HDR]->blk_size = sizeof(struct img_hdr);
	}

	/* Initialise ext_img_hdr node*/
	gd.cmbhdrptr[EXTENDED_HDR] = new_node();
	if (((gd.group == 3) || (gd.group == 4) || (gd.group == 5)) &&
	    (gd.esbc_flag == 0)) {
		gd.cmbhdrptr[EXTENDED_HDR]->blk_ptr = (struct ext_img_hdr *)
					calloc(1, sizeof(struct ext_img_hdr));
		gd.cmbhdrptr[EXTENDED_HDR]->blk_size =
					sizeof(struct ext_img_hdr);
	}

	/* Initialise ext_esbc_ie_hdr node*/
	gd.cmbhdrptr[EXT_ESBC_HDR] = new_node();
	if (gd.ie_flag == 1 && gd.esbc_flag == 1) {
		gd.cmbhdrptr[EXT_ESBC_HDR]->blk_ptr =
					(struct ext_esbc_ie_hdr *)
					calloc(1,
					       sizeof(struct ext_esbc_ie_hdr));
		gd.cmbhdrptr[EXT_ESBC_HDR]->blk_size =
					sizeof(struct ext_esbc_ie_hdr);
	}

	/* Initialise srk_table node*/
	gd.cmbhdrptr[SRK_TABLE] = new_node();
	if (gd.key_type_req != NO_KEY) {
		if (gd.srk_table_flag == 0) {
			gd.cmbhdrptr[SRK_TABLE]->blk_ptr = (void *)
					calloc(1, 2 * RSA_size(gd.srk[0]));
			gd.cmbhdrptr[SRK_TABLE]->blk_size = 2 *
					RSA_size(gd.srk[0]);
		} else {
			gd.cmbhdrptr[SRK_TABLE]->blk_ptr = (struct srk_table *)
					calloc(1, gd.num_srk_entries *
					sizeof(struct srk_table));
			gd.cmbhdrptr[SRK_TABLE]->blk_size =
					gd.num_srk_entries *
					sizeof(struct srk_table);
		}
	}

	/* Initialise sg table node*/
	gd.cmbhdrptr[SG_TABLE] = new_node();
	if (((gd.group == 2) || (gd.group == 3) || (gd.group == 4) ||
	     (gd.group == 5) || (gd.group == 6)) && (gd.esbc_flag == 0)) {
		gd.cmbhdrptr[SG_TABLE]->blk_ptr = (struct sg_table_offset *)
					calloc(1, gd.num_entries *
					 sizeof(struct sg_table_offset));
		gd.cmbhdrptr[SG_TABLE]->blk_size = gd.num_entries *
					 sizeof(struct sg_table_offset);
	}

	/* Initialise ie_key_table node*/
	gd.cmbhdrptr[IE_TABLE] = new_node();
	if (gd.ie_flag == 1 && gd.esbc_flag == 0) {
		gd.cmbhdrptr[IE_TABLE]->blk_ptr = (struct ie_key_table *)
			calloc(1,
			       (gd.num_ie_keys * sizeof(struct ie_key_table)) +
			       (2 * sizeof(uint32_t)));
		gd.cmbhdrptr[IE_TABLE]->blk_size =
			(gd.num_ie_keys * sizeof(struct ie_key_table)) +
			(2 * sizeof(uint32_t));
	}

	/* Initialise signature node*/
	gd.cmbhdrptr[SIGNATURE] = new_node();
}

/* This function populates Offsets for all the blocks. */
static void fill_offset()
{
	int i;

	if (gd.key_type_req != NO_KEY) {
		if (gd.srk_table_flag == 0) {
			gd.cmbhdrptr[SIGNATURE]->blk_size =
					RSA_size(gd.srk[0]);
		} else {
			i = 0;
			while (i != gd.num_srk_entries) {
				gd.key_table[i].key_len = RSA_size(gd.srk[i]);
				i++;
			}
			gd.cmbhdrptr[SIGNATURE]->blk_size =
					gd.key_table[gd.srk_sel - 1].key_len;
		}
	} else {
		gd.cmbhdrptr[SIGNATURE]->blk_size = gd.sign_size;
	}

	if (gd.ie_flag == 1 && gd.esbc_flag == 0) {
		i = 0;
		while (i != gd.num_ie_keys) {
			gd.ie_key_entry[i].key_len = RSA_size(gd.ie_key[i]);
			i++;
		}
	}

	/* To add padding in the header */
	gd.cmbhdrptr[CSF_HDR_LS]->blk_offset = CSF_HDR_OFFSET;
	gd.cmbhdrptr[CSF_HDR]->blk_offset = CSF_HDR_OFFSET;
	gd.cmbhdrptr[EXTENDED_HDR]->blk_offset =
					gd.cmbhdrptr[CSF_HDR]->blk_size;
	gd.cmbhdrptr[EXT_ESBC_HDR]->blk_offset =
					gd.cmbhdrptr[CSF_HDR]->blk_size;
	gd.cmbhdrptr[SRK_TABLE]->blk_offset = SRK_TABLE_OFFSET;

	gd.cmbhdrptr[SG_TABLE]->blk_offset =
					gd.cmbhdrptr[SRK_TABLE]->blk_offset +
					gd.cmbhdrptr[SRK_TABLE]->blk_size;
	if (gd.cmbhdrptr[SG_TABLE]->blk_offset & ADDR_ALIGN_MASK) {
		gd.cmbhdrptr[SG_TABLE]->blk_offset =
					(gd.cmbhdrptr[SG_TABLE]->blk_offset &
					(~ADDR_ALIGN_MASK)) + ADDR_ALIGN_OFFSET;
	}

	gd.cmbhdrptr[IE_TABLE]->blk_offset =
					gd.cmbhdrptr[SG_TABLE]->blk_offset +
					gd.cmbhdrptr[SG_TABLE]->blk_size;
	if (gd.cmbhdrptr[IE_TABLE]->blk_offset & ADDR_ALIGN_MASK) {
		gd.cmbhdrptr[IE_TABLE]->blk_offset =
					(gd.cmbhdrptr[IE_TABLE]->blk_offset &
					(~ADDR_ALIGN_MASK)) + ADDR_ALIGN_OFFSET;
	}
}

/* Deallocates all nodes and memory being allocated*/
static void free_mem()
{
	int i;
	for (i = 0; i < gd.num_srk_entries; i++) {
		if (gd.key_type_req == PRIV_KEY_ONLY ||
		    gd.key_type_req == BOTH_KEY)
			RSA_free(gd.srk_pri[i]);

		if (gd.key_type_req == PUB_KEY_ONLY ||
		    gd.key_type_req == BOTH_KEY)
			RSA_free(gd.srk_pub[i]);
	}

	for (i = 0; i < gd.num_ie_keys; i++) {
		fclose(gd.fie_key[i]);
		RSA_free(gd.ie_key[i]);
	}

	for (i = 0; i != gd.pub_fname_count; i++)
		free(gd.pub_fname[i]);

	for (i = 0; i != gd.priv_fname_count; i++)
		free(gd.priv_fname[i]);

	for (i = 0; i != gd.ie_key_fname_count; i++)
		free(gd.ie_key_fname[i]);

	for (i = 0; i != NUM_SG_ENTRIES; i++)
		free(gd.entries[i].name);

	if (gd.target_flag == 1)
		free(gd.target_name);

	if (gd.sgfile_flag == 1)
		free(gd.sgfile);

	if (gd.hdrfile_flag == 1)
		free(gd.hdrfile);

	for (i = CSF_HDR_LS; i != BLOCK_END; i++) {
		free(gd.cmbhdrptr[i]->blk_ptr);
		free(gd.cmbhdrptr[i]);
	}
}

void compare_key_pairs()
{
	int n = 0;
	int ret;
	u8 key_pri[KEY_SIZE_BYTES];
	u8 key_pub[KEY_SIZE_BYTES];

	n = 0;
	while (n != gd.num_srk_entries) {
		/* extract_key function would return only the N and E
		 * components of the RSA key passed.
		 * Passing Public and Private keys to the function and doing
		 * their byte wise comparison conforms validity of pair.
		 * */
		extract_key(key_pri, RSA_size(gd.srk_pri[n]), n, gd.srk_pri);
		extract_key(key_pub, RSA_size(gd.srk_pub[n]), n, gd.srk_pub);

		ret = memcmp(key_pri, key_pub, RSA_size(gd.srk_pri[n]));
		if (ret != 0) {
			printf("Public Private Key Pair is not matching\n");
			exit(EXIT_FAILURE);
		}
		n++;
	}
}

int check_group(char *platform)
{

	int i = 0;
	while (strcmp(group[i][0], "LAST")) {
		if (strcmp(group[i][0], platform) == 0) {
			gd.group = STR_TO_UL(group[i][1], 0, 10);
			return 0;
		}
		i++;
	}
	return -1;
}

/* return the size of the give file */
static int get_size(const char *c)
{
	FILE *fp;
	unsigned char buf[IOBLOCK];
	size_t bytes = 0;

	fp = fopen(c, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", c);
		exit(0);
	}

	while (!feof(fp)) {
		/* read some data */
		bytes += fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file\n");
			return -1;
		} else if (feof(fp) && (bytes == 0))
			break;
	}

	printf("size of file %s is %x - %d\n", c, bytes, bytes);

	fclose(fp);
	return bytes;
}

int get_size_and_updatehash(const char *fname, SHA256_CTX * ctx)
{
	FILE *fp;
	unsigned char buf[IOBLOCK];
	size_t bytes = 0;
	size_t len = 0;

	/* open the file */
	fp = fopen(fname, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", fname);
		exit(0);
	}

	/* go to the begenning */
	fseek(fp, 0L, SEEK_SET);

	while (!feof(fp)) {
		/* read some data */
		bytes = fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file\n");
			exit(0);
		} else if (feof(fp) && (bytes == 0))
			break;

		SHA256_Update(ctx, buf, bytes);
#ifdef DEBUG
	int j;
		for (j = 0; j < bytes / 4; j++)
			printf("%x\n", BYTE_ORDER_L(*((uint32_t *) buf + j)));
#endif
		len += bytes;
	}

	fclose(fp);

	return len;
}

/*
 * Reads public key when compiled with img_hash option otherwise
 * reads private key.
 * */
int open_key_file(void)
{
	int i = 0;
	char *fname_pub, *fname_pri;

	for (i = 0; i < gd.num_srk_entries; i++) {
		/* open public key file and get the key */
		if (gd.key_type_req == PUB_KEY_ONLY ||
		    gd.key_type_req == BOTH_KEY) {
			fname_pub = gd.pub_fname[i];
			gd.fsrk_pub[i] = fopen(fname_pub, "r");
			if (gd.fsrk_pub[i] == NULL) {
				fprintf(stderr, "Error in file opening:\n");
				return -1;
			}

			/* read the public key using RSA API*/
			gd.srk_pub[i] = PEM_read_RSAPublicKey
				    (gd.fsrk_pub[i], NULL, NULL, NULL);
			if (gd.srk_pub[i] == NULL) {
				fprintf(stderr, "Error in key reading:\n");
				return -1;
			}

			gd.srk[i] = gd.srk_pub[i];
			fclose(gd.fsrk_pub[i]);
		}

		/* open private key file and get the key */
		if (gd.key_type_req == PRIV_KEY_ONLY ||
		    gd.key_type_req == BOTH_KEY) {
			fname_pri = gd.priv_fname[i];
			gd.fsrk_pri[i] = fopen(fname_pri, "r");
			if (gd.fsrk_pri[i] == NULL) {
				fprintf(stderr, "Error in file opening:\n");
				return -1;
			}

			/* read the private key using RSA API*/
			gd.srk_pri[i] = PEM_read_RSAPrivateKey
				    (gd.fsrk_pri[i], NULL, NULL, NULL);
			if (gd.srk_pri[i] == NULL) {
				fprintf(stderr, "Error in key reading:\n");
				return -1;
			}

			gd.srk[i] = gd.srk_pri[i];
			fclose(gd.fsrk_pri[i]);
		}
	}

	for (i = 0; i < gd.num_ie_keys; i++) {
		/* open IE private key file and get the key */
		gd.fie_key[i] = fopen(gd.ie_key_fname[i], "r");
		if (gd.fie_key[i] == NULL) {
			fprintf(stderr, "Error in opening the file: %s\n",
				gd.ie_key_fname[i]);
			return -1;
		}

		gd.ie_key[i] =
		    PEM_read_RSAPublicKey(gd.fie_key[i], NULL, NULL, NULL);
		if (gd.ie_key[i] == NULL) {
			fprintf(stderr, "Error in reading key from : %s\n",
				gd.ie_key_fname[i]);
			fclose(gd.fie_key[i]);
			return -1;
		}
	}
	return 0;
}

void fill_header_ls(SHA256_CTX *ctx)
{
	u8 uid_flags, misc_flags;
	u8 uid_bit, misc_bit;
	int i;
	struct img_hdr_ls2 *hdr_ptr = (struct img_hdr_ls2 *)
				  gd.cmbhdrptr[CSF_HDR_LS]->blk_ptr;

	u8 barker[BARKER_LEN] = {0x12, 0x19, 0x20, 0x01};
	hdr_ptr->barker[0] = barker[0];
	hdr_ptr->barker[1] = barker[1];
	hdr_ptr->barker[2] = barker[2];
	hdr_ptr->barker[3] = barker[3];
	hdr_ptr->srk_table_offset = BYTE_ORDER_L
					(gd.cmbhdrptr[SRK_TABLE]->blk_offset);

	hdr_ptr->num_keys = (u8)gd.num_srk_entries;
	hdr_ptr->key_num_verify = (u8)gd.srk_sel;

	/* Populating misc_flags depending upon which all flags are set*/
	misc_flags = 0x00;
	misc_bit = 0x01;
	if (gd.ie_flag == 1 && gd.esbc_flag == 0)
		misc_flags = misc_flags | misc_bit;

	misc_bit = misc_bit << 4;
	if (gd.mp_flag == 1 && gd.esbc_flag == 0)
		misc_flags = misc_flags | misc_bit;

	misc_bit = misc_bit << 1;
	if (gd.iss_flag == 1 && gd.esbc_flag == 0)
		misc_flags = misc_flags | misc_bit;

	misc_bit = misc_bit << 1;
	if (gd.b01_flag == 1 && gd.esbc_flag == 0)
		misc_flags = misc_flags | misc_bit;

	misc_bit = misc_bit << 1;
	if (gd.lw_flag == 1 && gd.esbc_flag == 0)
		misc_flags = misc_flags | misc_bit;

	hdr_ptr->misc_flags = (u8)misc_flags;

	/* Populating signature and sg_table fields*/
	hdr_ptr->psign = BYTE_ORDER_L(gd.cmbhdrptr[SIGNATURE]->blk_offset);
	hdr_ptr->sign_len = BYTE_ORDER_L(gd.cmbhdrptr[SIGNATURE]->blk_size);
	hdr_ptr->sg_table_addr = BYTE_ORDER_L
				 (gd.cmbhdrptr[SG_TABLE]->blk_offset);
	hdr_ptr->sg_entries = BYTE_ORDER_L(gd.num_entries);
	hdr_ptr->entry_point = BYTE_ORDER_L(gd.entry_addr);

	/* Populating fsl, oem uids and uid_flags*/
	uid_flags = 0x00;
	uid_bit = 0x02;
	for (i = 0; i < 5; i++) {
		if (gd.oemuid_flag[i] != 0) {
			uid_flags = uid_flags | (uid_bit << (5 - i));
			hdr_ptr->oem_uid[i] = BYTE_ORDER_L(gd.oemuid[i]);
		}
	}

	if (gd.fsluid_flag[0] != 0 || gd.fsluid_flag[1] != 0) {
		uid_flags = uid_flags | 0x80;
	}
	hdr_ptr->fsl_uid[0] = BYTE_ORDER_L(gd.fsluid[0]);
	hdr_ptr->fsl_uid[1] = BYTE_ORDER_L(gd.fsluid[1]);

	hdr_ptr->uid_flags = (u8)uid_flags;

	SHA256_Update(ctx, (u8 *)hdr_ptr, gd.cmbhdrptr[CSF_HDR_LS]->blk_size);
}

void fill_header(SHA256_CTX *ctx, u32 key_len)
{
	struct img_hdr *hdr_ptr = (struct img_hdr *)
				  gd.cmbhdrptr[CSF_HDR]->blk_ptr;
	struct ext_img_hdr *ext_hdr_ptr = (struct ext_img_hdr *)
					  gd.cmbhdrptr[EXTENDED_HDR]->blk_ptr;
	struct ext_esbc_ie_hdr *ext_esbc_ie_ptr = (struct ext_esbc_ie_hdr *)
					 gd.cmbhdrptr[EXT_ESBC_HDR]->blk_ptr;

	u8 barker[BARKER_LEN] = {0x68, 0x39, 0x27, 0x81};
	hdr_ptr->barker[0] = barker[0];
	hdr_ptr->barker[1] = barker[1];
	hdr_ptr->barker[2] = barker[2];
	hdr_ptr->barker[3] = barker[3];
	if ((gd.sg_flag == 0 && gd.group == 1) || (gd.esbc_flag == 1)) {
		hdr_ptr->img_size = BYTE_ORDER_L(get_size(gd.entries[0].name));
		hdr_ptr->pimg = BYTE_ORDER_L(gd.entries[0].addr);
	} else {
		if (gd.group == 1) {
			hdr_ptr->psgtable = BYTE_ORDER_L(gd.sg_addr);
		} else {
			hdr_ptr->psgtable =
			    BYTE_ORDER_L(gd.cmbhdrptr[SG_TABLE]->blk_offset);
		}
		hdr_ptr->sg_entries = BYTE_ORDER_L(gd.num_entries);
	}

	if (!(gd.ie_flag == 1 && gd.esbc_flag == 1)) {
		if (gd.srk_table_flag == 0) {
			hdr_ptr->key_len = BYTE_ORDER_L(2 * key_len);
			hdr_ptr->pkey = BYTE_ORDER_L
					(gd.cmbhdrptr[SRK_TABLE]->blk_offset);
		} else {
			hdr_ptr->len_kr.srk_table_flag = (u8)gd.srk_table_flag;
			hdr_ptr->len_kr.srk_sel = (u8)gd.srk_sel;
			hdr_ptr->len_kr.num_srk_entries = BYTE_ORDER_S
					(gd.num_srk_entries);
			hdr_ptr->srk_table_offset = BYTE_ORDER_L
					(gd.cmbhdrptr[SRK_TABLE]->blk_offset);
		}
	}

	hdr_ptr->sign_len = BYTE_ORDER_L(gd.cmbhdrptr[SIGNATURE]->blk_size);
	hdr_ptr->psign =
	    BYTE_ORDER_L(gd.cmbhdrptr[SIGNATURE]->blk_offset);
	hdr_ptr->img_start = BYTE_ORDER_L(gd.entry_addr);

	hdr_ptr->fsl_uid = BYTE_ORDER_L(gd.fsluid[0]);
	hdr_ptr->oem_uid = BYTE_ORDER_L(gd.oemuid[0]);

	if ((gd.group == 1) || (gd.group == 2)) {
		if (gd.fsluid_flag[0] && gd.oemuid_flag[0])
			hdr_ptr->uid_flag = BYTE_ORDER_L(OUID_FUID_BOTH);
		else if (gd.fsluid_flag[0])
			hdr_ptr->uid_flag = BYTE_ORDER_L(FUID_ONLY);
		else if (gd.oemuid_flag[0])
			hdr_ptr->uid_flag = BYTE_ORDER_L(OUID_ONLY);
		else
			hdr_ptr->uid_flag = BYTE_ORDER_L(NO_UID);
	} else {
		if (gd.fsluid_flag[0] && gd.oemuid_flag[0])
			hdr_ptr->uid_n_wp.uid_flag = BYTE_ORDER_S
						     (OUID_FUID_BOTH);
		else if (gd.fsluid_flag[0])
			hdr_ptr->uid_n_wp.uid_flag = BYTE_ORDER_S(FUID_ONLY);
		else if (gd.oemuid_flag[0])
			hdr_ptr->uid_n_wp.uid_flag = BYTE_ORDER_S(OUID_ONLY);
		else
			hdr_ptr->uid_n_wp.uid_flag = BYTE_ORDER_S(NO_UID);


		hdr_ptr->uid_n_wp.sfp_wp = (u8)gd.sfp_wp;
		hdr_ptr->uid_n_wp.sec_image_flag = (u8)gd.sec_image;
        }

	if (gd.group == 5) {
		if (gd.esbc_flag == 0) {
			hdr_ptr->mp_n_sg_flag.mp_flag = BYTE_ORDER_S
							(gd.mp_flag);
			hdr_ptr->mp_n_sg_flag.sg_flag = BYTE_ORDER_S(1);
		}
	} else if ((gd.group != 1) && (gd.esbc_flag == 0)) {
		hdr_ptr->sg_flag = BYTE_ORDER_L(1);
	} else {
		hdr_ptr->sg_flag = BYTE_ORDER_L(gd.sg_flag);
	}

	/* fill external image header */
	if (gd.group == 5 && gd.esbc_flag == 0) {
		ext_hdr_ptr->fsl_uid_1 = BYTE_ORDER_L(gd.fsluid[1]);
		ext_hdr_ptr->oem_uid_1 = BYTE_ORDER_L(gd.oemuid[1]);
	}

	if ((gd.group == 3 || gd.group == 4) && (gd.esbc_flag == 0)) {
		ext_hdr_ptr->hkptr = BYTE_ORDER_L(gd.hkptr);
		ext_hdr_ptr->hksize = BYTE_ORDER_L(gd.hksize);
	}

	/* fill external image header of IE Key usage for ESBC*/
	if (gd.ie_flag == 1 && gd.esbc_flag == 1) {
		ext_esbc_ie_ptr->ie_flag = BYTE_ORDER_L(gd.ie_flag);
		ext_esbc_ie_ptr->ie_sel = BYTE_ORDER_L(gd.ie_key_sel);
	}

	SHA256_Update(ctx, (u8 *)hdr_ptr, gd.cmbhdrptr[CSF_HDR]->blk_size);
	SHA256_Update(ctx, (u8 *)ext_hdr_ptr,
		      gd.cmbhdrptr[EXTENDED_HDR]->blk_size);
	SHA256_Update(ctx, (u8 *)ext_esbc_ie_ptr,
		      gd.cmbhdrptr[EXT_ESBC_HDR]->blk_size);
}

void extract_key(u8 *key_ptr, u32 key_len, u32 key_number, RSA * key_type[])
{
	unsigned char *tmp;
	int i, j = 0;

	/* copy N and E */

	/* Copy N component */
	tmp = (unsigned char *)(((BIGNUM *)key_type[key_number]->n)->d);
	for (j = key_len - 1, i = 0;
	     i < ((BIGNUM *)key_type[key_number]->n)->top * sizeof(BIGNUM *);
	     i++, j--)
		key_ptr[j] = tmp[i];

	/* Copy E component */
	key_ptr = key_ptr + key_len;
	tmp = (unsigned char *)(((BIGNUM *)key_type[key_number]->e)->d);
	for (j = key_len - 1, i = 0;
	     i < ((BIGNUM *)key_type[key_number]->e)->top * sizeof(BIGNUM *);
	     i++, j--)
		key_ptr[j] = tmp[i];
}

void fill_and_update_keys(SHA256_CTX *ctx, u8 *header, u32 key_len)
{
	unsigned char *key;
	unsigned char *ie_key_offset;
	int n = 0;
	u32 total_key_len, ie_revoc, ie_keys;

	/*pointer to the location of key */
	key = header + gd.cmbhdrptr[SRK_TABLE]->blk_offset;
	memset(key, 0, gd.cmbhdrptr[SRK_TABLE]->blk_size);

	if (gd.srk_table_flag == 0) {
		/* Copy N component and E component*/
		extract_key(key, key_len, 0, gd.srk);

		SHA256_Update(ctx,
			      header + gd.cmbhdrptr[SRK_TABLE]->blk_offset,
			      2 * key_len);

	} else {
		/* SRK table */
		n = 0;
		while (n != gd.num_srk_entries) {
			key =
			    header + gd.cmbhdrptr[SRK_TABLE]->blk_offset +
			    (n) * (sizeof(struct srk_table));

			/* Copy length */
			total_key_len = BYTE_ORDER_L
					(2 * gd.key_table[n].key_len);
			memcpy(key, &total_key_len, sizeof(u32));
			key = key + sizeof(u32);

			/* Copy N component and E component*/
			extract_key(key, gd.key_table[n].key_len, n, gd.srk);

			/*Update for all the keys present in the Key table */
			n++;
		}
		SHA256_Update(ctx,
			      header + gd.cmbhdrptr[SRK_TABLE]->blk_offset,
			      gd.num_srk_entries * sizeof(struct srk_table));
	}


	/*pointer to the location of IE key */
	ie_key_offset = header + gd.cmbhdrptr[IE_TABLE]->blk_offset;
	memset(ie_key_offset, 0, gd.cmbhdrptr[IE_TABLE]->blk_size);

	if (gd.ie_flag == 1 && gd.esbc_flag == 0) {
		/* ie_key table */
		ie_revoc = BYTE_ORDER_L(gd.ie_key_revoc);
		memcpy(ie_key_offset, &ie_revoc, sizeof(u32));
		ie_key_offset = ie_key_offset + sizeof(u32);

		ie_keys = BYTE_ORDER_L(gd.num_ie_keys);
		memcpy(ie_key_offset, &ie_keys, sizeof(u32));
		ie_key_offset = ie_key_offset + sizeof(u32);

		n = 0;
		while (n != gd.num_ie_keys) {
			key =
			    ie_key_offset + n * (sizeof(struct ie_key_table));

			/* Copy length */
			total_key_len = BYTE_ORDER_L
					(2 * gd.ie_key_entry[n].key_len);
			memcpy(key, &total_key_len, sizeof(u32));
			key = key + sizeof(u32);

			/* Copy N component and E component*/
			extract_key(key, gd.ie_key_entry[n].key_len, n,
				    gd.ie_key);

			/*Update for all the keys present in the Key table */
			n++;
		}
	}
}

void fill_and_update_sg_tbl(SHA256_CTX *ctx)
{
	int i = 0;
	for (i = 0; i < gd.num_entries; i++) {
		gd.hsgtbl[i].len = BYTE_ORDER_L(get_size(gd.entries[i].name));
		gd.hsgtbl[i].pdata = BYTE_ORDER_L(gd.entries[i].addr);
	}
	SHA256_Update(ctx, &gd.hsgtbl,
		      sizeof(struct sg_table) * gd.num_entries);
}

void fill_and_update_sg_tbl_offset(SHA256_CTX *ctx)
{
	int i = 0;
	int img_index = 0;
	struct sg_table_offset *osgtbl = (struct sg_table_offset *)
					 gd.cmbhdrptr[SG_TABLE]->blk_ptr;

	if (gd.ie_flag == 1) {
		img_index = 1;
		gd.entries[i].d_addr = DESTINATION_ADDR;
		osgtbl[i].len = BYTE_ORDER_L(gd.cmbhdrptr[IE_TABLE]->blk_size);
		osgtbl[i].source = BYTE_ORDER_L(gd.entries[i].addr);
		osgtbl[i].target_id = BYTE_ORDER_L(gd.targetid);
		osgtbl[i].destination = BYTE_ORDER_L(gd.entries[i].d_addr);
	}

	for (i = img_index; i < gd.num_entries; i++) {
		if (gd.sdhc_flag == 0) {
			osgtbl[i].len = BYTE_ORDER_L
					(get_size(gd.entries[i].name));
			osgtbl[i].source = BYTE_ORDER_L
					   (gd.entries[i].addr);
		} else {
			osgtbl[i].len = BYTE_ORDER_L
					(get_size(gd.entries[i].name));
			if (osgtbl[i].len % gd.sdhc_bsize != 0) {
				printf("ERROR : length of image is not "
				       "blocksize aligned\n");
				usage();
				exit(1);
			}
			if (gd.entries[i].addr % gd.sdhc_bsize != 0) {
				printf("ERROR : image source address is not "
				       "blocksize aligned\n");
				usage();
				exit(1);
			}
			osgtbl[i].len = BYTE_ORDER_L
					(get_size(gd.entries[i].name) /
					 gd.sdhc_bsize);
			osgtbl[i].source = BYTE_ORDER_L(gd.entries[i].addr /
							gd.sdhc_bsize);
		}
		osgtbl[i].target_id = BYTE_ORDER_L(gd.targetid);

		if (gd.group == 3 || gd.group ==5)
			gd.entries[i].d_addr = DESTINATION_ADDR;

		osgtbl[i].destination = BYTE_ORDER_L(gd.entries[i].d_addr);
	}
	SHA256_Update(ctx, (u8 *)osgtbl,
		      sizeof(struct sg_table_offset) * gd.num_entries);
}

void check_set_esbc_flag(char *file_name)
{
	FILE *fp;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", file_name);
		exit(1);
	}

	find_value_from_file("ESBC", fp);
	if (file_field.count == 1) {
		gd.esbc_flag = STR_TO_UL(file_field.value[0], 0, 10);
		if (gd.esbc_flag != 1 && gd.esbc_flag != 0) {
			printf("Error. Invalid Usage of ESBC Flag "
				"in input file. Refer usage\n");
			exit(1);
		}
	}
	fclose(fp);
}

void parse_file(char *file_name)
{
	int i, ret;
	uint32_t val, bit;
	char *image_name;
	image_name = malloc(strlen("IMAGE_1") + 1);

	FILE *fp;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", file_name);
		exit(1);
	}

	/* Parse Platform from input file */
	find_value_from_file("PLATFORM", fp);
	if (file_field.count == 1) {
		ret = check_group(file_field.value[0]);
		if (ret == -1) {
			printf("Error. Invalid Platform Name. Refer usage\n");
			exit(1);
		}
	} else if ((file_field.count == 0) || (file_field.count == -1)) {
		printf("Error. Platform field not found in "
			"input file. Refer usage\n");
		exit(1);

	}

	/* Parsing esbc_hdr address*/
	if (gd.esbc_flag == 0 && gd.key_ext_flag == 1) {
		find_value_from_file("ESBC_HDRADDR", fp);
		if (file_field.count == 1) {
			gd.esbc_hdr = STR_TO_UL(file_field.value[0], 0, 16);
		} else {
			printf("ERROR. Missing ESBC_HDRADDR in Input File\n");
			exit(1);
		}
	}

	/* Parse Key Info from input file */
	find_value_from_file("KEY_SELECT", fp);
	if (file_field.count == 1) {
		gd.srk_sel = STR_TO_UL(file_field.value[0], 0, 10);
		gd.srk_table_flag = 1;
	}

	find_value_from_file("PRI_KEY", fp);
	if (file_field.count >= 1) {
		gd.priv_fname_count = file_field.count;
		if ((gd.priv_fname_count > 1) || (gd.group == 6))
			gd.srk_table_flag = 1;

		i = 0;
		while (i != gd.priv_fname_count) {

			gd.priv_fname[i] =
			    malloc(strlen(file_field.value[i]) + 1);
			strcpy(gd.priv_fname[i], file_field.value[i]);

			i++;
		}
		gd.num_srk_entries = gd.priv_fname_count;
	} else {
		gd.key_check_flag = 0;
	}

	find_value_from_file("PUB_KEY", fp);
	if (file_field.count >= 1) {
		gd.pub_fname_count = file_field.count;
		if ((gd.pub_fname_count > 1) || (gd.group == 6))
			gd.srk_table_flag = 1;

		i = 0;
		while (i != gd.pub_fname_count) {

			gd.pub_fname[i] =
			    malloc(strlen(file_field.value[i]) + 1);
			strcpy(gd.pub_fname[i], file_field.value[i]);

			i++;
		}

	} else if (!(gd.key_ext_flag == 1 && gd.esbc_flag == 1) &&
		   (gd.img_hash_flag == 1 || gd.sign_app_flag == 1)) {
		printf("ERROR. Missing PUB_KEY field in Input File\n");
		exit(1);
	} else if (!(gd.key_ext_flag == 1 && gd.esbc_flag == 1)) {
		gd.key_check_flag = 0;
	}

	if (gd.img_hash_flag == 1 || gd.sign_app_flag == 1) {
		gd.priv_fname_count = 0;
		gd.key_check_flag = 0;
		gd.num_srk_entries = gd.pub_fname_count;
	} else if (gd.key_check_flag == 0) {
		printf("PRI_KEY, PUB_KEY fields are not provided in"
		       " correct pairs in Input File.Default keys are used\n");
		gd.pub_fname[0] = PUB_KEY_FILE;
		gd.priv_fname[0] = PRI_KEY_FILE;
		gd.priv_fname_count = 0;
		gd.pub_fname_count = 0;
		gd.num_srk_entries = 1;
		gd.srk_table_flag = 0;
		gd.srk_sel = 1;
	}

	/*Parsing IE keys*/
	if (gd.esbc_flag == 0 && gd.key_ext_flag == 1) {
		find_value_from_file("IE_KEY", fp);
		if (file_field.count >= 1) {
			gd.ie_key_fname_count = file_field.count;
			gd.ie_flag = 1;

			i = 0;
			while (i != gd.ie_key_fname_count) {
				gd.ie_key_fname[i] =
				    malloc(strlen(file_field.value[i]) + 1);
				strcpy(gd.ie_key_fname[i],
				       file_field.value[i]);
				i++;
			}
		} else {
			printf("ERROR. Missing IE_KEY field in Input File\n");
			exit(1);
		}
		gd.num_ie_keys = gd.ie_key_fname_count;
	}

	/* Parsing IE_revoc field*/
	if (gd.esbc_flag == 0 && gd.key_ext_flag == 1) {
		find_value_from_file("IE_REVOC", fp);
		if (file_field.count >= 1) {
			gd.ie_key_num_revoc = file_field.count;
			if (gd.ie_key_num_revoc >= gd.ie_key_fname_count ||
			    gd.ie_key_num_revoc >= MAX_IE_KEYS) {
				printf("ERROR.Keys revoked are greater than"
				       " possible\n");
				exit(1);
			}

			i = 0; val = 0; bit = 1;
			while (i != gd.ie_key_num_revoc) {
				val = STR_TO_UL(file_field.value[i], 0, 16);
				bit = bit << (val - 1);
				gd.ie_key_revoc = gd.ie_key_revoc | bit;
				bit = 1;
				i++;
			}
		}
	}

	/* Parsing IE key select*/
	if (gd.esbc_flag == 1 && gd.key_ext_flag == 1) {
		find_value_from_file("IE_KEY_SEL", fp);
		if (file_field.count == 1) {
			gd.ie_key_sel = STR_TO_UL(file_field.value[0], 0, 16);
			gd.ie_flag = 1;
		} else {
			printf("ERROR. Missing IE_KEY_SEL field in"
			       " Input File\n");
			exit(1);
		}
		gd.pub_fname_count = 0;
		gd.key_check_flag = 0;
	}

	/* Parse Entry Point from input file */
	find_value_from_file("ENTRY_POINT", fp);
	if (file_field.count == 1) {
		gd.entry_addr = STR_TO_UL(file_field.value[0], 0, 16);
		gd.entry_flag = 1;
	}

	/* Parse Image target from input file */
	find_value_from_file("IMAGE_TARGET", fp);
	if (file_field.count == 1) {
		gd.target_name = malloc(strlen(file_field.value[0]) + 1);
		strcpy(gd.target_name, file_field.value[0]);
		gd.target_flag = 1;
		if (strcmp(gd.target_name, "SDHC") == 0)
			gd.sdhc_flag = 1;
	}

	/* Parse blocksize if image target is SDHC*/
	find_value_from_file("BSIZE", fp);
	if (file_field.count == 1)
		gd.sdhc_bsize = STR_TO_UL(file_field.value[0], 0, 10);

	/* Parse Images from input file */
	i = 0;
	gd.num_entries = 0;
	if (gd.ie_flag == 1 && gd.esbc_flag == 0) {
		gd.num_entries = 1;
		i = 1;
	}
	while (i != NUM_SG_ENTRIES) {
		if (gd.ie_flag == 1 && gd.esbc_flag == 0)
			sprintf(image_name, "IMAGE_%c", (char)(i + (int)'0'));
		else
			sprintf(image_name, "IMAGE_%c",
				(char)(i + 1 + (int)'0'));

		find_value_from_file(image_name, fp);
		if (((gd.group == 1) || (gd.group == 3) || (gd.esbc_flag == 1))
		&& ((file_field.count != 2) && (file_field.count != 3)
		&& (file_field.count != 0) && (file_field.count != -1))) {

			printf("Error. Invalid Usage of Input File for "
				"field %s. Refer usage\n", image_name);
			exit(1);
		}
		if (((gd.group == 2) || (gd.group == 4) || (gd.group == 5) ||
		     (gd.group == 6)) && ((file_field.count != 3) &&
		    (file_field.count != 0) && (file_field.count != -1) &&
		    (gd.esbc_flag == 0))) {
			printf("Error. Invalid Usage. Please check %s "
				"in input file. Refer usage\n", image_name);
			exit(1);
		}

		if ((file_field.count != 0) && (file_field.count != -1)) {
			gd.entries[i].name =
			    malloc(strlen(file_field.value[0]) + 1);
			strcpy(gd.entries[i].name, file_field.value[0]);
			gd.entries[i].addr =
			    STR_TO_UL(file_field.value[1], 0, 16);

			if (((gd.group == 2) || (gd.group == 4) ||
			     (gd.group == 6)) && (gd.esbc_flag == 0)) {
				gd.entries[i].d_addr =
				    STR_TO_UL(file_field.value[2], 0, 16);
			}
			gd.num_entries++;
		}
#ifdef DEBUG
		printf("%s ", gd.entries[i].name);
		printf("%x ", gd.entries[i].addr);
#endif
		i++;
	}

	/* Parse UID from input file */
	find_value_from_file("FSL_UID", fp);
	if (file_field.count == 1) {
		gd.fsluid[0] = STR_TO_UL(file_field.value[0], 0, 16);
		gd.fsluid_flag[0] = 1;
	}
	find_value_from_file("FSL_UID_1", fp);
	if (file_field.count == 1) {
		gd.fsluid[1] = STR_TO_UL(file_field.value[0], 0, 16);
		gd.fsluid_flag[1] = 1;
	}

	if (gd.group == 6 && gd.esbc_flag == 0) {
		if (gd.fsluid_flag[0] ^ gd.fsluid_flag[1]) {
			printf("ERROR. Missing FSL UID in Input File\n");
			exit(1);
		}
	}

	find_value_from_file("OEM_UID", fp);
	if (file_field.count == 1) {
		gd.oemuid[0] = STR_TO_UL(file_field.value[0], 0, 16);
		gd.oemuid_flag[0] = 1;
	}
	find_value_from_file("OEM_UID_1", fp);
	if (file_field.count == 1) {
		gd.oemuid[1] = STR_TO_UL(file_field.value[0], 0, 16);
		gd.oemuid_flag[1] = 1;
	}
	find_value_from_file("OEM_UID_2", fp);
	if (file_field.count == 1) {
		gd.oemuid[2] = STR_TO_UL(file_field.value[0], 0, 16);
		gd.oemuid_flag[2] = 1;
	}
	find_value_from_file("OEM_UID_3", fp);
	if (file_field.count == 1) {
		gd.oemuid[3] = STR_TO_UL(file_field.value[0], 0, 16);
		gd.oemuid_flag[3] = 1;
	}
	find_value_from_file("OEM_UID_4", fp);
	if (file_field.count == 1) {
		gd.oemuid[4] = STR_TO_UL(file_field.value[0], 0, 16);
		gd.oemuid_flag[4] = 1;
	}

	/* Parsing sign_size address*/
	find_value_from_file("SIGN_SIZE", fp);
	if (file_field.count == 1) {
		gd.sign_size = STR_TO_UL(file_field.value[0], 0, 16);
	} else if (gd.key_type_req == NO_KEY) {
		printf("ERROR. Missing SIGN_SIZE in Input File\n");
		exit(1);
	}

	/* Parse File Names from input file */
	find_value_from_file("OUTPUT_HDR_FILENAME", fp);
	if (file_field.count == 1) {
		gd.hdrfile = malloc(strlen(file_field.value[0]) + 1);
		strcpy(gd.hdrfile, file_field.value[0]);
		gd.hdrfile_flag = 1;
	}

	find_value_from_file("HASH_FILENAME", fp);
	if (file_field.count == 1) {
		gd.hash_file = malloc(strlen(file_field.value[0]) + 1);
		strcpy(gd.hash_file, file_field.value[0]);
	} else if (gd.sign_app_flag == 1) {
		printf("ERROR. Missing HASH_FILENAME in Input File\n");
		exit(1);
	}

	find_value_from_file("INPUT_SIGN_FILENAME", fp);
	if (file_field.count == 1) {
		gd.sign_file = malloc(strlen(file_field.value[0]) + 1);
		strcpy(gd.sign_file, file_field.value[0]);
	} else if (gd.sign_app_flag == 1) {
		printf("ERROR. Missing INPUT_SIGN_FILENAME in Input File\n");
		exit(1);
	}

	find_value_from_file("OUTPUT_SG_BIN", fp);
	if (file_field.count == 1) {
		gd.sgfile = malloc(strlen(file_field.value[0]) + 1);
		strcpy(gd.sgfile, file_field.value[0]);
		gd.sgfile_flag = 1;
	}

	/* Parse SG Table Address from input file */
	find_value_from_file("SG_TABLE_ADDR", fp);
	if (file_field.count == 1) {
		gd.sg_addr = STR_TO_UL(file_field.value[0], 0, 16);
		gd.sg_flag = 1;
	}
	if (gd.num_entries > 1 && gd.sg_flag == 0 && gd.group == 1
	    && gd.esbc_flag == 0) {
		printf("Error. SG table address missing in Input File\n");
		exit(1);
	}

	/* Parse HK Area Info from input file */
	find_value_from_file("HK_AREA_POINTER", fp);
	if (file_field.count == 1) {
		gd.hkptr = STR_TO_UL(file_field.value[0], 0, 16);
		gd.hkptr_flag = 1;
	}
	find_value_from_file("HK_AREA_SIZE", fp);
	if (file_field.count == 1) {
		gd.hksize = STR_TO_UL(file_field.value[0], 0, 16);
		gd.hksize_flag = 1;
	}

	/* Parse SFP Write Protect from input file */
	find_value_from_file("SFP_WP", fp);
	if (file_field.count == 1) {
		gd.sfp_wp = STR_TO_UL(file_field.value[0], 0, 16);
	}
	/* Parse SFP Write Protect from input file */
	find_value_from_file("SEC_IMAGE", fp);
	if (file_field.count == 1) {
		gd.sec_image = STR_TO_UL(file_field.value[0], 0, 16);
	}

	/* Parse Manufacturing Protection Flag from input file */
	find_value_from_file("MP_FLAG", fp);
	if (file_field.count == 1) {
		gd.mp_flag = STR_TO_UL(file_field.value[0], 0, 16);
	}

	/* Layerscape flags*/
	find_value_from_file("ISS_FLAG", fp);
	if (file_field.count == 1)
		gd.iss_flag = STR_TO_UL(file_field.value[0], 0, 16);

	find_value_from_file("BOOT01_FLAG", fp);
	if (file_field.count == 1)
		gd.b01_flag = STR_TO_UL(file_field.value[0], 0, 16);

	find_value_from_file("LW_FLAG", fp);
	if (file_field.count == 1)
		gd.lw_flag = STR_TO_UL(file_field.value[0], 0, 16);


	find_value_from_file("VERBOSE", fp);
	if (file_field.count == 1)
		gd.verbose_flag = STR_TO_UL(file_field.value[0], 0, 16);

	free(image_name);
	fclose(fp);

}

void check_error(int argc, char **argv)
{
	int ret;

	if ((gd.sg_flag == 1)
	    && ((gd.group != 1) || (gd.esbc_flag == 1))) {
		printf("Error. SG Table Address not required for "
			"the given Platform.\n");
		usage();
		exit(1);
	}
	if (gd.target_flag == 1 && ((gd.group == 1) || (gd.group == 3)
			|| (gd.group == 5) || (gd.esbc_flag == 1))) {
		printf("Error. Image Target Name not required for "
			"the given Platform.\n");
		usage();
		exit(1);
	}
	if ((gd.hkptr_flag == 1 || gd.hksize_flag == 1) &&
	    ((gd.group == 1) || (gd.group == 2) || (gd.group == 5) ||
	     (gd.group == 6) || (gd.esbc_flag == 1))) {
		printf("Error. hkptr/hksize not required for "
			"the given Platform.\n");
		usage();
		exit(1);
	}
	if (!(gd.hkptr_flag == 1 && gd.hksize_flag == 1)
	    && ((gd.group == 3) || (gd.group == 4))
	    && (gd.esbc_flag == 0)) {
		printf("Error. hkptr and hksize are mandatory for "
			"the given Platform.\n");
		usage();
		exit(1);
	}

	if ((gd.hkptr_flag == 1 && gd.hksize_flag == 1)
	    && ((gd.group == 3) || (gd.group == 4))) {
		if ((gd.hkptr < 0 || gd.hkptr > 0xffffffff) ||
		    (gd.hksize < 0 || gd.hksize > 0xffffffff)) {
			printf("Error. Wrong values for hkptr/hksize.\n");
			usage();
			exit(1);
		}
	}

	if ((gd.sgfile_flag == 1)
	    && ((gd.group != 1) || (gd.esbc_flag == 1))) {
		printf("Error. Sgfile field not required for"
			" the given Platform.\n");
		usage();
		exit(1);
	}

	if ((gd.sgfile_flag == 1)
	    && (gd.sg_flag == 0)) {
		printf("Error. Sg Address field is required for the "
			"given Platform.\n");
		usage();
		exit(1);
	}
	if ((gd.srk_table_flag == 1)
	    && ((gd.group == 1) || (gd.group == 2))) {
		printf("Error. Key Select feature or More than one key not"
			" required for the given Platform.\n");
		usage();
		exit(1);
	} else if ((gd.srk_table_flag == 1) && (gd.group != 6)) {
		if ((gd.srk_sel < 1 || gd.srk_sel > 4)) {
			printf("Error. Key select number should be any "
			       "number from 1 to 4.\n");
			usage();
			exit(1);
		}
		if (gd.priv_fname_count > 4) {
			printf("Error. No. of key files should not be more"
			       " than 4.\n");
			usage();
			exit(1);
		}
	} else if ((gd.srk_table_flag == 1) && (gd.group == 6)) {
		if ((gd.srk_sel < 1 || gd.srk_sel > 8)) {
			printf("Error. Key select number should be any "
			       "number from 1 to 8.\n");
			usage();
			exit(1);
		}
		if (gd.priv_fname_count > 8) {
			printf("Error. No. of key files should not be more"
			       " than 8.\n");
			usage();
			exit(1);
		}
	}

	if (gd.target_flag == 1) {
		ret = check_target(gd.target_name, &gd.targetid);
		if (ret == -1) {
			printf("Error. Invalid Target Name. Refer usage\n");
			usage();
			exit(1);
		}
	}
	if ((gd.srk_sel > gd.priv_fname_count) && (gd.key_check_flag == 1)) {
		printf("Error. Invalid keyselect Option.\n");
		usage();
		exit(1);

	}
	if ((gd.sfp_wp == 1)
	    && ((gd.group == 1) || (gd.group == 2))) {
		printf("Error. SFP WP setting not required"
			" for the given Platform.\n");
		usage();
		exit(1);
	}

	if ((gd.sec_image == 1)
	    && ((gd.group == 1) || (gd.group == 2))) {
		printf("Error. Sec Image setting not required"
			" for the given Platform.\n");
		usage();
		exit(1);
	}

	if ((gd.priv_fname_count > 1) && (gd.group == 1 || gd.group == 2)) {
		printf("Error. More than 1 key is not required"
			" for the given platform.\n");
		usage();
		exit(1);
	}

	if (gd.priv_fname_count != gd.pub_fname_count &&
	    gd.key_check_flag == 1) {
		printf("Error. Public Key Count is not equal "
			"to Private Key Count.\n");
		usage();
		exit(1);

	}

	if (gd.hash_flag) {
		printonlyhash(gd.srk_table_flag, gd.pub_fname,
			      gd.pub_fname_count);
		exit(0);
	}

	if (gd.num_entries == 0) {
		if (gd.help_flag) {
			usage();
			exit(0);
		} else {
			printf("Error in usage. Image is not provided\n");
			usage();
			exit(1);
		}
	} else if ((gd.num_entries > 1) && (gd.esbc_flag == 1)) {
		printf("Error in usage. Single Image is required for ESBC\n");
		usage();
		exit(1);
	}

}

int main(int argc, char **argv)
{
	int c;
	int i, ret;
	u32 key_len, hdrlen;
	u8 *header;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char hash_fval[SHA256_DIGEST_LENGTH];
	unsigned char *sign;
	uint32_t img_index;
	uint32_t fsize;

	SHA256_CTX ctx;
	FILE *ftbl;
	FILE *fhdr;
	FILE *fhash;
	FILE *fsign;

	printf("\n");
	printf("============================================================"
		"===\n");
	printf("This product includes software developed by the OpenSSL"
		" Project\n");
	printf("for use in the OpenSSL Toolkit (http://www.openssl.org/)\n");
	printf("This product includes cryptographic software written by\n");
	printf("Eric Young (eay@cryptsoft.com)\n");
	printf("==========================================================="
		"====\n");
	printf("\n\n");

	memset(&gd, 0, sizeof(struct global));
	gd.pub_fname[0] = PUB_KEY_FILE;
	gd.priv_fname[0] = PRI_KEY_FILE;
	gd.pub_fname_count = 1;
	gd.priv_fname_count = 1;
	gd.ie_key_fname_count = 0;

	gd.hdrfile = HDR_FILE;
	gd.hash_file = HASH_FILE;
	gd.sgfile = TBL_FILE;
	gd.targetid = 0x0000000f;
	gd.srk_sel = 1;
	gd.num_srk_entries = 1;
	gd.sdhc_bsize = BLOCK_SIZE;
	gd.key_check_flag = 1;
	gd.b01_flag = 1;

	while (1) {
		static struct option long_options[] = {
			{"verbose", no_argument, &gd.verbose_flag, 1},
			{"key_ext", no_argument, &gd.key_ext_flag, 1},
			{"hash", no_argument, &gd.hash_flag, 1},
			{"img_hash", no_argument, &gd.img_hash_flag, 1},
			{"sign_app_verify", no_argument, &gd.sign_app_flag, 1},
			{"help", no_argument, &gd.help_flag, 1},
			{0, 0, 0, 0}
		};
		int option_index = 0;

		c = getopt_long(argc, argv, "",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;
	}

	/*Error checking for options used*/
	if (argc == 2 && gd.help_flag != 1)
		gd.file_flag = 1;

	if ((argc != 3) && gd.help_flag != 1 && gd.file_flag != 1 &&
	    !(gd.key_ext_flag == 1 &&  gd.img_hash_flag == 1) &&
	    !(gd.key_ext_flag == 1 &&  gd.sign_app_flag == 1)) {
		printf
		    ("Error.Invalid Usage. With this --option only filename is"
			" required. Refer usage\n");
		usage();
		exit(1);
	}

	/* Check and set ESBC flag if provided as input*/
	check_set_esbc_flag(argv[argc-1]);


	/* Flags would be set as per the option enabled and keys needed.
	 * If img_hash or sign_app option is used only public keys are needed.
	 * If key_ext option with esbc image is used only private keys are
	 * needed.
	 * If both of above option are used simultaneously no key is needed.
	 * Otherwise both keys are needed.And hence corresponding flag is set.
	 * */
	if ((gd.img_hash_flag == 1 || gd.sign_app_flag == 1) &&
	    (gd.key_ext_flag == 1 && gd.esbc_flag == 1)) {
		gd.key_type_req = NO_KEY;
		gd.num_srk_entries = 0;

	} else	if (gd.img_hash_flag == 1 || gd.sign_app_flag == 1) {
		gd.key_type_req = PUB_KEY_ONLY;

	} else	if (gd.key_ext_flag == 1 && gd.esbc_flag == 1) {
		gd.key_type_req = PRIV_KEY_ONLY;

	} else {
		gd.key_type_req = BOTH_KEY;

	}

	/* Parse input file for the fields */
	if (!gd.help_flag)
		parse_file(argv[argc-1]);

	check_error(argc, argv);

	if (gd.entry_flag == 0)
		gd.entry_addr = gd.entries[0].addr;
	printf("\n");

	/* Open RSA keys*/
	if (gd.key_type_req != NO_KEY)
		ret = open_key_file();
	if (ret < 0)
		exit(1);

	/* Compare RSA private and public key pairs*/
	if (gd.key_type_req == BOTH_KEY)
		compare_key_pairs();

	/* Initialise nodes for all components of header */
	initialise_nodes();

	/* Calculate blocks offsets for the combined header*/
	fill_offset();

	if (gd.key_type_req != NO_KEY)
		key_len = RSA_size(gd.srk[0]);

	/* Hdrlen - size of header, key, sign and padding */
	gd.cmbhdrptr[SIGNATURE]->blk_offset =
					gd.cmbhdrptr[SG_TABLE]->blk_offset +
					gd.cmbhdrptr[SG_TABLE]->blk_size;
	if (gd.ie_flag == 1 && gd.esbc_flag == 0)
		gd.cmbhdrptr[SIGNATURE]->blk_offset =
					gd.cmbhdrptr[IE_TABLE]->blk_offset +
					gd.cmbhdrptr[IE_TABLE]->blk_size;

	if (gd.cmbhdrptr[SIGNATURE]->blk_offset & ADDR_ALIGN_MASK) {
		gd.cmbhdrptr[SIGNATURE]->blk_offset =
					(gd.cmbhdrptr[SIGNATURE]->blk_offset &
					(~ADDR_ALIGN_MASK)) + ADDR_ALIGN_OFFSET;
	}

	hdrlen = gd.cmbhdrptr[SIGNATURE]->blk_offset;
	if (gd.img_hash_flag != 1)
		hdrlen = hdrlen + gd.cmbhdrptr[SIGNATURE]->blk_size;

	header = malloc(hdrlen);
	if (header == NULL) {
		fprintf(stderr,
			"Error in allocating memory of %d bytes\n", hdrlen);
		goto exit1;
	}
	memset(header, 0, hdrlen);

	SHA256_Init(&ctx);
	/* Update the headers contents in SHA */
	if (gd.group == 6)
		fill_header_ls(&ctx);
	else
		fill_header(&ctx, key_len);
#ifdef DEBUG
	dump_gd(&gd);
#endif

	memcpy(header,
	       (u8 *)(gd.cmbhdrptr[CSF_HDR_LS]->blk_ptr),
	       gd.cmbhdrptr[CSF_HDR_LS]->blk_size);

	memcpy(header,
	       (u8 *)(gd.cmbhdrptr[CSF_HDR]->blk_ptr),
	       gd.cmbhdrptr[CSF_HDR]->blk_size);

	/* copies ext_img_hdr if present otherwise copy nothing*/
	memcpy(header + gd.cmbhdrptr[EXTENDED_HDR]->blk_offset,
	       (u8 *)(gd.cmbhdrptr[EXTENDED_HDR]->blk_ptr),
	       gd.cmbhdrptr[EXTENDED_HDR]->blk_size);

	/* copies ext_esbc_ie_hdr if present otherwise copy nothing*/
	memcpy(header + gd.cmbhdrptr[EXT_ESBC_HDR]->blk_offset,
	       (u8 *)(gd.cmbhdrptr[EXT_ESBC_HDR]->blk_ptr),
	       gd.cmbhdrptr[EXT_ESBC_HDR]->blk_size);

	/*Add first entry for ie key in sg table*/
	if (gd.ie_flag == 1 && gd.esbc_flag == 0) {
		gd.entries[0].name = malloc(strlen("ie_key_table") + 1);
		strcpy(gd.entries[0].name, "ie_key_table");
		gd.entries[0].addr = gd.esbc_hdr +
				gd.cmbhdrptr[IE_TABLE]->blk_offset;
		gd.entries[0].d_addr = DESTINATION_ADDR;
	}

	/* Insert key, srk table and ie_key table*/
	if (!(gd.ie_flag == 1 && gd.esbc_flag == 1))
		fill_and_update_keys(&ctx, header, key_len);

	/* Print key hash*/
	if (!(gd.key_ext_flag == 1 && gd.esbc_flag == 1)) {
		printkeyhash(header + gd.cmbhdrptr[SRK_TABLE]->blk_offset,
			     2 * key_len, gd.srk_table_flag, gd.num_srk_entries);
	}

	/* Sequence of signature generation as per P1010 */
	if ((gd.group == 2) && (gd.esbc_flag == 0)) {
		for (i = 0; i < gd.num_entries; i++)
			get_size_and_updatehash(gd.entries[i].name, &ctx);
	}

	if ((gd.sg_flag == 1) && (gd.group == 1))
		fill_and_update_sg_tbl(&ctx);

	if (((gd.group == 2) || (gd.group == 3) || (gd.group == 4) ||
	     (gd.group == 5) || (gd.group == 6)) && (gd.esbc_flag == 0)) {
		fill_and_update_sg_tbl_offset(&ctx);
	}

	/* Signature generation for SG table images*/
	if ((gd.group != 2) && (gd.esbc_flag == 0)) {
		img_index = 0;

		if (gd.ie_flag == 1) {
			SHA256_Update(&ctx, header +
				      gd.cmbhdrptr[IE_TABLE]->blk_offset,
				      gd.cmbhdrptr[IE_TABLE]->blk_size);
			img_index = 1;
		}
		for (i = img_index; i < gd.num_entries; i++)
			get_size_and_updatehash(gd.entries[i].name, &ctx);
	}

	if (gd.esbc_flag == 1) {
		for (i = 0; i < gd.num_entries; i++)
			get_size_and_updatehash(gd.entries[i].name, &ctx);
	}

	SHA256_Final(hash, &ctx);

	/* Hash is exported by populating in hash_file*/
	if (gd.img_hash_flag) {
		fhash = fopen(gd.hash_file, "wb");
		if (fhash == NULL) {
			fprintf(stderr, "Error in opening the"
				" file: %s\n", gd.hash_file);
			goto exit2;
		}
		ret = fwrite((unsigned char *)hash, 1, SHA256_DIGEST_LENGTH,
			     fhash);
		printf("HASH file %s created\n", gd.hash_file);
		fclose(fhash);
	}

	/* Compare hash with hash present in file, if sign_app flag is ON*/
	if (gd.sign_app_flag == 1) {
		fhash = fopen(gd.hash_file, "rb");
		if (fhash == NULL) {
			fprintf(stderr, "Error in opening the"
				" file: %s\n", gd.hash_file);
			goto exit2;
		}
		fseek(fhash, 0, SEEK_END);
		fsize = ftell(fhash);
		fseek(fhash, 0, SEEK_SET);
		ret = fread((unsigned char *)hash_fval, 1, fsize,
			     fhash);
		fclose(fhash);

		i = 0;
		while ((i < SHA256_DIGEST_LENGTH) && (hash_fval[i] == hash[i]))
			i++;

		if (i < SHA256_DIGEST_LENGTH) {
			printf("HASH file %s value is not consistent with"
			       " input file\n", gd.hash_file);
			exit(1);
		}
	}

	/* copy Sign */
	sign = header + gd.cmbhdrptr[SIGNATURE]->blk_offset;

	if (gd.sign_app_flag == 1) {
		fsign = fopen(gd.sign_file, "rb");
		if (fsign == NULL) {
			fprintf(stderr, "Error in opening the"
				" file: %s\n", gd.sign_file);
			goto exit2;
		}
		fseek(fsign, 0, SEEK_END);
		fsize = ftell(fsign);
		fseek(fsign, 0, SEEK_SET);
		if (fsize != gd.cmbhdrptr[SIGNATURE]->blk_size) {
			printf("Signature length in signnature file is not"
			       " consistent with the signature length provided"
			       " through keys and fields in Input File\n");
			exit(1);
		}
		ret = fread((unsigned char *)sign, 1,
			     gd.cmbhdrptr[SIGNATURE]->blk_size, fsign);
		fclose(fsign);
	}

	if ((gd.img_hash_flag != 1) && (gd.sign_app_flag != 1)) {
		if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
			     &gd.cmbhdrptr[SIGNATURE]->blk_size,
			     gd.srk[gd.srk_sel - 1]) != 1) {
			printf("Error in generating signature\n");
			goto exit2;
		}
	}

	/* Copy SG Table in the header at the offset */
	if (((gd.group == 2) || (gd.group == 3) || (gd.group == 4) ||
	     (gd.group == 5) || (gd.group == 6)) && (gd.esbc_flag == 0)) {
		memcpy(header + gd.cmbhdrptr[SG_TABLE]->blk_offset,
		       gd.cmbhdrptr[SG_TABLE]->blk_ptr,
		       gd.cmbhdrptr[SG_TABLE]->blk_size);
	}

	if (gd.verbose_flag) {
		printf("\n");
		printf("Image Hash :");
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02x", hash[i]);
		printf("\n");

		/* Dumping signature to sign.out file*/
		sign = header + gd.cmbhdrptr[SIGNATURE]->blk_offset;
		fsign = fopen("sign.out", "wb");
		if (fsign == NULL) {
			fprintf(stderr, "Error in opening the"
				" file: %s\n", "sign.out");
			goto exit2;
		}
		ret = fwrite((unsigned char *)sign, 1,
			     gd.cmbhdrptr[SIGNATURE]->blk_size, fsign);
		printf("HEADER file %s created\n", "sign.out");
	}

	if (gd.verbose_flag) {
		printf("********** HEADER **************\n");
		dump_img_hdr1(&gd);
		if (gd.esbc_flag == 0) {
			if ((gd.group == 1) && (gd.sg_flag == 1)) {
				printf("********** SG TABLE ************\n");
				dump_sg_table1((struct sg_table *)gd.hsgtbl,
					       gd.num_entries);
			} else if (gd.group != 1) {
				printf("********** SG TABLE ************\n");
				dump_sg_table2((struct sg_table_offset *)
					       gd.cmbhdrptr[SG_TABLE]->blk_ptr,
					       gd.num_entries, gd.group);
			}
		}
	}

	/* Create the header file */
	fhdr = fopen(gd.hdrfile, "wb");
	if (fhdr == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", gd.hdrfile);
		goto exit2;
	}
	ret = fwrite((unsigned char *)header, 1, hdrlen, fhdr);
	printf("HEADER file %s created\n", gd.hdrfile);

	/* Create the SG Table file for group 1 */
	if ((gd.sg_flag == 1) && (gd.group == 1)) {
		ftbl = fopen(gd.sgfile, "wb");
		if (ftbl == NULL) {
			fprintf(stderr, "Error in opening the file: %s\n",
				gd.sgfile);
			goto exit3;
		}
		ret = fwrite((unsigned char *)gd.hsgtbl, 1,
			     sizeof(struct sg_table) * gd.num_entries, ftbl);
		fclose(ftbl);
		printf("SG Table file %s created\n", gd.sgfile);
	}
	printf("\n");
exit3:
	fclose(fhdr);
exit2:
	free(header);
exit1:

	free_mem();

	exit(0);
}
