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
#include "uni_pbi.h"
#include "dump_fields_pbi.h"

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
	gd.cmbhdrptr[CSF_HDR_LS]->blk_ptr = &gd.pbi_sec.pbi_sec_hdr;
	gd.cmbhdrptr[CSF_HDR_LS]->blk_size = sizeof(struct img_hdr_ls2);

	/* Initialise srk_table node*/
	gd.cmbhdrptr[SRK_TABLE] = new_node();
	gd.cmbhdrptr[SRK_TABLE]->blk_ptr = (struct srk_table *)
					calloc(1, gd.num_srk_entries *
					sizeof(struct srk_table));
	gd.cmbhdrptr[SRK_TABLE]->blk_size =
					gd.num_srk_entries *
					sizeof(struct srk_table);

	/* Initialise signature node*/
	gd.cmbhdrptr[SIGNATURE] = new_node();
}

/* This function populates Offsets for all the blocks. */
static void fill_offset()
{
	int i = 0;
	u32 offset;
	while (i != gd.num_srk_entries) {
		gd.key_table[i].key_len = RSA_size(gd.srk[i]);
		i++;
	}
	gd.cmbhdrptr[SIGNATURE]->blk_size = gd.key_table[gd.srk_sel - 1].key_len;

	/* To add padding in the header */
	gd.cmbhdrptr[CSF_HDR_LS]->blk_offset = 0;
	offset = sizeof(struct img_hdr_ls2) + (gd.no_pbi_words * 4);
	if ((offset & 0xFF) != 0)
		offset = (offset + 0x100) & 0xFFFFFF00;
	gd.cmbhdrptr[SRK_TABLE]->blk_offset = offset;

	offset = offset + (gd.num_srk_entries * sizeof(struct srk_table));
	if ((offset & 0xFF) != 0)
		offset = (offset + 0x100) & 0xFFFFFF00;
	gd.cmbhdrptr[SIGNATURE]->blk_offset = offset;
}

/* Deallocates all nodes and memory being allocated*/
static void free_mem()
{
	int i;
	for (i = 0; i < gd.num_srk_entries; i++) {
		fclose(gd.fsrk[i]);
		RSA_free(gd.srk[i]);
	}

	for (i = 0; i != gd.pub_fname_count; i++)
		free(gd.pub_fname[i]);

	for (i = 0; i != gd.priv_fname_count; i++)
		free(gd.priv_fname[i]);

	if (gd.hdrfile_flag == 1)
		free(gd.hdrfile);

	free(gd.cmbhdrptr[SRK_TABLE]->blk_ptr);
	free(gd.cmbhdrptr[SRK_TABLE]);

	free(gd.cmbhdrptr[SIGNATURE]->blk_ptr);
	free(gd.cmbhdrptr[SIGNATURE]);

	free(gd.cmbhdrptr[CSF_HDR_LS]);
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
	char *fname;

	for (i = 0; i < gd.num_srk_entries; i++) {
		/* open SRK key file and get the key */
		fname = gd.priv_fname[i];

		gd.fsrk[i] = fopen(fname, "r");
		if (gd.fsrk[i] == NULL) {
			fprintf(stderr, "Error in opening the file: %s\n",
				fname);
			return -1;
		}

		gd.srk[i] = PEM_read_RSAPrivateKey
				    (gd.fsrk[i], NULL, NULL, NULL);

		if (gd.srk[i] == NULL) {
			fprintf(stderr, "Error in reading key from : %s\n",
				fname);
			fclose(gd.fsrk[i]);
			return -1;
		}

	}

	return 0;
}

void fill_header_ls()
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
	if (gd.ie_flag == 1)
		misc_flags = misc_flags | misc_bit;

	misc_bit = misc_bit << 4;
	if (gd.mp_flag == 1)
		misc_flags = misc_flags | misc_bit;

	misc_bit = misc_bit << 1;
	if (gd.iss_flag == 1)
		misc_flags = misc_flags | misc_bit;

	misc_bit = misc_bit << 1;
	if (gd.b01_flag == 1)
		misc_flags = misc_flags | misc_bit;

	misc_bit = misc_bit << 1;
	if (gd.lw_flag == 1)
		misc_flags = misc_flags | misc_bit;

	hdr_ptr->misc_flags = (u8)misc_flags;

	/* Populating signature and sg_table fields*/
	hdr_ptr->psign = BYTE_ORDER_L(gd.cmbhdrptr[SIGNATURE]->blk_offset);
	hdr_ptr->sign_len = BYTE_ORDER_L(gd.cmbhdrptr[SIGNATURE]->blk_size);
	hdr_ptr->sg_table_addr = 0;
	hdr_ptr->sg_entries = 0;
	hdr_ptr->entry_point = 0;

	/* Populating fsl, oem uids and uid_flags*/
	uid_flags = 0x00;
	uid_bit = 0x02;
	for (i = 0; i < 5; i++) {
		if (gd.oemuid_flag[i] != 0) {
			uid_bit = uid_bit << 1;
			uid_flags = uid_flags | uid_bit;
			hdr_ptr->oem_uid[i] = BYTE_ORDER_L(gd.oemuid[i]);
		}
	}

	if (gd.fsluid_flag[0] != 0 || gd.fsluid_flag[1] != 0) {
		uid_bit = uid_bit << 1;
		uid_flags = uid_flags | uid_bit;
	}
	hdr_ptr->fsl_uid[0] = BYTE_ORDER_L(gd.fsluid[0]);
	hdr_ptr->fsl_uid[1] = BYTE_ORDER_L(gd.fsluid[1]);

	hdr_ptr->uid_flags = (u8)uid_flags;
}

void fill_and_update_keys(SHA256_CTX *ctx, u8 *header)
{
	unsigned char *key;
	unsigned char *tmp;
	int i, n, j = 0;
	u32 total_key_len;
	/*pointer to the location of key */
	key = header + gd.cmbhdrptr[SRK_TABLE]->blk_offset;
	memset(key, 0, gd.cmbhdrptr[SRK_TABLE]->blk_size);

		/* SRK table */
		n = 0;
		while (n != gd.num_srk_entries) {
			/* copy N and E */
			key =
			    header + gd.cmbhdrptr[SRK_TABLE]->blk_offset +
			    (n) * (sizeof(struct srk_table));

			/* Copy length */
			total_key_len = BYTE_ORDER_L
					(2 * gd.key_table[n].key_len);
			memcpy(key, &total_key_len, sizeof(u32));
			key = key + sizeof(u32);

			/* Copy N component */
			tmp = (unsigned char *)(((BIGNUM *)gd.srk[n]->n)->d);
			for (j = gd.key_table[n].key_len - 1, i = 0;
			     i <
			     ((BIGNUM *)gd.srk[n]->n)->top * sizeof(BIGNUM *);
			     i++, j--)
				key[j] = tmp[i];

			/* Copy E component */
			key =
			    header + gd.cmbhdrptr[SRK_TABLE]->blk_offset +
			    (n) * (sizeof(struct srk_table)) + sizeof(u32) +
			    gd.key_table[n].key_len;
			tmp = (unsigned char *)(((BIGNUM *)gd.srk[n]->e)->d);
			for (j = gd.key_table[n].key_len - 1, i = 0;
			     i <
			     ((BIGNUM *)gd.srk[n]->e)->top * sizeof(BIGNUM *);
			     i++, j--)
				key[j] = tmp[i];

			memcpy(gd.key_table[n].pkey,
			       header + gd.cmbhdrptr[SRK_TABLE]->blk_offset +
			       n * sizeof(struct srk_table) + 4,
			       2 * gd.key_table[n].key_len);
			/*Update for all the keys present in the Key table */
			n++;
		}
		SHA256_Update(ctx,
			      header + gd.cmbhdrptr[SRK_TABLE]->blk_offset,
			      gd.num_srk_entries * sizeof(struct srk_table));
}

void parse_file(char *file_name)
{
	int i;
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
	}

	/* Parse Key Info from input file */
	find_value_from_file("KEY_SELECT", fp);
	if (file_field.count == 1) {
		gd.srk_sel = strtoul(file_field.value[0], 0, 10);
		gd.srk_table_flag = 1;
	}

	find_value_from_file("PRI_KEY", fp);
	if (file_field.count >= 1) {
		gd.priv_fname_count = file_field.count;
		if ((gd.priv_fname_count > 1))
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
		if ((gd.pub_fname_count > 1))
			gd.srk_table_flag = 1;

		i = 0;
		while (i != gd.pub_fname_count) {

			gd.pub_fname[i] =
			    malloc(strlen(file_field.value[i]) + 1);
			strcpy(gd.pub_fname[i], file_field.value[i]);

			i++;
		}
	}
	/* Parse Entry Point from input file */
	find_value_from_file("BOOT1_POINTER", fp);
	if (file_field.count == 1) {
		gd.boot1_ptr = strtoul(file_field.value[0], 0, 16);
		gd.boot1_flag = 1;
	}

	/* Parse UID from input file */
	find_value_from_file("FSL_UID", fp);
	if (file_field.count == 1) {
		gd.fsluid[0] = strtoul(file_field.value[0], 0, 16);
		gd.fsluid_flag[0] = 1;
	}
	find_value_from_file("FSL_UID_1", fp);
	if (file_field.count == 1) {
		gd.fsluid[1] = strtoul(file_field.value[0], 0, 16);
		gd.fsluid_flag[1] = 1;
	}

	if ((gd.fsluid_flag[0] && !gd.fsluid_flag[1]) ||
			(gd.fsluid_flag[1] && !gd.fsluid_flag[0])
		) {
			printf("ERROR. Missing FSL UID in Input File\n");
			exit(1);
	}

	find_value_from_file("OEM_UID", fp);
	if (file_field.count == 1) {
		gd.oemuid[0] = strtoul(file_field.value[0], 0, 16);
		gd.oemuid_flag[0] = 1;
	}
	find_value_from_file("OEM_UID_1", fp);
	if (file_field.count == 1) {
		gd.oemuid[1] = strtoul(file_field.value[0], 0, 16);
		gd.oemuid_flag[1] = 1;
	}
	find_value_from_file("OEM_UID_2", fp);
	if (file_field.count == 1) {
		gd.oemuid[2] = strtoul(file_field.value[0], 0, 16);
		gd.oemuid_flag[2] = 1;
	}
	find_value_from_file("OEM_UID_3", fp);
	if (file_field.count == 1) {
		gd.oemuid[3] = strtoul(file_field.value[0], 0, 16);
		gd.oemuid_flag[3] = 1;
	}
	find_value_from_file("OEM_UID_4", fp);
	if (file_field.count == 1) {
		gd.oemuid[4] = strtoul(file_field.value[0], 0, 16);
		gd.oemuid_flag[4] = 1;
	}

	/* Parse File Names from input file */
	find_value_from_file("OUTPUT_HDR_FILENAME", fp);
	if (file_field.count == 1) {
		gd.hdrfile = malloc(strlen(file_field.value[0]) + 1);
		strcpy(gd.hdrfile, file_field.value[0]);
		gd.hdrfile_flag = 1;
	}

	find_value_from_file("RCW_FILE", fp);
	if (file_field.count == 1) {
		gd.rcwfile = malloc(strlen(file_field.value[0]) + 1);
		strcpy(gd.rcwfile, file_field.value[0]);
		gd.rcwfile_flag = 1;
	}


	/* Parse Manufacturing Protection Flag from input file */
	find_value_from_file("MP_FLAG", fp);
	if (file_field.count == 1) {
		gd.mp_flag = strtoul(file_field.value[0], 0, 16);
	}

	/* Layerscape flags*/
	find_value_from_file("ISS_FLAG", fp);
	if (file_field.count == 1)
		gd.iss_flag = strtoul(file_field.value[0], 0, 16);

	find_value_from_file("BOOT01_FLAG", fp);
	if (file_field.count == 1)
		gd.b01_flag = strtoul(file_field.value[0], 0, 16);

	find_value_from_file("LW_FLAG", fp);
	if (file_field.count == 1)
		gd.lw_flag = strtoul(file_field.value[0], 0, 16);


	find_value_from_file("VERBOSE", fp);
	if (file_field.count == 1)
		gd.verbose_flag = strtoul(file_field.value[0], 0, 16);

	free(image_name);
	fclose(fp);

}

void check_error(int argc, char **argv)
{
	if (gd.rcwfile_flag == 0) {
		printf("\nERROR !! RCW File required\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	int c, i;
	int ret;
	u32 hdrlen, file_len, pbi_len;
	u8 *header, *rcw;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char *sign;
	u32 word;

	SHA256_CTX ctx;
	FILE *fhdr, *frcw;

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

	gd.hdrfile = HDR_FILE;
	gd.srk_sel = 1;
	gd.num_srk_entries = 1;
	gd.key_check_flag = 1;

	while (1) {
		static struct option long_options[] = {
			{"verbose", no_argument, &gd.verbose_flag, 1},
			{"hash", no_argument, &gd.hash_flag, 1},
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

	if (argc == 2 && gd.help_flag != 1)
		gd.file_flag = 1;

	if ((argc != 3) && gd.help_flag != 1 && gd.file_flag != 1 &&
	    !(gd.hash_flag == 1 )) {
		printf
		    ("Error.Invalid Usage. With this --option only filename is"
			" required. Refer usage\n");
		usage();
		exit(1);
	}

	/* Parse input file for the fields */
	if (!gd.help_flag)
		parse_file(argv[argc-1]);

	check_error(argc, argv);

	frcw = fopen(gd.rcwfile, "rb+");
        if ((frcw == NULL)) {
                fprintf(stderr, "Error in opening the file\n");
                return 1;
        }

	fseek(frcw, 0, SEEK_END);
	file_len = ftell(frcw) - 1;
	fseek(frcw, 0, SEEK_SET);

	for (i = 0; i < 35; i++) {
		fread(&word, sizeof(word), 1, frcw);
		gd.pbi_sec.rcw_words[i] = word;
	}

	if (gd.boot1_flag == 1) {
		gd.pbi_sec.pbi_words[0] = 0x80220000;
		gd.pbi_sec.pbi_words[1] = gd.boot1_ptr;
		gd.no_pbi_words = 2;
	}

	while (ftell(frcw) < file_len) {
		fread(&word, sizeof(word), 1, frcw);
		gd.no_pbi_words ++;
		gd.pbi_sec.pbi_words[gd.no_pbi_words - 1] = word;
	}

	fclose(frcw);

	gd.pbi_sec.load_sec_hdr_cmd = 0x80200000;

	printf("\n");


	if (gd.no_key_flag == 0)
		ret = open_key_file();
	if (ret < 0)
		exit(1);

	/* Initialise nodes for all components of header */
	initialise_nodes();

	/* Calculate blocks offsets for the combined header*/
	fill_offset();

	/* Hdrlen - size of rcw, load sec hdr command, header, PBI, sign and padding */
	hdrlen = (sizeof(u32) * (NO_RCW_WORD + 1)) +
			gd.cmbhdrptr[SIGNATURE]->blk_offset +
			gd.cmbhdrptr[SIGNATURE]->blk_size;
	rcw = malloc(hdrlen);
	if (rcw == NULL) {
		fprintf(stderr,
			"Error in allocating memory of %d bytes\n", hdrlen);
		goto exit1;
	}
	memset(rcw, 0, hdrlen);

	SHA256_Init(&ctx);
	/* Update the headers contents in SHA */
	fill_header_ls();

	pbi_len = sizeof(struct img_hdr_ls2) +
			(sizeof(u32) * (gd.no_pbi_words + 1));

	printf("\nFinal PBI Length = 0x%x", pbi_len);
	gd.pbi_sec.rcw_words[10] = gd.pbi_sec.rcw_words[10] & ~PBI_LEN_MASK;
	gd.pbi_sec.rcw_words[10] = gd.pbi_sec.rcw_words[10] | SB_EN_MASK |
					((pbi_len / sizeof(u32)) << PBI_LEN_SHIFT);
	SHA256_Update(&ctx, (u8 *)&gd.pbi_sec.load_sec_hdr_cmd, pbi_len);
	memcpy(rcw,
	       (u8 *)(&gd.pbi_sec),
	       (sizeof(u32) * (NO_RCW_WORD + 1)) + sizeof(struct img_hdr_ls2) + (sizeof(u32) * gd.no_pbi_words));


	header = rcw + (sizeof(u32) * (NO_RCW_WORD + 1));
	/* Insert key, srk table and ie_key table*/
	fill_and_update_keys(&ctx, header);

	SHA256_Final(hash, &ctx);

	/* Print key hash*/
	printsrkhash(header + gd.cmbhdrptr[SRK_TABLE]->blk_offset,
				gd.num_srk_entries);

	sign = header + gd.cmbhdrptr[SIGNATURE]->blk_offset;

	if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
			     &gd.cmbhdrptr[SIGNATURE]->blk_size,
			     gd.srk[gd.srk_sel - 1]) != 1) {
		printf("Error in generating signature\n");
		goto exit2;
	}


	/* Create the header file */
	fhdr = fopen(gd.hdrfile, "wb");
	if (fhdr == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", gd.hdrfile);
		goto exit2;
	}
	ret = fwrite((unsigned char *)rcw, 1, hdrlen, fhdr);
	printf("HEADER file %s created\n", gd.hdrfile);

	fclose(fhdr);
exit2:
	free(rcw);
exit1:

	free_mem();

	exit(0);
}
