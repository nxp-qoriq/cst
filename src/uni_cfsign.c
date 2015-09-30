/* This code generates CF HEADER For Non-PBL Devices
 */

/* Copyright (c) 2012, Freescale Semiconductor, Inc.
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
 *"This product includes software developed by the OpenSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 */
/*
 *"This product includes cryptographic software written by
 * Eric Young (eay@cryptsoft.com)"
 */

#define OPENSSL_NO_KRB5
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <getopt.h>
#include <unistd.h>
#include <unistd.h>
#include "common.h"
#include "uni_cfsign.h"

#define IOBLOCK 128		/* I/O block size used for hashing operations */

FILE *fhdr;
u32 targetid, esbc_hdr, esbc_hdr_simg;
struct size_format size;

struct input_field input_pri_key;
struct global gd;

u32 words[2048];
u32 word_pairs;
int word_count;
int legacy_flag;

char *image_name;
u32 code_len;
u32 src_addr;
u32 dst_addr;
u32 entry_point;


/* return the size of the give file */
static int get_size(const char *c)
{
	FILE *fp;
	unsigned char buf[IOBLOCK];
	size_t bytes = 0;

	if (c == NULL)
		return 0;

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
			fclose(fp);
			return -1;
		} else if (feof(fp) && (bytes == 0))
			break;
	}

	fclose(fp);
	return bytes;
}

int check_group(char *platform)
{

	int i = 0;
	while (strcmp(group[i][0], "LAST")) {
		if (strcmp(group[i][0], platform) == 0) {
			gd.group = strtoul(group[i][1], 0, 10);
			printf("\nPlatform - %s\n", platform);
			return 0;
		}
		i++;
	}
	return -1;
}

void find_cfw_from_file(char *field_name, FILE * fp)
{
	int line_size = 0;
	u32 addr, data;
	file_field.value[0] = NULL;
	file_field.value[1] = NULL;
	file_field.value[2] = NULL;
	file_field.value[3] = NULL;
	file_field.count = 0;

	fseek(fp, 0, SEEK_SET);
	line_size = cal_line_size(fp);
	fseek(fp, -line_size, SEEK_CUR);

	while (fread(line_data, 1, line_size, fp)) {
		*(line_data + line_size) = '\0';
		remove_whitespace(line_data);
		if ((strstr(line_data, field_name)) && (*line_data != '#')) {
			get_field_from_file(line_data, field_name);
			if (file_field.count == 2) {
				addr = strtoul(file_field.value[0], 0, 16);
				data = strtoul(file_field.value[1], 0, 16);
				if (word_count == 2048) {
					printf("Error:Only 1024 CF WORD Pairs"
						" Allowed\n");
					exit(1);
				} else {
					MAKE_WORD(addr, data);
				}
			} else {
				printf("Error:Wrong Format in Input File\n"
				       "Usage: CF_WORD = (ADDR, DATA)\n");
				exit(1);
			}
		}
		line_size = cal_line_size(fp);
		fseek(fp, -line_size, SEEK_CUR);
	}
}

void parse_file(char *file_name)
{
	int i, ret;

	FILE *fp;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", file_name);
		exit(1);
	}

	/* Parse from input file */
	find_value_from_file("PLATFORM", fp);
	if (file_field.count == 1) {
		ret = check_group(file_field.value[0]);
		if (ret == -1) {
			printf("Error. Invalid Platform Name. Refer usage\n");
			exit(1);
		}

	} else if ((file_field.count == 0) || (file_field.count == -1)) {
		printf("Error.Platform not found in input file.Refer usage\n");
		exit(1);
	}
	/* Parse from input file */
	find_value_from_file("IMAGE_TARGET", fp);
	if (file_field.count == 1) {
		ret = check_target(file_field.value[0], &targetid);
		if (ret == -1) {
			printf("Error. Invalid Target Name. Refer usage\n");
			exit(1);
		}
	} else if ((file_field.count == 0) || (file_field.count == -1)) {
		printf
		    ("Error.Target ID not found in input file. Refer usage\n");
		exit(1);
	}


	/* Parse Images from input file */

		find_value_from_file("IMAGE_LOC", fp);
		if (((gd.group == 1) || (gd.group == 2)) &&
			(file_field.count != 3)
			&& (file_field.count != -1)) {

			printf("Error. Invalid Usage. Please check IMAGE in"
				" input file. Refer usage ::\n");
			exit(1);
		}

		if (file_field.count == 3) {
			image_name =
				malloc(strlen(file_field.value[0]) + 1);
			strcpy(image_name, file_field.value[0]);
			src_addr =
				strtoul(file_field.value[1], 0, 16);

			if (((gd.group == 1) || (gd.group == 2))) {
				dst_addr =
					strtoul(file_field.value[2], 0, 16);
			}

		}
#ifdef DEBUG
		printf("%s ", gd.entries[i].name);
		printf("%x ", gd.entries[i].addr);
#endif

	/* get the length of image file */
	code_len = get_size(image_name);


	/* if it is legacy boot than flag is set otherwise it remains unset*/
	if (code_len && image_name != NULL)
		legacy_flag = 1;


	/* Parse Entry Point from input file */
		find_value_from_file("ENTRY_POINT", fp);
		if (file_field.count == 1)
			entry_point = strtoul(file_field.value[0], 0, 16);
		else if (legacy_flag != 0) {
			printf("Error. Invalid Usage. Please check ENTRY_POINT"
				"in input file. Refer usage ::\n");
			exit(1);
		}



	find_value_from_file("ESBC_HDRADDR", fp);
	if (file_field.count == 1) {
		esbc_hdr = strtoul(file_field.value[0], 0, 16);

	} else if (((file_field.count == 0) || (file_field.count == -1))
			&& (legacy_flag == 0)) {
		printf("Error.Primary ESBC Header not found in"
			" input file. Refer usage\n");
		exit(1);
	}

	find_value_from_file("ESBC_HDRADDR_SEC_IMAGE", fp);
	if (file_field.count == 1) {
		if (gd.group == 1) {
			printf("Error.Secondaery Image not required for"
				" this platform. Refer usage\n");
			exit(1);
		} else {
			esbc_hdr_simg = strtoul(file_field.value[0], 0, 16);
		}

	} else if (((file_field.count == 0) || (file_field.count == -1))
		   && (gd.group == 2)) {
		printf("Error.Secondary Image HDR Addr not found in"
			" input file. Refer usage\n");
		exit(1);
	}
	/* Parse Key Info from input file */
	find_value_from_file("KEY_SELECT", fp);
	if (file_field.count == 1) {
		if (gd.group == 1) {
			printf("Error.Key Select not required for this"
				" platform. Refer usage\n");
			exit(1);
		} else {

			gd.srk_sel = strtoul(file_field.value[0], 0, 10);
			gd.srk_table_flag = 1;
		}
	}

	find_value_from_file("PRI_KEY", fp);
	if (file_field.count >= 1) {
		input_pri_key.count = file_field.count;
		if (input_pri_key.count > 1)
			gd.srk_table_flag = 1;

		i = 0;
		free(input_pri_key.value[0]);
		while (i != input_pri_key.count) {
			input_pri_key.value[i] =
			    malloc(strlen(file_field.value[i]) + 1);
			strcpy(input_pri_key.value[i], file_field.value[i]);
			i++;
		}
	}



	find_cfw_from_file("CF_WORD", fp);

	find_value_from_file("OUTPUT_HDR_FILENAME", fp);
	if (file_field.count == 1) {
		free(gd.hdrfile);
		gd.hdrfile = malloc(strlen(file_field.value[0]) + 1);
		strcpy(gd.hdrfile, file_field.value[0]);
	}

	fclose(fp);
}

int open_priv_file(void)
{
	int i = 0;

	for (i = 0; i < gd.num_srk_entries; i++) {
		/* open SRK private key file and get the key */
		gd.fsrk_pri[i] = fopen(gd.priv_fname[i], "r");
		if (gd.fsrk_pri[i] == NULL) {
			fprintf(stderr, "Error in opening the file: %s\n",
				gd.priv_fname[i]);
			return -1;
		}

		gd.srk[i] =
		    PEM_read_RSAPrivateKey(gd.fsrk_pri[i], NULL, NULL, NULL);
		if (gd.srk[i] == NULL) {
			fprintf(stderr, "Error in reading key from : %s\n",
				gd.priv_fname[i]);
			fclose(gd.fsrk_pri[i]);
			return -1;
		}

	}
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	int i, j, n ;
	u8 *tmp;
	u8 *sign;
	uint32_t sign_len;
	u8 *key;
	int key_len = 0;
	/* this buffer is written to the file */
	u8 *buf;
	int buf_len;
	u8 *cwds;
	int key_offset;
	int sign_offset;
	u16 temp;
	int factor = 1;
	u32 total_key_len = 0;

	struct cf_hdr_legacy *cfl;
	struct cf_hdr_secure *cfs;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	memset(&gd, 0, sizeof(struct global));
	gd.group = 1;
	gd.priv_fname[0] = PRI_KEY_FILE;
	gd.srk_sel = 1;
	gd.srk_table_flag = 0;
	gd.num_srk_entries = 1;
	input_pri_key.count = 1;
	input_pri_key.value[0] = malloc(strlen(PRI_KEY_FILE) + 1);
	strcpy(input_pri_key.value[0], PRI_KEY_FILE);
	gd.hdrfile = malloc(strlen(HDR_FILE) + 1);
	strcpy(gd.hdrfile, HDR_FILE);
	image_name = NULL;

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


	if (argc == 2) {
		if ((strcmp(argv[1], "--help") == 0)
		    || (strcmp(argv[1], "-h") == 0)) {
			printf("\nUsage: ./uni_cfsign <input_file>\n\n");
			exit(0);
		} else
			parse_file(argv[1]);
	} else {
		printf("\nError: Usage ./uni_cfsign <input_file>\n\n");
		exit(1);

	}
	i = 0;
	if ((input_pri_key.count > 1) && (gd.group == 1)) {
		printf("Error. More than 1 key is not required"
		       " for the given platform.\n");
		exit(1);

	} else {
		while (i != input_pri_key.count) {
			gd.priv_fname[i] = input_pri_key.value[i];
			i++;
		}
		gd.num_srk_entries = input_pri_key.count;
	}



	if (legacy_flag == 0) {
		ret = open_priv_file();
		if (ret < 0)
			exit(1);

#ifdef DEBUG
	printf("\nNo. of keys - %d", gd.num_srk_entries);
	printf("\nGroup - %d", gd.group);
#endif

		if (gd.srk_table_flag == 0) {
			key_len = size.sign_len = RSA_size(gd.srk[0]);
			size.key_table = 2 * key_len;
		} else {
			i = 0;
			while (i != gd.num_srk_entries) {
				gd.key_table[i].key_len = RSA_size(gd.srk[i]);
				i++;
			}
			size.sign_len = gd.key_table[gd.srk_sel - 1].key_len;
			size.key_table = gd.num_srk_entries *
					sizeof(struct srk_table);
		}
	}

	word_pairs = word_count / 2;
	size.hdr_legacy = sizeof(struct cf_hdr_legacy);
	if (gd.group == 1) {
		size.hdr_secure = sizeof(struct cf_hdr_secure) - sizeof(u32);
	} else {
		size.hdr_secure = sizeof(struct cf_hdr_secure);
	}
	size.cfw = sizeof(u32) * 2 * word_pairs;

	/* total size of the CFHDR header and its RSA sign, and public key */
	factor = size.cfw / 512;

	/* Increase the size of pad on the basis of config words present */
	size.padd1 =
	    (factor + 2) * 512 - (size.hdr_legacy + size.cfw + size.hdr_secure +
				  0x40);
	size.padd2 = 0x1200 - size.key_table;

	/* cfheader size would be different in secure boot and legacy boot. */
	if (legacy_flag == 0)
		buf_len = 0x40 + size.hdr_legacy + size.cfw + size.hdr_secure +
			size.key_table + size.sign_len + size.padd1 +
			size.padd2;
	else
		buf_len = 0x40 + size.hdr_legacy + size.cfw;


	buf = malloc(buf_len);
	if (buf == NULL) {
		fprintf(stderr,
			"Error in allocating mem of %d bytes \n", buf_len);
		return -1;
	}
	memset(buf, 0, buf_len);

	/* calculte the key and signature offset */
	key_offset = size.hdr_legacy + size.cfw + size.hdr_secure + size.padd1;
	/* placing key just after CFHdr and sign just after key */
	sign_offset = key_offset + size.key_table + size.padd2;

	/* Update the legacy and secure data structures */
	cfl = (struct cf_hdr_legacy *)(buf + 0x40);

	cfl->boot_sig = htonl(BOOT_SIG);
	cfl->no_conf_pairs = htonl(size.cfw / 8);

	/* Configuration words store */
	cwds = (u8 *) cfl + size.hdr_legacy;
	if (size.cfw > sizeof(words)) {
		printf("Error:Only 1024 CF WORD Pairs Allowed\n");
		exit(1);
	}
	memcpy(cwds, (u8 *) words, size.cfw);

	/* store code_len, src_addr, dst_addr, entry_point in case of legacy
		boot and if image_name is null all fields will be zeroised */
	if (legacy_flag == 1) {
		cfl->code_len = htonl(code_len);
		cfl->src_addr = htonl(src_addr);
		cfl->dst_addr = htonl(dst_addr);
		cfl->entry_point = htonl(entry_point);
	}

	if (legacy_flag == 0) {
		/* Secure boot additions to legacy header */
		cfs = (struct cf_hdr_secure *)((u8 *) cfl + size.hdr_legacy +
			size.cfw);

		cfs->ehdrloc = htonl(esbc_hdr);
		cfs->esbc_target_id = htonl(targetid);
		cfs->psign_off = htonl(sign_offset);
		cfs->sign_len = htonl(size.sign_len);
		if (gd.srk_table_flag == 0) {
			cfs->pkey_off = htonl(key_offset);
			cfs->key_len = htonl(2 * key_len);
		} else {
			temp = 0;
			temp = temp | (u16)gd.srk_table_flag;
			temp = temp << 12;
			temp = temp | (u16)gd.srk_sel;
			temp = htons(temp);
			memcpy((u8 *) &(cfs->len_kr), &temp, 2);
			cfs->len_kr.num_srk_entries =
				htons((uint16_t)gd.num_srk_entries);
			cfs->srk_table_offset = htonl(key_offset);
		}
		if (gd.group == 2) {
			/*Secobdary Image header Location */
			cfs->ehdrloc_simg = htonl(esbc_hdr_simg);
		}
		/* Copy PublicKey */
		/* copy N and E */

		if (gd.srk_table_flag == 0) {
			/* copy N and E */

			key = (u8 *) cfl + key_offset;
			/* Copy N component */
			tmp = (unsigned char *)(((BIGNUM *) gd.srk[0]->n)->d);
			for (j = key_len - 1, i = 0;
				i < ((BIGNUM *) gd.srk[0]->n)->top *
				sizeof(BIGNUM *); i++, j--)
					key[j] = tmp[i];

			/* Copy E component */
			key = (u8 *) cfl + key_offset + key_len;
			tmp = (unsigned char *)(((BIGNUM *) gd.srk[0]->e)->d);
			for (j = key_len - 1, i = 0;
				i < ((BIGNUM *) gd.srk[0]->e)->top *
				sizeof(BIGNUM *); i++, j--)
					key[j] = tmp[i];

		} else {
			/* SRK table */
			n = 0;
			while (n != gd.num_srk_entries) {
				/* copy N and E */
				key =
				    (u8 *) cfl + key_offset +
				    (n) * (sizeof(struct srk_table));

				/* Copy length */
				total_key_len =
					htonl(2 * gd.key_table[n].key_len);
				memcpy(key, &total_key_len, sizeof(u32));
				key = key + sizeof(u32);

				/* Copy N component */
				tmp = (unsigned char *)
					(((BIGNUM *) gd.srk[n]->n)->d);
				for (j = gd.key_table[n].key_len - 1, i = 0;
					i < ((BIGNUM *) gd.srk[n]->n)->top *
					sizeof(BIGNUM *); i++, j--)
						key[j] = tmp[i];

				/* Copy E component */
				key =
					(u8 *) cfl + key_offset +
					(n) * (sizeof(struct srk_table)) +
					sizeof(u32) + gd.key_table[n].key_len;
				tmp = (unsigned char *)
					(((BIGNUM *) gd.srk[n]->e)->d);
				for (j = gd.key_table[n].key_len - 1, i = 0;
					i < ((BIGNUM *) gd.srk[n]->e)->top *
					sizeof(BIGNUM *); i++, j--)
						key[j] = tmp[i];

				memcpy(gd.key_table[n].pkey,
				       (u8 *) cfl + key_offset +
				       n * sizeof(struct srk_table) + 4,
				       2 * gd.key_table[n].key_len);
				/*Update for all the keys present in the
					Key table */
				n++;
			}

		}

		SHA256_CTX ctx;
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, (u8 *) cfl + key_offset, size.key_table);
		SHA256_Final(hash, &ctx);

		printf("\n");
		printf("######################################################\n");
		printf("## Generating CFHeader composite image (pkey & sign)##\n");
		printf("######################################################\n");

		printf("\n");
		printf("pkey Hash :");
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02x", hash[i]);

		/* hash-->hdr+key + */

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, cfl, size.hdr_legacy);
		SHA256_Update(&ctx, cwds, size.cfw);
		SHA256_Update(&ctx, cfs, size.hdr_secure);
		SHA256_Update(&ctx, (u8 *) cfl + key_offset, size.key_table);
		SHA256_Final(hash, &ctx);

		printf("\n");
#ifdef DEBUG
		printf("Hash :");
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02x", hash[i]);
			printf("\n");
#endif

		/* copy Sign */
		sign = (u8 *) (cfl) + sign_offset;
		if (RSA_sign
			(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
			&sign_len, gd.srk[gd.srk_sel - 1]) != 1) {
			fprintf(stderr, "Error signing the data\n");
			free(buf);
			return -1;
		}

	}

	fhdr = fopen(gd.hdrfile, "wb");
	if (fhdr == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", gd.hdrfile);
		free(buf);
		return -1;
	}
	printf("\n");

#ifdef DEBUG
	printf("Sign :");
	for (i = 0; i < sign_len; i++)
		printf("0x%02x,", sign[i]);
	printf("\n");
#endif

	/* Concatinating Header, Sign */
	fwrite((unsigned char *)buf, 1, buf_len, fhdr);
	printf("\nHeader File Created : %s\n", gd.hdrfile);
	if (legacy_flag == 0 && buf_len > esbc_hdr)
		printf("\nError cfheader overlaps esbc header\n"
			"buf_len : %xESBC HEADER %x\n", buf_len, esbc_hdr);
	/* clean up */
	free(buf);
	free(gd.hdrfile);

	if (legacy_flag == 0) {
		for (i = 0; i < gd.num_srk_entries; i++) {
			free(input_pri_key.value[i]);
			fclose(gd.fsrk_pri[i]);
			RSA_free(gd.srk[i]);
		}
	}
	fclose(fhdr);
	return 0;
}
