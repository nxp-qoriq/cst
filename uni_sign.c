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

struct size_format size;
struct global gd;
struct input_field input_pri_key, input_pub_key;
extern struct input_field file_field;	/* Required for parsing input file */
extern char *line;

int check_group(char *platform)
{

	int i = 0;
	while (strcmp(group[i][0], "LAST")) {
		if (strcmp(group[i][0], platform) == 0) {
			gd.group = strtoul(group[i][1], 0, 10);
			return 0;
		}
		i++;
	}
	return -1;
}

struct input_field get_field(char *line)
{
	struct input_field field = { {NULL, NULL, NULL, NULL}, 0 };

	int i = 0;
	char delims[] = ",";
	char *result = NULL;
	result = strtok(line, delims);
	while (result != NULL) {
		field.value[i] = result;
		result = strtok(NULL, delims);
		i++;
	}
	field.count = i;
	return field;

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

static void dump_img_hdr1(struct img_hdr *h)
{
	int i;
	printf("barker:0x");
	for (i = 0; i < BARKER_LEN; i++)
		printf("%.2x",
		       (unsigned)(unsigned char)((BYTE_ORDER_L(h->barker[i])) >> 24));
	printf("\n");
	if (gd.srk_table_flag) {
		printf("srk_table_offset %x\n", BYTE_ORDER_L(h->srk_table_offset));
		printf("srk_table_flag(8) : %x\nsrk_sel(8) : %x\nnum_srk_entries(16) : %x\n",
				(h->len_kr.srk_table_flag),
				(h->len_kr.srk_sel),
				BYTE_ORDER_S(h->len_kr.num_srk_entries)
				);
	} else {
		printf("pkey %x, key length %d\n", BYTE_ORDER_L(h->pkey),
		       BYTE_ORDER_L(h->key_len));
	}
	printf("psign %x, length %d\n", BYTE_ORDER_L(h->psign), BYTE_ORDER_L(h->sign_len));
	printf("uid_flag %x\n", BYTE_ORDER_L(h->uid_flag));
	printf("sfp_wp(8) : %x\nsec_image_flag(8) : %x\nuid_flag(16) : %x\n",
				(h->uid_n_wp.sfp_wp),
				(h->uid_n_wp.sec_image_flag),
			 	BYTE_ORDER_S(h->uid_n_wp.uid_flag)
				);
	if (BYTE_ORDER_L(h->sg_flag) || ((gd.esbc_flag == 0) && (gd.group != 1))) {
		printf("psgtable  %x num_entries %d\n",
		       BYTE_ORDER_L(h->psgtable), BYTE_ORDER_L(h->sg_entries));
	} else if (gd.group == 1 || gd.esbc_flag == 1) {
		printf("pimg %x len %d\n", BYTE_ORDER_L(h->pimg), BYTE_ORDER_L(h->img_size));
	}
	printf("img start %x\n", BYTE_ORDER_L(h->img_start));
	printf("FSL UID %x\n", BYTE_ORDER_L(h->fsl_uid));
	printf("OEM UID %x\n", BYTE_ORDER_L(h->oem_uid));
	if (gd.group == 5) {
		printf("FSL UID 1%x\n", BYTE_ORDER_L(h->fsl_uid_1));
		printf("OEM UID 1%x\n", BYTE_ORDER_L(h->oem_uid_1));
		printf("Manufacturing Protection Flag %x\n", BYTE_ORDER_S(h->mp_n_sg_flag.mp_flag));
		printf("sg_flag %d\n", BYTE_ORDER_S(h->mp_n_sg_flag.sg_flag));
	}
	else
		printf("sg_flag %d\n", BYTE_ORDER_L(h->sg_flag));
	if (gd.hkptr_flag == 1) {
		printf("hkptr %x\n", BYTE_ORDER_L(h->hkptr));
		printf("hksize %x\n", BYTE_ORDER_L(h->hksize));
	}
}

static void dump_sg_table1(struct sg_table *t, int n)
{
	int i;
	printf("no of entries  %d\n", n);
	for (i = 0; i < n; i++)
		printf("entry %d  len %d ptr %x\n",
		       i, BYTE_ORDER_L((t + i)->len), BYTE_ORDER_L((t + i)->pdata));
}

static void dump_sg_table2(struct sg_table_offset *t, int n)
{
	int i;
	printf("no of entries  %d\n", n);
	for (i = 0; i < n; i++) {
		printf("entry %d  len %d ptr %x",
		       i, BYTE_ORDER_L((t + i)->len), BYTE_ORDER_L((t + i)->source));
		if ((gd.group == 2 || gd.group == 4)) {
			printf(" target_id %x destination %x ",
			       (t + i)->target_id, (t + i)->destination);
		}
		printf("\n");
	}
}

#ifdef DEBUG
static void dump_gd(void)
{
	int i = 0;
	printf("group		: %d\n", gd.group);
	printf("file_flag	: %d\n", gd.file_flag);
	printf("esbc_flag	: %d\n", gd.esbc_flag);
	printf("sg_flag		: %d\n", gd.sg_flag);
	printf("entry_flag	: %d\n", gd.entry_flag);
	printf("hash_flag	: %d\n", gd.hash_flag);
	printf("num_entries	: %d\n", gd.num_entries);
	printf("num_srk_entries	: %d\n", gd.num_srk_entries);
	for (i = 0; i < gd.num_srk_entries; i++) {
		printf("pub_fname %d	: %s\n", i + 1, gd.pub_fname[i]);
		printf("priv_fname %d	: %s\n", i + 1, gd.priv_fname[i]);
	}
	printf("fslid		: %x\n", gd.fslid);
	printf("oemid		: %x\n", gd.oemid);
	printf("sg_addr		: %x\n", gd.sg_addr);
	printf("entry_addr	: %x\n", gd.entry_addr);
	printf("img_addr	: %x\n", gd.img_addr);
	for (i = 0; i < gd.num_entries; i++) {
		printf("binary name %s .. addr %x\n",
		       gd.entries[i].name, gd.entries[i].addr);
	}
	if ((gd.group == 3 || gd.group == 4) && (gd.esbc_flag == 0)) {
		printf("hkptr		: %x\n", gd.hkptr);
		printf("hksize		: %x\n", gd.hksize);
	}
	else if (gd.group == 5) {
		printf("fslid_1		: %x\n", gd.fslid_1);
		printf("oemid_1		: %x\n", gd.oemid_1);
		printf("mp_flag		: %x\n", gd.mp_flag);
	}
	if (gd.group == 3 || gd.group == 4 || gd.group == 5) {
		printf("srk_sel		: %x\n", gd.srk_sel);
		printf("srk_table_flag	: %x\n", gd.srk_table_flag);
		printf("sfp_wp		: %x\n", gd.sfp_wp);
	}

	if ((gd.group == 2 || gd.group == 4) && (gd.esbc_flag == 0))
		printf("target_id	: %x\n", gd.targetid);
	/* Variables used across functions */
	/* These entries are filled by parsing the arguments */
}
#endif

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

void fill_header(SHA256_CTX *ctx, u32 key_len, u32 sign_len)
{
	u8 barker[BARKER_LEN] = {0x68, 0x39, 0x27, 0x81};
	gd.himg.barker[0] = barker[0];
	gd.himg.barker[1] = barker[1];
	gd.himg.barker[2] = barker[2];
	gd.himg.barker[3] = barker[3];
	if ((gd.sg_flag == 0 && gd.group == 1) || (gd.esbc_flag == 1)) {
		gd.himg.img_size = BYTE_ORDER_L(get_size(gd.entries[0].name));
		gd.himg.pimg = BYTE_ORDER_L(gd.entries[0].addr);
	} else {
		if (gd.group == 1) {
			gd.himg.psgtable = BYTE_ORDER_L(gd.sg_addr);
		} else {
			gd.himg.psgtable =
			    BYTE_ORDER_L(size.header + size.padd1 + size.key_table +
				  size.padd2 + size.sign_len + size.padd3);
		}
		gd.himg.sg_entries = BYTE_ORDER_L(gd.num_entries);
	}

	if (gd.srk_table_flag == 0) {
		gd.himg.key_len = BYTE_ORDER_L(2 * key_len);
		gd.himg.sign_len = BYTE_ORDER_L(size.sign_len);
		gd.himg.pkey = BYTE_ORDER_L(size.header + size.padd1);
	} else {
		gd.himg.len_kr.srk_table_flag = (u8)gd.srk_table_flag;
		gd.himg.len_kr.srk_sel= (u8)gd.srk_sel;
		gd.himg.len_kr.num_srk_entries = BYTE_ORDER_S(gd.num_srk_entries);
		gd.himg.sign_len = BYTE_ORDER_L(size.sign_len);
		gd.himg.srk_table_offset = BYTE_ORDER_L(size.header + size.padd1);
	}
	gd.himg.psign =
	    BYTE_ORDER_L(size.header + size.padd1 + size.key_table + size.padd2);
	gd.himg.img_start = BYTE_ORDER_L(gd.entry_addr);

	if (gd.group == 5) {
		gd.himg.mp_n_sg_flag.mp_flag = BYTE_ORDER_S(gd.mp_flag);
		gd.himg.mp_n_sg_flag.sg_flag = BYTE_ORDER_S(1);
		gd.himg.fsl_uid_1 = BYTE_ORDER_L(gd.fslid_1);
		gd.himg.oem_uid_1 = BYTE_ORDER_L(gd.oemid_1);
	}
	else if ((gd.group != 1) && (gd.esbc_flag == 0))
		gd.himg.sg_flag = BYTE_ORDER_L(1);
	else
		gd.himg.sg_flag = BYTE_ORDER_L(gd.sg_flag);

	if ((gd.group == 1) || (gd.group == 2)) {
		if (gd.fsluid_flag && gd.oemuid_flag)
			gd.himg.uid_flag = BYTE_ORDER_L(OUID_FUID_BOTH);
		else if (gd.fsluid_flag)
			gd.himg.uid_flag = BYTE_ORDER_L(FUID_ONLY);
		else if (gd.oemuid_flag)
			gd.himg.uid_flag = BYTE_ORDER_L(OUID_ONLY);
		else
			gd.himg.uid_flag = BYTE_ORDER_L(NO_UID);
	} else {
		if (gd.fsluid_flag && gd.oemuid_flag)
			gd.himg.uid_n_wp.uid_flag = BYTE_ORDER_S(OUID_FUID_BOTH);
		else if (gd.fsluid_flag)
			gd.himg.uid_n_wp.uid_flag = BYTE_ORDER_S(FUID_ONLY);
		else if (gd.oemuid_flag)
			gd.himg.uid_n_wp.uid_flag = BYTE_ORDER_S(OUID_ONLY);
		else
			gd.himg.uid_n_wp.uid_flag = BYTE_ORDER_S(NO_UID);


		gd.himg.uid_n_wp.sfp_wp = (u8)gd.sfp_wp;
		gd.himg.uid_n_wp.sec_image_flag = (u8)gd.sec_image;
        }

	gd.himg.fsl_uid = BYTE_ORDER_L(gd.fslid);
	gd.himg.oem_uid = BYTE_ORDER_L(gd.oemid);
	if (gd.hkptr_flag == 1) {
		gd.himg.hkptr = BYTE_ORDER_L(gd.hkptr);
		gd.himg.hksize = BYTE_ORDER_L(gd.hksize);
	}
	SHA256_Update(ctx, &gd.himg, size.header);
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
	char buf[120];
	for (i = 0; i < gd.num_entries; i++) {
		if (gd.sdhc_flag == 0) {
			gd.osgtbl[i].len = BYTE_ORDER_L(get_size(gd.entries[i].name));
			gd.osgtbl[i].source = BYTE_ORDER_L(gd.entries[i].addr);
		} else {
			gd.osgtbl[i].len = BYTE_ORDER_L(get_size(gd.entries[i].name));
			if (gd.osgtbl[i].len % gd.sdhc_bsize != 0) {
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
			gd.osgtbl[i].len = BYTE_ORDER_L(get_size(gd.entries[i].name) / gd.sdhc_bsize);
			gd.osgtbl[i].source = BYTE_ORDER_L(gd.entries[i].addr / gd.sdhc_bsize);
		}
		gd.osgtbl[i].target_id = BYTE_ORDER_L(gd.targetid);

		if (gd.group == 3 || gd.group ==5)
			gd.entries[i].d_addr = 0xffffffff;

		gd.osgtbl[i].destination = BYTE_ORDER_L(gd.entries[i].d_addr);
	}
	SHA256_Update(ctx, &gd.osgtbl,
		      sizeof(struct sg_table_offset) * gd.num_entries);
}

void printkeyhash(u8 *addr, uint32_t len, uint32_t srk_table_flag)
{
	SHA256_CTX key_ctx;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	int i;

	SHA256_Init(&key_ctx);
	if (srk_table_flag == 0) {
		SHA256_Update(&key_ctx, addr, len);
	} else {

		SHA256_Update(&key_ctx, addr,
				gd.num_srk_entries* sizeof(struct srk_table));
	}
	
	SHA256_Final(hash, &key_ctx);
	printf("\n");
	printf("Key Hash :\n");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", hash[i]);
	printf("\n\n");
}

void printonlyhash(void)
{
	int i, j, n;
	SHA256_CTX key_ctx;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	FILE *fsrk_pub[MAX_NUM_KEYS];
	RSA * srk_pub[MAX_NUM_KEYS];
	unsigned char *tmp;
	unsigned char *exponent;
	u8 key[1024];
	unsigned char *key_len_ptr;
	u32 key_len = 0, total_key_len;
	n = 0;
	if (input_pub_key.count > 1)
		gd.srk_table_flag = 1;

	SHA256_Init(&key_ctx);
	/* open SRK public key file and get the key */
	while (n != input_pub_key.count) {
		fsrk_pub[n] = fopen(gd.pub_fname[n], "r");
		if (fsrk_pub[n] == NULL) {
			fprintf(stderr, "Error in opening the file: %s\n",
				gd.pub_fname[n]);
			return;
		}

		srk_pub[n] =
		    PEM_read_RSAPublicKey(fsrk_pub[n], NULL, NULL, NULL);
		if (srk_pub[n] == NULL) {
			fprintf(stderr, "Error in reading key from : %s\n",
				gd.pub_fname[n]);
			fclose(fsrk_pub[n]);
			return;
		}

		key_len = RSA_size(srk_pub[n]);
		memset(key, 0, 1024);
		tmp = (unsigned char *)(((BIGNUM *) srk_pub[n]->n)->d);
		for (j = key_len - 1, i = 0;
		     i < ((BIGNUM *) srk_pub[n]->n)->top * sizeof(BIGNUM *);
		     i++, j--)
			key[j] = tmp[i];

		exponent = key + key_len;
		tmp = (unsigned char *)(((BIGNUM *) srk_pub[n]->e)->d);
		for (j = key_len - 1, i = 0;
		     i < ((BIGNUM *) srk_pub[n]->e)->top * sizeof(BIGNUM *);
		     i++, j--)
			exponent[j] = tmp[i];

		if (gd.srk_table_flag == 1) {
			total_key_len = BYTE_ORDER_L(2 * key_len);
			key_len_ptr = (u8 *) &total_key_len;
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
			printf("0x%0.2x ", *(key + ctr));
#endif
		SHA256_Update(&key_ctx, (u8 *) key, 2 * key_len);
		n++;
	}
	SHA256_Final(hash, &key_ctx);
	printf("\n");
	printf("Key Hash :\n");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", hash[i]);
	printf("\n\n");
	n = 0;
	while (n != input_pub_key.count) {
		fclose(fsrk_pub[n]);
		RSA_free(srk_pub[n]);
		n++;
	}
}

void usage(void)
{
	if (gd.file_flag == 0) {
		printf("\nThis script signs the files and generates the header"
		       "as understood by ");
		printf("ISBC/ESBC with signature embedded in it.\n");
		printf("For format of header generated refer to the "
			"User Document.\n");
		printf("\nUsage I:\n");
		printf("./uni_sign --file INPUT_FILE" "\n");
		printf("--file INPUT_FILE\t");
		printf("Refer Default input_file and provide all the input "
			"in the input file for header generation .\n");

		printf("\nUsage II:\n");
		printf("./uni_sign PLATFORM [OPTION] FILE ADDR [DEST_ADDR]"
			"[FILE ADDR [DEST_ADDR]...]\n");
		printf("\nPLATFORM\t\tChoose Platform - "
			"1010/1040/3041/4080/5020/5040/9131/9132/4860/4240/LS1");
		printf("\nFILE\t\t\tFile to be signed\n");
		printf("ADDR\t\t\tAddress where this binary would be "
			"loaded by user.\n");
		printf("\t\t\tFor non-PBL, this address would be mapped on "
			"device as selected form target field.\n");
		printf("DEST_ADDR\t\tSpecify dest address in case of platforms"
		       " specified that do not have PBL support.\n\n");

		printf("\nOptions:\n");

		printf("-s,--sgaddr ADDR\t");
		printf("The address of scatter gather table.\n"
		     "\t\t\t(Required for P3041/P4080/P5020/P5040 only)\n");
		printf("\t\t\t(default sg_flag = 0 for PBL devices. "
			"For non-PBL devices sg_flag would always be 1)\n");
		printf("-e,--entraddr ADDR\t");
		printf("Entry Point/Image start addr field in the header.\n");
		printf("\t\t\t(default=ADDRESS of first file specified "
			"in command)\n");
		printf("-p,--privkey FILE1[,FILE2, FILE3, FILE4]\n");
		printf("\t\t\tPrivate key filename to be used for signing"
			" the image.\n");
		printf("\t\t\t(File has to be in PEM format)"
		       "(default = srk.pri generated by genkeys command)\n");
		printf("\t\t\t(More than one key file is required for 9164 "
			"and 1040 only )\n");
		printf("-k,--pubkey FILE1[,FILE2, FILE3, FILE4]\n");
		printf("\t\t\tPublic key filename in PEM format.\n");
		printf("\t\t\t(default=srk.pub generated by genkeys).\n");
		printf("\t\t\tRequired for --hash option in case private key "
		       "is not available.\n");
		printf("\t\t\t(More than one key file is required for 9164 "
			"and 1040 only)\n");
		printf("-o,--keyselect KEY_NUM\t");
		printf("Specify the key to be used in signature generation when"
		       " more than one key has been given as input.\n");
		printf("\t\t\t(Default=1, first key will be selected)\n");
		printf("\t\t\t(Required for 9164 and 1040 only )\n");
		printf("-t,--targetid TARGET\t");
		printf("Specify the target where image will be loaded. "
			"Default is NOR_16B\n");
		printf("\t\t\tOnly required for Non-PBL Devices\n");
		printf("\t\t\tSelect from - NOR_8B/NOR_16B/NAND_8B_512/"
			"NAND_8B_2K/NAND_8B_4K/\n");
		printf("\t\t\tNAND_16B_512/NAND_16B_2K/NAND_16B_4K/SD/MMC/SPI"
			"\n");
		printf("--oemuid OEMUID\t\t");
		printf("OEM UID to be populated in the header "
			"\n");
		printf("--fsluid FSLUID\t\t");
		printf("FSL UID to be populated in header."
			"\n");
		printf("--hkptr HK_AREA\t\t");
		printf("House Keeping Area Starting Pointer Required by Sec\n");
		printf("\t\t\t(Required for 9164 and 1040 only when esbc "
			"option is not provided)\n");
		printf("--hksize HK_SIZE\tHouse Keeping Area Size\n");
		printf("\t\t\t(Required for 9164 and 1040 only when esbc "
			"option is not provided)\n");
		printf("--sgfile FILE\t\t");
		printf("Binary file which would be generated for scatter "
			"gather table.(default=sg_tbl.out)\n");
		printf("\t\t\t(Required for P3041/P4080/P5020/P5040 only)\n");
		printf("--hdrfile FILE\t\t");
		printf("Binary file that would be generated for header."
		       "(default=hdr.out)\n");
		printf("--esbc\t\t\t");
		printf("Specify this flag if header is required for "
			"ESBC header.\n");
		printf("--hash\t\t\t");
		printf("Print the hash of the public key.\n");
		printf("\t\t\tThis hash value can be used with validate"
			" command to populate the SFP.\n");

		printf("-h,--help\t\t");
		printf("Show this help message and exit\n");
	} else {
		printf("\n\nRefer default input file or User documnet\n");
	}

}

void parse_file(char *file_name)
{
	int i, ret;
	char *image_name;
	image_name = malloc(strlen("IMAGE_1" + 1));

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

	find_value_from_file("ESBC", fp);
	if (file_field.count == 1) {
		gd.esbc_flag = strtoul(file_field.value[0], 0, 10);
		if (gd.esbc_flag != 1 && gd.esbc_flag != 0) {
			printf("Error. Invalid Usage of ESBC Flag "
				"in input file. Refer usage\n");
			exit(1);
		}
	}

	/* Parse Key Info from input file */
	find_value_from_file("KEY_SELECT", fp);
	if (file_field.count == 1) {
		gd.srk_sel = strtoul(file_field.value[0], 0, 10);
		gd.srk_table_flag = 1;
	}

	find_value_from_file("PRI_KEY", fp);
	if (file_field.count >= 1) {
		input_pri_key.count = file_field.count;
		if (input_pri_key.count > 1)
			gd.srk_table_flag = 1;

		i = 0;
		while (i != input_pri_key.count) {

			input_pri_key.value[i] =
			    malloc(strlen(file_field.value[i]));
			strcpy(input_pri_key.value[i], file_field.value[i]);

			i++;
		}

	}

	find_value_from_file("PUB_KEY", fp);
	if (file_field.count >= 1) {
		input_pub_key.count = file_field.count;
		if (input_pub_key.count > 1)
			gd.srk_table_flag = 1;

		i = 0;
		while (i != input_pub_key.count) {

			input_pub_key.value[i] =
			    malloc(strlen(file_field.value[i]));
			strcpy(input_pub_key.value[i], file_field.value[i]);

			i++;
		}

	}
	/* Parse Entry Point from input file */
	find_value_from_file("ENTRY_POINT", fp);
	if (file_field.count == 1) {
		gd.entry_addr = strtoul(file_field.value[0], 0, 16);
		gd.entry_flag = 1;
	}

	/* Parse Image target from input file */
	find_value_from_file("IMAGE_TARGET", fp);
	if (file_field.count == 1) {
		gd.target_name = malloc(strlen(file_field.value[0]));
		strcpy(gd.target_name, file_field.value[0]);
		gd.target_flag = 1;
		if (strcmp(gd.target_name, "SDHC") == 0)
			gd.sdhc_flag = 1;
	}


	/* Parse blocksize if image target is SDHC*/
	find_value_from_file("BSIZE", fp);
	if (file_field.count == 1)
		gd.sdhc_bsize = strtoul(file_field.value[0], 0, 10);

	/* Parse Images from input file */
	i = 0;
	gd.num_entries = 0;
	while (i != NUM_SG_ENTRIES) {
		sprintf(image_name, "IMAGE_%d", i + 1);
		find_value_from_file(image_name, fp);
		if (((gd.group == 1) || (gd.group == 3) || (gd.esbc_flag == 1))
		&& ((file_field.count != 2) && (file_field.count != 3)
		&& (file_field.count != 0) && (file_field.count != -1))) {

			printf("Error. Invalid Usage of Input File for "
				"field %s. Refer usage\n", image_name);
			exit(1);
		}
		if (((gd.group == 2) || (gd.group == 4) || (gd.group == 5)) &&
		    ((file_field.count != 3) && (file_field.count != 0)
		     && (file_field.count != -1) && (gd.esbc_flag == 0))) {

			printf("Error. Invalid Usage. Please check %s "
				"in input file. Refer usage\n", image_name);
			exit(1);
		}

		if ((file_field.count != 0) && (file_field.count != -1)) {
			gd.entries[i].name =
			    malloc(strlen(file_field.value[0]));
			strcpy(gd.entries[i].name, file_field.value[0]);
			gd.entries[i].addr =
			    strtoul(file_field.value[1], 0, 16);

			if (((gd.group == 2) || (gd.group == 4))
			    && (gd.esbc_flag == 0)) {
				gd.entries[i].d_addr =
				    strtoul(file_field.value[2], 0, 16);
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
	find_value_from_file("OEM_UID", fp);
	if (file_field.count == 1) {
		gd.oemid = strtoul(file_field.value[0], 0, 16);
		gd.oemuid_flag = 1;
	}

	find_value_from_file("FSL_UID", fp);
	if (file_field.count == 1) {
		gd.fslid = strtoul(file_field.value[0], 0, 16);
		gd.fsluid_flag = 1;
	}
	find_value_from_file("OEM_UID_1", fp);
	if (file_field.count == 1) {
		gd.oemid_1 = strtoul(file_field.value[0], 0, 16);
		gd.oemuid_1_flag = 1;
	}

	find_value_from_file("FSL_UID_1", fp);
	if (file_field.count == 1) {
		gd.fslid_1 = strtoul(file_field.value[0], 0, 16);
		gd.fsluid_1_flag = 1;
	}


	/* Parse File Names from input file */
	find_value_from_file("OEM_UID", fp);
	find_value_from_file("OUTPUT_HDR_FILENAME", fp);
	if (file_field.count == 1) {
		gd.hdrfile = malloc(strlen(file_field.value[0]));
		strcpy(gd.hdrfile, file_field.value[0]);
	}

	find_value_from_file("OUTPUT_SG_FILE", fp);
	if (file_field.count == 1) {
		gd.sgfile = malloc(strlen(file_field.value[0]));
		strcpy(gd.sgfile, file_field.value[0]);
		gd.sgfile_flag = 1;
	}

	/* Parse SG Table Address from input file */
	find_value_from_file("SG_TABLE_ADDR", fp);
	if (file_field.count == 1) {
		gd.sg_addr = strtoul(file_field.value[0], 0, 16);
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
		gd.hkptr = strtoul(file_field.value[0], 0, 16);
		gd.hkptr_flag = 1;
	}
	find_value_from_file("HK_AREA_SIZE", fp);
	if (file_field.count == 1) {
		gd.hksize = strtoul(file_field.value[0], 0, 16);
		gd.hksize_flag = 1;
	}

	/* Parse SFP Write Protect from input file */
	find_value_from_file("SFP_WP", fp);
	if (file_field.count == 1) {
		gd.sfp_wp = strtoul(file_field.value[0], 0, 16);
	}
	/* Parse SFP Write Protect from input file */
	find_value_from_file("SEC_IMAGE", fp);
	if (file_field.count == 1) {
		gd.sec_image = strtoul(file_field.value[0], 0, 16);
	}

	/* Parse Manufacturing Protection Flag from input file */
	find_value_from_file("MP_FLAG", fp);
	if (file_field.count == 1) {
		gd.mp_flag = strtoul(file_field.value[0], 0, 16);
	}
	find_value_from_file("VERBOSE", fp);
	if (file_field.count == 1)
		gd.verbose_flag = strtoul(file_field.value[0], 0, 16);

	free(image_name);
	free(line);
	fclose(fp);

}

void check_error(int argc, char **argv)
{
	int i, ret;

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
	if ((gd.hkptr_flag == 1 || gd.hksize_flag == 1)
	    && ((gd.group == 1) || (gd.group == 2) || (gd.group == 5)
		|| (gd.esbc_flag == 1))) {
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
	} else if ((gd.srk_table_flag == 1)
		   && (gd.srk_sel < 1 || gd.srk_sel > 4)) {
		printf("Error. Key select number should be any "
			"number from 1 to 4.\n");
		usage();
		exit(1);
	} else if ((gd.srk_table_flag == 1) && (input_pri_key.count > 4)) {
		printf("Error. No. of key files should not be more than 4.\n");
		usage();
		exit(1);
	}

	if (gd.target_flag == 1) {
		ret = check_target(gd.target_name, &gd.targetid);
		if (ret == -1) {
			printf("Error. Invalid Target Name. Refer usage\n");
			usage();
			exit(1);
		}
	}
	if (gd.srk_sel > input_pri_key.count) {
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
	i = 0;
	if ((input_pri_key.count > 1) && (gd.group == 1 || gd.group == 2)) {
		printf("Error. More than 1 key is not required"
			" for the given platform.\n");
		usage();
		exit(1);

	} else if (input_pri_key.count != input_pub_key.count) {
		printf("Error. Public Key Count is not equal "
			"to Private Key Count.\n");
		usage();
		exit(1);

	} else {
		while (i != input_pri_key.count) {
			gd.priv_fname[i] = input_pri_key.value[i];
			gd.pub_fname[i] = input_pub_key.value[i];
			i++;
		}
		gd.num_srk_entries = input_pri_key.count;
	}

	if (gd.num_entries == 0) {
		if (gd.hash_flag) {
			printonlyhash();
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
	int i, n, ret, j = 0;
	u32 key_len, total_key_len, hdrlen;
	u8 *header;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned char *tmp;
	unsigned char *sign;
	unsigned char *key;

	SHA256_CTX ctx;
	FILE *ftbl;
	FILE *fhdr;

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
	gd.hdrfile = HDR_FILE;
	gd.sgfile = TBL_FILE;
	gd.oemuid_flag = 0;
	gd.fsluid_flag = 0;
	gd.target_flag = 0;
	gd.sgfile_flag = 0;
	gd.hkptr_flag = 0;
	gd.hksize_flag = 0;
	gd.hkptr = 0;
	gd.hksize = 0;
	gd.oemid = 0;
	gd.fslid = 0;
	gd.targetid = 0x0000000f;
	gd.srk_sel = 1;
	gd.srk_table_flag = 0;
	gd.sfp_wp = 0;
	gd.sec_image = 0;
	gd.num_srk_entries = 1;
	gd.file_flag = 0;
	gd.mp_flag = 0;
	gd.oemuid_1_flag = 0;
	gd.fsluid_1_flag = 0;
	gd.sdhc_bsize = BLOCK_SIZE;
	gd.sdhc_flag = 0;

	input_pri_key.count = 1;
	input_pri_key.value[0] = PRI_KEY_FILE;

	input_pub_key.count = 1;
	input_pub_key.value[0] = PUB_KEY_FILE;

	size.padd1 = 0;
	size.padd2 = 0;
	size.padd3 = 0;

	while (1) {
		static struct option long_options[] = {
			{"verbose", no_argument, &gd.verbose_flag, 1},
			{"hash", no_argument, &gd.hash_flag, 1},
			{"esbc", no_argument, &gd.esbc_flag, 1},
			{"sfpwp", no_argument, &gd.sfp_wp, 1},
			{"simg", no_argument, &gd.sec_image, 1},
			{"file", no_argument, &gd.file_flag, 1},
			{"help", no_argument, 0, 'h'},
			/* These options don't set a flag.
			 * We distinguish them by their indices. */
			{"sgaddr", required_argument, 0, 's'},
			{"pubkey", required_argument, 0, 'k'},
			{"privkey", required_argument, 0, 'p'},
			{"entryaddr", required_argument, 0, 'e'},
			{"targetid", required_argument, 0, 't'},
			{"keyselect", required_argument, 0, 'o'},
			{"hdrfile", required_argument, 0, 0},
			{"sgfile", required_argument, 0, 0},
			{"oemuid", required_argument, 0, 0},
			{"fsluid", required_argument, 0, 0},
			{"hkptr", required_argument, 0, 0},
			{"hksize", required_argument, 0, 0},
			{0, 0, 0, 0}
		};
		int option_index = 0;

		c = getopt_long(argc, argv, "p:a:t:s:k:e:o:h:m",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 0:
			/* If this option set a flag, do nothing else now. */
			if (long_options[option_index].flag != 0)
				break;
			if (strcmp(long_options[option_index].name, "hdrfile")
			    == 0) {
				gd.hdrfile = optarg;
			} else
			    if (strcmp
				(long_options[option_index].name,
				 "sgfile") == 0) {
				gd.sgfile = optarg;
				gd.sgfile_flag = 1;
			} else
			    if (strcmp
				(long_options[option_index].name,
				 "oemuid") == 0) {
				gd.oemid = strtoul(optarg, 0, 16);
				gd.oemuid_flag = 1;
			} else
			    if (strcmp
				(long_options[option_index].name,
				 "fsluid") == 0) {
				gd.fslid = strtoul(optarg, 0, 16);
				gd.fsluid_flag = 1;
			} else
			    if (strcmp
				(long_options[option_index].name,
				 "targetid") == 0) {
				gd.target_name = optarg;
				gd.target_flag = 1;
			} else
			    if (strcmp(long_options[option_index].name, "hkptr")
				== 0) {
				gd.hkptr = strtoul(optarg, 0, 16);
				gd.hkptr_flag = 1;
			} else
			    if (strcmp
				(long_options[option_index].name,
				 "hksize") == 0) {
				gd.hksize = strtoul(optarg, 0, 16);
				gd.hksize_flag = 1;
			} else
			    if (strcmp
				(long_options[option_index].name,
				 "keyselect") == 0) {
				gd.srk_sel = strtoul(optarg, 0, 16);
				gd.srk_table_flag = 1;
			} else
			    if (strcmp
				(long_options[option_index].name,
				 "sfpwp") == 0) {
				gd.sfp_wp = strtoul(optarg, 0, 10);
			}
			break;

		case 's':
			gd.sg_addr = strtoul(optarg, 0, 16);
			gd.sg_flag = 1;
			break;

		case 'a':
			gd.img_addr = strtoul(optarg, 0, 16);
			break;

		case 'k':
			input_pub_key = get_field(optarg);
			if (input_pub_key.count > 1)
				gd.srk_table_flag = 1;
			break;

		case 'p':
			input_pri_key = get_field(optarg);
			if (input_pri_key.count > 1)
				gd.srk_table_flag = 1;
			break;

		case 'e':
			gd.entry_addr = strtoul(optarg, 0, 16);
			gd.entry_flag = 1;
			break;

		case 'o':
			gd.srk_sel = strtoul(optarg, 0, 16);
			gd.srk_table_flag = 1;
			break;

		case 't':
			gd.target_name = optarg;
			gd.target_flag = 1;
			break;

		case 'm':
			gd.mp_flag = 1;
			break;

		case 'h':
			usage();
			exit(0);

		case '?':
			/* getopt_long already printed an error message. */
			break;

		default:
			abort();
		}
	}

	if (optind < argc) {
		if (!gd.file_flag) {
			if ((argc > 1)) {
				/* Check Group on the basis of Platform */
				ret = check_group(argv[optind++]);
				if (ret == -1) {
					printf
					    ("Error. Invalid Platform Name."
						" Refer usage\n");
					usage();
					exit(1);
				}
			} else {
				printf("Error in usage\n");
				usage();
				exit(1);
			}

			if ((gd.group == 2 || gd.group == 4)
			    && (gd.esbc_flag == 0)) {
				if ((argc - optind) % 3 != 0) {
					printf
					    ("Error.Format should be- FILE "
					"ADDR DEST_ADDR. Refer usage\n");
					usage();
					exit(1);
				}
			} else {
				if ((argc - optind) % 2 != 0) {
					printf
					    ("Error. File address parameter "
						"not in pair. Refer usage\n");
					usage();
					exit(1);
				}
			}
			if ((argc - optind) / 2 > 1 && gd.sg_flag == 0
			    && gd.group == 1 && gd.esbc_flag == 0) {
				printf("Error. SG table address missing\n");
				usage();
				exit(1);
			}

			i = 0;
			while (optind < argc) {
				gd.entries[i].name = argv[optind++];
				gd.entries[i].addr =
				    strtoul(argv[optind++], 0, 16);
				if ((gd.group == 2 || gd.group == 4)
				    && (gd.esbc_flag == 0)) {
					gd.entries[i].d_addr =
					    strtoul(argv[optind++], 0, 16);
				}
#ifdef DEBUG
				printf("%s ", gd.entries[i].name);
				printf("%x ", gd.entries[i].addr);
#endif
				i++;
			}
			gd.num_entries = i;
		}
	}

	if ((argc == 2) && (gd.file_flag)) {
		printf("Error.Invalid Usage. Filename missing. Refer usage\n");
		usage();
		exit(1);
	}

	if ((argc != 3) && (gd.file_flag)) {
		printf
		    ("Error.Invalid Usage. With --file only filename is"
			" required. Refer usage\n");
		usage();
		exit(1);
	}

	if (gd.file_flag) {
		/* Parse input file for the fields */
		parse_file(argv[2]);
	}

	check_error(argc, argv);

	if (gd.entry_flag == 0)
		gd.entry_addr = gd.entries[0].addr;
	printf("\n");

	ret = open_priv_file();
	if (ret < 0)
		exit(1);

	/* Calculate size of all the components of header */
	if ((gd.group == 1) || (gd.group == 2) || (gd.esbc_flag == 1))
		size.header = sizeof(struct img_hdr) - sizeof(struct hk) - 2*sizeof(uint32_t);
	else
		size.header = sizeof(struct img_hdr);

	if (((gd.group == 2) || (gd.group == 3) || (gd.group == 4) || (gd.group == 5))
	    && (gd.esbc_flag != 1)) {
		size.sg_table = gd.num_entries * sizeof(struct sg_table_offset);
	} else {
		size.sg_table = 0;
	}

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
		size.key_table = gd.num_srk_entries * sizeof(struct srk_table);
	}

	/* To add padding in the header */
#ifndef MIN_HDR
	size.padd1 = 512 - size.header;
	size.padd2 = 0x1200 - size.key_table;
	size.padd3 = 512 - size.sign_len;
#endif
	/* Hdrlen - size of header, key, sign and padding */
	hdrlen =
	    size.header + size.padd1 + size.key_table + size.padd2 +
	    size.sign_len + size.padd3 + size.sg_table;

	header = malloc(hdrlen);
	if (header == NULL) {
		fprintf(stderr,
			"Error in allocating memory of %d bytes\n", hdrlen);
		goto exit1;
	}
	memset(header, 0, hdrlen);

	SHA256_Init(&ctx);
	/* Update the headers contents in SHA */
	/* Also update `the image contents in SHA if sg = 0 */
	fill_header(&ctx, key_len, size.sign_len);
#ifdef DEBUG
	dump_gd();
#endif
	memcpy(header, &gd.himg, size.header);

	/*pointer to the location of key */
	key = header + size.header + size.padd1;
	memset(key, 0, size.key_table);

	if (gd.srk_table_flag == 0) {
		/* copy N and E */

		/* Copy N component */
		tmp = (unsigned char *)(((BIGNUM *) gd.srk[0]->n)->d);
		for (j = key_len - 1, i = 0;
		     i < ((BIGNUM *) gd.srk[0]->n)->top * sizeof(BIGNUM *);
		     i++, j--)
			key[j] = tmp[i];

		/* Copy E component */
		key = header + size.header + size.padd1 + key_len;
		tmp = (unsigned char *)(((BIGNUM *) gd.srk[0]->e)->d);
		for (j = key_len - 1, i = 0;
		     i < ((BIGNUM *) gd.srk[0]->e)->top * sizeof(BIGNUM *);
		     i++, j--)
			key[j] = tmp[i];

		SHA256_Update(&ctx, header + size.header + size.padd1,
			      2 * key_len);

	} else {
		/* SRK table */
		n = 0;
		while (n != gd.num_srk_entries) {
			/* copy N and E */
			key =
			    header + size.header + size.padd1 +
			    (n) * (sizeof(struct srk_table));

			/* Copy length */
			total_key_len = BYTE_ORDER_L(2 * gd.key_table[n].key_len);
			memcpy(key, &total_key_len, sizeof(u32));
			key = key + sizeof(u32);

			/* Copy N component */
			tmp = (unsigned char *)(((BIGNUM *) gd.srk[n]->n)->d);
			for (j = gd.key_table[n].key_len - 1, i = 0;
			     i <
			     ((BIGNUM *) gd.srk[n]->n)->top * sizeof(BIGNUM *);
			     i++, j--)
				key[j] = tmp[i];

			/* Copy E component */
			key =
			    header + size.header + size.padd1 +
			    (n) * (sizeof(struct srk_table)) + sizeof(u32) +
			    gd.key_table[n].key_len;
			tmp = (unsigned char *)(((BIGNUM *) gd.srk[n]->e)->d);
			for (j = gd.key_table[n].key_len - 1, i = 0;
			     i <
			     ((BIGNUM *) gd.srk[n]->e)->top * sizeof(BIGNUM *);
			     i++, j--)
				key[j] = tmp[i];

			memcpy(gd.key_table[n].pkey,
			       header + size.header + size.padd1 +
			       n * sizeof(struct srk_table) + 4,
			       2 * gd.key_table[n].key_len);
			/*Update for all the keys present in the Key table */
			n++;
		}
		SHA256_Update(&ctx, header + size.header + size.padd1,
			gd.num_srk_entries * sizeof(struct srk_table));

	}

	if (gd.hash_flag == 1 || gd.file_flag == 1) {
		printkeyhash(header + size.header + size.padd1,
			     2 * key_len, gd.srk_table_flag);
	}

	/* Sequence of signature generation as per P1010 */
	if ((gd.group == 2) && (gd.esbc_flag == 0)) {
		for (i = 0; i < gd.num_entries; i++)
			get_size_and_updatehash(gd.entries[i].name, &ctx);
	}

	if ((gd.sg_flag == 1) && (gd.group == 1))
		fill_and_update_sg_tbl(&ctx);

	if (((gd.group == 2) || (gd.group == 3) || (gd.group == 4) || (gd.group == 5))
	    && (gd.esbc_flag == 0))
		fill_and_update_sg_tbl_offset(&ctx);

	if ((gd.group != 2) || (gd.esbc_flag == 1)) {
		for (i = 0; i < gd.num_entries; i++)
			get_size_and_updatehash(gd.entries[i].name, &ctx);
	}
	SHA256_Final(hash, &ctx);

	if (gd.verbose_flag) {
		printf("\n");
		printf("Image Hash :");
		for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
			printf("%02x", hash[i]);
		printf("\n");
	}
	/* copy Sign */

	sign = header + size.header + size.padd1 + size.key_table + size.padd2;

	if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign,
		     &size.sign_len, gd.srk[gd.srk_sel - 1])
	    != 1) {
		printf("Error in generating signature\n");
		goto exit2;
	}

	if (gd.verbose_flag) {
		printf("********** HEADER **************\n");
		dump_img_hdr1(&gd.himg);
		if (gd.esbc_flag == 0) {
			if ((gd.group == 1) && (gd.sg_flag == 1)) {
				printf("********** SG TABLE ************\n");
				dump_sg_table1((struct sg_table *)gd.hsgtbl,
					       gd.num_entries);
			} else if (gd.group != 1) {
				printf("********** SG TABLE ************\n");
				dump_sg_table2((struct sg_table_offset *)gd.
					       osgtbl, gd.num_entries);
			}
		}
	}

	/* Copy SG Table in the header at the offset */
	if (((gd.group == 2) || (gd.group == 3) || (gd.group == 4) || (gd.group == 5))
	    && (gd.esbc_flag == 0)) {
		memcpy(header + size.header + size.padd1 + size.key_table +
		       size.padd2 + size.sign_len + size.padd3, gd.osgtbl,
		       size.sg_table);
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
	for (i = 0; i < gd.num_srk_entries; i++) {
		fclose(gd.fsrk_pri[i]);
		RSA_free(gd.srk[i]);
	}
	exit(0);
}
