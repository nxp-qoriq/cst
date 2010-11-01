/* This code generates and puts ESBC header, public key and signature
 * on top of the image / data to be validated.
 */

/* Copyright (c) 2008 - 2010 Freescale Semiconductor, Inc.
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
#include <stdio.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>

#define ESBC_START_ADDR 0x20002000
#define FSL_UID1 0x11111111
#define OEM_UID1 0x99999999

#define ESBC_BARKER_LEN 4	/* barker code length in ESBC header */
#define IOBLOCK 128		/* I/O block size to use for hashing operations */
#define SHA256_DIGEST_LENGTH 32
#define NUM_SG_ENTRIES	8
#define NID_sha256 672
#define PRI_KEY_FILE "srk.pri"
#define TBL_FILE "sg_table.out"
#define HDR_FILE "esbc_hdr.out"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct sg_table {
	u32 len;		/* length of the segment */
	u8 *pdata;		/* ptr to the data segment*/
};

struct hsg_table {
	u32 len;		/* length of the segment */
#ifdef LINUX
	u8 *pdata;		/* ptr to the data segment*/
#else
	u32 pdata;		/* ptr to the data segment*/
#endif
};

struct esbc_hdr {
	u8 barker[ESBC_BARKER_LEN];	/* barker code */
	u32 pkey;		/* public key offset */
	u32 key_len;		/* pub key length */
	u32 psign;		/* sign ptr */
	u32 sign_len;		/* length of the signature */
	union {
#ifdef LINUX
		struct sg_table *psgtable;	/* prt to SG table */
		u8 *pesbc;		/* esbc offset */
#else
		u32 psgtable;	/* prt to SG table */
		u32 pesbc;		/* esbc offset */
#endif
	};
	union {
		u32 sg_entries;		/* no of entries in SG table */
		u32 esbc_size;		/* esbc_size length */
	};
	u32 esbc_start;		/* start ptr */
	u32 sg_flag;		/* Scatter gather flag */
	u32 uid_flag;		/* Flag to indicate uid is present or not*/
	u32 fsl_uid;		/* Freescale unique id */
	u32 oem_uid;		/* OEM unique id */
};

/* calculate SHA256 hash of the given file */
static int read_file(FILE *fp, u8 *buf)
{
	size_t bytes;

	while (!feof(fp)) {
		/* read some data */
		bytes = fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file \n");
			return -1;
		} else if (feof(fp) && (bytes == 0))
			break;
		buf += bytes;
	}

	return 0;
}

/* return the size of the give file */
static int get_size(const char *c)
{
	FILE *fp;
	unsigned char buf[IOBLOCK];
	size_t bytes = 0;

	fp = fopen(c, "rb");

	while (!feof(fp)) {
		/* read some data */
		bytes += fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file \n");
			return -1;
		} else if (feof(fp) && (bytes == 0))
			break;
	}

	return bytes;
}

static void dump_esbc_hdr1(struct esbc_hdr *h)
{
	int i;
	printf("barker:0x");
	for (i = 0; i < ESBC_BARKER_LEN; i++)
		printf("%02.2x", h->barker[i]);
	printf("\n");
	printf("pkey %d , key length %d\n", h->pkey, h->key_len);
	printf("psign %d , length %d\n", h->psign, h->sign_len);
	printf("sg_flag %d \n", h->sg_flag);
	if (h->sg_flag)
		printf(" psgtable  %x len %d\n", h->psgtable, h->sg_entries);
	else
		printf(" pesbc %x len %d\n", h->pesbc, h->esbc_size);
	printf("esbc start %x \n ", h->esbc_start);
	printf("FSL UID %x \n ", h->fsl_uid);
	printf("OEM UID %x \n ", h->oem_uid);
}

static void dump_sg_table1(struct sg_table *t, int n)
{
	int i;
	printf("no of entries  %d \n", n);
	for (i = 0; i < n; i++)
		printf(" entry %d  len %d ptr %x\n", i, (t+i)->len, (t+i)->pdata);
}

u8 *esbc;
struct sg_table sgtbl[NUM_SG_ENTRIES];  /* SG table */
struct hsg_table hsgtbl[NUM_SG_ENTRIES];  /* SG table */

#ifdef LINUX
int init_sg (const int argc, const char **argv)
#else
int main(const int argc, const char **argv)
#endif
{
	int ret;
	size_t ret_w;
	int i, j;
	unsigned char *tmp;
	unsigned char *sign;
	unsigned char *key;
	int sg_entries;

	struct esbc_hdr *hesbc, *hdr;
	int key_len, sign_len, total;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	FILE *ftbl;
	FILE *fhdr;
	FILE *fesbc;
	FILE *fsrk_pri;
	RSA *srk;

	printf("\n");
	printf("===============================================================\n");
	printf("This product includes software developed by the OpenSSL Project\n");
	printf("for use in the OpenSSL Toolkit (http://www.openssl.org/)\n");
	printf("This product includes cryptographic software written by\n");
	printf("Eric Young (eay@cryptsoft.com)\n");
	printf("===============================================================\n");
	printf("\n");
	printf("Signing the ESBC\n");

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <no of SG entries> <Entry1, Entry2...Entry8> <header address> <table address> <entry1 address,entry2 address .......\n", argv[0]);
		exit(1);
	}

	sg_entries = atol(argv[1]);
	if (sg_entries > 8) {
		fprintf(stderr, "number of SG entries should be <=8 \n");
	}

	/* open SRK private key file and get the key */
	fsrk_pri = fopen(PRI_KEY_FILE, "r");
	if (fsrk_pri == NULL) {
		fprintf(stderr, "Error in opening the file: %s \n",
			PRI_KEY_FILE);
		return -1;
	}

	if ((srk = PEM_read_RSAPrivateKey(fsrk_pri, NULL, NULL, NULL)) == NULL) {
		fprintf(stderr, "Error in reading key from : %s \n",
			PRI_KEY_FILE);
		fclose(fsrk_pri);
		return -1;
	}

	/* total size of the ESBC sign, SRK and header */
	key_len = sign_len = RSA_size(srk);
	total = 2 * key_len + sign_len + sizeof(struct esbc_hdr);
	esbc = malloc(total);
	if (esbc == NULL) {
		fprintf(stderr, "Error in allocating memory of %d bytes \n", total);
		fclose(fsrk_pri);
		RSA_free(srk);
		return -1;
	}

	memset(esbc, 0, total);

	/* make header */
	hesbc = (struct esbc_hdr *)esbc;

	hesbc->barker[0] = 0x68;
	hesbc->barker[1] = 0x39;
	hesbc->barker[2] = 0x27;
	hesbc->barker[3] = 0x81;

	hdr = malloc(sizeof(struct esbc_hdr));
	if (hdr == NULL) {
		fprintf(stderr, "Error in allocating memory \n");
		fclose(fsrk_pri);
		free(esbc);
		RSA_free(srk);
		return -1;
	}

	hdr->key_len = 2 * key_len;
	hdr->sign_len = sign_len;
	hdr->sg_entries = sg_entries;
	hdr->pkey = sizeof(struct esbc_hdr);
	hdr->psign = hdr->pkey + hdr->key_len;
	/* hdr->psgtable = &sgtbl[0]; */
	hdr->esbc_start = ESBC_START_ADDR;
	hdr->sg_flag = 1;
	hdr->uid_flag = 1;
	hdr->fsl_uid = FSL_UID1;
	hdr->oem_uid = OEM_UID1;

#ifdef SIMICS
	hesbc->key_len = htonl(hdr->key_len);
	hesbc->sign_len = htonl(hdr->sign_len);
	hesbc->sg_entries = htonl(hdr->sg_entries);
	hesbc->pkey = htonl(hdr->pkey);
	hesbc->psign = htonl(hdr->psign);
	hesbc->esbc_start = htonl(hdr->esbc_start);
	hesbc->sg_flag = htonl(hdr->sg_flag);
	hesbc->uid_flag = htonl(hdr->uid_flag);
	hesbc->fsl_uid = htonl(hdr->fsl_uid);
	hesbc->oem_uid = htonl(hdr->oem_uid);
	/* see the usage */
	hesbc->psgtable = htonl(strtol(argv[3+sg_entries], 0, 16));
#else
	hesbc->key_len = hdr->key_len;
	hesbc->sign_len = hdr->sign_len;
	hesbc->sg_entries = hdr->sg_entries;
	hesbc->pkey = hdr->pkey;
	hesbc->psign = hdr->psign;
	hesbc->psgtable = (struct sg_table *) &sgtbl[0];
	hesbc->esbc_start = hdr->esbc_start;
	hesbc->sg_flag = hdr->sg_flag;
	hesbc->uid_flag = hdr->uid_flag;
	hesbc->fsl_uid = hdr->fsl_uid;
	hesbc->oem_uid = hdr->oem_uid;
#endif

	/* copy N and E */
	key = esbc + hdr->pkey;
	tmp = (unsigned char *)(((BIGNUM *) srk->n)->d);
	for (j = key_len - 1, i = 0; i < ((BIGNUM *) srk->n)->top * 8; i++, j--)
		key[j] = tmp[i];

	key = esbc + hdr->pkey + key_len;
	tmp = (unsigned char *)(((BIGNUM *) srk->e)->d);
	for (j = key_len - 1, i = 0; i < ((BIGNUM *) srk->e)->top * 8; i++, j--)
		key[j] = tmp[i];

	/* populate sg_table */
	for (i = 0; i < sg_entries; i++) {
		/* open the file */
		fesbc = fopen(argv[2+i], "rb");
		if (fesbc == NULL) {
			fprintf(stderr, "Error in opening the file: %s \n", argv[2+i]);
			fclose(fsrk_pri);
			free(esbc);
			free(hdr);
			RSA_free(srk);
			return -1;
		}

		sgtbl[i].len = get_size(argv[2+i]);
		sgtbl[i].pdata = malloc(sgtbl[i].len);
		if (sgtbl[i].pdata == NULL) {
			fprintf(stderr, "Error in allocating memory \n");
			fclose(fsrk_pri);
			free(esbc);
			free(hdr);
			RSA_free(srk);
			return -1;
		}

		/* compute a SHA-256 hash of the input file */
		ret = read_file(fesbc, sgtbl[i].pdata);
		if (ret != 0) {
			fprintf(stderr, "Error in computing the hash of %s \n", argv[1]);
			fclose(fsrk_pri);
			fclose(fesbc);
			free(esbc);
			free(hdr);
			free(sgtbl[i].pdata);
			RSA_free(srk);
			return -1;
		}
	}

	for (i = 0; i < sg_entries; i++) {
#ifdef SIMICS
		hsgtbl[i].len = htonl(sgtbl[i].len);
		hsgtbl[i].pdata = htonl(strtol(argv[4+sg_entries+i], 0, 16));
#else
		hsgtbl[i].len = sgtbl[i].len;
		hsgtbl[i].pdata = (u8 *) sgtbl[i].pdata;
#endif
	}

	/* hash-->hdr+key +sgtable + table entries */
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hesbc, sizeof(struct esbc_hdr));
	SHA256_Update(&ctx, esbc+hdr->pkey, hdr->key_len);
	for (i = 0; i < sg_entries; i++) {
		SHA256_Update(&ctx, &hsgtbl[i], sizeof(struct hsg_table));
	}

	for (i = 0; i < sg_entries; i++) {
		SHA256_Update(&ctx, sgtbl[i].pdata, sgtbl[i].len);
	}

	SHA256_Final(hash, &ctx);

	/* copy Sign */
	sign = esbc + hdr->psign;
	if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, &sign_len, srk)
		!= 1) {
		fprintf(stderr, "Error signing the data\n");
		fclose(fsrk_pri);
		fclose(fesbc);
		free(esbc);
		free(hdr);

		for (i = 0; i < sg_entries; i++)
			free(sgtbl[i].pdata);

		RSA_free(srk);
		return -1;
	}

#ifdef DEBUG
	dump_esbc_hdr1(hesbc);
	dump_sg_table1((struct sg_table *) hsgtbl, sg_entries);
#endif

	fhdr = fopen(HDR_FILE, "wb");
	if (fhdr == NULL) {
		fprintf(stderr, "Error in opening the file: %s \n",
			HDR_FILE);
		fclose(fsrk_pri);
		fclose(fesbc);
		free(esbc);
		free(hdr);

		for (i = 0; i < sg_entries; i++)
			free(sgtbl[i].pdata);

		RSA_free(srk);
		return -1;
	}

	/* Concatinating Header, Sign */
	ret_w = fwrite((unsigned char *)esbc, 1, total, fhdr);
	if (ret_w != total) {
		fprintf(stderr, "Error in writing the file: %s \n",
			HDR_FILE);
		fclose(fsrk_pri);
		fclose(fesbc);
		fclose(fhdr);
		free(esbc);
		free(hdr);

		for (i = 0; i < sg_entries; i++)
			free(sgtbl[i].pdata);

		RSA_free(srk);
		return -1;
	}

	ftbl = fopen(TBL_FILE, "wb");
	if (ftbl == NULL) {
		fprintf(stderr, "Error in opening the file: %s \n",
			TBL_FILE);
		fclose(fsrk_pri);
		fclose(fesbc);
		fclose(fhdr);
		free(esbc);
		free(hdr);

		for (i = 0; i < sg_entries; i++)
			free(sgtbl[i].pdata);

		RSA_free(srk);
		return -1;
	}

	ret_w = 0;

	/* Concatinating Header, Sign */
	ret_w = fwrite((unsigned char *)hsgtbl, 1, sizeof(hsgtbl), ftbl);
	if (ret_w != sizeof(hsgtbl)) {
		fprintf(stderr, "Error in writing the file: %s \n",
			TBL_FILE);
		fclose(fsrk_pri);
		fclose(fesbc);
		fclose(fhdr);
		fclose(ftbl);
		free(esbc);
		free(hdr);

		for (i = 0; i < sg_entries; i++)
			free(sgtbl[i].pdata);

		RSA_free(srk);
		return -1;
	}

#ifdef SIMICS
	printf ("Load %s at %x\n", HDR_FILE, strtol(argv[2+sg_entries], 0, 16));
	printf ("Load %s at %x\n", TBL_FILE, strtol(argv[3+sg_entries], 0, 16));
	for (i = 0; i < sg_entries; i++) {
		hsgtbl[i].len = htonl(sgtbl[i].len);
		hsgtbl[i].pdata = htonl(strtol(argv[4+sg_entries+i], 0, 16));
		printf("load %s at %x \n", argv[2+i], strtol(argv[4+sg_entries+i], 0, 16));
	}
#endif

	/* clean up */
	fclose(fsrk_pri);
	fclose(fesbc);
	fclose(fhdr);
	fclose(ftbl);
	free(esbc);
	free(hdr);

	for (i = 0; i < sg_entries; i++)
		free(sgtbl[i].pdata);

	RSA_free(srk);
	return 0;
}
