/* This file populates SFP and SNVS files to be used
 * on simics.
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

#define ESBC_BARKER_LEN 4	/* barker code length in ESBC header */
#define IOBLOCK 128		/* I/O block size to use for hashing operations */
#define SHA256_DIGEST_LENGTH 32
#define NID_sha256 672
#define PRI_KEY_FILE "srk.pri"
#define SFP_FILE "sfp.out"
#define SNVS_FILE "snvs.out"

#define SFP_ADDRESS 0xffff0000
#define SNVS_ADDRESS 0xffff1000

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

struct sfp_regs {
	volatile u8 reserved0[0x40];
	volatile u32 ospr;	/* 0x40  OEM Security Policy Register */
	volatile u8 reserved2[0x38];
	volatile u8 srk[32];	/* 0x7c  Super Root Key Hash */
	volatile u32 oem_uid;	/* 0x9c  OEM Unique ID */
	volatile u8 reserved4[0x10];
	volatile u32 fsl_uid;	/* 0xB0  FSL Unique ID */
};

struct snvs_regs {
	volatile u8 reserved0[0x04];
	volatile u32 hp_com;	/* 0x04 SNVS_HP Command Register */
	volatile u8 reserved2[0x0c];
	volatile u32 hp_stat;	/* 0x0C SNVS_HP Status Register */
};

void dump_sfp(struct sfp_regs *sfp)
{
	int i;
	printf("SRK Hash :0x");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%2.2x", sfp->srk[i]);
	printf("\n");
	printf("FSL UID: 0x%x \nOEM UID:  0x%x\n", ntohl(sfp->fsl_uid), ntohl(sfp->oem_uid));
	printf("ITS : 0x%x \n", ntohl(sfp->ospr >> 2));
}

void dump_snvs(struct snvs_regs *snvs)
{
	printf(" SNVS HP_COM 0x%x \n", snvs->hp_com);
	printf(" SNVS HP_STS 0x%x \n", snvs->hp_stat);
}

struct sfp_regs sfp;
struct snvs_regs snvs;

int main(const int argc, const char **argv)
{
	int i, j;
	size_t ret = 0;
	unsigned char *buf;
	unsigned char *tmp;
	unsigned char *key;

	int key_len;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	FILE *fsfp;
	FILE *fsnvs;
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
	printf("Creating files for SFP and SNVS blocks\n");

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <FSL UID> <OEM UID> \n", argv[0]);
		exit(1);
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
	key_len = RSA_size(srk);

	buf = malloc(key_len * 2);
	if (buf == NULL) {
		fprintf(stderr, "Error in allocating memory \n");
		fclose(fsrk_pri);
		RSA_free(srk);
		return -1;
	}

	memset(buf, 0, key_len * 2);

	/* copy N and E */
	key = buf;
	tmp = (unsigned char *)(((BIGNUM *) srk->n)->d);
	for (j = key_len - 1, i = 0; i < ((BIGNUM *) srk->n)->top * sizeof(BIGNUM *); i++, j--)
		key[j] = tmp[i];

	key = buf + key_len;
	tmp = (unsigned char *)(((BIGNUM *) srk->e)->d);
	for (j = key_len - 1, i = 0; i < ((BIGNUM *) srk->e)->top * sizeof(BIGNUM *); i++, j--)
		key[j] = tmp[i];

	/* hash-->srk n e entries */
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, buf, key_len * 2);
	SHA256_Final(hash, &ctx);

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sfp.srk[i] = hash[i];
	sfp.fsl_uid = htonl(strtol(argv[1], 0, 16));
	sfp.oem_uid = htonl(strtol(argv[2], 0, 16));
	sfp.ospr = htonl(strtol(argv[3], 0, 16));

#ifdef DEBUG
	dump_sfp(&sfp);
	dump_snvs(&snvs);
#endif

	fsfp = fopen(SFP_FILE, "wb");
	if (fsfp == NULL) {
		fprintf(stderr, "Error in opening the file: %s \n", SFP_FILE);
		fclose(fsrk_pri);
		free(buf);
		RSA_free(srk);
		return -1;
	}

	ret = fwrite((unsigned char *)&sfp, 1, sizeof(sfp), fsfp);
	if (ret != sizeof(sfp)) {
	fprintf(stderr, "Error in writing the file: %s \n", SFP_FILE);
		fclose(fsrk_pri);
		fclose(fsfp);
		free(buf);
		RSA_free(srk);
	return -1;
	}

	ret = 0;

	fsnvs = fopen(SNVS_FILE, "wb");
	if (fsnvs == NULL) {
		fprintf(stderr, "Error in opening the file: %s \n", SNVS_FILE);
		fclose(fsrk_pri);
		fclose(fsfp);
		free(buf);
		RSA_free(srk);
		return -1;
	}

	ret = fwrite((unsigned char *)&snvs, 1, sizeof(snvs), fsnvs);
	if (ret != sizeof(snvs)) {
		fprintf(stderr, "Error in writing the file: %s \n", SNVS_FILE);
		fclose(fsrk_pri);
		fclose(fsfp);
		fclose(fsnvs);
		free(buf);
		RSA_free(srk);
		return -1;
	}

	printf ("Load %s at 0x%x\n", SFP_FILE, SFP_ADDRESS);
	printf ("Load %s at 0x%x\n", SNVS_FILE, SNVS_ADDRESS);

	/* clean up */
	fclose(fsrk_pri);
	fclose(fsfp);
	fclose(fsnvs);
	free(buf);
	RSA_free(srk);
	return 0;
}
