/* This code generates RSA public and private keys and stores the
 * keys in file.
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
#define POWERPC
#define OPENSSL_NO_KRB5
#include <stdio.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include "sign_includes.h"
#include "ibr.h"
#include "config.h"

#define IOBLOCK 256 
#define MAX_SGL	10
#define FSL_UID1 0x11111111
#define OEM_UID1 0x99999999
#define HDR_FILE "esbc_hdr.out"
#define BLOCK_SIZE 512
/*
 * 	Memory Map of NOR
 * 	0x0 -> cf_header
 * 	0x100000 -> esbc_hdr
 * 		pkey
 * 		sign
 *		sgtbl
 *
 */

struct esbc_hdr hdr;
struct sg_table sgtbl[MAX_SGL];
FILE *fhdr;
FILE *fsrk_pri;
RSA *srk;
int sg_entries = 0;
int key_len=0;
int sign_len=0;
u32 esbc_entry_point = ESBC_EP;
u32 padd1, padd2, padd3;
int read_file(FILE * fp, u8* buf)
{
	size_t bytes;
	fseek(fp, 0L, SEEK_SET);
	while (!feof(fp)) {
		/* read some data */
		bytes = fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file \n");
			return -1;
		} else if (feof(fp) && (bytes == 0))
			break;
		buf +=bytes;

	}

	return 0;
}

void create_header_file(u8 * buf, int buf_len)
{
	int i=0,sz=0;
	char line1[] = "unsigned char buf[] = { \0";
	char line2[] = "};\0";
	char c = ',';
	char tmp[10];

	FILE *fh;
	fh = fopen("cf_header.h","w");

	if(!fh) {
		printf("\n File Open Err \n");
		return;
	}
	fwrite(line1,strlen(line1),1,fh);
	for(i=0;i<buf_len;i++) {
		sz = sprintf(tmp,"0x%02x",buf[i]);
		fwrite(tmp,sz,1,fh);
		if(i!=buf_len-1)
		fwrite(&c,1,1,fh);
	}		 		
	fwrite(line2,strlen(line2),1,fh);
	fclose(fh);
}

void open_prvk()
{
	/* open SRK private key file and get */
	fsrk_pri = fopen(PRI_KEY_FILE, "r");
	if (fsrk_pri == NULL) {
		fprintf(stderr, "Error in opening the file: %s \n",
			PRI_KEY_FILE);
	}

	if ((srk = PEM_read_RSAPrivateKey(fsrk_pri, NULL, NULL, NULL)) == NULL) {
		fprintf(stderr, "Error in reading key from : %s \n",
			PRI_KEY_FILE);
	}
}

void fill_esbc_hdr(SHA256_CTX *ctx)
{
	u32 size = sizeof(struct esbc_hdr);	
	hdr.barker[0] = 0x68;
	hdr.barker[1] = 0x39;
	hdr.barker[2] = 0x27;
	hdr.barker[3] = 0x81;

	hdr.key_len = htonl(2 * key_len);
	hdr.sign_len = htonl(sign_len);

	hdr.sg_entries = htonl(sg_entries);
	hdr.pkey = htonl(size + padd1 ); 
	/* signature follows the key */
	hdr.psign = htonl(size + 2*key_len + padd1 + padd2);
	hdr.entry_point = htonl(esbc_entry_point);
	/* scatter gather table follows signature */
	hdr.sg_table_addr =  htonl(size + 2*key_len + sign_len + padd1 + padd2 + padd3); 	
	hdr.sg_flag= htonl(1);
	hdr.uid_flag= htonl(1);
	hdr.fsl_uid= htonl(FSL_UID1);
	hdr.oem_uid= htonl(OEM_UID1);

	/* generate the hash of the header */
	SHA256_Update(ctx, &hdr, size);
	int i=0;
	for(i=0;i<size;i++) {
	if(!(i%4)) printf("\n");
	 printf("%02x",*((u8*)&hdr +i));
	}
}

int get_size_and_updatehash(const char *fname, SHA256_CTX *ctx)
{
	FILE *fp;
	unsigned char buf[IOBLOCK];
	size_t bytes = 0;
	size_t len = 0;

	/* open the file */
	fp = fopen(fname, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s \n", fname);
		exit(0);
	}

	/* go to the begenning */	
	fseek(fp, 0L, SEEK_SET);
	
	while (!feof(fp)) {
		/* read some data */
		bytes = fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file \n");
			exit(0);
		} else if (feof(fp) && (bytes == 0))
			break;

		SHA256_Update(ctx, buf, bytes);
		len += bytes;
	}
	
	fclose(fp);

	return len;
}


void fill_sgtbl(SHA256_CTX *ctx)
{
	int i;
	/*populate sg_table */
	for(i=0; i<sg_entries; i++) {
#ifndef BLOCK_ADDRESS_FORMAT
		sgtbl[i].src_addr = htonl(tbl[i].src_addr);
#else
		sgtbl[i].src_addr = htonl(tbl[i].src_addr/BLOCK_SIZE);
#endif		
		sgtbl[i].dst_addr = htonl(tbl[i].dst_addr);
		sgtbl[i].trgt_id = htonl(tbl[i].trgt);
#ifndef BLOCK_ADDRESS_FORMAT
		sgtbl[i].len = htonl(get_size_and_updatehash(tbl[i].fname, ctx));
#else
		sgtbl[i].len = htonl(get_size_and_updatehash(tbl[i].fname, ctx)/BLOCK_SIZE);
#endif
	}
	SHA256_Update(ctx, sgtbl, sizeof(struct sg_table)*sg_entries);

}

int main()
{
	int ret;
	int i, j;
	u8 *tmp;
	u8 *sign;
	u8 *key;
	SHA256_CTX ctx;
	FILE *fhdr;
	/* this buffer is written to the file */
	u8* buf; int buf_len;
	int key_offset;
	int sign_offset;
	int size_words=0;

	struct esbc_hdr *ehdr;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	printf("\n");
	printf("#########################################\n");
	printf("## Generating ESBCHeader composite image \n");
	printf("	(key & sign & SgTbl##\n");
	printf("#########################################\n");

	open_prvk();
	
	key_len = sign_len = RSA_size(srk);
	sg_entries = sizeof(tbl)/sizeof(struct sg_in);
	printf("sg_entries%d\n",sg_entries);
	padd1 = 512 - sizeof(struct esbc_hdr);
	padd2 = 2048 - (2*key_len);	
	padd3 = 1024 - sign_len;
	buf_len = sizeof(struct esbc_hdr) + padd1 + 
			 (2*key_len) + padd2 + sign_len + padd3 +
			 sizeof(struct sg_table) * sg_entries;

	buf  = malloc(buf_len);
	if (buf == NULL) {
		fprintf(stderr, 
		"Error in allocating mem of %d bytes \n", buf_len);
		return -1;
	}
	memset(buf, 0, buf_len);

	
	SHA256_Init(&ctx);
	/*1-  fill esbc_header */	
	fill_esbc_hdr(&ctx);
	memcpy(buf, &hdr, sizeof(struct esbc_hdr));
	
	/*2- Copy PublicKey */
	/* copy N and E */
	key = buf + sizeof(struct esbc_hdr) + padd1;
	tmp = (unsigned char *)(((BIGNUM *) srk->n)->d);
	for (j = key_len - 1, i = 0; i < ((BIGNUM *) srk->n)->top * sizeof(long); i++, j--)
	{
		key[j] = tmp[i];
	}

	key = buf + sizeof(struct esbc_hdr) + key_len +padd1;
	tmp = (unsigned char *)(((BIGNUM *) srk->e)->d);
	for (j = key_len - 1, i = 0; i < ((BIGNUM *) srk->e)->top * sizeof(long); i++, j--)
	{
		key[j] = tmp[i];
	}

	/*3- calculate the hash of public key*/
	SHA256_Update(&ctx, buf + sizeof(struct esbc_hdr) + padd1, 
			2*key_len);
	
	/*4- fill the sg_table */
	fill_sgtbl(&ctx);
	memcpy(buf + sizeof(struct esbc_hdr) + (2*key_len) + sign_len + padd1 + padd2 + padd3,
		sgtbl, sizeof(struct sg_table)*sg_entries); 


	/*5- finalize hash and calculate signature */
	SHA256_Final(hash, &ctx);
	printf("\n");
	printf("Hash :");
	for(i=0;i<SHA256_DIGEST_LENGTH;i++)
		printf("%02x",hash[i]);
	printf("\n");
	
	sign = buf + sizeof(struct esbc_hdr) + (2*key_len) + padd1 + padd2;
	if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, &sign_len, srk)
	    != 1) {
		fprintf(stderr, "Error signing the data\n");
		return -1;
	}
	printf("\n");
	printf("Sign :");
	for(i=0;i<sign_len;i++)
		printf("0x%02x,",sign[i]);
	printf("\n");
	
	key = buf + sizeof(struct esbc_hdr) + padd1;
	for(i=0;i<2*key_len;i++)
		printf("0x%02x,",key[i]);
	printf("\n");

        fhdr = fopen(HDR_FILE, "wb");
        if (fhdr == NULL) {
                fprintf(stderr, "Error in opening the file: %s \n",
                        HDR_FILE);
                return -1;
        }
	
        fwrite((unsigned char *)buf, 1, buf_len, fhdr);

	/* clean up */
	free(buf);
	fclose(fsrk_pri);
	fclose(fhdr);
	return 0;
}
