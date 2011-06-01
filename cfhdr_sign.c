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

#define HDR_FILE "cf_hdr.out"
FILE *fhdr;
FILE *fsrk_pri;
RSA *srk;
u32 padd1, padd2, padd3;
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

int main()
{
	int ret;
	int i, j;
	u8 *tmp;
	u8 *sign; int sign_len;
	u8 *key; int key_len;
	/* this buffer is written to the file */
	u8* buf; int buf_len;
	u8* cwds;
	int key_offset;
	int sign_offset;
	int size_words=0;

	struct cf_hdr_legacy *cfl;
	struct cf_hdr_secure *cfs;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	printf("\n");
	printf("######################################################\n");
	printf("## Generating CFHeader composite image (pkey & sign ##\n");
	printf("######################################################\n");
	open_prvk();
	fill_words();
	
	size_words = sizeof(u32)*2*word_pairs; 
	/* total size of the CFHDR header and its RSA sign, and public key */
	key_len = sign_len = RSA_size(srk);
	padd1 = 512 - (sizeof(struct cf_hdr_legacy) + size_words + sizeof(struct cf_hdr_secure)+ 0x40 );
	padd2 = 2048 - (2*key_len);
	buf_len = 0x40 + sizeof(struct cf_hdr_legacy) + 
			sizeof(struct cf_hdr_secure) + 
			size_words + (2*key_len) + sign_len + padd1 + padd2;
	
	buf  = malloc(buf_len);
	if (buf == NULL) {
		fprintf(stderr, 
		"Error in allocating mem of %d bytes \n", buf_len);
		return -1;
	}
	memset(buf, 0, buf_len);

	/* calculte the key and signature offset */
	key_offset = sizeof(struct cf_hdr_legacy) 
			+ size_words 
			+ sizeof(struct cf_hdr_secure) + padd1;
	/* placing key just after CFHdr and sign just after key */
	sign_offset = key_offset + 2*key_len + padd2;

	/* Update the legacy and secure data structures */
	cfl = (struct cf_hdr_legacy *)(buf + 0x40);	
#ifndef POWERPC
	cfl->boot_sig = BOOT_SIG;
	cfl->no_conf_pairs= size_words/8;
#else
	cfl->boot_sig = htonl(BOOT_SIG);
	cfl->no_conf_pairs= htonl(size_words/8);
		
#endif
	/* Configuration words store */
	cwds = (u8*)cfl +  sizeof(struct cf_hdr_legacy);
	memcpy(cwds, (u8*)words, size_words);

	/* Secure boot additions to legacy header */	
	cfs = (struct cf_hdr_secure*)( 
		(u8*)cfl + sizeof(struct cf_hdr_legacy) + size_words);
#ifndef POWERPC
	cfs->key_len = 2 * key_len;
	cfs->sign_len = sign_len;
	cfs->esbc_target_id = ESBC_TARGET_ID;
	cfs->ehdrloc = ESBC_HDRADDR;
	cfs->pkey_off = key_offset;
        cfs->psign_off = sign_offset;	
#else
	cfs->key_len = htonl(2 * key_len);
	cfs->sign_len = htonl(sign_len);
	cfs->ehdrloc = htonl(ESBC_HDRADDR);
	cfs->esbc_target_id = htonl(ESBC_TARGET_ID);
	cfs->pkey_off = htonl(key_offset);
        cfs->psign_off = htonl(sign_offset);	

#endif
	/* Copy PublicKey */
	/* copy N and E */
	key = (u8*)cfl + key_offset;
	tmp = (unsigned char *)(((BIGNUM *) srk->n)->d);
	for (j = key_len - 1, i = 0; i < ((BIGNUM *) srk->n)->top * sizeof (long); i++, j--)
	{
		key[j] = tmp[i];
	}

	key = (u8*)cfl + key_offset + key_len;
	tmp = (unsigned char *)(((BIGNUM *) srk->e)->d);
	for (j = key_len - 1, i = 0; i < ((BIGNUM *) srk->e)->top * sizeof(long); i++, j--)
	{
		key[j] = tmp[i];
	}
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, (u8*)cfl + key_offset ,2* key_len);
	SHA256_Final(hash, &ctx);

	printf("\n");
	printf("pkey Hash :");
	for(i=0;i<SHA256_DIGEST_LENGTH;i++)
		printf("%02x",hash[i]);
	printf("\n");

	/* hash-->hdr+key + */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, cfl, sizeof(struct cf_hdr_legacy));
	printf("H%x,",(struct cf_hdr_legacy *)cfl);
	SHA256_Update(&ctx, cwds, size_words);
	printf("W%x,",(struct cf_hdr_legacy *)cwds);
	SHA256_Update(&ctx, cfs, sizeof(struct cf_hdr_secure));
	printf("S%x,",(struct cf_hdr_legacy *)cfs);
	SHA256_Update(&ctx, (u8*)cfl + key_offset ,2* key_len);
	printf("K%x,",(struct cf_hdr_legacy *)cfl + key_offset);
	SHA256_Final(hash, &ctx);

	printf("\n");
	printf("Hash :");
	for(i=0;i<SHA256_DIGEST_LENGTH;i++)
		printf("%02x",hash[i]);
	printf("\n");
	/* copy Sign */
	sign = (u8*)(cfl) + sign_offset;
	if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sign, &sign_len, srk)
	    != 1) {
		fprintf(stderr, "Error signing the data\n");
		return -1;
	}

        fhdr = fopen(HDR_FILE, "wb");
        if (fhdr == NULL) {
                fprintf(stderr, "Error in opening the file: %s \n",
                        HDR_FILE);
                return -1;
        }
	printf("\n");
	printf("Sign :");
	for(i=0;i<sign_len;i++)
		printf("0x%02x,",sign[i]);
	printf("\n");

	
	key = (u8*)(cfl)+ key_offset;
	for(i=0;i<2*key_len;i++)
		printf("0x%02x,",key[i]);
	printf("\n");
	
        /* Concatinating Header, Sign */
        fwrite((unsigned char *)buf, 1, buf_len, fhdr);

	/* create a cf_header.h for test appication */
	create_header_file(buf,buf_len);
	/* clean up */
	free(buf);
	fclose(fsrk_pri);
	fclose(fhdr);
	return 0;
}
