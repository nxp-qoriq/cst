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
#define POWERPC
#define OPENSSL_NO_KRB5
#include <stdio.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sign_includes.h"
#include "ibr.h"
#include "config_legacy.h"

#define HDR_FILE "cf_hdr_legacy.bin"
FILE *fhdr;

#define BLOCK_SIZE 512

void create_header_file(u8 * buf, int buf_len)
{
	int i=0,sz=0;
	char line1[] = "unsigned char buf[] = { \0";
	char line2[] = "};\0";
	char c = ',';
	char tmp[10];

	FILE *fh;
	fh = fopen("cf_header_legacy.h","w");

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

#define IOBLOCK 256 
int get_file_size (const char *fname)
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

		len += bytes;
	}
	
	fclose(fp);

	return len;
}



int main()
{
	int ret;
	int i, j;
	u8 *tmp;
	/* this buffer is written to the file */
	u8* buf; int buf_len;
	u8* cwds;
	int size_words=0;

	struct cf_hdr_legacy *cfl;

	printf("\n");
	printf("######################################################\n");
	printf("## Generating CFHeader 			            ##\n");
	printf("######################################################\n");
	fill_words();
	
	size_words = sizeof(u32)*2*word_pairs; 
	/* total size of the CFHDR header and its RSA sign, and public key */
	
	buf_len = sizeof(struct cf_hdr_legacy) + size_words;

	buf  = malloc(buf_len);
	if (buf == NULL) {
		fprintf(stderr, 
		"Error in allocating mem of %d bytes \n", buf_len);
		return -1;
	}
	memset(buf, 0, buf_len);

	/* Update the legacy and secure data structures */
	cfl = (struct cf_hdr_legacy *)buf;	
#ifndef POWERPC
	cfl->boot_sig = BOOT_SIG;
	cfl->no_conf_pairs= size_words/8;
	cfl->dst_addr = LEGACY_USER_CODE_DST_ADDR;
	cfl->entry_point = LEGACY_USER_CODE_ENTRY_POINT;

#ifdef BLOCK_ADDRESS_FORMAT
	cfl->code_len = get_file_size(LEGACY_USER_CODE_BINARY)/BLOCK_SIZE;
	cfl->src_addr = LEGACY_USER_CODE_SRC_ADDR / BLOCK_SIZE;
#else
	cfl->code_len = get_file_size(LEGACY_USER_CODE_BINARY);
	cfl->src_addr = LEGACY_USER_CODE_SRC_ADDR;
#endif

#else
	cfl->boot_sig = htonl(BOOT_SIG);
	cfl->no_conf_pairs= htonl(size_words/8);
	cfl->dst_addr = htonl(LEGACY_USER_CODE_DST_ADDR);
	cfl->entry_point = htonl(LEGACY_USER_CODE_ENTRY_POINT);
#ifdef BLOCK_ADDRESS_FORMAT
	cfl->code_len = htonl(get_file_size(LEGACY_USER_CODE_BINARY)/BLOCK_SIZE);
	cfl->src_addr = htonl(LEGACY_USER_CODE_SRC_ADDR/BLOCK_SIZE);
#else
	cfl->code_len = htonl(get_file_size(LEGACY_USER_CODE_BINARY));
	cfl->src_addr = htonl(LEGACY_USER_CODE_SRC_ADDR);
#endif
#endif
	/* Configuration words store */
	cwds = (u8*)buf +  sizeof(struct cf_hdr_legacy);
	memcpy(cwds, (u8*)words, size_words);


        fhdr = fopen(HDR_FILE, "wb");
        if (fhdr == NULL) {
                fprintf(stderr, "Error in opening the file: %s \n",
                        HDR_FILE);
                return -1;
        }
	printf("\n");

		
	char padd[0x40]={0};
	/* write padd */
	fwrite((unsigned char*)padd, 1, 0x40, fhdr);
        /* Concatinating Header,*/
        fwrite((unsigned char *)buf, 1, buf_len, fhdr);

	/* create a cf_header.h for test appication */
	create_header_file(buf,buf_len);
	/* clean up */
	free(buf);
	fclose(fhdr);

	printf (" \n CF header file: %s\n\n", HDR_FILE ); 
	return 0;
}
