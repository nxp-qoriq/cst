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

#define HDR_OUT		"hdr_new.out"

static void usage_sign_embed(void)
{
	printf("\n./sign_embed [option] HDR_FILE SIGN_FILE\n\n"
	       "--trust_arch TRUST_ARCH\tTRUST_ARCH is the value of\n\t\t\t"
	       "trust arch of the platform.Only LS2 users need to\n\t\t\t"
	       "provide its value as 3 for other platforms its default\n\t\t\t"
	       "value as 1 would be suffice.\n\n"
	       "--hdr_file HDR_OUT\tHDR_OUT is the output file \n\t\t\t"
	       "generated, its default value is hdr_new.out.\n\t\t\t"
	       "HDR_OUT is generated embedding signature from\n\t\t\t"
	       "SIGN_FILE in HDR_FILE generated using --img_hash\n\t\t\t"
	       "option.\n\n");

	printf("HDR_FILE: name of header file in which signature needs to"
	       " be embed.\n");
	printf("SIGN_FILE: name of sign file containing signature which needs"
	       " to be embed.\n\n");

	printf("--help\t\t\t");
	printf("Show this help message and exit.\n");
	exit(1);
}

void sign_embed(char *hdr_file, char *sign_file, char *hdr_out,
		uint32_t trust_arch)
{
	FILE *hdr_ptr;
	FILE *sign_ptr;
	FILE *new_hdr_ptr;
	unsigned char *buf;
	struct img_hdr *img_hdr;
	struct img_hdr_ls2 *img_hdr_ls2;
	u32 sign_size, sign_offset, fsize, fhdr_size;

	img_hdr = (struct img_hdr *)malloc(sizeof(struct img_hdr));
	img_hdr_ls2 = (struct img_hdr_ls2 *)malloc(sizeof(struct img_hdr_ls2));

	hdr_ptr = fopen(hdr_file, "rb");
	if (hdr_ptr == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", hdr_file);
		exit(1);
	}

	/* extract signature pointer, barker and signature size from header*/
	if (trust_arch == 1 || trust_arch == 2) {
		fread((unsigned char *)img_hdr, 1, sizeof(struct img_hdr),
		      hdr_ptr);
		sign_offset = BYTE_ORDER_L(img_hdr->psign);
		sign_size = BYTE_ORDER_L(img_hdr->sign_len);

		/* Barker checking to validate header file passed to
		 * embed signature.*/
		u8 barker[BARKER_LEN] = {0x68, 0x39, 0x27, 0x81};
		if (!(img_hdr->barker[0] == barker[0] &&
		    img_hdr->barker[1] == barker[1] &&
		    img_hdr->barker[2] == barker[2] &&
		    img_hdr->barker[3] == barker[3])) {
			printf("Error.Invalid HDR_FILE. Barker Failure\n");
			exit(1);
		}
	} else if (trust_arch == '3') {
		fread((unsigned char *)img_hdr_ls2, 1,
		      sizeof(struct img_hdr_ls2), hdr_ptr);
		sign_offset = BYTE_ORDER_L(img_hdr_ls2->psign);
		sign_size = BYTE_ORDER_L(img_hdr_ls2->sign_len);

		/* Barker checking to validate header file passed to
		 * embed signature.*/
		u8 barker[BARKER_LEN] = {0x12, 0x19, 0x20, 0x01};
		if (!(img_hdr->barker[0] == barker[0] &&
		    img_hdr->barker[1] == barker[1] &&
		    img_hdr->barker[2] == barker[2] &&
		    img_hdr->barker[3] == barker[3])) {
			printf("Error.Invalid HDR_FILE. Barker Failure\n");
			exit(1);
		}
	} else {
		printf("Error.Invalid Usage. See help\n");
		usage_sign_embed();
	}

	sign_ptr = fopen(sign_file, "rb");
	if (sign_ptr == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", sign_file);
		exit(1);
	}

	new_hdr_ptr = fopen(hdr_out, "wb");
	if (new_hdr_ptr == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", hdr_out);
		exit(1);
	}

	fseek(sign_ptr, 0, SEEK_END);
	fsize = ftell(sign_ptr);

	fseek(hdr_ptr, 0, SEEK_END);
	fhdr_size = ftell(hdr_ptr);

	if (fsize != sign_size) {
		printf("Error.Input signature file size is not compatible"
		       " with the size of signature in header\n");
		exit(1);
	}

	/* Create new header file with embedding signature in it*/
	/* Set pointers to start of file*/
	fseek(hdr_ptr, 0, SEEK_SET);
	fseek(sign_ptr, 0, SEEK_SET);
	fseek(new_hdr_ptr, 0, SEEK_SET);

	buf = (unsigned char *)malloc(fhdr_size + 1);

	/* Copy header from input header till signature offset*/
	fread((unsigned char *)buf, 1, sign_offset, hdr_ptr);
	fwrite((unsigned char *)buf, 1, sign_offset, new_hdr_ptr);

	/* Copy signature from input signature till signature size*/
	fread((unsigned char *)buf, 1, sign_size, sign_ptr);
	fwrite((unsigned char *)buf, 1, sign_size, new_hdr_ptr);
	fseek(hdr_ptr, sign_size, SEEK_CUR);

	/* Copy header from input header from signature offset + sign_size
	 * till end of header.
	 * */
	if (fhdr_size > (sign_offset + sign_size)) {
		fread((unsigned char *)buf, 1,
		      fhdr_size - (sign_offset + sign_size), hdr_ptr);
		fwrite((unsigned char *)buf, 1,
		       fhdr_size - (sign_offset + sign_size), new_hdr_ptr);
	}

	fclose(hdr_ptr);
	fclose(sign_ptr);
	fclose(new_hdr_ptr);
	free(buf);
	free(img_hdr);
	free(img_hdr_ls2);
	printf("HEADER file %s created\n", hdr_out);
	exit(1);
}

int main(int argc, char **argv)
{
	int c, req_args;
	int hdr_out_flag = 0;
	int trust_arch_flag = 0;
	static int help_flag;
	char *hdr_out = HDR_OUT;
	uint32_t trust_arch = 1;

	while (1) {
		static struct option long_options[] = {
			{"help", no_argument, &help_flag, 1},
			{"hdr_file", required_argument, 0, 'h'},
			{"trust_arch", required_argument, 0, 't'},
			{0, 0, 0, 0}
		};
		int option_index = 0;

		c = getopt_long(argc, argv, "h:t:",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		if (c == 'h') {
			hdr_out_flag = 1;
			hdr_out = optarg;
		}

		if (c == 't') {
			trust_arch_flag = 1;
			trust_arch = STR_TO_UL(optarg, 0, 16);
		}
	}

	/* check if help is called*/
	if (help_flag == 1)
		usage_sign_embed();

	/* Error checking for required input file*/
	req_args = 4;
	if (hdr_out_flag)
		req_args = req_args + 2;

	if (trust_arch_flag)
		req_args = req_args + 2;

	if (argc != req_args) {
		printf("Error.Inavlid Usage. With --sign_embed option"
			" only header file and signature file are"
			" mandatory arguments.\n");
		usage_sign_embed();
	} else {
		sign_embed(argv[optind], argv[optind + 1],
			   hdr_out, trust_arch);
	}

	exit(1);

}
