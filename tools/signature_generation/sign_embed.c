/* Copyright (c) 2015 Freescale Semiconductor, Inc.
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <global.h>

static uint32_t get_file_size(const char *c)
{
	FILE *fp;
	unsigned char buf[IOBLOCK];
	uint32_t bytes = 0;

	printf("\n\t#----------------------------------------------------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#------- CST (Code Signing Tool) Version 2.0  -------#");
	printf("\n\t#-------         --------     --------        -------#");
	printf("\n\t#----------------------------------------------------#");
	printf("\n");

	fp = fopen(c, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", c);
		return FAILURE;
	}

	while (!feof(fp)) {
		/* read some data */
		bytes += fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file\n");
			fclose(fp);
			exit(EXIT_FAILURE);
		} else if (feof(fp) && (bytes == 0)) {
			break;
		}
	}

	fclose(fp);
	return bytes;
}

/***************************************************************************
 * Function	:	main
 * Arguments	:	argc - Argument Count
 *			argv - Argumnet List
 * Return	:	SUCCESS or FAILURE
 * Description	:	Main function where execution starts
 ***************************************************************************/
int main(int argc, char **argv)
{
	int ch;
	int i;
	uint32_t len;
	char *hdr_file, *sign_file;
	FILE *fhdr, *fsign;

	/* Check the command line argument */
	if (argc != 3) {
		/* Incorrect Usage */
		printf("\nIncorrect Usage");
		printf("\nCorrect Usage: %s <hdr_file> <sign_file>\n",
			argv[0]);
		return 1;
	} else if ((strcmp(argv[1], "--help") == 0) ||
		   (strcmp(argv[1], "-h") == 0)) {
		/* Command Help */
		printf("\nCorrect Usage: %s <hdr_file> <sign_file>\n",
			argv[0]);
		return 0;
	} else {
		hdr_file = argv[1];
		sign_file = argv[2];
	}

	/* Open the OUTPUT_HDR_FILENAME in 'Append Binary' Mode */
	fhdr = fopen(hdr_file, "ab");
	if (fhdr == NULL) {
		printf("Error in opening the file: %s\n", hdr_file);
		return FAILURE;
	}

	len = get_file_size(sign_file);
	/* Open the RSA_SIGN_FILENAME in 'Read Binary' Mode */
	fsign = fopen(sign_file, "rb");
	if (fsign == NULL) {
		printf("Error in opening the file: %s\n", sign_file);
		fclose(fhdr);
		return FAILURE;
	}

	/* Append the contents of RSA_SIGN_FILENAME to end of
	 * OUTPUT_HDR_FILENAME
	 */
	for (i = 0; i < len; i++) {
		ch = fgetc(fsign);
		if (feof(fsign))
			break;
		fputc(ch, fhdr);
	}

	fclose(fhdr);
	fclose(fsign);

	printf("\n%s is appended with file %s (0x%x)\n\n",
			hdr_file, sign_file, len);
	return 0;
}
