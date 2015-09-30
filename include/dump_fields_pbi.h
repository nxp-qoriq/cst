/** @file
 * dump_fields.h
 */

/* Copyright (c) 2011,2012 Freescale Semiconductor, Inc.
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

#ifndef __DUMP_FIELDS_H__
#define __DUMP_FIELDS_H__

#include "common.h"
#include "uni_sign.h"

static void printsrkhash(u8 *addr, uint32_t num_srk_entries)
{
	SHA256_CTX key_ctx;
	u32 hash[SHA256_DIGEST_LENGTH / 4];
	int i;

	SHA256_Init(&key_ctx);
	SHA256_Update(&key_ctx, addr,
			      num_srk_entries * sizeof(struct srk_table));

	SHA256_Final((u8 *)hash, &key_ctx);
	printf("\n");
	printf("Key Hash :\n");
	for (i = 0; i < SHA256_DIGEST_LENGTH / 4; i++)
		printf("%08x", (hash[i]));
	printf("\n\n");
}

static void usage(void)
{
		printf("\nThis script signs the files and generates the header"
		       " as understood by ");
		printf("ISBC/ESBC with signature embedded in it.\n");
		printf("For format of header generated refer to the "
			"User Document.\n");
		printf("\nUsage :\n");
		printf("./uni_sign [options] INPUT_FILE\n");

		printf("--verbose \t");
		printf("Generate output header alongwith displays the"
		       " headerinfo. Dumps signature in sign.out file.\n");

		printf("--hash \t\t");
		printf("Print the hash of public key(srk table) as specified"
		       " in input file.\n");

		printf("--help\t\t");
		printf("Show this help message and exit.\n");

		printf("INPUT_FILE\tRefer Default input_file and provide all"
		       " the input in the file for header generation .\n");
}
#endif
