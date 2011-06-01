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

#ifndef _WORDS_H
#define _WORDS_H
#include <netinet/in.h>
u32 words[1024];
u32 word_pairs;
int cnt=0;
#define MAKE_WORD(ADDR,DATA)	\
	words[cnt++] = htonl(ADDR);	\
	words[cnt++] = htonl(DATA);

#define ESBC_EP 0xcffffffc
#define ESBC_TARGET_ID  0x0000000f
#define ESBC_HDRADDR 	0xce001000

struct sg_in {
	char fname[256];
	u32 src_addr;
	u32 dst_addr;
	u32 trgt;
};


void fill_words()
{
	MAKE_WORD(0xff700c08 , 0x000ce000)
	MAKE_WORD(0xff700c10 , 0x80400018)
	
	word_pairs = cnt/2;
}

struct sg_in tbl[] = {
	{ "u-boot.bin", 0xcff80000, 0xffffffff, 0xf} ,
};



#endif

