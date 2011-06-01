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
int word_count = 0;

#define MAKE_WORD(ADDR,DATA)	\
	words[word_count++] = htonl(ADDR);	\
	words[word_count++] = htonl(DATA);


/* if legacy mode is used set the following */
#define LEGACY_USER_CODE_BINARY		"u-boot.bin"	/* legacy user code binary file */
#define LEGACY_USER_CODE_SRC_ADDR	0x0002000	/* Contains the starting address of the user.s code as an offset from the SD/MMCcard/SPIflash  starting address. */
#define LEGACY_USER_CODE_DST_ADDR	0x0200000	/* target address in the system.s local memory address space in which the user.s code is copied to. */
#define LEGACY_USER_CODE_ENTRY_POINT	0x0200000	/* jump address in the system.s local memory address space into the user.s code first instruction to be executed */


void fill_words()
{
	/* ddr config  */
	MAKE_WORD(0xff702000, 0x000000ff);
	MAKE_WORD(0xff702080, 0x80004102);
	MAKE_WORD(0xff702100, 0x00001000);
	MAKE_WORD(0xff702104, 0xff000004);
	MAKE_WORD(0xff702108, 0x7771e134);
	MAKE_WORD(0xff70210c, 0x0228c800);
	MAKE_WORD(0xff702160, 0x44440000);
	MAKE_WORD(0xff702114, 0x04000000);
	MAKE_WORD(0xff702118, 0x00000050); 
	MAKE_WORD(0xff702130, 0x02000000); 
	MAKE_WORD(0xff702170, 0x87070800); 	
	MAKE_WORD(0xff702b20, 0xa2008888);
	MAKE_WORD(0xff702b24, 0x88000000);
	MAKE_WORD(0xff702110, 0xc7280000);

	/* law0 config */
	MAKE_WORD(0xff700c28, 0x00000000);
	MAKE_WORD(0xff700c30, 0x80f0001D);

	/* ddr data */
	MAKE_WORD(0x0,0xAABBCCDD)
	MAKE_WORD(0x4,0xDEADBEEF)
	MAKE_WORD(0x8,0x00000000)
	MAKE_WORD(0xC,0x11111111)

	word_pairs = word_count/2;
}

#endif
