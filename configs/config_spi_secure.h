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
int word_count;

#define MAKE_WORD(ADDR, DATA)\
	words[word_count++] = htonl(ADDR);\
	words[word_count++] = htonl(DATA);

#define ESBC_EP 0x1107F000
#define ESBC_TARGET_ID  0x00000006
#define ESBC_HDRADDR 	0x00001000

struct sg_in {
	char fname[256];
	u32 src_addr;
	u32 dst_addr;
	u32 trgt;
};

void fill_words()
{
	/* DDR config */

	/*DDR_SDRAM_CFG*/
	MAKE_WORD(0xff702110, 0x470C0000);

	/*CS0_BNDS*/
	MAKE_WORD(0xff702000, 0x0000003F);

	/*CS0_CONFIG*/
	MAKE_WORD(0xff702080, 0x80014302);

	/*TIMING_CFG_3*/
	MAKE_WORD(0xff702100, 0x00020000);

	/*TIMING_CFG_0*/
	MAKE_WORD(0xff702104, 0x00330004);

	/*TIMING_CFG_1*/
	MAKE_WORD(0xff702108, 0x6f6B4644);

	/*TIMING_CFG_2*/
	MAKE_WORD(0xff70210C, 0x0FA888CF);

	/*DDR_SDRAM_CFG_2*/
	MAKE_WORD(0xff702114, 0x04401000);

	/*DDR_SDRAM_MODE*/
	MAKE_WORD(0xff702118, 0x40461520);

	/*DDR_SDRAM_MODE_2*/
	MAKE_WORD(0xff70211C, 0x8000c000);

	/*DDR_SDRAM_MD_CNTL*/
	MAKE_WORD(0xff702120, 0x00000000);

	/*DDR_SDRAM_INTERVAL*/
	MAKE_WORD(0xff702124, 0x0C300000);

	/*DDR_DATA_INIT*/
	MAKE_WORD(0xff702128, 0xDEADBEEF);

	/*DDR_SDRAM_CLK_CNTL*/
	MAKE_WORD(0xff702130, 0x03000000);

	/*TIMING_CFG_4*/
	MAKE_WORD(0xff702160, 0x00000001);

	/*TIMING_CFG_5*/
	MAKE_WORD(0xff702164, 0x03402400);

	/*DDR_ZQ_CNTL*/
	MAKE_WORD(0xff702170, 0x89080600);

	/*DDR_WRLVL_CNTL*/
	MAKE_WORD(0xff702174, 0x8655A608);

	/*ERR_INT_EN*/
	MAKE_WORD(0xff702e48, 0x00000000);

	/*DDR_ERR_SBE*/
	MAKE_WORD(0xff702e58, 0x00000000);

	/*DDR_CDR1*/
	MAKE_WORD(0xff702b28, 0x00000000);

	/*DDR_CDR2*/
	MAKE_WORD(0xff702b2c, 0x00000000);

	/* SPI change Frequency */
	MAKE_WORD(0x20000001, 0x02000000);

	/*DDR_SDRAM_CFG*/
	MAKE_WORD(0xff702110, 0xC70C0000);

	/* law0 config */
	MAKE_WORD(0xff700d68, 0x00000000);
	MAKE_WORD(0xff700d70, 0x80f0001d);

	/* delay */
	MAKE_WORD(0x40000001, 0x00000FFF)

	/* ddr test data */
	MAKE_WORD(0x0, 0xAABBCCDD)
	MAKE_WORD(0x4, 0xDEADBEEF)
	MAKE_WORD(0x8, 0x00000000)
	MAKE_WORD(0xC, 0x11111111)

	word_pairs = word_count/2;

	MAKE_WORD(0xefefefef,0x00000000)
}

struct sg_in tbl[] = {
	{ "u-boot.bin", 0x4000, 0x11000000, ESBC_TARGET_ID},
};
#endif

