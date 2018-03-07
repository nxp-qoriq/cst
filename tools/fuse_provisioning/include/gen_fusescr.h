/*
 * Copyright 2018 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the above-listed copyright holders nor the
 *     names of any contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _GEN_FUSESCR_H_
#define _GEN_FUSESCR_H_

/**********************************************************
 * HEADER Structures
 **********************************************************/
struct fuse_hdr_t {
	uint8_t barker[BARKER_LEN];	/* 0x00 Barker code */
	uint32_t flags;			/* 0x04 Script flags */
	uint32_t povdd_gpio;		/* 0x08 GPIO for POVDD */

	uint32_t otpmk[8];		/* 0x0C-0x2B OTPMK */
	uint32_t srkh[8];		/* 0x2C-0x4B SRKH */

	uint32_t oem_uid[5];		/* 0x4C-0x5F OEM unique id's */

	uint32_t dcv[2];		/* 0x60-0x67 Debug Challenge */
	uint32_t drv[2];		/* 0x68-0x6F Debug Response */

	uint32_t ospr1;			/* 0x70 OSPR1 */
	uint32_t sc;			/* 0x74 OSPR0 (System Configuration) */

	uint32_t reserved[2];		/* 0x78-0x7F Reserved */
};
#endif
