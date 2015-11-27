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

#ifndef _TA_2_X_H_
#define _TA_2_X_H_

/**********************************************************
 * Function Pointers for TAAL
 **********************************************************/
int parse_input_file_ta_2_0_pbl(void);
int parse_input_file_ta_2_0_nonpbl(void);
int parse_input_file_ta_2_1_arm7(void);
int parse_input_file_ta_2_1_arm8(void);

int fill_structure_ta_2_0_pbl(void);
int fill_structure_ta_2_0_nonpbl(void);
int fill_structure_ta_2_1_arm7(void);
int fill_structure_ta_2_1_arm8(void);

int create_header_ta_2_0_pbl(void);
int create_header_ta_2_0_nonpbl(void);
int create_header_ta_2_1_arm7(void);
int create_header_ta_2_1_arm8(void);

int calc_img_hash_ta_2_0_pbl(void);
int calc_img_hash_ta_2_0_nonpbl(void);
int calc_img_hash_ta_2_1_arm7(void);
int calc_img_hash_ta_2_1_arm8(void);

int calc_srk_hash_ta_2_0_pbl(void);
int calc_srk_hash_ta_2_0_nonpbl(void);
int calc_srk_hash_ta_2_1_arm7(void);
int calc_srk_hash_ta_2_1_arm8(void);

int dump_hdr_ta_2_0_pbl(void);
int dump_hdr_ta_2_0_nonpbl(void);
int dump_hdr_ta_2_1_arm7(void);
int dump_hdr_ta_2_1_arm8(void);

#endif
