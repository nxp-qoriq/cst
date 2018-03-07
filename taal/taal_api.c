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

#include <global.h>
#include <ta_1_x.h>
#include <ta_2_x.h>
#include <ta_3_x.h>

#define __weak		__attribute__((weak))

/*****************************************************************************
 * Error For Unsupported Platforms
 *****************************************************************************/
static int error_unsupported(void)
{
	printf("\nError !!! ");
	printf("This tool is not applicable for the Platform specified\n");
	return FAILURE;
}

/****************************************************
 * Trust Arch's should override below weak API's
 ****************************************************/

__weak int parse_input_file_ta_1_x_pbl(void) { return (error_unsupported()); }
__weak int parse_input_file_ta_1_x_nonpbl(void) { return (error_unsupported()); }

__weak int fill_structure_ta_1_x_pbl(void) { return (error_unsupported()); }
__weak int fill_structure_ta_1_x_nonpbl(void) { return (error_unsupported()); }

__weak int create_header_ta_1_x_pbl(void) { return (error_unsupported()); }
__weak int create_header_ta_1_x_nonpbl(void) { return (error_unsupported()); }

__weak int calc_img_hash_ta_1_x_pbl(void) { return (error_unsupported()); }
__weak int calc_img_hash_ta_1_x_nonpbl(void) { return (error_unsupported()); }

__weak int calc_srk_hash_ta_1_x_pbl(void) { return (error_unsupported()); }
__weak int calc_srk_hash_ta_1_x_nonpbl(void) { return (error_unsupported()); }

__weak int dump_hdr_ta_1_x_pbl(void) { return (error_unsupported()); }
__weak int dump_hdr_ta_1_x_nonpbl(void) { return (error_unsupported()); }

__weak int parse_input_file_ta_2_0_pbl(void) { return (error_unsupported()); }
__weak int parse_input_file_ta_2_0_nonpbl(void) { return (error_unsupported()); }
__weak int parse_input_file_ta_2_1_arm7(void) { return (error_unsupported()); }
__weak int parse_input_file_ta_2_1_arm8(void) { return (error_unsupported()); }

__weak int fill_structure_ta_2_0_pbl(void) { return (error_unsupported()); }
__weak int fill_structure_ta_2_0_nonpbl(void) { return (error_unsupported()); }
__weak int fill_structure_ta_2_1_arm7(void) { return (error_unsupported()); }
__weak int fill_structure_ta_2_1_arm8(void) { return (error_unsupported()); }

__weak int create_header_ta_2_0_pbl(void) { return (error_unsupported()); }
__weak int create_header_ta_2_0_nonpbl(void) { return (error_unsupported()); }
__weak int create_header_ta_2_1_arm7(void) { return (error_unsupported()); }
__weak int create_header_ta_2_1_arm8(void) { return (error_unsupported()); }

__weak int calc_img_hash_ta_2_0_pbl(void) { return (error_unsupported()); }
__weak int calc_img_hash_ta_2_0_nonpbl(void) { return (error_unsupported()); }
__weak int calc_img_hash_ta_2_1_arm7(void) { return (error_unsupported()); }
__weak int calc_img_hash_ta_2_1_arm8(void) { return (error_unsupported()); }

__weak int calc_srk_hash_ta_2_0_pbl(void) { return (error_unsupported()); }
__weak int calc_srk_hash_ta_2_0_nonpbl(void) { return (error_unsupported()); }
__weak int calc_srk_hash_ta_2_1_arm7(void) { return (error_unsupported()); }
__weak int calc_srk_hash_ta_2_1_arm8(void) { return (error_unsupported()); }

__weak int dump_hdr_ta_2_0_pbl(void) { return (error_unsupported()); }
__weak int dump_hdr_ta_2_0_nonpbl(void) { return (error_unsupported()); }
__weak int dump_hdr_ta_2_1_arm7(void) { return (error_unsupported()); }
__weak int dump_hdr_ta_2_1_arm8(void) { return (error_unsupported()); }

__weak int parse_input_file_ta_3_0(void) { return (error_unsupported()); }
__weak int parse_input_file_ta_3_1(void) { return (error_unsupported()); }

__weak int fill_structure_ta_3_0(void) { return (error_unsupported()); }
__weak int fill_structure_ta_3_1(void) { return (error_unsupported()); }

__weak int create_header_ta_3_0(void) { return (error_unsupported()); }
__weak int create_header_ta_3_1(void) { return (error_unsupported()); }

__weak int calc_img_hash_ta_3_0(void) { return (error_unsupported()); }
__weak int calc_img_hash_ta_3_1(void) { return (error_unsupported()); }

__weak int calc_srk_hash_ta_3_0(void) { return (error_unsupported()); }
__weak int calc_srk_hash_ta_3_1(void) { return (error_unsupported()); }

__weak int dump_hdr_ta_3_0(void) { return (error_unsupported()); }
__weak int dump_hdr_ta_3_1(void) { return (error_unsupported()); }
