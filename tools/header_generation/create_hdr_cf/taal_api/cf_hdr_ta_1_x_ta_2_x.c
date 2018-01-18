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

#include <global.h>
#include <parse_utils.h>
#include <crypto_utils.h>
#include <cf_hdr_ta_1_x_ta_2_x.h>

extern struct g_data_t gd;

/****************************************************************************
 * API's for PARSING INPUT FILES
 ****************************************************************************/
static char *parse_list[] = {
	"PUB_KEY",
	"PRI_KEY",
	"KEY_SELECT",
	"OUTPUT_HDR_FILENAME",
	"IMAGE_HASH_FILENAME",
	"ESBC_HDRADDR",
	"IMAGE_TARGET",
	"ESBC_HDRADDR_SEC_IMAGE",
	"VERBOSE"
};

#define NUM_PARSE_LIST (sizeof(parse_list) / sizeof(char *))

int parse_input_file_ta_1_x_nonpbl(void)
{
	int ret;
	gd.hton_flag = 1;
	ret = find_cfw_from_file(gd.input_file);
	if (ret != SUCCESS)
		return ret;
	return (parse_input_file(parse_list, NUM_PARSE_LIST));
}

int parse_input_file_ta_2_0_nonpbl(void)
{
	int ret;
	gd.hton_flag = 1;
	ret = find_cfw_from_file(gd.input_file);
	if (ret != SUCCESS)
		return ret;
	return (parse_input_file(parse_list, NUM_PARSE_LIST));
}

/****************************************************************************
 * API's for Filling STRUCTURES
 ****************************************************************************/
int fill_structure_ta_1_x_nonpbl(void)
{
	struct cf_hdr_legacy *hdr_legacy =
		(struct cf_hdr_legacy *)gd.hdr_struct;

	struct cf_hdr_secure *hdr_secure =
		(struct cf_hdr_secure *)(gd.hdr_struct + SIZE_HDR_LEGACY);

	memset(hdr_legacy, 0, SIZE_HDR_LEGACY);
	memset(hdr_secure, 0, SIZE_HDR_SECURE_TA_1);

	hdr_legacy->boot_sig = htonl(BOOT_SIGNATURE);
	hdr_legacy->no_conf_pairs = htonl(gd.cf_count);

	/* Calculate Offsets and Size */
	gd.hdr_size = SIZE_HDR_SECURE_TA_1;
	gd.rsa_size = gd.key_len / 2;
	gd.srk_offset = OFFSET_ALIGN(SIZE_HDR_LEGACY + SIZE_CF_WORD +
				gd.hdr_size) - SIZE_RESERVED;
	gd.rsa_offset = OFFSET_ALIGN(gd.srk_offset + gd.key_len) -
				SIZE_RESERVED;

	/* Pouplate the fields in Secure Header */
	hdr_secure->ehdrloc = htonl(gd.hdr_addr);
	hdr_secure->esbc_target_id = htonl(gd.img_target);
	hdr_secure->pkey_off = htonl(gd.srk_offset);
	hdr_secure->key_len = htonl(gd.key_len);
	hdr_secure->psign_off = htonl(gd.rsa_offset);
	hdr_secure->sign_len = htonl(gd.rsa_size);
	
	return SUCCESS;
}

int fill_structure_ta_2_0_nonpbl(void)
{
	struct cf_hdr_legacy *hdr_legacy =
		(struct cf_hdr_legacy *)gd.hdr_struct;

	struct cf_hdr_secure *hdr_secure =
		(struct cf_hdr_secure *)(gd.hdr_struct + SIZE_HDR_LEGACY);

	memset(hdr_legacy, 0, SIZE_HDR_LEGACY);
	memset(hdr_secure, 0, SIZE_HDR_SECURE_TA_2);

	hdr_legacy->boot_sig = htonl(BOOT_SIGNATURE);
	hdr_legacy->no_conf_pairs = htonl(gd.cf_count);

	/* Calculate Offsets and Size */
	gd.hdr_size = SIZE_HDR_SECURE_TA_2;
	gd.srk_offset = OFFSET_ALIGN(SIZE_HDR_LEGACY + SIZE_CF_WORD +
				gd.hdr_size) - SIZE_RESERVED;

	if (gd.srk_flag == 0) {
		gd.rsa_offset = OFFSET_ALIGN(gd.srk_offset + gd.key_len) -
				SIZE_RESERVED;
		gd.rsa_size = gd.key_len / 2;
	} else {
		gd.rsa_offset = OFFSET_ALIGN(gd.srk_offset + gd.srk_size) -
				SIZE_RESERVED;
		gd.rsa_size = htonl(gd.key_table[gd.srk_sel - 1].key_len) / 2;
	}

	/* Pouplate the fields in Secure Header */
	hdr_secure->ehdrloc = htonl(gd.hdr_addr);
	hdr_secure->esbc_target_id = htonl(gd.img_target);
	if (gd.srk_flag == 0) {
		hdr_secure->pkey_off = htonl(gd.srk_offset);
		hdr_secure->key_len = htonl(gd.key_len);
	} else {
		hdr_secure->srk_table_offset = htonl(gd.srk_offset);
		/* Set the SRK FLAG in Header */
		hdr_secure->len_kr.srk_sel =
				htons((uint16_t)gd.srk_sel | 0x1000);
		hdr_secure->len_kr.num_srk_entries =
				htons((uint16_t)gd.num_srk_entries);
	}

	hdr_secure->psign_off = htonl(gd.rsa_offset);
	hdr_secure->sign_len = htonl(gd.rsa_size);
	hdr_secure->ehdrloc_simg = htonl(gd.hdr_addr_sec);

	return SUCCESS;
}

/****************************************************************************
 * API's for Creating HEADER FILES
 ****************************************************************************/
int create_header_ta_1_ta_2(void)
{
	int ret;
	uint8_t *header, *sec_hdr;
	FILE *fp;
	uint32_t hdrlen;

	hdrlen = SIZE_RESERVED + gd.rsa_offset;

	header = malloc(hdrlen);
	if (header == NULL) {
		printf("Error in allocating memory of %d bytes\n", hdrlen);
		return FAILURE;
	}

	memset(header, 0, hdrlen);

	memcpy(header + SIZE_RESERVED,
		gd.hdr_struct,
		SIZE_HDR_LEGACY);

	memcpy(header + SIZE_RESERVED + SIZE_HDR_LEGACY,
		gd.cf_word,
		SIZE_CF_WORD);

	sec_hdr = (uint8_t *)(header + SIZE_RESERVED +
			SIZE_HDR_LEGACY + SIZE_CF_WORD);

	memcpy(sec_hdr,
		(gd.hdr_struct + SIZE_HDR_LEGACY),
		gd.hdr_size);

	if (gd.srk_flag == 1)
		memcpy(header + SIZE_RESERVED + gd.srk_offset,
			gd.key_table, gd.srk_size);
	else
		memcpy(header + SIZE_RESERVED + gd.srk_offset,
			gd.pkey, gd.key_len);

	/* Create the header file */
	fp = fopen(gd.hdr_file_name, "wb");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", gd.hdr_file_name);
		free(header);
		return FAILURE;
	}
	ret = fwrite(header, 1, hdrlen, fp);
	fclose(fp);
	free(header);

	if (ret == 0) {
		printf("Error in Writing to file");
		return FAILURE;
	}

	return SUCCESS;
}

int create_header_ta_1_x_nonpbl(void)
{
	return (create_header_ta_1_ta_2());
}

int create_header_ta_2_0_nonpbl(void)
{
	return (create_header_ta_1_ta_2());
}

/****************************************************************************
 * API's for Calculating Image Hash
 ****************************************************************************/
int calc_img_hash_ta_1_ta_2(void)
{
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	crypto_hash_init(ctx);

	crypto_hash_update(ctx, gd.hdr_struct, SIZE_HDR_LEGACY);
	crypto_hash_update(ctx, gd.cf_word, SIZE_CF_WORD);
	crypto_hash_update(ctx, (gd.hdr_struct + SIZE_HDR_LEGACY),
				gd.hdr_size);

	if (gd.srk_flag == 1)
		crypto_hash_update(ctx, gd.key_table, gd.srk_size);
	else
		crypto_hash_update(ctx, gd.pkey, gd.key_len);


	crypto_hash_final(gd.img_hash, ctx);

	return SUCCESS;
}

int calc_img_hash_ta_1_x_nonpbl(void)
{
	return (calc_img_hash_ta_1_ta_2());
}

int calc_img_hash_ta_2_0_nonpbl(void)
{
	return (calc_img_hash_ta_1_ta_2());
}

/****************************************************************************
 * API's for Calculating SRK Hash
 ****************************************************************************/
int calc_srk_hash_ta_1_x_nonpbl(void)
{
	gd.srk_flag = 0;
	if (gd.num_srk_entries > 1) {
		printf("Error !! SRK Table not supported by this SoC\n");
		return FAILURE;
	}
	return (create_srk_calc_hash(1));
}

int calc_srk_hash_ta_2_0_nonpbl(void)
{
	return (create_srk_calc_hash(MAX_SRK_ESBC_X));
}

/****************************************************************************
 * API's for Dumping Headers
 ****************************************************************************/
int dump_hdr_ta_1_ta_2(void)
{
	return SUCCESS;
}

int dump_hdr_ta_1_x_nonpbl(void)
{
	return (dump_hdr_ta_1_ta_2());
}

int dump_hdr_ta_2_0_nonpbl(void)
{
	return (dump_hdr_ta_1_ta_2());
}
