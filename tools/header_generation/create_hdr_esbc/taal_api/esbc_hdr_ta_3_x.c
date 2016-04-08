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
#include <esbc_hdr_ta_3_x.h>

extern struct g_data_t gd;
uint8_t barker[] = {0x12, 0x19, 0x20, 0x01};

/****************************************************************************
 * API's for PARSING INPUT FILES
 ****************************************************************************/
static char *parse_list[] = {
	"PUB_KEY",
	"PRI_KEY",
	"KEY_SELECT",
	"IMAGE_1",
	"FSL_UID_0",
	"FSL_UID_1",
	"OEM_UID_0",
	"OEM_UID_1",
	"OEM_UID_2",
	"OEM_UID_3",
	"OEM_UID_4",
	"OUTPUT_HDR_FILENAME",
	"IMAGE_HASH_FILENAME",
	"IE_KEY_SEL",
	"VERBOSE"
};

#define NUM_PARSE_LIST (sizeof(parse_list) / sizeof(char *))

int parse_input_file_ta_3_0(void)
{
	return (parse_input_file(parse_list, NUM_PARSE_LIST));
}

int parse_input_file_ta_3_1(void)
{
	return (parse_input_file(parse_list, NUM_PARSE_LIST));
}

/****************************************************************************
 * API's for Filling STRUCTURES
 ****************************************************************************/
void calculate_offset_size(void)
{
	if (gd.iek_flag == 1) {
		gd.rsa_size = gd.key_len / 2;
		gd.rsa_offset = OFFSET_ALIGN(gd.hdr_size);
		return;
	}

	gd.srk_size = gd.num_srk_entries * sizeof(struct srk_table_t);
	gd.rsa_size = gd.key_table[gd.srk_sel - 1].key_len / 2;

	/* Calculate the offsets of blocks aligne to boundry 0x200 */
	gd.srk_offset = OFFSET_ALIGN(gd.hdr_size);
	gd.rsa_offset = OFFSET_ALIGN(gd.srk_offset + gd.srk_size);
}

uint8_t get_misc_flags(void)
{
	uint8_t flag = 0;

	if (gd.iek_flag == 1)
		flag |= IE_FLAG_MASK;

	return flag;
}

uint8_t get_uid_flags(void)
{
	uint8_t flag = 0;

	if (gd.fsluid_flag[0])
		flag |= FID_MASK;
	if (gd.fsluid_flag[1])
		flag |= FID_MASK;
	if (gd.oemuid_flag[0])
		flag |= OID_0_MASK;
	if (gd.oemuid_flag[1])
		flag |= OID_1_MASK;
	if (gd.oemuid_flag[2])
		flag |= OID_2_MASK;
	if (gd.oemuid_flag[3])
		flag |= OID_3_MASK;
	if (gd.oemuid_flag[4])
		flag |= OID_4_MASK;

	return flag;
}

int fill_structure_ta_3_x(void)
{
	int ret;
	struct esbc_hdr_ta_3_x *hdr = (struct esbc_hdr_ta_3_x *)gd.hdr_struct;
	memset(hdr, 0, sizeof(struct esbc_hdr_ta_3_x));

	/* Get The Image Information from Image_1 */
	ret = get_file_size(gd.entries[0].name);
	if (ret == FAILURE)
		return ret;

	hdr->img_len = ret;
	hdr->img_addr_l = gd.entries[0].addr_low;
	hdr->img_addr_h = gd.entries[0].addr_high;

	/* Calculate Offsets and Size */
	gd.hdr_size = sizeof(struct esbc_hdr_ta_3_x);
	calculate_offset_size();

	/* Pouplate the fields in Header */
	hdr->barker[0] = barker[0];
	hdr->barker[1] = barker[1];
	hdr->barker[2] = barker[2];
	hdr->barker[3] = barker[3];
	if (gd.iek_flag == 0) {
		hdr->srk_table_offset = gd.srk_offset;
		hdr->num_keys = (uint8_t)gd.num_srk_entries;
		hdr->key_num_verify = (uint8_t)gd.srk_sel;
	} else {
		hdr->ie_key_select = gd.iek_sel;
	}
	hdr->psign = gd.rsa_offset;
	hdr->sign_len = gd.rsa_size;
	hdr->fsl_uid[0] = gd.fsluid[0];
	hdr->fsl_uid[1] = gd.fsluid[1];
	hdr->oem_uid[0] = gd.oemuid[0];
	hdr->oem_uid[1] = gd.oemuid[1];
	hdr->oem_uid[2] = gd.oemuid[2];
	hdr->oem_uid[3] = gd.oemuid[3];
	hdr->oem_uid[4] = gd.oemuid[4];

	/* Pouplate the Flags in Header */
	hdr->misc_flags = get_misc_flags();
	hdr->uid_flags = get_uid_flags();

	return SUCCESS;
}

int fill_structure_ta_3_0(void)
{
	return (fill_structure_ta_3_x());
}

int fill_structure_ta_3_1(void)
{
	return (fill_structure_ta_3_x());
}

/****************************************************************************
 * API's for Creating HEADER FILES
 ****************************************************************************/
int create_header_ta_3_x(void)
{
	int ret;
	uint8_t *header;
	FILE *fp;
	uint32_t hdrlen = gd.rsa_offset;

	header = malloc(hdrlen);
	if (header == NULL) {
		printf("Error in allocating memory of %d bytes\n", hdrlen);
		return FAILURE;
	}

	memset(header, 0, hdrlen);

	memcpy(header, gd.hdr_struct, gd.hdr_size);
	if (gd.iek_flag == 0)
		memcpy(header + gd.srk_offset, gd.key_table, gd.srk_size);

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

int create_header_ta_3_0(void)
{
	return (create_header_ta_3_x());
}

int create_header_ta_3_1(void)
{
	return (create_header_ta_3_x());
}

/****************************************************************************
 * API's for Calculating Image Hash
 ****************************************************************************/
int calc_img_hash_ta_3_x(void)
{
	int ret;
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	crypto_hash_init(ctx);

	crypto_hash_update(ctx, gd.hdr_struct, gd.hdr_size);
	if (gd.iek_flag == 0)
		crypto_hash_update(ctx, gd.key_table, gd.srk_size);
	ret = crypto_hash_update_file(ctx, gd.entries[0].name);
	if (ret == FAILURE)
		return ret;

	crypto_hash_final(gd.img_hash, ctx);

	return SUCCESS;
}

int calc_img_hash_ta_3_0(void)
{
	return (calc_img_hash_ta_3_x());
}

int calc_img_hash_ta_3_1(void)
{
	return (calc_img_hash_ta_3_x());
}

/****************************************************************************
 * API's for Calculating SRK Hash
 ****************************************************************************/
static int calc_srk_hash_ta_3_x(uint32_t max_keys)
{
	int ret;
	if (gd.iek_flag == 1) {
		printf("\nSRK/Public Key Hash not calculated.. IE = 1");
		if (gd.num_pri_key > 1) {
			printf("Error !! IE=1, Only 1 Private Key required\n");
			return FAILURE;
		}
		gd.srk_hash_flag = 0;
		gd.srk_flag = 0;
		gd.srk_sel = 1;
		ret = crypto_extract_pub_key(gd.pub_fname[0],
					&gd.key_len,
					gd.key_table[0].pkey);

		return ret;
	}

	gd.srk_flag = 1;
	return (create_srk_calc_hash(max_keys));
}

int calc_srk_hash_ta_3_0(void)
{
	return (calc_srk_hash_ta_3_x(MAX_SRK_TA_3_X));
}

int calc_srk_hash_ta_3_1(void)
{
	return (calc_srk_hash_ta_3_x(MAX_SRK_TA_3_X));
}

/****************************************************************************
 * API's for Dumping Headers
 ****************************************************************************/
int dump_hdr_ta_3_x(void)
{
	int i;
	struct esbc_hdr_ta_3_x *hdr = (struct esbc_hdr_ta_3_x *)gd.hdr_struct;

	printf("\n-----------------------------------------------");
	printf("\n-\tDumping the Header Fields");
	printf("\n-----------------------------------------------");
	if (gd.iek_flag == 1) {
	printf("\n- IE FLAG = 1. No SRK/Public Key");
	printf("\n- \t IE Key Select : %x", hdr->ie_key_select);
	printf("\n- \t IE Key : %s(%x)", gd.pub_fname[0], gd.key_len);
	} else {
	printf("\n- SRK Information");
	printf("\n-\t SRK Offset : %x", hdr->srk_table_offset);
	printf("\n-\t Number of Keys : %x", hdr->num_keys);
	printf("\n-\t Key Select : %x", hdr->key_num_verify);
	printf("\n-\t Key List : ");
	for (i = 0; i < gd.num_srk_entries; i++) {
		printf("\n-\t\tKey%d %s(%x)", i + 1, gd.pub_fname[i],
				gd.key_table[i].key_len);
	}
	}

	printf("\n- UID Information");
	printf("\n-\t UID Flags = %02x", hdr->uid_flags);
	printf("\n-\t FSL UID = %08x_%08x",
			hdr->fsl_uid[0], hdr->fsl_uid[1]);
	for (i = 0; i < 5; i++)
		printf("\n-\t OEM UID%d = %08x", i, hdr->oem_uid[i]);
	printf("\n- FLAGS Information");
	printf("\n-\t MISC Flags = %02x", hdr->misc_flags);
	printf("\n- Image Information");
	printf("\n-\t %s (Size = %08x SRC = %08x_%08x) ",
		gd.entries[0].name, hdr->img_len,
		hdr->img_addr_h, hdr->img_addr_l);
	printf("\n- RSA Signature Information");
	printf("\n-\t RSA Offset : %x", hdr->psign);
	printf("\n-\t RSA Size : %x", hdr->sign_len);
	printf("\n-----------------------------------------------\n");

	return SUCCESS;
}

int dump_hdr_ta_3_0(void)
{
	return (dump_hdr_ta_3_x());
}

int dump_hdr_ta_3_1(void)
{
	return (dump_hdr_ta_3_x());
}
