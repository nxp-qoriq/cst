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
#include <isbc_hdr_ta_2_x.h>

extern struct g_data_t gd;
static uint8_t barker[] = {0x68, 0x39, 0x27, 0x81};

/****************************************************************************
 * API's for PARSING INPUT FILES
 ****************************************************************************/
static char *parse_list[] = {
	"ENTRY_POINT",
	"PUB_KEY",
	"PRI_KEY",
	"KEY_SELECT",
	"IMAGE_1",
	"IMAGE_2",
	"IMAGE_3",
	"IMAGE_4",
	"IMAGE_5",
	"IMAGE_6",
	"IMAGE_7",
	"IMAGE_8",
	"FSL_UID_0",
	"FSL_UID_1",
	"OEM_UID_0",
	"OEM_UID_1",
	"OUTPUT_HDR_FILENAME",
	"IMAGE_HASH_FILENAME",
	"MP_FLAG",
	"SEC_IMAGE",
	"WP_FLAG",
	"HK_AREA_POINTER",
	"HK_AREA_SIZE",
	"IMAGE_TARGET",
	"ESBC_HDRADDR",
	"IE_KEY",
	"IE_REVOC",
	"VERBOSE"
};

#define NUM_PARSE_LIST (sizeof(parse_list) / sizeof(char *))

int parse_input_file_ta_2_0_pbl(void)
{
	gd.hton_flag = 1;
	return (parse_input_file(parse_list, NUM_PARSE_LIST));
}

int parse_input_file_ta_2_0_nonpbl(void)
{
	gd.hton_flag = 1;
	return (parse_input_file(parse_list, NUM_PARSE_LIST));
}

int parse_input_file_ta_2_1_arm7(void)
{
	return (parse_input_file(parse_list, NUM_PARSE_LIST));
}

int parse_input_file_ta_2_1_arm8(void)
{
	return (parse_input_file(parse_list, NUM_PARSE_LIST));
}

/****************************************************************************
 * API's for Filling STRUCTURES
 ****************************************************************************/
static void calculate_offset_size(void)
{
	uint32_t key_len;

	gd.sg_size = gd.num_entries * sizeof(struct sg_table_t);

	if (gd.hton_flag == 0)
		key_len = gd.key_table[gd.srk_sel - 1].key_len;
	else
		key_len = htonl(gd.key_table[gd.srk_sel - 1].key_len);

	gd.rsa_size = key_len / 2;

	/* Calculate the offsets of blocks aligne to boundry 0x200 */
	gd.srk_offset = OFFSET_ALIGN(gd.hdr_size);
	if (gd.srk_flag == 1)
		gd.sg_offset = OFFSET_ALIGN(gd.srk_offset + gd.srk_size);
	else
		gd.sg_offset = OFFSET_ALIGN(gd.srk_offset + gd.key_len);

	gd.ie_table_offset = OFFSET_ALIGN(gd.sg_offset + gd.sg_size);
	gd.rsa_offset = OFFSET_ALIGN(gd.ie_table_offset + gd.ie_table_size);
}

static uint16_t get_uid_flags(void)
{
	uint8_t fsluid = 0;
	uint8_t oemuid = 0;

	if ((gd.fsluid_flag[0]) || (gd.fsluid_flag[1]))
		fsluid = 1;

	if ((gd.oemuid_flag[0]) || (gd.oemuid_flag[1]))
		oemuid = 1;

	if ((fsluid == 1) && (oemuid == 1))
		return 0x1;

	if (oemuid == 1)
		return 0x2;

	if (fsluid == 1)
		return 0x4;

	return 0;
}

int fill_structure_ta_2_0(void)
{
	int ret, i;
	struct isbc_hdr_ta_2_0 *hdr = (struct isbc_hdr_ta_2_0 *)gd.hdr_struct;
	memset(hdr, 0, sizeof(struct isbc_hdr_ta_2_0));

	if(gd.iek_flag == 1) {
		ret = create_ie_file(DEFAULT_IE_FILE_NAME);
		if (ret != SUCCESS)
			return ret;
		gd.ie_table_size = get_file_size(DEFAULT_IE_FILE_NAME);
		gd.num_entries++;
	}

	/* Calculate Offsets and Size */
	gd.hdr_size = sizeof(struct isbc_hdr_ta_2_0);
	calculate_offset_size();
	
	if(gd.iek_flag == 1) {
		/* Shift the SG Entries as First entry would be IEK Table */
		for (i = 0; i < gd.num_entries - 1; i++)
			gd.entries[i + 1] = gd.entries[i];

		strcpy(gd.entries[0].name, DEFAULT_IE_FILE_NAME);
		if (gd.hdr_addr == 0) {
			printf("Error !!! Header Address not specified"
				" though IE enabled\n");
			return FAILURE;
		}
		/* IE Table is first entry in SG Table */
		gd.entries[0].addr_high = 0;
		gd.entries[0].addr_low = gd.hdr_addr + gd.ie_table_offset;
		gd.entries[0].dst_addr = 0xFFFFFFFF;
	}

	/* Create the SG Table */
	for (i = 0; i < gd.num_entries; i++) {
		ret = get_file_size(gd.entries[i].name);
		if (ret == FAILURE)
			return ret;
		gd.sg_table[i].len = htonl(ret);
		gd.sg_table[i].target = htonl(gd.img_target);
		gd.sg_table[i].src_addr_low = htonl(gd.entries[i].addr_low);
		gd.sg_table[i].dst_addr = htonl(gd.entries[i].dst_addr);
	}

	/* Pouplate the fields in Header */
	hdr->barker[0] = barker[0];
	hdr->barker[1] = barker[1];
	hdr->barker[2] = barker[2];
	hdr->barker[3] = barker[3];
	if (gd.srk_flag == 1) {
		hdr->srk_table_offset = htonl(gd.srk_offset);
		hdr->len_kr.num_keys = htons((uint16_t)gd.num_srk_entries);
		hdr->len_kr.key_num_verify = (uint8_t)(gd.srk_sel);
		hdr->len_kr.srk_table_flag = gd.srk_flag;
	} else {
		hdr->key_len = htonl(gd.key_len);
		hdr->pkey = htonl(gd.srk_offset);
	}
	hdr->psign = htonl(gd.rsa_offset);
	hdr->sign_len = htonl(gd.rsa_size);
	hdr->sg_table_addr = htonl(gd.sg_offset);
	hdr->sg_entries = htonl(gd.num_entries);
	hdr->entry_point = htonl(gd.entry_addr_low);
	hdr->fsl_uid_0 = htonl(gd.fsluid[0]);
	hdr->oem_uid_0 = htonl(gd.oemuid[0]);
	hdr->hkarea = htonl(gd.hkarea);
	hdr->hksize = htonl(gd.hksize);

	/* Pouplate the Flags in Header */
	hdr->uid_n_wp.uid_flag = htons(get_uid_flags());
	hdr->uid_n_wp.sec_image_flag = gd.sec_image_flag;
	hdr->uid_n_wp.sfp_wp = gd.wp_flag;

	return SUCCESS;
}

int fill_structure_ta_2_0_pbl(void)
{
	return (fill_structure_ta_2_0());
}

int fill_structure_ta_2_0_nonpbl(void)
{
	return (fill_structure_ta_2_0());
}

int fill_structure_ta_2_1(void)
{
	int ret, i;
	struct isbc_hdr_ta_2_1 *hdr = (struct isbc_hdr_ta_2_1 *)gd.hdr_struct;
	memset(hdr, 0, sizeof(struct isbc_hdr_ta_2_1));

	if(gd.iek_flag == 1) {
		ret = create_ie_file(DEFAULT_IE_FILE_NAME);
		if (ret != SUCCESS)
			return ret;
		gd.ie_table_size = get_file_size(DEFAULT_IE_FILE_NAME);
		gd.num_entries++;
	}

	/* Calculate Offsets and Size */
	gd.hdr_size = sizeof(struct isbc_hdr_ta_2_1);
	calculate_offset_size();
	
	if(gd.iek_flag == 1) {
		/* Shift the SG Entries as First entry would be IEK Table */
		for (i = 0; i < gd.num_entries - 1; i++)
			gd.entries[i + 1] = gd.entries[i];

		strcpy(gd.entries[0].name, DEFAULT_IE_FILE_NAME);
		gd.entries[0].addr_high = 0;
		gd.entries[0].addr_low = gd.hdr_addr + gd.ie_table_offset;
		gd.entries[0].dst_addr = 0xFFFFFFFF;
	}

	/* Create the SG Table */
	for (i = 0; i < gd.num_entries; i++) {
		ret = get_file_size(gd.entries[i].name);
		if (ret == FAILURE)
			return ret;
		gd.sg_table[i].len = ret;
		gd.sg_table[i].src_addr_low = gd.entries[i].addr_low;
		gd.sg_table[i].dst_addr = gd.entries[i].dst_addr;
	}

	/* Pouplate the fields in Header */
	hdr->barker[0] = barker[0];
	hdr->barker[1] = barker[1];
	hdr->barker[2] = barker[2];
	hdr->barker[3] = barker[3];
	if (gd.srk_flag == 1) {
		hdr->srk_table_offset = gd.srk_offset;
		hdr->len_kr.num_keys = gd.num_srk_entries;
		hdr->len_kr.key_num_verify = gd.srk_sel;
		hdr->len_kr.srk_table_flag = gd.srk_flag;
	} else {
		hdr->key_len = gd.key_len;
		hdr->pkey = gd.srk_offset;
	}
	hdr->psign = gd.rsa_offset;
	hdr->sign_len = gd.rsa_size;
	hdr->sg_table_addr = gd.sg_offset;
	hdr->sg_entries = gd.num_entries;
	hdr->entry_point = gd.entry_addr_low;
	hdr->fsl_uid_0 = gd.fsluid[0];
	hdr->fsl_uid_1 = gd.fsluid[1];
	hdr->oem_uid_0 = gd.oemuid[0];
	hdr->oem_uid_1 = gd.oemuid[1];

	/* Pouplate the Flags in Header */
	hdr->uid_n_wp.uid_flag = get_uid_flags();
	hdr->uid_n_wp.sec_image_flag = gd.sec_image_flag;
	hdr->uid_n_wp.sfp_wp = gd.wp_flag;
	hdr->mp_n_sg_flag.mp_flag = gd.mp_flag;

	return SUCCESS;
}

int fill_structure_ta_2_1_arm7(void)
{
	return (fill_structure_ta_2_1());
}

int fill_structure_ta_2_1_arm8(void)
{
	return (fill_structure_ta_2_1());
}

/****************************************************************************
 * API's for Creating HEADER FILES
 ****************************************************************************/
int create_header_ta_2_x(void)
{
	int ret;
	uint8_t *header;
	FILE *fp;
	uint32_t hdrlen = gd.rsa_offset;

	header = malloc(hdrlen);
	if (header == NULL) {
		printf("Error in allocating memory of %d bytes\n", hdrlen);
		ret = FAILURE;
		goto exit;
	}

	memset(header, 0, hdrlen);

	memcpy(header, gd.hdr_struct, gd.hdr_size);
	if (gd.srk_flag == 1)
		memcpy(header + gd.srk_offset, gd.key_table, gd.srk_size);
	else
		memcpy(header + gd.srk_offset, gd.pkey, gd.key_len);
	memcpy(header + gd.sg_offset, gd.sg_table, gd.sg_size);

	if(gd.iek_flag == 1) {
		ret = read_file_in_buffer(header + gd.ie_table_offset,
					  gd.entries[0].name);
		if (ret != SUCCESS)
			goto exit;
	}

	/* Create the header file */
	fp = fopen(gd.hdr_file_name, "wb");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", gd.hdr_file_name);
		ret = FAILURE;
		goto exit;
	}
	ret = fwrite(header, 1, hdrlen, fp);
	fclose(fp);

	if (ret == 0) {
		printf("Error in Writing to file");
		ret = FAILURE;
		goto exit;
	}
	ret = SUCCESS;
exit:
	free(header);
	return ret;
}

int create_header_ta_2_0_pbl(void)
{
	return (create_header_ta_2_x());
}

int create_header_ta_2_0_nonpbl(void)
{
	return (create_header_ta_2_x());
}

int create_header_ta_2_1_arm7(void)
{
	return (create_header_ta_2_x());
}

int create_header_ta_2_1_arm8(void)
{
	return (create_header_ta_2_x());
}

/****************************************************************************
 * API's for Calculating Image Hash
 ****************************************************************************/
int calc_img_hash_ta_2_x(void)
{
	int i, ret;
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	crypto_hash_init(ctx);

	crypto_hash_update(ctx, gd.hdr_struct, gd.hdr_size);
	if (gd.srk_flag == 1)
		crypto_hash_update(ctx, gd.key_table, gd.srk_size);
	else
		crypto_hash_update(ctx, gd.pkey, gd.key_len);
	crypto_hash_update(ctx, gd.sg_table, gd.sg_size);

	for (i = 0; i < gd.num_entries; i++) {
		ret = crypto_hash_update_file(ctx, gd.entries[i].name);
		if (ret == FAILURE)
			return ret;
	}

	crypto_hash_final(gd.img_hash, ctx);

	return SUCCESS;
}

int calc_img_hash_ta_2_0_pbl(void)
{
	return (calc_img_hash_ta_2_x());
}

int calc_img_hash_ta_2_0_nonpbl(void)
{
	return (calc_img_hash_ta_2_x());
}

int calc_img_hash_ta_2_1_arm7(void)
{
	return (calc_img_hash_ta_2_x());
}

int calc_img_hash_ta_2_1_arm8(void)
{
	return (calc_img_hash_ta_2_x());
}

/****************************************************************************
 * API's for Calculating SRK Hash
 ****************************************************************************/
int calc_srk_hash_ta_2_0_pbl(void)
{
	return (create_srk_calc_hash(MAX_SRK_TA_2_X));
}

int calc_srk_hash_ta_2_0_nonpbl(void)
{
	return (create_srk_calc_hash(MAX_SRK_TA_2_X));
}

int calc_srk_hash_ta_2_1_arm7(void)
{
	return (create_srk_calc_hash(MAX_SRK_TA_2_X));
}

int calc_srk_hash_ta_2_1_arm8(void)
{
	return (create_srk_calc_hash(MAX_SRK_TA_2_X));
}

/****************************************************************************
 * API's for Dumping Headers
 ****************************************************************************/
int dump_hdr_ta_2_0(void)
{
	int i;
	struct isbc_hdr_ta_2_0 *hdr = (struct isbc_hdr_ta_2_0 *)gd.hdr_struct;

	printf("\n-----------------------------------------------");
	printf("\n-\tDumping the Header Fields");
	printf("\n-----------------------------------------------");
	printf("\n- SRK Information");
	printf("\n-\t SRK/Public Key Offset : %x",
		htonl(hdr->srk_table_offset));
	printf("\n-\t SRK Flag = %x", hdr->len_kr.srk_table_flag);
	if (hdr->len_kr.srk_table_flag) {
		printf("\n-\t Number of Keys : %x",
			htons((uint16_t)hdr->len_kr.num_keys));
		printf("\n-\t Key Select : %x",
			hdr->len_kr.key_num_verify);
		printf("\n-\t Key List : ");
		for (i = 0; i < gd.num_srk_entries; i++) {
			printf("\n-\t\tKey%d %s(%x)", i + 1, gd.pub_fname[i],
				htonl(gd.key_table[i].key_len));
		}
	} else {
		printf("\n-\t Single Key: %s(%x)", gd.pub_fname[0],
			htonl(gd.key_table[0].key_len));
	}

	printf("\n- UID Information");
	printf("\n-\t UID Flags = %02x", htons((uint16_t)hdr->uid_n_wp.uid_flag));
	printf("\n-\t FSL UID = %08x", htonl(hdr->fsl_uid_0));
	printf("\n-\t OEM UID = %08x", htonl(hdr->oem_uid_0));
	printf("\n- FLAGS Information");
	printf("\n-\t Secondary Image = %x", hdr->uid_n_wp.sec_image_flag);
	printf("\n- Image Information");
	printf("\n-\t SG Table Offset : %x", htonl(hdr->sg_table_addr));
	printf("\n-\t Number of entries : %x", htonl(hdr->sg_entries));
	printf("\n-\t Entry Point : %08x", htonl(hdr->entry_point));
	for (i = 0; i < gd.num_entries; i++)
		printf("\n-\t Entry %d : %s (Size = %08x SRC = %08x DST = %08x) ",
			i + 1, gd.entries[i].name, htonl(gd.sg_table[i].len),
			htonl(gd.sg_table[i].src_addr_low),
			htonl(gd.sg_table[i].dst_addr));
	printf("\n- RSA Signature Information");
	printf("\n-\t RSA Offset : %x", htonl(hdr->psign));
	printf("\n-\t RSA Size : %x", htonl(hdr->sign_len));
	printf("\n-----------------------------------------------\n");

	return SUCCESS;
}

int dump_hdr_ta_2_0_pbl(void)
{
	return (dump_hdr_ta_2_0());
}

int dump_hdr_ta_2_0_nonpbl(void)
{
	return (dump_hdr_ta_2_0());
}

int dump_hdr_ta_2_1(void)
{
	int i;
	struct isbc_hdr_ta_2_1 *hdr = (struct isbc_hdr_ta_2_1 *)gd.hdr_struct;

	printf("\n-----------------------------------------------");
	printf("\n-\tDumping the Header Fields");
	printf("\n-----------------------------------------------");
	printf("\n- SRK Information");
	printf("\n-\t SRK Offset : %x", hdr->srk_table_offset);
	printf("\n-\t SRK Flag = %x", hdr->len_kr.srk_table_flag);
	if (hdr->len_kr.srk_table_flag) {
		printf("\n-\t Number of Keys : %x", hdr->len_kr.num_keys);
		printf("\n-\t Key Select : %x", hdr->len_kr.key_num_verify);
		printf("\n-\t Key List : ");
		for (i = 0; i < gd.num_srk_entries; i++) {
			printf("\n-\t\tKey%d %s(%x)", i + 1, gd.pub_fname[i],
				gd.key_table[i].key_len);
		}
	} else {
		printf("\n-\t Single Key: %s(%x)", gd.pub_fname[0],
			gd.key_table[0].key_len);
	}

	printf("\n- UID Information");
	printf("\n-\t UID Flags = %02x", hdr->uid_n_wp.uid_flag);
	printf("\n-\t FSL UID = %08x_%08x",
			hdr->fsl_uid_0, hdr->fsl_uid_1);
	printf("\n-\t OEM UID = %08x_%08x",
			hdr->oem_uid_0, hdr->oem_uid_1);
	printf("\n- FLAGS Information");
	printf("\n-\t Secondary Image = %x", hdr->uid_n_wp.sec_image_flag);
	printf("\n-\t Manufacturing Protection = %x",
			hdr->mp_n_sg_flag.mp_flag);
	printf("\n- Image Information");
	printf("\n-\t SG Table Offset : %x", hdr->sg_table_addr);
	printf("\n-\t Number of entries : %x", hdr->sg_entries);
	printf("\n-\t Entry Point : %08x", hdr->entry_point);
	for (i = 0; i < gd.num_entries; i++)
		printf("\n-\t Entry %d : %s (Size = %08x SRC = %08x DST = %08x) ",
			i + 1, gd.entries[i].name, gd.sg_table[i].len,
			gd.sg_table[i].src_addr_low, gd.sg_table[i].dst_addr);
	printf("\n- RSA Signature Information");
	printf("\n-\t RSA Offset : %x", hdr->psign);
	printf("\n-\t RSA Size : %x", hdr->sign_len);
	printf("\n-----------------------------------------------\n");

	return SUCCESS;
}

int dump_hdr_ta_2_1_arm7(void)
{
	return (dump_hdr_ta_2_1());
}

int dump_hdr_ta_2_1_arm8(void)
{
	return (dump_hdr_ta_2_1());
}
