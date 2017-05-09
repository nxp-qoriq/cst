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
#include <isbc_hdr_ta_3_x.h>

extern struct g_data_t gd;
static uint8_t barker[] = {0x12, 0x19, 0x20, 0x01};

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
	"OEM_UID_2",
	"OEM_UID_3",
	"OEM_UID_4",
	"OUTPUT_HDR_FILENAME",
	"IMAGE_HASH_FILENAME",
	"MP_FLAG",
	"ISS_FLAG",
	"LW_FLAG",
	"ESBC_HDRADDR",
	"IE_KEY",
	"IE_REVOC",
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
static void calculate_offset_size(void)
{
	gd.srk_size = gd.num_srk_entries * sizeof(struct srk_table_t);
	gd.sg_size = gd.num_entries * sizeof(struct sg_table_t);
	gd.rsa_size = gd.key_table[gd.srk_sel - 1].key_len / 2;

	/* Calculate the offsets of blocks aligne to boundry 0x200 */
	gd.srk_offset = OFFSET_ALIGN(gd.hdr_size);
	gd.sg_offset = OFFSET_ALIGN(gd.srk_offset + gd.srk_size);

	gd.ie_table_offset = OFFSET_ALIGN(gd.sg_offset + gd.sg_size);
	gd.rsa_offset = OFFSET_ALIGN(gd.ie_table_offset + gd.ie_table_size);
}

static uint8_t get_misc_flags(void)
{
	uint8_t flag = 0;

	if (gd.mp_flag)
		flag |= MP_FLAG_MASK;
	if (gd.iss_flag)
		flag |= ISS_FLAG_MASK;
	if (gd.lw_flag)
		flag |= LW_FLAG_MASK;

	/* B01 flag is always set in Boot 1 Header */
	flag |= B01_FLAG_MASK;
	return flag;
}

static uint8_t get_uid_flags(void)
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

int fill_structure_ta_3_0(void)
{
	int ret, i;
	struct isbc_hdr_ta_3_0 *hdr = (struct isbc_hdr_ta_3_0 *)gd.hdr_struct;
	memset(hdr, 0, sizeof(struct isbc_hdr_ta_3_0));

	if(gd.iek_flag == 1) {
		ret = create_ie_file(DEFAULT_IE_FILE_NAME);
		if (ret != SUCCESS)
			return ret;
		gd.ie_table_size = get_file_size(DEFAULT_IE_FILE_NAME);
		gd.num_entries++;
	}

	/* Calculate Offsets and Size */
	gd.hdr_size = sizeof(struct isbc_hdr_ta_3_0);
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
		gd.sg_table[i].len = ret;
		gd.sg_table[i].src_addr_low = gd.entries[i].addr_low;
		gd.sg_table[i].dst_addr = gd.entries[i].dst_addr;
	}

	/* Pouplate the fields in Header */
	hdr->barker[0] = barker[0];
	hdr->barker[1] = barker[1];
	hdr->barker[2] = barker[2];
	hdr->barker[3] = barker[3];
	hdr->srk_table_offset = gd.srk_offset;
	hdr->num_keys = (uint8_t)gd.num_srk_entries;
	hdr->key_num_verify = (uint8_t)gd.srk_sel;
	hdr->psign = gd.rsa_offset;
	hdr->sign_len = gd.rsa_size;
	hdr->sg_table_addr = gd.sg_offset;
	hdr->sg_entries = gd.num_entries;
	hdr->entry_point = gd.entry_addr_low;
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

int fill_structure_ta_3_1(void)
{
	int ret, i;
	struct isbc_hdr_ta_3_1 *hdr = (struct isbc_hdr_ta_3_1 *)gd.hdr_struct;
	memset(hdr, 0, sizeof(struct isbc_hdr_ta_3_0));

	if(gd.iek_flag == 1) {
		ret = create_ie_file(DEFAULT_IE_FILE_NAME);
		if (ret != SUCCESS)
			return ret;
		gd.ie_table_size = get_file_size(DEFAULT_IE_FILE_NAME);
		gd.num_entries++;
	}

	/* Calculate Offsets and Size */
	gd.hdr_size = sizeof(struct isbc_hdr_ta_3_1);
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
		gd.sg_table[i].src_addr_high = gd.entries[i].addr_high;
	}

	/* Pouplate the fields in Header */
	hdr->barker[0] = barker[0];
	hdr->barker[1] = barker[1];
	hdr->barker[2] = barker[2];
	hdr->barker[3] = barker[3];
	hdr->srk_table_offset = gd.srk_offset;
	hdr->num_keys = (uint8_t)gd.num_srk_entries;
	hdr->key_num_verify = (uint8_t)gd.srk_sel;
	hdr->psign = gd.rsa_offset;
	hdr->sign_len = gd.rsa_size;
	hdr->sg_table_addr = gd.sg_offset;
	hdr->sg_entries = gd.num_entries;
	hdr->entry_point_l = gd.entry_addr_low;
	hdr->entry_point_h = gd.entry_addr_high;
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
		ret = FAILURE;
		goto exit;
	}

	memset(header, 0, hdrlen);

	memcpy(header, gd.hdr_struct, gd.hdr_size);
	memcpy(header + gd.srk_offset, gd.key_table, gd.srk_size);
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
	int i, ret;
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	crypto_hash_init(ctx);

	crypto_hash_update(ctx, gd.hdr_struct, gd.hdr_size);
	crypto_hash_update(ctx, gd.key_table, gd.srk_size);
	crypto_hash_update(ctx, gd.sg_table, gd.sg_size);

	for (i = 0; i < gd.num_entries; i++) {
		ret = crypto_hash_update_file(ctx, gd.entries[i].name);
		if (ret == FAILURE)
			return ret;
	}

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
int calc_srk_hash_ta_3_0(void)
{
	gd.srk_flag = 1;
	return (create_srk_calc_hash(MAX_SRK_TA_3_X));
}

int calc_srk_hash_ta_3_1(void)
{
	gd.srk_flag = 1;
	return (create_srk_calc_hash(MAX_SRK_TA_3_X));
}

/****************************************************************************
 * API's for Dumping Headers
 ****************************************************************************/
int dump_hdr_ta_3_0(void)
{
	int i;
	struct isbc_hdr_ta_3_0 *hdr = (struct isbc_hdr_ta_3_0 *)gd.hdr_struct;

	printf("\n-----------------------------------------------");
	printf("\n-\tDumping the Header Fields");
	printf("\n-----------------------------------------------");
	printf("\n- SRK Information");
	printf("\n-\t SRK Offset : %x", hdr->srk_table_offset);
	printf("\n-\t Number of Keys : %x", hdr->num_keys);
	printf("\n-\t Key Select : %x", hdr->key_num_verify);
	printf("\n-\t Key List : ");
	for (i = 0; i < gd.num_srk_entries; i++) {
		printf("\n-\t\tKey%d %s(%x)", i + 1, gd.pub_fname[i],
				gd.key_table[i].key_len);
	}

	printf("\n- UID Information");
	printf("\n-\t UID Flags = %02x", hdr->uid_flags);
	printf("\n-\t FSL UID = %08x_%08x",
			hdr->fsl_uid[0], hdr->fsl_uid[1]);
	for (i = 0; i < 5; i++)
		printf("\n-\t OEM UID%d = %08x", i, hdr->oem_uid[i]);
	printf("\n- FLAGS Information");
	printf("\n-\t MISC Flags = %02x", hdr->misc_flags);
	printf("\n-\t\t ISS = %x", gd.iss_flag);
	printf("\n-\t\t MP = %x", gd.mp_flag);
	printf("\n-\t\t LW = %x", gd.lw_flag);
	printf("\n-\t\t B01 = %x", 1);
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

int dump_hdr_ta_3_1(void)
{
	int i;
	struct isbc_hdr_ta_3_1 *hdr = (struct isbc_hdr_ta_3_1 *)gd.hdr_struct;

	printf("\n-----------------------------------------------");
	printf("\n-\tDumping the Header Fields");
	printf("\n-----------------------------------------------");
	printf("\n- SRK Information");
	printf("\n-\t SRK Offset : %x", hdr->srk_table_offset);
	printf("\n-\t Number of Keys : %x", hdr->num_keys);
	printf("\n-\t Key Select : %x", hdr->key_num_verify);
	printf("\n-\t Key List : ");
	for (i = 0; i < gd.num_srk_entries; i++) {
		printf("\n-\t\tKey%d %s(%x)", i + 1, gd.pub_fname[i],
				gd.key_table[i].key_len);
	}

	printf("\n- UID Information");
	printf("\n-\t UID Flags = %02x", hdr->uid_flags);
	printf("\n-\t FSL UID = %08x_%08x",
			hdr->fsl_uid[0], hdr->fsl_uid[1]);
	for (i = 0; i < 5; i++)
		printf("\n-\t OEM UID%d = %08x", i, hdr->oem_uid[i]);
	printf("\n- FLAGS Information");
	printf("\n-\t MISC Flags = %02x", hdr->misc_flags);
	printf("\n-\t\t ISS = %x", gd.iss_flag);
	printf("\n-\t\t MP = %x", gd.mp_flag);
	printf("\n-\t\t LW = %x", gd.lw_flag);
	printf("\n-\t\t B01 = %x", 1);
	printf("\n- Image Information");
	printf("\n-\t SG Table Offset : %x", hdr->sg_table_addr);
	printf("\n-\t Number of entries : %x", hdr->sg_entries);
	printf("\n-\t Entry Point : %08x_%08x",
			hdr->entry_point_h, hdr->entry_point_l);
	for (i = 0; i < gd.num_entries; i++)
		printf("\n-\t Entry %d : %s (Size = %08x SRC = %08x_%08x) ",
			i + 1, gd.entries[i].name, gd.sg_table[i].len,
			gd.sg_table[i].src_addr_high,
			gd.sg_table[i].src_addr_low);
	printf("\n- RSA Signature Information");
	printf("\n-\t RSA Offset : %x", hdr->psign);
	printf("\n-\t RSA Size : %x", hdr->sign_len);
	printf("\n-----------------------------------------------\n");

	return SUCCESS;
}
