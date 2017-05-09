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
#include <isbc_hdr_ta_1_x.h>

extern struct g_data_t gd;
static uint8_t barker[] = {0x68, 0x39, 0x27, 0x81};

/****************************************************************************
 * API's for PARSING INPUT FILES
 ****************************************************************************/
static char *parse_list[] = {
	"ENTRY_POINT",
	"PUB_KEY",
	"PRI_KEY",
	"IMAGE_1",
	"IMAGE_2",
	"IMAGE_3",
	"IMAGE_4",
	"IMAGE_5",
	"IMAGE_6",
	"IMAGE_7",
	"IMAGE_8",
	"FSL_UID_0",
	"OEM_UID_0",
	"OUTPUT_HDR_FILENAME",
	"IMAGE_HASH_FILENAME",
	"IMAGE_TARGET",
	"OUTPUT_SG_BIN",
	"SG_TABLE_ADDR",
	"ESBC_HDRADDR",
	"IE_KEY",
	"IE_REVOC",
	"VERBOSE"
};

#define NUM_PARSE_LIST (sizeof(parse_list) / sizeof(char *))

int parse_input_file_ta_1_x_pbl(void)
{
	gd.hton_flag = 1;
	return (parse_input_file(parse_list, NUM_PARSE_LIST));
}

int parse_input_file_ta_1_x_nonpbl(void)
{
	gd.hton_flag = 1;
	return (parse_input_file(parse_list, NUM_PARSE_LIST));
}

/****************************************************************************
 * API's for Filling STRUCTURES
 ****************************************************************************/
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

int fill_structure_ta_1_x_pbl(void)
{
	int ret, i;

	struct isbc_hdr_ta_1_x_pbl *hdr =
		(struct isbc_hdr_ta_1_x_pbl *)gd.hdr_struct;
	memset(hdr, 0, sizeof(struct isbc_hdr_ta_1_x_pbl));

	if(gd.iek_flag == 1) {
		ret = create_ie_file(DEFAULT_IE_FILE_NAME);
		if (ret != SUCCESS)
			return ret;
		gd.ie_table_size = get_file_size(DEFAULT_IE_FILE_NAME);
		gd.num_entries++;
	}

	/* Calculate Offsets and Size */
	gd.hdr_size = sizeof(struct isbc_hdr_ta_1_x_pbl);
	gd.rsa_size = gd.key_len / 2;

	/* Calculate the offsets of blocks aligne to boundry 0x200 */
	gd.srk_offset = OFFSET_ALIGN(gd.hdr_size);

	gd.ie_table_offset = OFFSET_ALIGN(gd.srk_offset + gd.key_len);
	gd.rsa_offset = OFFSET_ALIGN(gd.ie_table_offset + gd.ie_table_size);

	if ((gd.sg_flag == 0) && (gd.num_entries > 1)) {
		printf("Error !!! SG Table Address is not Specified\n");
		return FAILURE;
	}

	hdr->sg_flag = htonl((uint32_t)gd.sg_flag);

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

	if (gd.sg_flag == 1) {
		/* Create the SG Table */
		for (i = 0; i < gd.num_entries; i++) {
			ret = get_file_size(gd.entries[i].name);
			if (ret == FAILURE)
				return ret;
			gd.sg_table_ptr[i].len = htonl(ret);
			gd.sg_table_ptr[i].src_addr =
					htonl(gd.entries[i].addr_low);
		}

		hdr->sg_table_addr = htonl(gd.sg_addr);
		hdr->sg_entries = htonl(gd.num_entries);
		gd.sg_size = gd.num_entries * sizeof(struct sg_table_ptr_t);

	} else {
		ret = get_file_size(gd.entries[0].name);
		if (ret == FAILURE)
			return ret;
		hdr->img_size = htonl(ret);
		hdr->pimg = htonl(gd.entries[0].addr_low);
	}


	/* Pouplate the fields in Header */
	hdr->barker[0] = barker[0];
	hdr->barker[1] = barker[1];
	hdr->barker[2] = barker[2];
	hdr->barker[3] = barker[3];
	hdr->key_len = htonl(gd.key_len);
	hdr->pkey = htonl(gd.srk_offset);
	hdr->psign = htonl(gd.rsa_offset);
	hdr->sign_len = htonl(gd.rsa_size);
	hdr->entry_point = htonl(gd.entry_addr_low);
	hdr->fsl_uid_0 = htonl(gd.fsluid[0]);
	hdr->oem_uid_0 = htonl(gd.oemuid[0]);

	/* Pouplate the Flags in Header */
	hdr->uid_flag = htonl(get_uid_flags());

	return SUCCESS;
}

int fill_structure_ta_1_x_nonpbl(void)
{
	int ret, i;

	struct isbc_hdr_ta_1_x_nonpbl *hdr =
		(struct isbc_hdr_ta_1_x_nonpbl *)gd.hdr_struct;
	memset(hdr, 0, sizeof(struct isbc_hdr_ta_1_x_nonpbl));


	/* Calculate Offsets and Size */
	gd.hdr_size = sizeof(struct isbc_hdr_ta_1_x_nonpbl);
	gd.rsa_size = gd.key_len / 2;
	gd.sg_size = gd.num_entries * sizeof(struct sg_table_t);

	/* Calculate the offsets of blocks aligne to boundry 0x200 */
	gd.srk_offset = OFFSET_ALIGN(gd.hdr_size);
	gd.sg_offset = OFFSET_ALIGN(gd.srk_offset + gd.key_len);
	gd.rsa_offset = OFFSET_ALIGN(gd.sg_offset + gd.sg_size);

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
	hdr->key_len = htonl(gd.key_len);
	hdr->pkey = htonl(gd.srk_offset);
	hdr->psign = htonl(gd.rsa_offset);
	hdr->sign_len = htonl(gd.rsa_size);
	hdr->entry_point = htonl(gd.entry_addr_low);
	hdr->fsl_uid_0 = htonl(gd.fsluid[0]);
	hdr->oem_uid_0 = htonl(gd.oemuid[0]);

	hdr->sg_table_addr = htonl(gd.sg_offset);
	hdr->sg_entries = htonl(gd.num_entries);

	/* Pouplate the Flags in Header */
	hdr->uid_flag = htonl(get_uid_flags());

	return SUCCESS;
}


/****************************************************************************
 * API's for Creating HEADER FILES
 ****************************************************************************/
int create_header_ta_1_x_pbl(void)
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
	memcpy(header + gd.srk_offset, gd.pkey, gd.key_len);

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

	/* Create the SG Table */
	if (gd.sg_flag == 1) {
		fp = fopen(gd.sg_file_name, "wb");
		if (fp == NULL) {
			printf("Error in opening the file: %s\n",
				gd.sg_file_name);
			ret = FAILURE;
			goto exit;
		}
		ret = fwrite(gd.sg_table_ptr, 1, gd.sg_size, fp);
		fclose(fp);
		if (ret == 0) {
			printf("Error in Writing to file");
			ret = FAILURE;
			goto exit;
		}
	}
	ret = SUCCESS;
exit:
	free(header);
	return ret;
}

int create_header_ta_1_x_nonpbl(void)
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
	memcpy(header + gd.srk_offset, gd.pkey, gd.key_len);
	memcpy(header + gd.sg_offset, gd.sg_table, gd.sg_size);

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

/****************************************************************************
 * API's for Calculating Image Hash
 ****************************************************************************/
int calc_img_hash_ta_1_x_pbl(void)
{
	int i, ret;
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	crypto_hash_init(ctx);

	crypto_hash_update(ctx, gd.hdr_struct, gd.hdr_size);
	crypto_hash_update(ctx, gd.pkey, gd.key_len);

	if (gd.sg_flag == 1) {
		crypto_hash_update(ctx, gd.sg_table_ptr, gd.sg_size);

		for (i = 0; i < gd.num_entries; i++) {
			ret = crypto_hash_update_file(ctx, gd.entries[i].name);
			if (ret == FAILURE)
				return ret;
		}
	} else {
		ret = crypto_hash_update_file(ctx, gd.entries[0].name);
		if (ret == FAILURE)
			return ret;
	}

	crypto_hash_final(gd.img_hash, ctx);

	return SUCCESS;
}

int calc_img_hash_ta_1_x_nonpbl(void)
{
	int i, ret;
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	crypto_hash_init(ctx);

	crypto_hash_update(ctx, gd.hdr_struct, gd.hdr_size);
	crypto_hash_update(ctx, gd.pkey, gd.key_len);

	for (i = 0; i < gd.num_entries; i++) {
		ret = crypto_hash_update_file(ctx, gd.entries[i].name);
		if (ret == FAILURE)
			return ret;
	}

	crypto_hash_update(ctx, gd.sg_table, gd.sg_size);

	crypto_hash_final(gd.img_hash, ctx);

	return SUCCESS;
}

/****************************************************************************
 * API's for Calculating SRK Hash
 ****************************************************************************/
int calc_srk_hash_ta_1_x_pbl(void)
{
	gd.srk_flag = 0;
	gd.srk_sel = 1;
	if (gd.num_srk_entries > 1) {
		printf("Error !! SRK Table not supported by this SoC\n");
		return FAILURE;
	}
	return (create_srk_calc_hash(1));
}

int calc_srk_hash_ta_1_x_nonpbl(void)
{
	gd.srk_flag = 0;
	gd.srk_sel = 1;
	if (gd.num_srk_entries > 1) {
		printf("Error !! SRK Table not supported by this SoC\n");
		return FAILURE;
	}
	return (create_srk_calc_hash(1));
}

/****************************************************************************
 * API's for Dumping Headers
 ****************************************************************************/
int dump_hdr_ta_1_x_pbl(void)
{
	int i;
	struct isbc_hdr_ta_1_x_pbl *hdr =
			(struct isbc_hdr_ta_1_x_pbl *)gd.hdr_struct;

	printf("\n-----------------------------------------------");
	printf("\n-\tDumping the Header Fields");
	printf("\n-----------------------------------------------");
	printf("\n- SRK Information");
	printf("\n-\t Public Key Offset : %x",
		htonl(hdr->pkey));
	printf("\n-\t Single Key: %s(%x)", gd.pub_fname[0],
			htonl(hdr->key_len));

	printf("\n- UID Information");
	printf("\n-\t UID Flags = %x", htonl(hdr->uid_flag));
	printf("\n-\t FSL UID = %08x", htonl(hdr->fsl_uid_0));
	printf("\n-\t OEM UID = %08x", htonl(hdr->oem_uid_0));
	printf("\n- Image Information");
	printf("\n-\t Entry Point : %08x", htonl(hdr->entry_point));
	printf("\n-\t SG Table Flag : %x", htonl(hdr->sg_flag));
	if (hdr->sg_flag == 0) {
		printf("\n-\t Image Name : %s", gd.entries[0].name);
		printf("\n-\t Image Address : %08x", htonl(hdr->pimg));
		printf("\n-\t Image Size : %08x", htonl(hdr->img_size));
	} else {
		printf("\n-\t SG Table Address : %x",
			htonl(hdr->sg_table_addr));
		printf("\n-\t Number of entries : %x", htonl(hdr->sg_entries));
		for (i = 0; i < gd.num_entries; i++)
			printf("\n-\t Entry %d : %s (Size = %08x SRC = %08x) ",
			i + 1, gd.entries[i].name,
			htonl(gd.sg_table_ptr[i].len),
			htonl(gd.sg_table_ptr[i].src_addr));
	}
	printf("\n- RSA Signature Information");
	printf("\n-\t RSA Offset : %x", htonl(hdr->psign));
	printf("\n-\t RSA Size : %x", htonl(hdr->sign_len));
	printf("\n-----------------------------------------------\n");

	return SUCCESS;
}

int dump_hdr_ta_1_x_nonpbl(void)
{
	int i;
	struct isbc_hdr_ta_1_x_nonpbl *hdr =
			(struct isbc_hdr_ta_1_x_nonpbl *)gd.hdr_struct;

	printf("\n-----------------------------------------------");
	printf("\n-\tDumping the Header Fields");
	printf("\n-----------------------------------------------");
	printf("\n- SRK Information");
	printf("\n-\t Public Key Offset : %x",
		htonl(hdr->pkey));
	printf("\n-\t Single Key: %s(%x)", gd.pub_fname[0],
			htonl(hdr->key_len));

	printf("\n- UID Information");
	printf("\n-\t UID Flags = %2x", htons((uint16_t)hdr->uid_flag));
	printf("\n-\t FSL UID = %08x", htonl(hdr->fsl_uid_0));
	printf("\n-\t OEM UID = %08x", htonl(hdr->oem_uid_0));
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
