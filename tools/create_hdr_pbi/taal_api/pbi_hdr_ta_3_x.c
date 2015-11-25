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
#include <pbi_hdr_ta_3_x.h>

extern struct g_data_t gd;
uint8_t barker[] = {0x12, 0x19, 0x20, 0x01};

/****************************************************************************
 * API's for PARSING INPUT FILES
 ****************************************************************************/
static char *parse_list[] = {
	"PUB_KEY",
	"PRI_KEY",
	"KEY_SELECT",
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
	"RCW_PBI_FILENAME",
	"BOOT1_PTR",
	"VERBOSE"
};

#define NUM_PARSE_LIST (sizeof(parse_list) / sizeof(char *))

int parse_input_file_ta_3_x(void)
{
	int i, ret = 0;
	FILE *fp;
	fp = fopen(gd.input_file, "r");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", gd.input_file);
		return FAILURE;
	}

	for (i = 0; i < NUM_PARSE_LIST; i++) {
		ret = fill_gd_input_file(parse_list[i], fp);
		if (ret != SUCCESS)
			break;
	}

	fclose(fp);
	return ret;
}

/****************************************************************************
 * API's for Filling STRUCTURES
 ****************************************************************************/
int create_pbi(uint32_t hdr_size)
{
	int ret, i;
	uint32_t *rcw_word;
	uint32_t *pbi_word;
	uint32_t file_len, word, pbi_start;
	FILE *frcw;

	pbi_start = NUM_RCW_WORD * sizeof(uint32_t);

	rcw_word = (uint32_t *)gd.hdr_struct;
	pbi_word = (uint32_t *)(gd.hdr_struct + pbi_start);

	/* Open the RCW (+ PBI) Table */
	ret = get_file_size(gd.rcw_fname);
	if (ret == FAILURE)
		return ret;

	file_len = ret;
	if (file_len < NUM_RCW_WORD * sizeof(uint32_t)) {
		printf ("Invalid RCW File (%s). Does not have the RCW words\n",
			gd.rcw_fname);
		return FAILURE;
	}

	frcw = fopen(gd.rcw_fname, "rb");
        if (frcw == NULL) {
                printf("Error in opening the file: %s\n", gd.rcw_fname);
                return FAILURE;
        }

	/* Read the RCW Words */
	for (i = 0; i < NUM_RCW_WORD; i++) {
		fread(&word, sizeof(word), 1, frcw);
		rcw_word[i] = word;
	}

	gd.pbi_len = (rcw_word[10] & PBI_LEN_MASK) >> PBI_LEN_SHIFT;
	gd.num_pbi_words = 0;

	/* First PBI Word is LOAD_SEC_HDR_CMD */
	pbi_word[gd.num_pbi_words++] = LOAD_SEC_HDR_CMD;

	/* Reserve Space for Security Header */
	gd.num_pbi_words += (hdr_size / sizeof(word));

	/* Next PBI Command is LOAD_BOOT1_CSF_PTR_CMD */
	pbi_word[gd.num_pbi_words++] = LOAD_BOOT1_CSF_PTR_CMD;
	pbi_word[gd.num_pbi_words++] = gd.boot1_ptr;
	if (gd.boot1_ptr == 0) {
		printf("Error: BOOT1 PTR is not specified\n");
		fclose(frcw);
		return FAILURE;
	}

	/* Read Other PBI commands
	 * pbi_len indicates no. of PBI words */
	for (i = 0; i < gd.pbi_len; i++) {
		ret = fread(&word, sizeof(word), 1, frcw);
		if (ret == 0) {
			printf("Error in Reading PBI Commands\n");
			fclose(frcw);
			return FAILURE;
		}
		pbi_word[gd.num_pbi_words++] = word;
	}

	fclose(frcw);

	if ((pbi_word[gd.num_pbi_words - 2] != CRC_STOP_CMD) &&
	    (pbi_word[gd.num_pbi_words - 2] != STOP_CMD)) {
		printf("Error: Invalid PBI. No Stop Command\n");
		return FAILURE;
	}

	/* Update the Header Size */
	gd.hdr_size = (gd.num_pbi_words + NUM_RCW_WORD) * sizeof(word);

	/* Update the PBI Length and SB_EN in RCW */
	rcw_word[10] = rcw_word[10] & ~PBI_LEN_MASK;
	rcw_word[10] = rcw_word[10] | SB_EN_MASK |
			(gd.num_pbi_words << PBI_LEN_SHIFT);

	return SUCCESS;
}

int update_crc_checksum(void)
{
	uint32_t crc, checksum;
	uint32_t *rcw_word;
	uint32_t *pbi_word;
	uint32_t pbi_start;

	pbi_start = NUM_RCW_WORD * sizeof(uint32_t);

	rcw_word = (uint32_t *)gd.hdr_struct;
	pbi_word = (uint32_t *)(gd.hdr_struct + pbi_start);

	/* Check and Update Checksum in RCW
	 * rcw_word[0] = Preamble
	 * rcw_word[1] = Load RCW Command
	 * rcw_word[2 - 33] = 1024 RCW bits
	 * rcw_word[34] = Checksum
	 */
	if (rcw_word[1] == LOAD_RCW_CHECKSUM) {
		checksum = crypto_calculate_checksum(rcw_word,
						NUM_RCW_WORD - 1);
		rcw_word[NUM_RCW_WORD - 1] = checksum;
	} else if (rcw_word[1] != LOAD_RCW_WO_CHECKSUM) {
		printf("Error: Invalid Load RCW Command\n");
		return FAILURE;
	}

	/* Check and Update CRC in PBI
	 * pbi_word[num_pbi - 1] = crc
	 * pbi_word[num_pbi - 2] = STOP Command
	 */
	if (pbi_word[gd.num_pbi_words - 2] == CRC_STOP_CMD) {
		crc = crypto_calculate_crc(pbi_word,
			(gd.num_pbi_words * sizeof(uint32_t)));
		pbi_word[gd.num_pbi_words - 1] = crc;
	} else if (pbi_word[gd.num_pbi_words - 2] != STOP_CMD) {
		printf("Error: Invalid PBI. No Stop Command\n");
		return FAILURE;
	}

	return SUCCESS;
}

void calculate_offset_size(void)
{
	gd.srk_size = gd.num_srk_entries * sizeof(struct srk_table_t);
	gd.rsa_size = gd.key_table[gd.srk_sel - 1].key_len / 2;

	/* Calculate the offsets of blocks aligne to boundry 0x200 */
	gd.srk_offset = OFFSET_ALIGN((gd.num_pbi_words / sizeof(uint32_t)));
	gd.rsa_offset = OFFSET_ALIGN(gd.srk_offset + gd.srk_size);
}

uint8_t get_misc_flags(void)
{
	uint8_t flag = 0;

	if (gd.mp_flag)
		flag |= MP_FLAG_MASK;
	if (gd.iss_flag)
		flag |= ISS_FLAG_MASK;
	if (gd.lw_flag)
		flag |= LW_FLAG_MASK;

	/* B01 flag is always 0 in PBI Header */
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

int fill_structure_ta_3_0(void)
{
	int ret;
	struct pbi_hdr_ta_3_0 *hdr;
	uint32_t hdr_start;

	memset(gd.hdr_struct, 0, sizeof(gd.hdr_struct));

	ret = create_pbi(sizeof(struct pbi_hdr_ta_3_0));
	if (ret != SUCCESS)
		return ret;

	hdr_start = (NUM_RCW_WORD + 1) * sizeof(uint32_t);
	hdr = (struct pbi_hdr_ta_3_0 *)(gd.hdr_struct + hdr_start);

	/* Calculate Offsets and Size */
	calculate_offset_size();

	/* Pouplate the fields in Header */
	hdr->barker[0] = barker[0];
	hdr->barker[1] = barker[1];
	hdr->barker[2] = barker[2];
	hdr->barker[3] = barker[3];
	hdr->srk_table_offset = gd.srk_offset;
	hdr->num_keys = gd.num_srk_entries;
	hdr->key_num_verify = gd.srk_sel;
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

	/* Update CRC Value in PBI if CRC & Stop Command
	 * Checksum Value in RCW if Load RCW with Checksum */
	ret = update_crc_checksum();

	return ret;
}

int fill_structure_ta_3_1(void)
{
	int ret;
	struct pbi_hdr_ta_3_1 *hdr;
	uint32_t hdr_start;

	memset(gd.hdr_struct, 0, sizeof(gd.hdr_struct));

	ret = create_pbi(sizeof(struct pbi_hdr_ta_3_1));
	if (ret != SUCCESS)
		return ret;

	hdr_start = (NUM_RCW_WORD + 1) * sizeof(uint32_t);
	hdr = (struct pbi_hdr_ta_3_1 *)(gd.hdr_struct + hdr_start);

	/* Calculate Offsets and Size */
	calculate_offset_size();

	/* Pouplate the fields in Header */
	hdr->barker[0] = barker[0];
	hdr->barker[1] = barker[1];
	hdr->barker[2] = barker[2];
	hdr->barker[3] = barker[3];
	hdr->srk_table_offset = gd.srk_offset;
	hdr->num_keys = gd.num_srk_entries;
	hdr->key_num_verify = gd.srk_sel;
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

	/* Update CRC Value in PBI if CRC & Stop Command
	 * Checksum Value in RCW if Load RCW with Checksum */
	ret = update_crc_checksum();

	return ret;
}

/****************************************************************************
 * API's for Creating HEADER FILES
 ****************************************************************************/
int create_header_ta_3_x(void)
{
	int ret;
	uint8_t *header;
	FILE *fp;
	uint32_t hdrlen;
	uint32_t hdr_start;

	hdr_start = ((NUM_RCW_WORD + 1) * sizeof(uint32_t));
	hdrlen = gd.rsa_offset + hdr_start;

	if (gd.option_img_hash == 0)
		hdrlen += gd.rsa_size;

	header = malloc(hdrlen);
	if (header == NULL) {
		printf("Error in allocating memory of %d bytes\n", hdrlen);
		return FAILURE;
	}

	memset(header, 0, hdrlen);

	memcpy(header, gd.hdr_struct, gd.hdr_size);
	memcpy(header + hdr_start + gd.srk_offset, gd.key_table, gd.srk_size);

	if (gd.option_img_hash == 0)
		memcpy(header + hdr_start+ gd.rsa_offset,
			gd.rsa_sign, gd.rsa_size);

	/* Create the header file */
	fp = fopen(gd.hdr_file_name, "wb");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", gd.hdr_file_name);
		free(header);
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

/****************************************************************************
 * API's for Calculating Image Hash
 ****************************************************************************/
int calc_img_hash_ta_3_x(void)
{
	int ret;
	FILE *fp;
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	uint32_t len;
	crypto_hash_init(ctx);

	crypto_hash_update(ctx, gd.hdr_struct, gd.hdr_size);
	crypto_hash_update(ctx, gd.key_table, gd.srk_size);

	crypto_hash_final(gd.img_hash, ctx);

	if (gd.option_img_hash == 0) {
		ret = crypto_rsa_sign(gd.img_hash, SHA256_DIGEST_LENGTH,
			gd.rsa_sign, &len, gd.pri_fname[gd.srk_sel - 1]);
		if (ret != SUCCESS) {
			printf("Error in Signing\n");
			return FAILURE;
		}
	} else {
		fp = fopen(gd.img_hash_file_name, "wb");
		if (fp == NULL) {
			printf("Error in opening the file: %s\n",
				gd.img_hash_file_name);
			return FAILURE;
		}
		ret = fwrite(gd.img_hash, 1, SHA256_DIGEST_LENGTH, fp);
		fclose(fp);

		if (ret == 0) {
			printf("Error in Writing to file");
			return FAILURE;
		}
	}

	return SUCCESS;
}

/****************************************************************************
 * API's for Calculating SRK Hash
 ****************************************************************************/
int create_srk(void)
{
	int i, ret;
	uint32_t key_len;

	/* Check if Num of Entries and Key Select is Correct */
	ret = FAILURE;
	if (gd.num_srk_entries > 8) {
		printf("\n Invalid Number of Keys");
		return FAILURE;
	}
	if ((gd.srk_sel > gd.num_srk_entries) ||
	    (gd.srk_sel == 0)) {
		printf("\n Invalid Key Select");
		return FAILURE;
	}
	if (gd.option_img_hash == 0) {
		if (gd.num_srk_entries != gd.num_pri_key) {
			printf("\n Public and Private Key Count Mismatch");
			return FAILURE;
		}
	}

	/* Read all the public Keys and Store in SRK Table */
	for (i = 0; i < gd.num_srk_entries; i++) {
		key_len = 0;
		ret = crypto_extract_pub_key(gd.pub_fname[i],
					&key_len,
					gd.key_table[i].pkey);
		gd.key_table[i].key_len = key_len;
		if (ret != SUCCESS)
			break;
	}

	return ret;
}

int calc_srk_hash_ta_3_x(void)
{
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	int ret;

	/* Create the SRK Table */
	ret = create_srk();
	if (ret != SUCCESS)
		return ret;

	crypto_hash_init(ctx);

	crypto_hash_update(ctx, gd.key_table, gd.srk_size);
	crypto_hash_final(gd.srk_hash, ctx);
	return SUCCESS;
}

/****************************************************************************
 * API's for Dumping Headers
 ****************************************************************************/
int dump_hdr_ta_3_0(void)
{
	int i;
	struct pbi_hdr_ta_3_0 *hdr;
	uint32_t hdr_start;

	hdr_start = (NUM_RCW_WORD + 1) * sizeof(uint32_t);
	hdr = (struct pbi_hdr_ta_3_0 *)(gd.hdr_struct + hdr_start);

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
	printf("\n-\t\t B01 = %x", 0);
	printf("\n- Image Information");
	printf("\n-\t RCW File : %s", gd.rcw_fname);
	printf("\n-\t Boot1 PTR : %x", gd.boot1_ptr);
	printf("\n-\t Initial No. Of PBI Words : %d (0x%x)",
			gd.pbi_len, gd.pbi_len);
	printf("\n-\t Final No. Of PBI Words : %d (0x%x)",
			gd.num_pbi_words, gd.num_pbi_words);
	printf("\n- RSA Signature Information");
	printf("\n-\t RSA Offset : %x", hdr->psign);
	printf("\n-\t RSA Size : %x", hdr->sign_len);
	printf("\n-----------------------------------------------\n");

	return SUCCESS;
}

int dump_hdr_ta_3_1(void)
{
	int i;
	struct pbi_hdr_ta_3_1 *hdr;
	uint32_t hdr_start;

	hdr_start = (NUM_RCW_WORD + 1) * sizeof(uint32_t);
	hdr = (struct pbi_hdr_ta_3_1 *)(gd.hdr_struct + hdr_start);

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
	printf("\n-\t\t B01 = %x", 0);
	printf("\n- Image Information");
	printf("\n-\t RCW File : %s", gd.rcw_fname);
	printf("\n-\t Boot1 PTR : %x", gd.boot1_ptr);
	printf("\n-\t Initial No. Of PBI Words : %d (0x%x)",
			gd.pbi_len, gd.pbi_len);
	printf("\n-\t Final No. Of PBI Words : %d (0x%x)",
			gd.num_pbi_words, gd.num_pbi_words);
	printf("\n- RSA Signature Information");
	printf("\n-\t RSA Offset : %x", hdr->psign);
	printf("\n-\t RSA Size : %x", hdr->sign_len);
	printf("\n-----------------------------------------------\n");

	return SUCCESS;
}
