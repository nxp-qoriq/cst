/* Copyright (c) 2015 Freescale Semiconductor, Inc.
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

#include <parse_utils.h>

struct input_field file_field;
char line_data[MAX_LINE_SIZE];
extern struct g_data_t gd;

static parse_struct_t parse_table[] = {
	{ "PLATFORM", FIELD_PLATFORM },
	{ "ENTRY_POINT", FIELD_ENTRY_POINT },
	{ "BOOT_SRC", FIELD_BOOT_SRC },
	{ "BOOT_HO", FIELD_BOOT_HO },
	{ "SB_EN", FIELD_SB_EN },
	{ "PUB_KEY", FIELD_PUB_KEY },
	{ "KEY_SELECT", FIELD_KEY_SELECT },
	{ "IMAGE_1", FIELD_IMAGE_1 },
	{ "IMAGE_2", FIELD_IMAGE_2 },
	{ "IMAGE_3", FIELD_IMAGE_3 },
	{ "IMAGE_4", FIELD_IMAGE_4 },
	{ "IMAGE_5", FIELD_IMAGE_5 },
	{ "IMAGE_6", FIELD_IMAGE_6 },
	{ "IMAGE_7", FIELD_IMAGE_7 },
	{ "IMAGE_8", FIELD_IMAGE_8 },
	{ "FSL_UID_0", FIELD_FSL_UID_0 },
	{ "FSL_UID_1", FIELD_FSL_UID_1 },
	{ "OEM_UID_0", FIELD_OEM_UID_0 },
	{ "OEM_UID_1", FIELD_OEM_UID_1 },
	{ "OEM_UID_2", FIELD_OEM_UID_2 },
	{ "OEM_UID_3", FIELD_OEM_UID_3 },
	{ "OEM_UID_4", FIELD_OEM_UID_4 },
	{ "OUTPUT_HDR_FILENAME", FIELD_OUTPUT_HDR_FILENAME },
	{ "MP_FLAG", FIELD_MP_FLAG },
	{ "ISS_FLAG", FIELD_ISS_FLAG },
	{ "LW_FLAG", FIELD_LW_FLAG },
	{ "PRI_KEY", FIELD_PRI_KEY },
	{ "IMAGE_HASH_FILENAME", FIELD_IMAGE_HASH_FILENAME },
	{ "RSA_SIGN_FILENAME", FIELD_RSA_SIGN_FILENAME },
	{ "RCW_PBI_FILENAME", FIELD_RCW_PBI_FILENAME },
	{ "BOOT1_PTR", FIELD_BOOT1_PTR },
	{ "VERBOSE", FIELD_VERBOSE },
	{ "SEC_IMAGE", FIELD_SEC_IMAGE },
	{ "WP_FLAG", FIELD_WP_FLAG },
	{ "HK_AREA_POINTER", FIELD_HK_AREA_POINTER },
	{ "HK_AREA_SIZE", FIELD_HK_AREA_SIZE },
	{ "IMAGE_TARGET", FIELD_IMAGE_TARGET },
	{ "SG_TABLE_ADDR", FIELD_SG_TABLE_ADDR },
	{ "OUTPUT_SG_BIN", FIELD_OUTPUT_SG_BIN },
	{ "ESBC_HDRADDR_SEC_IMAGE", FIELD_ESBC_HDRADDR_SEC_IMAGE },
	{ "IE_KEY_SEL", FIELD_IE_KEY_SEL },
	{ "ESBC_HDRADDR", FIELD_ESBC_HDRADDR },
	{ "IE_KEY", FIELD_IE_KEY},
	{ "IE_REVOC", FIELD_IE_REVOC},
	{ "IE_TABLE_ADDR", FIELD_IE_TABLE_ADDR},
	{ "OUTPUT_RCW_PBI_FILENAME", FIELD_OUTPUT_RCW_PBI_FILENAME },
	{ "POVDD_GPIO", FIELD_POVDD_GPIO },
	{ "OTPMK_FLAGS", FIELD_OTPMK_FLAGS },
	{ "OTPMK_0", FIELD_OTPMK_0 },
	{ "OTPMK_1", FIELD_OTPMK_1 },
	{ "OTPMK_2", FIELD_OTPMK_2 },
	{ "OTPMK_3", FIELD_OTPMK_3 },
	{ "OTPMK_4", FIELD_OTPMK_4 },
	{ "OTPMK_5", FIELD_OTPMK_5 },
	{ "OTPMK_6", FIELD_OTPMK_6 },
	{ "OTPMK_7", FIELD_OTPMK_7 },
	{ "SRKH_0", FIELD_SRKH_0 },
	{ "SRKH_1", FIELD_SRKH_1 },
	{ "SRKH_2", FIELD_SRKH_2 },
	{ "SRKH_3", FIELD_SRKH_3 },
	{ "SRKH_4", FIELD_SRKH_4 },
	{ "SRKH_5", FIELD_SRKH_5 },
	{ "SRKH_6", FIELD_SRKH_6 },
	{ "SRKH_7", FIELD_SRKH_7 },
	{ "DCV_0", FIELD_DCV_0 },
	{ "DCV_1", FIELD_DCV_1 },
	{ "DRV_0", FIELD_DRV_0 },
	{ "DRV_1", FIELD_DRV_1 },
	{ "MC_ERA", FIELD_MC_ERA },
	{ "DBG_LVL", FIELD_DBG_LVL },
	{ "WP", FIELD_WP },
	{ "ITS", FIELD_ITS },
	{ "NSEC", FIELD_NSEC },
	{ "ZD", FIELD_ZD },
	{ "K0", FIELD_K0 },
	{ "K1", FIELD_K1 },
	{ "K2", FIELD_K2 },
	{ "K3", FIELD_K3 },
	{ "K4", FIELD_K4 },
	{ "K5", FIELD_K5 },
	{ "K6", FIELD_K6 },
	{ "FR0", FIELD_FR0 },
	{ "FR1", FIELD_FR1 },
	{ "OUTPUT_FUSE_FILENAME", FIELD_OUTPUT_FUSE_FILENAME }
};

#define NUM_FIELDS (sizeof(parse_table) / sizeof(parse_struct_t))

enum input_field_t index_from_field(char *field)
{
	int i;
	for (i = 0; i < NUM_FIELDS; i++) {
		if (strcmp(parse_table[i].field_name, field) == 0)
			return parse_table[i].index;
	}
	return FIELD_UNKNOWN_MAX;
}

char *tar[][2] = { 
	{"NOR_8B", "b"},
	{"NOR_16B", "f"},
	{"NAND_8B_512", "8"},
	{"NAND_8B_2K", "9"},
	{"NAND_8B_4K", "a"},
	{"NAND_16B_512", "c"},
	{"NAND_16B_2K", "d"},
	{"NAND_16B_4K", "e"},
	{"MMC", "7"},
	{"SD", "7"},
	{"SDHC", "7"},
	{"SPI", "6"},
	{"LAST", "0"}
};

int check_target(char *target_name, uint32_t *targetid)
{
	int i = 0;
	while (strcmp(tar[i][0], "LAST")) {
		if (strcmp(tar[i][0], target_name) == 0) {
			*targetid = strtoul(tar[i][1], 0, 16);
			return SUCCESS;
		}
		i++;
	}
	printf("\nInvalid Image Target\n");
	return FAILURE;
}

static inline void check_field_length(char *field_name, char *field_val)
{
	if (strlen(field_val) >= MAX_FNAME_LEN) {
		printf("Lenght of field %s exceed maximum limit %d\n",
			field_name, MAX_FNAME_LEN);
		printf("\nExiting ...\n");
		exit(EXIT_FAILURE);
	}
}

/***************************************************************************
 * Function	:	STR_TO_UL
 * Arguments	:	str - String
 *			base - Base (Decimal, HEX)
 * Return	:	unsigned long value
 * Description	:	Converts the string to unsigned long value
 ***************************************************************************/
unsigned long STR_TO_UL(char *str, int base)
{
	unsigned long val;
	char *endptr;
	char *neg;

	/* To distinguish success/failure for strtoul*/
	errno = 0;

	/* Checking for negative values*/
	neg = str;
	if (strchr(neg, '-') != NULL) {
		printf("Field is populated incorrectly with negative value\n");
		exit(EXIT_FAILURE);
	}

	/* Convert string to unsigned long*/
	val = strtoul(str, &endptr, base);

	/* Some invalid character is there in the field value */
	if (*endptr != '\0') {
		printf("Field is populated incorrectly with value %s in %s\n",
			endptr, str);
		exit(EXIT_FAILURE);
	}

	/* Check for various possible errors */
	if (((errno == ERANGE) && (val == ULONG_MAX)) ||
	    (errno != 0 && val == 0)) {
		printf("Field populated incorrectly with value %s\n", endptr);
		exit(EXIT_FAILURE);
	}

	if (*endptr == '\0')
		return val;

	exit(EXIT_FAILURE);
}

/***************************************************************************
 * Function	:	STR_TO_ULL
 * Arguments	:	str - String
 *			base - Base (Decimal, HEX)
 * Return	:	unsigned long value
 * Description	:	Converts the string to unsigned long long value
 ***************************************************************************/
unsigned long long STR_TO_ULL(char *str, int base)
{
	unsigned long long val;
	char *endptr;
	char *neg;

	/* To distinguish success/failure for strtoul*/
	errno = 0;

	/* Checking for negative values*/
	neg = str;
	if (strchr(neg, '-') != NULL) {
		printf("Field is populated incorrectly with negative value\n");
		exit(EXIT_FAILURE);
	}

	/* Convert string to unsigned long*/
	val = strtoull(str, &endptr, base);

	/* Some invalid character is there in the field value */
	if (*endptr != '\0') {
		printf("Field is populated incorrectly with value %s in %s\n",
			endptr, str);
		exit(EXIT_FAILURE);
	}

	/* Check for various possible errors */
	if (((errno == ERANGE) && (val == ULLONG_MAX)) ||
	    (errno != 0 && val == 0)) {
		printf("Field populated incorrectly with value %s\n", endptr);
		exit(EXIT_FAILURE);
	}

	if (*endptr == '\0')
		return val;

	exit(EXIT_FAILURE);
}


/***************************************************************************
 * Functions from Parsing of Input File
 ****************************************************************************/
int cal_line_size(FILE *fp)
{
	int ctr = 0;
	int ch = 'a';
	while (ch != EOF) {
		if ((ch == '\n') && (ctr != 1))
			return ctr;

		ch = fgetc(fp);
		ctr++;
	}
	return 0;
}


void get_field_from_file(char *line, char *field_name)
{
	int i = 0;
	char delims[] = ",;=";
	char *result = NULL;

	result = strtok(line, delims);
	while (result != NULL) {
		result = strtok(NULL, delims);
		file_field.value[i] = result;
		i++;
	}
	file_field.count = i - 1;
}


void remove_whitespace(char *line)
{
	char *p1;
	char *p2 = line;
	p1 = line;
	while (*p1 != 0) {
		if (*p1 == '{' || *p1 == '}' || *p1 == '[' || *p1 == ']' ||
		    isspace(*p1) || *p1 == '(' || *p1 == ')') {
			++p1;
		} else {
			*p2++ = *p1++;
		}
	}
	*p2 = 0;
}

/* Search field_name in line_data. Also the char before and after the
 * 'field_name' string in 'line_data' must not be alphanumeric or '_'
 */
int found_whole_word(const char *line_data, const char *field_name)
{
	const char *match_pointer = strstr(line_data, field_name);
	if (!match_pointer)
		return 0;
	/* If match is not found in very start of string,
	 * check that char previous to field_name string is neither
	 * alphanumeric nor '_'
	 */
	if (line_data != match_pointer--)
		if (isalnum(*match_pointer) ||
				(*match_pointer == '_'))
			return 0;
	match_pointer += strlen(field_name) + 1;
	/* Check that char after 'field_name' string in 'line_data'
	 * is neither alphanumeric nor '_'
	 */
	if (isalnum(*match_pointer) ||
			(*match_pointer == '_'))
		return 0;
	return 1;
}

void find_value_from_file(char *field_name, FILE *fp)
{
	int line_size = 0;
	int i = 0;
	uint32_t ret = 0;
	for (i = 0; i < 64; i++)
		file_field.value[i] = NULL;

	file_field.count = 0;

	fseek(fp, 0, SEEK_SET);
	line_size = cal_line_size(fp);
	ret = fseek(fp, -line_size, SEEK_CUR);
	if (ret != 0)
		printf("Error in reading the file\n");
	while ((ret = fread(line_data, 1, line_size, fp))) {
		*(line_data + line_size) = '\0';
		remove_whitespace(line_data);
		if ((found_whole_word(line_data, field_name)) &&
				(*line_data != '#')) {
			get_field_from_file(line_data, field_name);
			return;
		}
		line_size = cal_line_size(fp);

		ret = fseek(fp, -line_size, SEEK_CUR);
		if (ret != 0)
			printf("Error in readeing the file\n");

	}
	file_field.count = 0;
}

int find_cfw_from_file(char *file_name)
{
	int line_size = 0;
	char *field_name = "CF_WORD";
	FILE *fp;
	uint32_t ret = 0;
	fp = fopen(file_name, "r");
	if (fp == NULL) {
		printf("Error in opening the file: %s\n", file_name);
		return FAILURE;
	}

	file_field.value[0] = NULL;
	file_field.value[1] = NULL;
	file_field.value[2] = NULL;
	file_field.value[3] = NULL;
	file_field.count = 0;

	fseek(fp, 0, SEEK_SET);
	line_size = cal_line_size(fp);
	ret = fseek(fp, -line_size, SEEK_CUR);
	if (ret != 0)
		printf("Error in readeing the file\n");

	while ((ret = fread(line_data, 1, line_size, fp))) {
		*(line_data + line_size) = '\0';
		remove_whitespace(line_data);
		if ((strstr(line_data, field_name)) && (*line_data != '#')) {
			get_field_from_file(line_data, field_name);
			if (file_field.count == 2) {
				gd.cf_word[gd.cf_count].addr =
				htonl(STR_TO_UL(file_field.value[0], 16));
				gd.cf_word[gd.cf_count].data =
				htonl(STR_TO_UL(file_field.value[1], 16));
				gd.cf_count++;
				if (gd.cf_count >= MAX_CF_WORD) {
					printf("Error:Only %d CF WORD Pairs"
						" Allowed\n", MAX_CF_WORD);
					fclose(fp);
					return FAILURE;
				}
			} else {
				printf("Error:Wrong Format in Input File\n"
				       "Usage: CF_WORD = (ADDR, DATA)\n");
				fclose(fp);
				return FAILURE;
			}
		}
		line_size = cal_line_size(fp);
		ret = fseek(fp, -line_size, SEEK_CUR);
		if (ret != 0)
			printf("Error in readeing the file\n");
	}

	fclose(fp);
	return SUCCESS;
}

int fill_gd_input_file(char *field_name, FILE *fp)
{
	int i, ret = SUCCESS;
	DWord val64;
	enum input_field_t idx;
	uint32_t flags = 0;

	idx = index_from_field(field_name);

	if (idx == FIELD_UNKNOWN_MAX) {
		printf("\n Invalid Field being parsed %s\n", field_name);
		return FAILURE;
	}

	find_value_from_file(field_name, fp);

	switch (idx) {
	case FIELD_ENTRY_POINT:
		if (file_field.count == 1) {
			val64.whole = STR_TO_ULL(file_field.value[0], 16);
			gd.entry_addr_high = val64.m_halfs.high;
			gd.entry_addr_low = val64.m_halfs.low;
		}
		break;

	case FIELD_PUB_KEY:
		gd.num_srk_entries = file_field.count;
		if (gd.num_srk_entries >= 1) {
			i = 0;
			while (i != gd.num_srk_entries) {
				check_field_length(field_name,
					file_field.value[i]);
				strcpy(gd.pub_fname[i], file_field.value[i]);
				i++;
				if (i == MAX_NUM_KEY) {
					printf("\n Key Number Limit reached");
					break;
				}
			}
		}
		break;

	case FIELD_PRI_KEY:
		gd.num_pri_key = file_field.count;
		if (gd.num_pri_key >= 1) {
			i = 0;
			while (i != gd.num_pri_key) {
				check_field_length(field_name,
					file_field.value[i]);
				strcpy(gd.pri_fname[i], file_field.value[i]);
				i++;
				if (i == MAX_NUM_KEY) {
					printf("\n Key Number Limit reached");
					break;
				}
			}
		}
		break;

	case FIELD_IE_KEY:
		gd.num_ie_key = file_field.count;
		if (gd.num_ie_key >= 1) {
			gd.ie_table_flag = 1;
			gd.iek_flag = 1;
			i = 0;
			while (i != gd.num_ie_key) {
				check_field_length(field_name,
					file_field.value[i]);
				strcpy(gd.iek_fname[i], file_field.value[i]);
				i++;
				if (i == MAX_NUM_IEKEY) {
					printf("\n Key Number Limit reached");
					break;
				}
			}
		}
		break;

	case FIELD_KEY_SELECT:
		if (file_field.count == 1) {
			gd.srk_sel = STR_TO_UL(file_field.value[0], 16);
		} else {
			gd.srk_sel = 1;
		}
			gd.srk_flag = 1;

		break;

	case FIELD_IMAGE_1:
		if (file_field.count >= 2) {
			check_field_length(field_name, file_field.value[0]);
			if (gd.entry1_flag == 0)
				strcpy(gd.entries[0].name, file_field.value[0]);
			val64.whole = STR_TO_ULL(file_field.value[1], 16);
			gd.entries[0].addr_high = val64.m_halfs.high;
			gd.entries[0].addr_low = val64.m_halfs.low;
			gd.num_entries++;
		}
		if (file_field.count >= 3) {
			gd.entries[0].dst_addr =
				STR_TO_UL(file_field.value[2], 16);
		}
		break;

	case FIELD_IMAGE_2:
		if (file_field.count >= 2) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.entries[1].name, file_field.value[0]);
			val64.whole = STR_TO_ULL(file_field.value[1], 16);
			gd.entries[1].addr_high = val64.m_halfs.high;
			gd.entries[1].addr_low = val64.m_halfs.low;
			gd.num_entries++;
		}
		if (file_field.count >= 3) {
			gd.entries[1].dst_addr =
				STR_TO_UL(file_field.value[2], 16);
		}
		break;

	case FIELD_IMAGE_3:
		if (file_field.count >= 2) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.entries[2].name, file_field.value[0]);
			val64.whole = STR_TO_ULL(file_field.value[1], 16);
			gd.entries[2].addr_high = val64.m_halfs.high;
			gd.entries[2].addr_low = val64.m_halfs.low;
			gd.num_entries++;
		}
		if (file_field.count >= 3) {
			gd.entries[2].dst_addr =
				STR_TO_UL(file_field.value[2], 16);
		}
		break;

	case FIELD_IMAGE_4:
		if (file_field.count >= 2) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.entries[3].name, file_field.value[0]);
			val64.whole = STR_TO_ULL(file_field.value[1], 16);
			gd.entries[3].addr_high = val64.m_halfs.high;
			gd.entries[3].addr_low = val64.m_halfs.low;
			gd.num_entries++;
		}
		if (file_field.count >= 3) {
			gd.entries[3].dst_addr =
				STR_TO_UL(file_field.value[2], 16);
		}
		break;

	case FIELD_IMAGE_5:
		if (file_field.count >= 2) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.entries[4].name, file_field.value[0]);
			val64.whole = STR_TO_ULL(file_field.value[1], 16);
			gd.entries[4].addr_high = val64.m_halfs.high;
			gd.entries[4].addr_low = val64.m_halfs.low;
			gd.num_entries++;
		}
		if (file_field.count >= 3) {
			gd.entries[4].dst_addr =
				STR_TO_UL(file_field.value[2], 16);
		}
		break;

	case FIELD_IMAGE_6:
		if (file_field.count >= 2) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.entries[5].name, file_field.value[0]);
			val64.whole = STR_TO_ULL(file_field.value[1], 16);
			gd.entries[5].addr_high = val64.m_halfs.high;
			gd.entries[5].addr_low = val64.m_halfs.low;
			gd.num_entries++;
		}
		if (file_field.count >= 3) {
			gd.entries[5].dst_addr =
				STR_TO_UL(file_field.value[2], 16);
		}
		break;

	case FIELD_IMAGE_7:
		if (file_field.count >= 2) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.entries[6].name, file_field.value[0]);
			val64.whole = STR_TO_ULL(file_field.value[1], 16);
			gd.entries[6].addr_high = val64.m_halfs.high;
			gd.entries[6].addr_low = val64.m_halfs.low;
			gd.num_entries++;
		}
		if (file_field.count >= 3) {
			gd.entries[6].dst_addr =
				STR_TO_UL(file_field.value[2], 16);
		}
		break;

	case FIELD_IMAGE_8:
		if (file_field.count >= 2) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.entries[7].name, file_field.value[0]);
			val64.whole = STR_TO_ULL(file_field.value[1], 16);
			gd.entries[7].addr_high = val64.m_halfs.high;
			gd.entries[7].addr_low = val64.m_halfs.low;
			gd.num_entries++;
		}
		if (file_field.count >= 3) {
			gd.entries[7].dst_addr =
				STR_TO_UL(file_field.value[2], 16);
		}
		break;

	case FIELD_FSL_UID_0:
		if (file_field.count == 1) {
			gd.fsluid[0] = STR_TO_UL(file_field.value[0], 16);
			gd.fsluid_flag[0] = 1;
		}
		break;

	case FIELD_FSL_UID_1:
		if (file_field.count == 1) {
			gd.fsluid[1] = STR_TO_UL(file_field.value[0], 16);
			gd.fsluid_flag[1] = 1;
		}
		break;

	case FIELD_OEM_UID_0:
		if (file_field.count == 1) {
			gd.oemuid[0] = STR_TO_UL(file_field.value[0], 16);
			gd.oemuid_flag[0] = 1;
			gd.flags |= (0x1 << FLAG_OUID0_SHIFT);
		}
		break;

	case FIELD_OEM_UID_1:
		if (file_field.count == 1) {
			gd.oemuid[1] = STR_TO_UL(file_field.value[0], 16);
			gd.oemuid_flag[1] = 1;
			gd.flags |= (0x1 << FLAG_OUID1_SHIFT);
		}
		break;

	case FIELD_OEM_UID_2:
		if (file_field.count == 1) {
			gd.oemuid[2] = STR_TO_UL(file_field.value[0], 16);
			gd.oemuid_flag[2] = 1;
			gd.flags |= (0x1 << FLAG_OUID2_SHIFT);
		}
		break;

	case FIELD_OEM_UID_3:
		if (file_field.count == 1) {
			gd.oemuid[3] = STR_TO_UL(file_field.value[0], 16);
			gd.oemuid_flag[3] = 1;
			gd.flags |= (0x1 << FLAG_OUID3_SHIFT);
		}
		break;

	case FIELD_OEM_UID_4:
		if (file_field.count == 1) {
			gd.oemuid[4] = STR_TO_UL(file_field.value[0], 16);
			gd.oemuid_flag[4] = 1;
			gd.flags |= (0x1 << FLAG_OUID4_SHIFT);
		}
		break;

	case FIELD_OUTPUT_HDR_FILENAME:
		if (gd.hdr_file_flag != 0)
			break;
		if (file_field.count == 1) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.hdr_file_name, file_field.value[0]);
		} else {
			strcpy(gd.hdr_file_name, DEFAULT_HDR_FILE_NAME);
		}
		break;

	case FIELD_IMAGE_HASH_FILENAME:
		if (file_field.count == 1) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.img_hash_file_name, file_field.value[0]);
		} else
			strcpy(gd.img_hash_file_name, DEFAULT_HASH_FILE_NAME);
		break;

	case FIELD_RSA_SIGN_FILENAME:
		if (file_field.count == 1) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.rsa_sign_file_name, file_field.value[0]);
		} else
			strcpy(gd.rsa_sign_file_name, DEFAULT_SIGN_FILE_NAME);
		break;

	case FIELD_OUTPUT_SG_BIN:
		if (file_field.count == 1) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.sg_file_name, file_field.value[0]);
		} else
			strcpy(gd.sg_file_name, DEFAULT_SG_FILE_NAME);
		break;

	case FIELD_BOOT_SRC:
		if (file_field.count == 1) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.boot_src, file_field.value[0]);
			printf("gd.boot_src %s", gd.boot_src);
		}
		break;

	case FIELD_RCW_PBI_FILENAME:
		if (gd.rcw_file_flag != 0) {
			break;
		}
		if (file_field.count == 1) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.rcw_fname, file_field.value[0]);
		}
		break;
	case FIELD_OUTPUT_RCW_PBI_FILENAME:
		if (gd.rcw_opfile_flag != 0) {
			break;
		}
		 if (file_field.count == 1) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.rcw_op_fname, file_field.value[0]);
		} else
			strcpy(gd.rcw_op_fname, DEFAULT_OUTPUT_RCW_FILE_NAME);

		break;

	case FIELD_BOOT1_PTR:
		if (file_field.count == 1)
			gd.boot1_ptr = STR_TO_UL(file_field.value[0], 16);
		break;

	case FIELD_MP_FLAG:
		if (file_field.count == 1)
			gd.mp_flag = STR_TO_UL(file_field.value[0], 16);

		break;

	case FIELD_ISS_FLAG:
		if (file_field.count == 1)
			gd.iss_flag = STR_TO_UL(file_field.value[0], 16);

		break;

	case FIELD_LW_FLAG:
		if (file_field.count == 1)
			gd.lw_flag = STR_TO_UL(file_field.value[0], 16);

		break;
	case FIELD_BOOT_HO:
		if (file_field.count == 1) {
			gd.bootho_flag = 1;
			gd.boot_ho = STR_TO_UL(file_field.value[0], 16);
		}
		break;
	case FIELD_SB_EN:
		if (file_field.count == 1) {
			gd.sben_flag = 1;
			gd.option_sb_en = STR_TO_UL(file_field.value[0], 16);
		}
		break;
	case FIELD_VERBOSE:
		if (file_field.count == 1)
			gd.verbose_flag |= STR_TO_UL(file_field.value[0], 16);

		break;

	case FIELD_SEC_IMAGE:
		if (file_field.count == 1)
			gd.sec_image_flag = STR_TO_UL(file_field.value[0], 16);

		break;

	case FIELD_WP_FLAG:
		if (file_field.count == 1)
			gd.wp_flag = STR_TO_UL(file_field.value[0], 16);

		break;

	case FIELD_HK_AREA_POINTER:
		if (file_field.count == 1)
			gd.hkarea = STR_TO_UL(file_field.value[0], 16);

		break;

	case FIELD_HK_AREA_SIZE:
		if (file_field.count == 1)
			gd.hksize = STR_TO_UL(file_field.value[0], 16);

		break;

	case FIELD_SG_TABLE_ADDR:
		if (file_field.count == 1) {
			gd.sg_addr = STR_TO_UL(file_field.value[0], 16);
			gd.sg_flag = 1;
		}

		break;

	case FIELD_IMAGE_TARGET:
		if (file_field.count == 1)
			ret = check_target(file_field.value[0],
					&gd.img_target);

		break;

	case FIELD_ESBC_HDRADDR:
		if (file_field.count == 1)
			gd.hdr_addr = STR_TO_UL(file_field.value[0], 16);

		break;

	case FIELD_ESBC_HDRADDR_SEC_IMAGE:
		if (file_field.count == 1)
			gd.hdr_addr_sec = STR_TO_UL(file_field.value[0], 16);

		break;

	case FIELD_IE_KEY_SEL:
		if (file_field.count == 1) {
			gd.iek_sel = STR_TO_UL(file_field.value[0], 16);
			gd.iek_flag = 1;
		}
		break;
	case FIELD_IE_REVOC:
		gd.num_iek_revok = file_field.count;
		for (i = 0; i < file_field.count; i++) {

			if (i == MAX_NUM_IEKEY) {
				printf("\n IE Key Revok Number Limit reached");
				break;
			}

			uint32_t key_revoked = STR_TO_UL(
				file_field.value[i], 16);

			gd.iek_revok[i] = key_revoked;
		}
		break;

	case FIELD_IE_TABLE_ADDR:
		if (file_field.count == 1)
			gd.ie_table_addr = STR_TO_ULL(file_field.value[0], 16);

		break;

	case FIELD_POVDD_GPIO:
		if (file_field.count == 1) {
			gd.povdd_gpio = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_POVDD_SHIFT);
		} else
			gd.povdd_gpio = -1;
		break;

	case FIELD_OTPMK_FLAGS:
		if (file_field.count == 1) {
			flags = STR_TO_UL(file_field.value[0], 2);
			gd.flags |= ((flags & FLAG_OTPMK_MASK)
					<< FLAG_OTPMK_SHIFT);
		}
		break;

	case FIELD_OTPMK_0:
		if (file_field.count == 1)
			gd.otpmk[0] = STR_TO_UL(file_field.value[0], 16);
		break;

	case FIELD_OTPMK_1:
		if (file_field.count == 1)
			gd.otpmk[1] = STR_TO_UL(file_field.value[0], 16);
		break;

	case FIELD_OTPMK_2:
		if (file_field.count == 1)
			gd.otpmk[2] = STR_TO_UL(file_field.value[0], 16);
		break;

	case FIELD_OTPMK_3:
		if (file_field.count == 1)
			gd.otpmk[3] = STR_TO_UL(file_field.value[0], 16);
		break;

	case FIELD_OTPMK_4:
		if (file_field.count == 1)
			gd.otpmk[4] = STR_TO_UL(file_field.value[0], 16);
		break;

	case FIELD_OTPMK_5:
		if (file_field.count == 1)
			gd.otpmk[5] = STR_TO_UL(file_field.value[0], 16);
		break;

	case FIELD_OTPMK_6:
		if (file_field.count == 1)
			gd.otpmk[6] = STR_TO_UL(file_field.value[0], 16);
		break;

	case FIELD_OTPMK_7:
		if (file_field.count == 1)
			gd.otpmk[7] = STR_TO_UL(file_field.value[0], 16);
		break;

	case FIELD_SRKH_0:
		if (file_field.count == 1) {
			gd.srkh[0] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_SRKH_SHIFT);
		}
		break;

	case FIELD_SRKH_1:
		if (file_field.count == 1) {
			gd.srkh[1] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_SRKH_SHIFT);
		}
		break;

	case FIELD_SRKH_2:
		if (file_field.count == 1) {
			gd.srkh[2] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_SRKH_SHIFT);
		}
		break;

	case FIELD_SRKH_3:
		if (file_field.count == 1) {
			gd.srkh[3] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_SRKH_SHIFT);
		}
		break;

	case FIELD_SRKH_4:
		if (file_field.count == 1) {
			gd.srkh[4] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_SRKH_SHIFT);
		}
		break;

	case FIELD_SRKH_5:
		if (file_field.count == 1) {
			gd.srkh[5] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_SRKH_SHIFT);
		}
		break;

	case FIELD_SRKH_6:
		if (file_field.count == 1) {
			gd.srkh[6] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_SRKH_SHIFT);
		}
		break;

	case FIELD_SRKH_7:
		if (file_field.count == 1) {
			gd.srkh[7] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_SRKH_SHIFT);
		}
		break;

	case FIELD_DCV_0:
		if (file_field.count == 1) {
			gd.dcv[0] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_DCV0_SHIFT);
		}
		break;

	case FIELD_DCV_1:
		if (file_field.count == 1) {
			gd.dcv[1] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_DCV1_SHIFT);
		}
		break;

	case FIELD_DRV_0:
		if (file_field.count == 1) {
			gd.drv[0] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_DRV0_SHIFT);
		}
		break;

	case FIELD_DRV_1:
		if (file_field.count == 1) {
			gd.drv[1] = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_DRV1_SHIFT);
		}
		break;

	case FIELD_MC_ERA:
		if (file_field.count == 1) {
			gd.mc_era = STR_TO_UL(file_field.value[0], 16);
			gd.flags |= (0x1 << FLAG_MC_SHIFT);
		}
		break;

	case FIELD_DBG_LVL:
		if (file_field.count == 1) {
			gd.dbg_lvl = STR_TO_UL(file_field.value[0], 2);
			gd.flags |= (0x1 << FLAG_DBG_LVL_SHIFT);
		}
		break;

	case FIELD_WP:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_WP_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_ITS:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_ITS_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_NSEC:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_NSEC_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_ZD:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_ZD_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_K0:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_K0_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_K1:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_K1_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_K2:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_K2_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_K3:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_K3_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_K4:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_K4_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_K5:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_K5_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_K6:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_K6_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_FR0:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_FR0_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_FR1:
		if (file_field.count == 1) {
			i = STR_TO_UL(file_field.value[0], 16);
			gd.scb = gd.scb | ((i & 0x1) << SCB_FR1_SHIFT);
			gd.flags |= (0x1 << FLAG_SYSCFG_SHIFT);
		}
		break;

	case FIELD_OUTPUT_FUSE_FILENAME:
		 if (file_field.count == 1) {
			check_field_length(field_name, file_field.value[0]);
			strcpy(gd.fuse_op_fname, file_field.value[0]);
		} else
			strcpy(gd.fuse_op_fname, DEFAULT_OUTPUT_RCW_FILE_NAME);

		break;

	default:
		printf("\n Invalid Field being parsed");
		return FAILURE;
	}

	return ret;
}

int get_file_size(const char *c)
{
	FILE *fp;
	unsigned char buf[IOBLOCK];
	int bytes = 0;

	fp = fopen(c, "rb");
	if (fp == NULL) {
		fprintf(stderr, "Error in opening the file: %s\n", c);
		return FAILURE;
	}

	while (!feof(fp)) {
		/* read some data */
		bytes += fread(buf, 1, IOBLOCK, fp);
		if (ferror(fp)) {
			fprintf(stderr, "Error in reading file\n");
			fclose(fp);
			exit(EXIT_FAILURE);
		} else if (feof(fp) && (bytes == 0)) {
			break;
		}
	}

	fclose(fp);
	return bytes;
}
