/*
 * Copyright 2026 Free Mobile, Vincent Jardin
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the above-listed copyright holders nor the
 *       names of any contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <verify.h>
#include <crypto_utils.h>

struct g_data_t gd;

enum {
	OPT_HDR = 256,
	OPT_IMG,
	OPT_IN,
	OPT_PBL,
	OPT_FLASH_BASE,
	OPT_XIP_WINDOW,
	OPT_HDR_SIZE,
	OPT_PLATFORM,
	OPT_TA,
	OPT_PUB,
	OPT_SRK_HASH,
	OPT_REVOKE_MASK,
	OPT_JSON,
};

static const struct option long_options[] = {
	{"hdr", required_argument, 0, OPT_HDR},
	{"img", required_argument, 0, OPT_IMG},
	{"in", required_argument, 0, OPT_IN},
	{"pbl", required_argument, 0, OPT_PBL},
	{"flash-base", required_argument, 0, OPT_FLASH_BASE},
	{"xip-window", required_argument, 0, OPT_XIP_WINDOW},
	{"hdr-size", required_argument, 0, OPT_HDR_SIZE},
	{"platform", required_argument, 0, OPT_PLATFORM},
	{"ta", required_argument, 0, OPT_TA},
	{"pub", required_argument, 0, OPT_PUB},
	{"srk-hash", required_argument, 0, OPT_SRK_HASH},
	{"revoke-mask", required_argument, 0, OPT_REVOKE_MASK},
	{"json", no_argument, 0, OPT_JSON},
	{"verbose", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static void print_usage(void)
{
	printf("Usage:\n"
	       "  cst_verify esbc --hdr <hdr> --img <image> [common]\n"
	       "  cst_verify esbc --in <image with prepended header> [common]\n"
	       "  cst_verify isbc --hdr <hdr_bl2> --img <img1> [--img <img2> ...] [common]\n"
	       "  cst_verify pbi  --pbl <pbl> [common]\n"
	       "  cst_verify pbl  --pbl <pbl> --flash-base <addr> [--xip-window <base>:<size>] [common]\n"
	       "  cst_verify dump <esbc|isbc|pbi|pbl> <same arguments>\n"
	       "\n"
	       "Verify the CSF headers, PBI and images produced by CST for the\n"
	       "trust architecture 3.x BootROM and TF-A BL2, from the output\n"
	       "files only.\n"
	       "\n"
	       "common:\n"
	       "  --platform <name>     LX2160, LS1028, LS2088, LS1088, LS2085 (default: TA 3.1 layout)\n"
	       "  --ta 3.0|3.1|3.2      trust architecture instead of --platform\n"
	       "  --pub <pem>[,<pem>..] expected SRK public keys, the whole table in order\n"
	       "  --srk-hash <hex>      expected SRK table hash (SFP SRKH), 64 hex digits\n"
	       "  --revoke-mask <hex>   SFP key revocation bits (SFP_OSPR[KEY_REVOC])\n"
	       "  --hdr-size <n>        image offset BL2 expects in --in files (default 0x%x, 0 = any)\n"
	       "  --json                machine readable report\n"
	       "  -v, --verbose         print every check, not only the failures\n"
	       "\n"
	       "Exit status: 0 all checks pass, 1 at least one check fails,\n"
	       "2 usage or I/O error.\n", VR_DEFAULT_HDR_SIZE);
}

static int parse_mode(const char *s, enum verify_mode *m)
{
	if (strcmp(s, "esbc") == 0)
		*m = VERIFY_ESBC;
	else if (strcmp(s, "isbc") == 0)
		*m = VERIFY_ISBC;
	else if (strcmp(s, "pbi") == 0)
		*m = VERIFY_PBI;
	else if (strcmp(s, "pbl") == 0)
		*m = VERIFY_PBL;
	else
		return -1;
	return 0;
}

static int parse_ta(const char *s, enum cfg_taal *ta)
{
	if (strcmp(s, "3.0") == 0)
		*ta = TA_3_0;
	else if (strcmp(s, "3.1") == 0)
		*ta = TA_3_1;
	else if (strcmp(s, "3.2") == 0)
		*ta = TA_3_2;
	else
		return -1;
	return 0;
}

static int parse_pub(struct verify_req *r, char *list)
{
	char *tok, *save = NULL;

	for (tok = strtok_r(list, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		if (r->num_pub == VR_MAX_PUB) {
			fprintf(stderr, "cst_verify: at most %d --pub keys\n",
				VR_MAX_PUB);
			return -1;
		}
		memset(&r->pub[r->num_pub], 0, sizeof(r->pub[0]));
		if (crypto_extract_pub_key(tok, &r->pub[r->num_pub].key_len,
					   r->pub[r->num_pub].pkey) != SUCCESS)
			return -1;
		r->num_pub++;
	}
	return r->num_pub ? 0 : -1;
}

static int parse_xip(struct verify_req *r, char *arg)
{
	char *colon = strchr(arg, ':');

	if (colon == NULL)
		return -1;
	*colon = '\0';
	if (vr_parse_u64(arg, &r->xip_base) != 0 ||
	    vr_parse_u64(colon + 1, &r->xip_size) != 0)
		return -1;
	r->xip_set = 1;
	return 0;
}

static void free_req(struct verify_req *r)
{
	int i;

	vr_free_blob(&r->hdr);
	vr_free_blob(&r->in);
	for (i = 0; i < r->num_img; i++)
		vr_free_blob(&r->img[i]);
	free(r->items);
}

int main(int argc, char **argv)
{
	struct verify_req r;
	const char *hdr_name = NULL, *in_name = NULL;
	const char *img_name[VR_MAX_IMG];
	int num_img = 0, i, c, ret;
	uint64_t v;

	memset(&r, 0, sizeof(r));
	r.hdr_size = VR_DEFAULT_HDR_SIZE;
	r.ta = TA_3_1;

	if (argc < 2) {
		print_usage();
		return VR_EXIT_ERROR;
	}
	if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		print_usage();
		return VR_EXIT_PASS;
	}
	optind = 1;
	if (strcmp(argv[1], "dump") == 0) {
		r.dump = 1;
		optind = 2;
	}
	if (optind >= argc || parse_mode(argv[optind], &r.mode) != 0) {
		fprintf(stderr, "cst_verify: expected esbc, isbc, pbi or pbl\n");
		return VR_EXIT_ERROR;
	}
	optind++;

	while ((c = getopt_long(argc, argv, "vh", long_options, NULL)) != -1) {
		switch (c) {
		case OPT_HDR:
			hdr_name = optarg;
			break;
		case OPT_IMG:
			if (num_img == VR_MAX_IMG) {
				fprintf(stderr, "cst_verify: at most %d --img\n",
					VR_MAX_IMG);
				return VR_EXIT_ERROR;
			}
			img_name[num_img++] = optarg;
			break;
		case OPT_IN:
		case OPT_PBL:
			in_name = optarg;
			break;
		case OPT_FLASH_BASE:
			if (vr_parse_u64(optarg, &r.flash_base) != 0)
				goto bad_arg;
			r.flash_base_set = 1;
			break;
		case OPT_XIP_WINDOW:
			if (parse_xip(&r, optarg) != 0)
				goto bad_arg;
			break;
		case OPT_HDR_SIZE:
			if (vr_parse_u64(optarg, &v) != 0 || v > 0xffffffffULL)
				goto bad_arg;
			r.hdr_size = (uint32_t)v;
			break;
		case OPT_PLATFORM:
			r.ta = get_ta_from_platform(optarg);
			if (r.ta != TA_3_0 && r.ta != TA_3_1 && r.ta != TA_3_2) {
				fprintf(stderr, "cst_verify: platform %s: only trust architecture 3.x is supported\n",
					optarg);
				return VR_EXIT_ERROR;
			}
			r.ta_set = 1;
			break;
		case OPT_TA:
			if (parse_ta(optarg, &r.ta) != 0)
				goto bad_arg;
			r.ta_set = 1;
			break;
		case OPT_PUB:
			if (parse_pub(&r, optarg) != 0)
				return VR_EXIT_ERROR;
			break;
		case OPT_SRK_HASH:
			if (vr_parse_hex(optarg, r.srk_hash, VR_HASH_LEN) != 0)
				goto bad_arg;
			r.srk_hash_set = 1;
			break;
		case OPT_REVOKE_MASK:
			if (vr_parse_u64(optarg, &v) != 0 || v > 0xffffffffULL)
				goto bad_arg;
			r.revoke_mask = (uint32_t)v;
			r.revoke_set = 1;
			break;
		case OPT_JSON:
			r.json = 1;
			break;
		case 'v':
			r.verbose = 1;
			break;
		case 'h':
			print_usage();
			return VR_EXIT_PASS;
		default:
			print_usage();
			return VR_EXIT_ERROR;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "cst_verify: unexpected argument %s\n",
			argv[optind]);
		return VR_EXIT_ERROR;
	}

	if (hdr_name && vr_load_file(&r.hdr, hdr_name) != 0)
		return VR_EXIT_ERROR;
	if (in_name && vr_load_file(&r.in, in_name) != 0)
		return VR_EXIT_ERROR;
	for (i = 0; i < num_img; i++) {
		if (vr_load_file(&r.img[i], img_name[i]) != 0)
			return VR_EXIT_ERROR;
		r.num_img++;
	}

	if (!r.ta_set && !r.dump)
		vr_report(&r, "TA", VR_INFO,
			  "no --platform given, assuming the TA 3.1/3.2 header layout (LX2160, LS1028, LS2088, LS1088)");

	ret = taal_verify(r.ta, &r);
	if (r.dump) {
		free_req(&r);
		return ret == SUCCESS ? VR_EXIT_PASS : VR_EXIT_ERROR;
	}
	if (ret != SUCCESS)
		r.error = 1;
	vr_print_report(&r);
	ret = vr_exit_code(&r);
	free_req(&r);
	return ret;

bad_arg:
	fprintf(stderr, "cst_verify: invalid value for %s: %s\n",
		argv[optind - 2], optarg);
	return VR_EXIT_ERROR;
}
