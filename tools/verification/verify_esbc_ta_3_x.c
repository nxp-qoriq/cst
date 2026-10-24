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
#include <string.h>

#include <verify.h>
#include <crypto_utils.h>

/***************************************************************************
 * Function	:	esbc_locate
 * Description	:	Select the header buffer and the image of an ESBC
 *			request, from --in (header followed by the image) or
 *			from --hdr and --img
 ***************************************************************************/
static int esbc_locate(struct verify_req *r, const uint8_t **hdr,
		       size_t *hdr_len, const char **hdr_name)
{
	if (r->in.data) {
		*hdr = r->in.data;
		*hdr_len = r->in.len;
		*hdr_name = r->in.name;
	} else if (r->hdr.data) {
		*hdr = r->hdr.data;
		*hdr_len = r->hdr.len;
		*hdr_name = r->hdr.name;
	} else {
		fprintf(stderr, "cst_verify: esbc needs --in or --hdr\n");
		return -1;
	}
	if (*hdr_len < VR_CSF_HDR_SIZE) {
		fprintf(stderr, "cst_verify: %s: %zu bytes, shorter than a CSF header\n",
			*hdr_name, *hdr_len);
		return -1;
	}
	return 0;
}

static void esbc_dump(struct verify_req *r, const char *name,
		      const uint8_t *buf, size_t len,
		      const struct csf_hdr_view *h)
{
	struct srk_view srk;

	printf("ESBC header %s (%zu bytes)\n", name, len);
	csf_dump_hdr(h);
	if (srk_view_init(&srk, buf, len, h->srk_tbl_off, h->num_srk) == 0)
		srk_dump(&srk);
	else
		printf("  SRK table outside the file\n");
	if (r->in.data && h->img_len <= len)
		printf("  image             : last 0x%x bytes, at offset 0x%zx\n",
		       h->img_len, len - h->img_len);
	else if (r->num_img)
		printf("  image             : %s (%zu bytes)\n", r->img[0].name,
		       r->img[0].len);
}

static const char *const esbc_ids[CK_MAX] = {
	[CK_BARKER] = "E1",
	[CK_NUM_SRK] = "E2",
	[CK_SRK_SEL] = "E3",
	[CK_REVOKED] = "E4",
	[CK_KEY_LEN] = "E5",
	[CK_SIGN_LEN] = "E6",
	[CK_SIG_LT_MOD] = "E7",
	[CK_SRKH] = "E8",
	[CK_SIGNATURE] = "E9",
	[CK_BOUNDS] = "E10",
	[CK_MODULUS] = "E11",
	[CK_PUB] = "E12",
};

/***************************************************************************
 * Function	:	esbc_verify
 * Description	:	Replay the checks of TF-A validate_esbc_header() and
 *			calc_img_hash() on an ESBC header and its image
 ***************************************************************************/
static void esbc_verify(struct verify_req *r, const uint8_t *buf, size_t len,
			const struct csf_hdr_view *h)
{
	struct srk_view srk;
	struct vr_key key;
	const uint8_t *img;
	uint64_t img_off, hdr_end;
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	uint8_t hash[VR_HASH_LEN];

	vr_report(r, "E0", VR_INFO, "image address 0x%llx, image length 0x%x",
		  (unsigned long long)h->img_addr, h->img_len);
	vr_report_flags(r, "E0", h);

	if (vr_check_barker(r, esbc_ids[CK_BARKER], h) != 0)
		return;
	if (vr_check_srk(r, esbc_ids, h, buf, len, 0, &srk, &key) != 0)
		return;

	if (h->misc_flags & 0x01) {
		vr_report(r, "E14", VR_FAIL,
			  "IE key extension flag set, not supported");
		return;
	}
	vr_report(r, "E14", VR_PASS, "no IE key extension");

	hdr_end = (uint64_t)h->psign + h->sign_len;
	if (r->in.data) {
		if (h->img_len > len || len - h->img_len < hdr_end) {
			vr_report(r, esbc_ids[CK_BOUNDS], VR_FAIL,
				  "image length 0x%x does not fit after the header (0x%llx bytes) in the %zu byte file",
				  h->img_len, (unsigned long long)hdr_end, len);
			return;
		}
		img_off = len - h->img_len;
		img = buf + img_off;
		vr_report(r, esbc_ids[CK_BOUNDS], VR_PASS,
			  "image of 0x%x bytes at offset 0x%llx", h->img_len,
			  (unsigned long long)img_off);
		if (r->hdr_size == 0)
			vr_report(r, "E13", VR_SKIP, "--hdr-size 0, image offset not checked");
		else if (img_off != r->hdr_size)
			vr_report(r, "E13", VR_FAIL,
				  "image at offset 0x%llx, BL2 hashes from 0x%x (CSF_HDR_SZ)",
				  (unsigned long long)img_off, r->hdr_size);
		else
			vr_report(r, "E13", VR_PASS,
				  "image offset 0x%llx matches CSF_HDR_SZ",
				  (unsigned long long)img_off);
	} else {
		if (r->num_img != 1) {
			vr_report(r, esbc_ids[CK_BOUNDS], VR_FAIL,
				  "esbc --hdr needs exactly one --img, %d given",
				  r->num_img);
			return;
		}
		if (r->img[0].len != h->img_len) {
			vr_report(r, esbc_ids[CK_BOUNDS], VR_FAIL,
				  "image length field 0x%x, %s is 0x%zx bytes",
				  h->img_len, r->img[0].name, r->img[0].len);
			return;
		}
		img = r->img[0].data;
		vr_report(r, esbc_ids[CK_BOUNDS], VR_PASS,
			  "image %s matches the image length 0x%x",
			  r->img[0].name, h->img_len);
		vr_report(r, "E13", VR_SKIP, "image given separately");
	}

	crypto_hash_init(ctx);
	crypto_hash_update(ctx, (void *)buf, VR_CSF_HDR_SIZE);
	crypto_hash_update(ctx, (void *)srk.tbl, srk.len);
	crypto_hash_update(ctx, (void *)img, h->img_len);
	crypto_hash_final(hash, ctx);
	vr_check_signature(r, esbc_ids[CK_SIGNATURE], hash, buf + h->psign,
			   h->sign_len, &key, "header, SRK table and image");
}

int verify_esbc_ta_3_x(struct verify_req *r, int ta30)
{
	const uint8_t *buf;
	size_t len;
	const char *name;
	struct csf_hdr_view h;

	if (esbc_locate(r, &buf, &len, &name) != 0)
		return FAILURE;
	csf_parse_hdr(buf, len, CSF_ESBC, ta30, &h);

	if (r->dump) {
		esbc_dump(r, name, buf, len, &h);
		return SUCCESS;
	}

	esbc_verify(r, buf, len, &h);
	return SUCCESS;
}
