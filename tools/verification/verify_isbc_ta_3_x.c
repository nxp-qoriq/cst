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

static void isbc_dump(const char *name, const uint8_t *buf, size_t len,
		      int ta30, const struct csf_hdr_view *h,
		      const struct verify_blob *img, int num_img)
{
	struct srk_view srk;
	struct sg_entry_view sg[VR_MAX_IMG];
	int i;

	printf("ISBC header %s (%zu bytes)\n", name, len);
	csf_dump_hdr(h);
	if (srk_view_init(&srk, buf, len, h->srk_tbl_off, h->num_srk) == 0)
		srk_dump(&srk);
	else
		printf("  SRK table outside the file\n");
	if (sg_parse(buf, len, h->sg_off, h->sg_entries, ta30, sg) == 0)
		sg_dump(sg, h->sg_entries);
	else
		printf("  SG table outside the file\n");
	for (i = 0; i < num_img; i++)
		printf("  image %d           : %s (%zu bytes)\n", i + 1,
		       img[i].name, img[i].len);
}

static const char *const isbc_ids[CK_MAX] = {
	[CK_BARKER] = "I1",
	[CK_NUM_SRK] = "I2",
	[CK_SRK_SEL] = "I3",
	[CK_REVOKED] = "I11",
	[CK_KEY_LEN] = "I4",
	[CK_SIGN_LEN] = "I4",
	[CK_SIG_LT_MOD] = "I4",
	[CK_SRKH] = "I5",
	[CK_SIGNATURE] = "I7",
	[CK_BOUNDS] = "I10",
	[CK_MODULUS] = "I13",
	[CK_PUB] = "I12",
};

/***************************************************************************
 * Function	:	verify_isbc_buffers
 * Arguments	:	what - where the header comes from, for messages
 *			hdr, hdr_len - header, SRK table, SG table, signature
 *			img, num_img - the images, one per SG entry, in order
 * Return	:	0 when every check ran, -1 when a check stopped them
 * Description	:	Replay the BootROM validation of a Boot1 (ISBC) header
 ***************************************************************************/
int verify_isbc_buffers(struct verify_req *r, int ta30, const char *what,
			const uint8_t *hdr, size_t hdr_len,
			const struct verify_blob *img, int num_img,
			struct csf_hdr_view *out_hdr, struct srk_view *out_srk,
			struct sg_entry_view *out_sg)
{
	struct csf_hdr_view h;
	struct srk_view srk;
	struct vr_key key;
	struct sg_entry_view sg[VR_MAX_IMG];
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	uint8_t hash[VR_HASH_LEN];
	uint32_t i;
	int bad = 0, ep_in = -1;

	if (csf_parse_hdr(hdr, hdr_len, CSF_ISBC, ta30, &h) != 0) {
		vr_report(r, isbc_ids[CK_BOUNDS], VR_FAIL,
			  "%s: %zu bytes, shorter than a CSF header", what,
			  hdr_len);
		return -1;
	}
	if (out_hdr)
		*out_hdr = h;
	vr_report(r, "I0", VR_INFO, "entry point 0x%llx, %u SG entries",
		  (unsigned long long)h.entry_point, h.sg_entries);
	vr_report_flags(r, "I0", &h);

	if (vr_check_barker(r, isbc_ids[CK_BARKER], &h) != 0)
		return -1;
	if (vr_check_srk(r, isbc_ids, &h, hdr, hdr_len, 0, &srk, &key) != 0)
		return -1;
	if (out_srk)
		*out_srk = srk;

	if ((h.misc_flags & 0x40) == 0) {
		vr_report(r, "I9", VR_FAIL,
			  "B01 flag clear, the BootROM expects it set in a Boot1 header");
		return -1;
	}
	if (h.misc_flags & 0x01) {
		vr_report(r, "I9", VR_FAIL,
			  "IE key extension flag set, not supported");
		return -1;
	}
	vr_report(r, "I9", VR_PASS, "B01 flag set, no IE key extension");

	if (h.sg_entries == 0 || h.sg_entries > VR_MAX_IMG) {
		vr_report(r, "I6", VR_FAIL, "%u SG entries, allowed 1 to %d",
			  h.sg_entries, VR_MAX_IMG);
		return -1;
	}
	if (sg_parse(hdr, hdr_len, h.sg_off, h.sg_entries, ta30, sg) != 0) {
		vr_report(r, "I6", VR_FAIL,
			  "SG table at 0x%x + %u * %zu bytes is outside %s (%zu bytes)",
			  h.sg_off, h.sg_entries, VR_SG_ENTRY_SIZE, what,
			  hdr_len);
		return -1;
	}
	vr_report(r, "I6", VR_PASS, "%u SG entries at 0x%x", h.sg_entries,
		  h.sg_off);
	if (out_sg)
		memcpy(out_sg, sg, sizeof(sg));

	if ((uint32_t)num_img != h.sg_entries) {
		vr_report(r, isbc_ids[CK_BOUNDS], VR_FAIL,
			  "%d image(s) for %u SG entries", num_img, h.sg_entries);
		return -1;
	}
	for (i = 0; i < h.sg_entries; i++) {
		if (img[i].len != sg[i].len) {
			vr_report(r, isbc_ids[CK_BOUNDS], VR_FAIL,
				  "SG %u length 0x%x, %s is 0x%zx bytes", i + 1,
				  sg[i].len, img[i].name, img[i].len);
			bad = 1;
		}
	}
	if (bad)
		return -1;
	vr_report(r, isbc_ids[CK_BOUNDS], VR_PASS,
		  "image sizes match the SG table");

	crypto_hash_init(ctx);
	crypto_hash_update(ctx, (void *)hdr, VR_CSF_HDR_SIZE);
	crypto_hash_update(ctx, (void *)srk.tbl, srk.len);
	crypto_hash_update(ctx, (void *)(hdr + h.sg_off),
			   h.sg_entries * VR_SG_ENTRY_SIZE);
	for (i = 0; i < h.sg_entries; i++)
		crypto_hash_update(ctx, img[i].data, img[i].len);
	crypto_hash_final(hash, ctx);
	if (vr_check_signature(r, isbc_ids[CK_SIGNATURE], hash, hdr + h.psign,
			       h.sign_len, &key,
			       "header, SRK table, SG table and images") != 0)
		bad = 1;

	for (i = 0; i < h.sg_entries; i++) {
		if (h.entry_point >= sg[i].src &&
		    h.entry_point - sg[i].src < sg[i].len)
			ep_in = i + 1;
	}
	if (ep_in < 0) {
		vr_report(r, "I8", VR_FAIL,
			  "entry point 0x%llx is outside every SG region",
			  (unsigned long long)h.entry_point);
		bad = 1;
	} else {
		vr_report(r, "I8", VR_PASS, "entry point 0x%llx inside SG %d",
			  (unsigned long long)h.entry_point, ep_in);
	}
	return bad ? -1 : 0;
}

int verify_isbc_ta_3_x(struct verify_req *r, int ta30)
{
	struct csf_hdr_view h;

	if (r->hdr.data == NULL) {
		fprintf(stderr, "cst_verify: isbc needs --hdr\n");
		return FAILURE;
	}
	if (r->hdr.len < VR_CSF_HDR_SIZE) {
		fprintf(stderr, "cst_verify: %s: %zu bytes, shorter than a CSF header\n",
			r->hdr.name, r->hdr.len);
		return FAILURE;
	}
	csf_parse_hdr(r->hdr.data, r->hdr.len, CSF_ISBC, ta30, &h);

	if (r->dump) {
		isbc_dump(r->hdr.name, r->hdr.data, r->hdr.len, ta30, &h,
			  r->img, r->num_img);
		return SUCCESS;
	}

	if (r->num_img == 0) {
		fprintf(stderr, "cst_verify: isbc needs one --img per SG entry\n");
		return FAILURE;
	}
	verify_isbc_buffers(r, ta30, r->hdr.name, r->hdr.data, r->hdr.len,
			    r->img, r->num_img, NULL, NULL, NULL);
	return SUCCESS;
}
