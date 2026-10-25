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
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>

#include <json-c/json.h>

#include <verify.h>
#include <crypto_utils.h>

#define VR_MAX_FILE_SIZE	(256UL * 1024 * 1024)

static const uint8_t barker_ta_3_x[BARKER_LEN] = { 0x12, 0x19, 0x20, 0x01 };

static const char *vr_status_name(enum vr_status st)
{
	switch (st) {
	case VR_PASS:
		return "PASS";
	case VR_FAIL:
		return "FAIL";
	case VR_SKIP:
		return "SKIP";
	case VR_INFO:
		return "INFO";
	}
	return "?";
}

void vr_report(struct verify_req *r, const char *id, enum vr_status st,
	       const char *fmt, ...)
{
	struct vr_item *it;
	va_list ap;

	if (r->num_items == r->cap_items) {
		int cap = r->cap_items ? r->cap_items * 2 : 32;
		struct vr_item *n = realloc(r->items, cap * sizeof(*n));

		if (n == NULL) {
			fprintf(stderr, "cst_verify: out of memory\n");
			exit(VR_EXIT_ERROR);
		}
		r->items = n;
		r->cap_items = cap;
	}
	it = &r->items[r->num_items++];
	memset(it, 0, sizeof(*it));
	snprintf(it->id, sizeof(it->id), "%s", id);
	it->status = st;
	va_start(ap, fmt);
	vsnprintf(it->msg, sizeof(it->msg), fmt, ap);
	va_end(ap);
	if (st == VR_FAIL)
		r->num_fail++;
}

int vr_load_file(struct verify_blob *b, const char *name)
{
	FILE *fp;
	long size;

	fp = fopen(name, "rb");
	if (fp == NULL) {
		fprintf(stderr, "cst_verify: cannot open %s: %s\n", name,
			strerror(errno));
		return -1;
	}
	if (fseek(fp, 0, SEEK_END) != 0 || (size = ftell(fp)) < 0 ||
	    (unsigned long)size > VR_MAX_FILE_SIZE ||
	    fseek(fp, 0, SEEK_SET) != 0) {
		fprintf(stderr, "cst_verify: cannot size %s\n", name);
		fclose(fp);
		return -1;
	}
	b->data = malloc(size ? size : 1);
	if (b->data == NULL) {
		fprintf(stderr, "cst_verify: out of memory\n");
		fclose(fp);
		return -1;
	}
	if (size && fread(b->data, 1, size, fp) != (size_t)size) {
		fprintf(stderr, "cst_verify: cannot read %s\n", name);
		fclose(fp);
		free(b->data);
		b->data = NULL;
		return -1;
	}
	fclose(fp);
	b->name = name;
	b->len = size;
	return 0;
}

void vr_free_blob(struct verify_blob *b)
{
	free(b->data);
	b->data = NULL;
	b->len = 0;
}

int vr_in_range(size_t len, uint64_t off, uint64_t n)
{
	return off <= len && n <= len - off;
}

int vr_rd32(const uint8_t *p, size_t len, uint64_t off, uint32_t *v)
{
	if (!vr_in_range(len, off, 4))
		return -1;
	*v = (uint32_t)p[off] | ((uint32_t)p[off + 1] << 8) |
	     ((uint32_t)p[off + 2] << 16) | ((uint32_t)p[off + 3] << 24);
	return 0;
}

int vr_parse_u64(const char *s, uint64_t *v)
{
	char *end;

	if (s == NULL || *s == '\0')
		return -1;
	errno = 0;
	*v = strtoull(s, &end, 0);
	if (errno != 0 || *end != '\0')
		return -1;
	return 0;
}

int vr_parse_hex(const char *s, uint8_t *out, size_t n)
{
	size_t i;

	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		s += 2;
	if (strlen(s) != 2 * n)
		return -1;
	for (i = 0; i < 2 * n; i++) {
		int c = tolower((unsigned char)s[i]);
		int d;

		if (c >= '0' && c <= '9')
			d = c - '0';
		else if (c >= 'a' && c <= 'f')
			d = c - 'a' + 10;
		else
			return -1;
		if (i % 2 == 0)
			out[i / 2] = d << 4;
		else
			out[i / 2] |= d;
	}
	return 0;
}

void vr_hex(char *dst, const uint8_t *p, size_t n)
{
	static const char digits[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		dst[2 * i] = digits[p[i] >> 4];
		dst[2 * i + 1] = digits[p[i] & 0xf];
	}
	dst[2 * n] = '\0';
}

static const char *mode_name(enum verify_mode m)
{
	switch (m) {
	case VERIFY_ESBC:
		return "esbc";
	case VERIFY_ISBC:
		return "isbc";
	case VERIFY_PBI:
		return "pbi";
	case VERIFY_PBL:
		return "pbl";
	}
	return "?";
}

void vr_print_report(struct verify_req *r)
{
	int i, checks = 0;
	char hex[2 * VR_HASH_LEN + 1];

	for (i = 0; i < r->num_items; i++)
		if (r->items[i].status != VR_INFO)
			checks++;

	if (r->json) {
		struct json_object *root = json_object_new_object();
		struct json_object *list = json_object_new_array();

		if (root == NULL || list == NULL) {
			fprintf(stderr, "cst_verify: out of memory\n");
			exit(VR_EXIT_ERROR);
		}
		json_object_object_add(root, "mode",
				       json_object_new_string(mode_name(r->mode)));
		for (i = 0; i < r->num_items; i++) {
			struct vr_item *it = &r->items[i];
			struct json_object *o = json_object_new_object();

			json_object_object_add(o, "id", json_object_new_string(it->id));
			json_object_object_add(o, "status",
					       json_object_new_string(vr_status_name(it->status)));
			json_object_object_add(o, "msg", json_object_new_string(it->msg));
			json_object_array_add(list, o);
		}
		json_object_object_add(root, "checks", list);
		if (r->img_hash_set) {
			vr_hex(hex, r->img_hash, VR_HASH_LEN);
			json_object_object_add(root, "image_hash",
					       json_object_new_string(hex));
		}
		if (r->srkh_set) {
			vr_hex(hex, r->srkh, VR_HASH_LEN);
			json_object_object_add(root, "srk_hash",
					       json_object_new_string(hex));
		}
		json_object_object_add(root, "failed", json_object_new_int(r->num_fail));
		json_object_object_add(root, "checks_run", json_object_new_int(checks));
		json_object_object_add(root, "verdict",
				       json_object_new_string(r->error ? "ERROR" :
							      r->num_fail ? "FAIL" : "PASS"));
		printf("%s\n", json_object_to_json_string_ext(root,
			JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED |
			JSON_C_TO_STRING_NOSLASHESCAPE));
		json_object_put(root);
		return;
	}

	for (i = 0; i < r->num_items; i++) {
		struct vr_item *it = &r->items[i];

		if (it->status == VR_FAIL || r->verbose)
			printf("%s %s: %s\n", it->id, vr_status_name(it->status),
			       it->msg);
	}
	if (r->srkh_set && (r->verbose || r->num_fail == 0)) {
		vr_hex(hex, r->srkh, VR_HASH_LEN);
		printf("SRK hash: %s\n", hex);
	}
	if (r->error)
		printf("verdict: ERROR\n");
	else if (r->num_fail)
		printf("verdict: FAIL (%d of %d checks failed)\n", r->num_fail,
		       checks);
	else
		printf("verdict: PASS (%d checks)\n", checks);
}

int vr_exit_code(struct verify_req *r)
{
	if (r->error)
		return VR_EXIT_ERROR;
	return r->num_fail ? VR_EXIT_FAIL : VR_EXIT_PASS;
}

/***************************************************************************
 * CSF header, SRK table and SG table views
 ***************************************************************************/
int csf_parse_hdr(const uint8_t *p, size_t len, enum csf_kind kind, int ta30,
		  struct csf_hdr_view *h)
{
	uint32_t lo, hi, uid_base;
	int i;

	if (len < VR_CSF_HDR_SIZE)
		return -1;
	memset(h, 0, sizeof(*h));
	h->kind = kind;
	h->ta30 = ta30;
	memcpy(h->barker, p, BARKER_LEN);
	vr_rd32(p, len, 0x04, &h->srk_tbl_off);
	h->num_srk = p[0x08];
	h->srk_sel = p[0x09];
	h->misc_flags = p[0x0b];
	h->uid_flags = p[0x0f];
	vr_rd32(p, len, 0x10, &h->psign);
	vr_rd32(p, len, 0x14, &h->sign_len);

	switch (kind) {
	case CSF_ESBC:
		vr_rd32(p, len, 0x18, &lo);
		vr_rd32(p, len, 0x1c, &hi);
		h->img_addr = ((uint64_t)hi << 32) | lo;
		vr_rd32(p, len, 0x20, &h->img_len);
		vr_rd32(p, len, 0x24, &h->ie_key_sel);
		uid_base = 0x28;
		break;
	case CSF_ISBC:
		vr_rd32(p, len, 0x18, &h->sg_off);
		vr_rd32(p, len, 0x1c, &h->sg_entries);
		vr_rd32(p, len, 0x20, &lo);
		if (ta30) {
			h->entry_point = lo;
			uid_base = 0x24;
		} else {
			vr_rd32(p, len, 0x24, &hi);
			h->entry_point = ((uint64_t)hi << 32) | lo;
			uid_base = 0x28;
		}
		break;
	case CSF_PBI:
	default:
		uid_base = ta30 ? 0x24 : 0x28;
		break;
	}
	for (i = 0; i < MAX_NUM_FSL_UID; i++)
		vr_rd32(p, len, uid_base + 4 * i, &h->fsl_uid[i]);
	for (i = 0; i < MAX_NUM_OEM_UID; i++)
		vr_rd32(p, len, uid_base + 4 * MAX_NUM_FSL_UID + 4 * i,
			&h->oem_uid[i]);
	return 0;
}

void csf_dump_hdr(const struct csf_hdr_view *h)
{
	int i;

	printf("  barker            : %02x %02x %02x %02x\n", h->barker[0],
	       h->barker[1], h->barker[2], h->barker[3]);
	printf("  SRK table offset  : 0x%x\n", h->srk_tbl_off);
	printf("  number of SRKs    : %u\n", h->num_srk);
	printf("  SRK select        : %u\n", h->srk_sel);
	printf("  misc flags        : 0x%02x (LW=%d B01=%d ISS=%d MP=%d IE=%d)\n",
	       h->misc_flags, !!(h->misc_flags & 0x80),
	       !!(h->misc_flags & 0x40), !!(h->misc_flags & 0x20),
	       !!(h->misc_flags & 0x10), !!(h->misc_flags & 0x01));
	printf("  UID flags         : 0x%02x (FUID=%d OID0..4=%d%d%d%d%d)\n",
	       h->uid_flags, !!(h->uid_flags & 0x80), !!(h->uid_flags & 0x40),
	       !!(h->uid_flags & 0x20), !!(h->uid_flags & 0x10),
	       !!(h->uid_flags & 0x08), !!(h->uid_flags & 0x04));
	printf("  signature offset  : 0x%x\n", h->psign);
	printf("  signature length  : 0x%x\n", h->sign_len);
	switch (h->kind) {
	case CSF_ESBC:
		printf("  image address     : 0x%llx\n",
		       (unsigned long long)h->img_addr);
		printf("  image length      : 0x%x\n", h->img_len);
		printf("  IE key select     : %u\n", h->ie_key_sel);
		break;
	case CSF_ISBC:
		printf("  SG table offset   : 0x%x\n", h->sg_off);
		printf("  SG entries        : %u\n", h->sg_entries);
		printf("  entry point       : 0x%llx\n",
		       (unsigned long long)h->entry_point);
		break;
	case CSF_PBI:
		break;
	}
	printf("  FSL UID           : %08x %08x\n", h->fsl_uid[0], h->fsl_uid[1]);
	printf("  OEM UID           :");
	for (i = 0; i < MAX_NUM_OEM_UID; i++)
		printf(" %08x", h->oem_uid[i]);
	printf("\n");
}

int srk_view_init(struct srk_view *s, const uint8_t *buf, size_t len,
		  uint64_t off, uint32_t num)
{
	uint64_t tlen = (uint64_t)num * VR_SRK_ENTRY_SIZE;

	if (!vr_in_range(len, off, tlen))
		return -1;
	s->num = num;
	s->tbl = buf + off;
	s->len = tlen;
	return 0;
}

uint32_t srk_key_len(const struct srk_view *s, int i)
{
	uint32_t v = 0;

	vr_rd32(s->tbl, s->len, (uint64_t)i * VR_SRK_ENTRY_SIZE, &v);
	return v;
}

const uint8_t *srk_key(const struct srk_view *s, int i)
{
	return s->tbl + (size_t)i * VR_SRK_ENTRY_SIZE + 4;
}

void srk_dump(const struct srk_view *s)
{
	uint32_t i;
	char hex[2 * 8 + 1];

	for (i = 0; i < s->num; i++) {
		uint32_t kl = srk_key_len(s, i);
		const uint8_t *k = srk_key(s, i);

		vr_hex(hex, k, 8);
		printf("  SRK %u: key_len 0x%x (RSA-%u) modulus %s...\n", i + 1,
		       kl, kl * 4, hex);
	}
}

void srk_hash(const struct srk_view *s, uint8_t *hash)
{
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];

	crypto_hash_init(ctx);
	crypto_hash_update(ctx, (void *)s->tbl, s->len);
	crypto_hash_final(hash, ctx);
}

int sg_parse(const uint8_t *p, size_t len, uint64_t off, uint32_t n,
	     int ta30, struct sg_entry_view *sg)
{
	uint32_t i, lo, hi;

	if (n > VR_MAX_IMG || !vr_in_range(len, off, (uint64_t)n * VR_SG_ENTRY_SIZE))
		return -1;
	for (i = 0; i < n; i++) {
		uint64_t e = off + (uint64_t)i * VR_SG_ENTRY_SIZE;

		vr_rd32(p, len, e, &sg[i].len);
		vr_rd32(p, len, e + 4, &sg[i].target);
		vr_rd32(p, len, e + 8, &lo);
		vr_rd32(p, len, e + 12, &hi);
		sg[i].src = ta30 ? lo : (((uint64_t)hi << 32) | lo);
	}
	return 0;
}

void sg_dump(const struct sg_entry_view *sg, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		printf("  SG %u: src 0x%llx len 0x%x target 0x%x\n", i + 1,
		       (unsigned long long)sg[i].src, sg[i].len, sg[i].target);
}

/***************************************************************************
 * Checks shared by the ESBC, ISBC and PBI headers
 ***************************************************************************/
int vr_check_barker(struct verify_req *r, const char *id,
		    const struct csf_hdr_view *h)
{
	if (memcmp(h->barker, barker_ta_3_x, BARKER_LEN) != 0) {
		vr_report(r, id, VR_FAIL,
			  "barker %02x%02x%02x%02x, expected 12192001",
			  h->barker[0], h->barker[1], h->barker[2], h->barker[3]);
		return -1;
	}
	vr_report(r, id, VR_PASS, "barker code 12192001");
	return 0;
}

static int valid_key_len(uint32_t key_len)
{
	return key_len == 2 * 128 || key_len == 2 * 256 || key_len == 2 * 512;
}

int vr_check_srk(struct verify_req *r, const char *const ids[CK_MAX],
		 const struct csf_hdr_view *h, const uint8_t *buf, size_t len,
		 uint64_t base, struct srk_view *srk, struct vr_key *key)
{
	uint32_t i, key_len;
	const uint8_t *sig;
	int bad = 0;

	if (h->num_srk == 0 || h->num_srk > VR_MAX_SRK) {
		vr_report(r, ids[CK_NUM_SRK], VR_FAIL,
			  "%u SRK entries, allowed 1 to %d", h->num_srk,
			  VR_MAX_SRK);
		return -1;
	}
	vr_report(r, ids[CK_NUM_SRK], VR_PASS, "%u SRK entries", h->num_srk);

	if (h->srk_sel == 0 || h->srk_sel > h->num_srk) {
		vr_report(r, ids[CK_SRK_SEL], VR_FAIL,
			  "SRK select %u, allowed 1 to %u", h->srk_sel,
			  h->num_srk);
		return -1;
	}
	vr_report(r, ids[CK_SRK_SEL], VR_PASS, "SRK %u selected", h->srk_sel);

	if (srk_view_init(srk, buf, len, base + h->srk_tbl_off, h->num_srk) != 0) {
		vr_report(r, ids[CK_BOUNDS], VR_FAIL,
			  "SRK table at 0x%llx + %u * %zu bytes is outside the file (%zu bytes)",
			  (unsigned long long)(base + h->srk_tbl_off),
			  h->num_srk, VR_SRK_ENTRY_SIZE, len);
		return -1;
	}
	if (!vr_in_range(len, base + h->psign, h->sign_len)) {
		vr_report(r, ids[CK_BOUNDS], VR_FAIL,
			  "signature at 0x%llx + 0x%x bytes is outside the file (%zu bytes)",
			  (unsigned long long)(base + h->psign), h->sign_len,
			  len);
		return -1;
	}
	if (base + h->psign < base + h->srk_tbl_off + srk->len &&
	    base + h->srk_tbl_off < base + h->psign + h->sign_len) {
		vr_report(r, ids[CK_BOUNDS], VR_FAIL,
			  "signature at 0x%x overlaps the SRK table at 0x%x",
			  h->psign, h->srk_tbl_off);
		return -1;
	}
	vr_report(r, ids[CK_BOUNDS], VR_PASS,
		  "SRK table at 0x%x and signature at 0x%x inside the file",
		  h->srk_tbl_off, h->psign);

	for (i = 0; i < h->num_srk; i++) {
		key_len = srk_key_len(srk, i);
		if (!valid_key_len(key_len)) {
			vr_report(r, ids[CK_KEY_LEN], VR_FAIL,
				  "SRK %u key_len 0x%x, allowed 0x100, 0x200 or 0x400",
				  i + 1, key_len);
			bad = 1;
		}
	}
	if (bad)
		return -1;
	vr_report(r, ids[CK_KEY_LEN], VR_PASS, "SRK key lengths valid");

	key_len = srk_key_len(srk, h->srk_sel - 1);
	if (h->sign_len != key_len / 2 ||
	    (h->sign_len != 128 && h->sign_len != 256 && h->sign_len != 512)) {
		vr_report(r, ids[CK_SIGN_LEN], VR_FAIL,
			  "signature length 0x%x, SRK %u key_len 0x%x needs 0x%x",
			  h->sign_len, h->srk_sel, key_len, key_len / 2);
		return -1;
	}
	vr_report(r, ids[CK_SIGN_LEN], VR_PASS,
		  "signature length 0x%x matches RSA-%u", h->sign_len,
		  key_len * 4);

	key->index = h->srk_sel;
	key->modulus = srk_key(srk, h->srk_sel - 1);
	key->mod_len = key_len / 2;
	key->exponent = key->modulus + key->mod_len;

	if ((key->modulus[0] & 0x80) == 0 ||
	    (key->modulus[key->mod_len - 1] & 0x01) == 0) {
		vr_report(r, ids[CK_MODULUS], VR_FAIL,
			  "SRK %u modulus: most significant bit %s, %s",
			  h->srk_sel, key->modulus[0] & 0x80 ? "set" : "clear",
			  key->modulus[key->mod_len - 1] & 1 ? "odd" : "even");
		return -1;
	}
	vr_report(r, ids[CK_MODULUS], VR_PASS,
		  "SRK %u modulus has its top bit set and is odd", h->srk_sel);

	sig = buf + base + h->psign;
	if (memcmp(sig, key->modulus, h->sign_len) >= 0) {
		vr_report(r, ids[CK_SIG_LT_MOD], VR_FAIL,
			  "signature is not numerically below the SRK %u modulus",
			  h->srk_sel);
		bad = 1;
	} else {
		vr_report(r, ids[CK_SIG_LT_MOD], VR_PASS,
			  "signature is below the modulus");
	}

	if (r->revoke_set) {
		if (h->srk_sel != VR_UNREVOCABLE_KEY &&
		    ((1u << (VR_UNREVOCABLE_KEY - 1 - h->srk_sel)) & r->revoke_mask)) {
			vr_report(r, ids[CK_REVOKED], VR_FAIL,
				  "SRK %u is revoked by mask 0x%x", h->srk_sel,
				  r->revoke_mask);
			bad = 1;
			} else {
			vr_report(r, ids[CK_REVOKED], VR_PASS,
				  "SRK %u not revoked by mask 0x%x", h->srk_sel,
				  r->revoke_mask);
		}
	} else {
		vr_report(r, ids[CK_REVOKED], VR_SKIP,
			  "no --revoke-mask given");
	}

	srk_hash(srk, r->srkh);
	r->srkh_set = 1;
	if (r->srk_hash_set) {
		if (memcmp(r->srkh, r->srk_hash, VR_HASH_LEN) != 0) {
			vr_report(r, ids[CK_SRKH], VR_FAIL,
				  "SRK table hash differs from --srk-hash");
			} else {
			vr_report(r, ids[CK_SRKH], VR_PASS,
				  "SRK table hash matches --srk-hash");
		}
	} else {
		vr_report(r, ids[CK_SRKH], VR_SKIP, "no --srk-hash given");
	}

	if (r->num_pub) {
		int mismatch = (uint32_t)r->num_pub != h->num_srk;

		for (i = 0; !mismatch && i < h->num_srk; i++) {
			if (srk_key_len(srk, i) != r->pub[i].key_len ||
			    memcmp(srk_key(srk, i), r->pub[i].pkey,
				   r->pub[i].key_len) != 0)
				mismatch = 1;
		}
		if (mismatch) {
			vr_report(r, ids[CK_PUB], VR_FAIL,
				  "SRK table differs from the %d --pub key(s)",
				  r->num_pub);
			} else {
			vr_report(r, ids[CK_PUB], VR_PASS,
				  "SRK table matches the %d --pub key(s)",
				  r->num_pub);
		}
	} else {
		vr_report(r, ids[CK_PUB], VR_SKIP, "no --pub given");
	}

	return bad ? -1 : 0;
}

int vr_check_signature(struct verify_req *r, const char *id,
		       const uint8_t *hash, const uint8_t *sig,
		       uint32_t sign_len, const struct vr_key *key,
		       const char *what)
{
	memcpy(r->img_hash, hash, VR_HASH_LEN);
	r->img_hash_set = 1;
	if (crypto_rsa_verify(hash, VR_HASH_LEN, sig, sign_len, key->modulus,
			      key->exponent, key->mod_len) != SUCCESS) {
		vr_report(r, id, VR_FAIL,
			  "signature does not verify with SRK %d over %s",
			  key->index, what);
		return -1;
	}
	vr_report(r, id, VR_PASS, "signature verifies with SRK %d over %s",
		  key->index, what);
	return 0;
}

void vr_report_flags(struct verify_req *r, const char *id,
		     const struct csf_hdr_view *h)
{
	vr_report(r, id, VR_INFO,
		  "misc flags 0x%02x (LW=%d B01=%d ISS=%d MP=%d IE=%d) UID flags 0x%02x (FUID=%d OID=%d%d%d%d%d)",
		  h->misc_flags, !!(h->misc_flags & 0x80),
		  !!(h->misc_flags & 0x40), !!(h->misc_flags & 0x20),
		  !!(h->misc_flags & 0x10), !!(h->misc_flags & 0x01),
		  h->uid_flags, !!(h->uid_flags & 0x80), !!(h->uid_flags & 0x40),
		  !!(h->uid_flags & 0x20), !!(h->uid_flags & 0x10),
		  !!(h->uid_flags & 0x08), !!(h->uid_flags & 0x04));
}
