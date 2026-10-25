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

#ifndef _VERIFY_H_
#define _VERIFY_H_

#include <stdint.h>
#include <stddef.h>
#include <global.h>
#include <taal.h>
#include <qoriq-rcw/rcw.h>

#define VR_CSF_HDR_SIZE		0x50
#define VR_SRK_ENTRY_SIZE	(sizeof(struct srk_table_t))
#define VR_SG_ENTRY_SIZE	(sizeof(struct sg_table_t))
#define VR_HASH_LEN		SHA256_DIGEST_LENGTH
#define VR_MAX_IMG		MAX_NUM_SG_ENTRY
#define VR_MAX_PUB		MAX_NUM_KEY
#define VR_MAX_SRK		MAX_NUM_KEY
#define VR_DEFAULT_HDR_SIZE	0x3000
#define VR_UNREVOCABLE_KEY	8

#define VR_EXIT_PASS		0
#define VR_EXIT_FAIL		1
#define VR_EXIT_ERROR		2

enum verify_mode {
	VERIFY_ESBC,
	VERIFY_ISBC,
	VERIFY_PBI,
	VERIFY_PBL,
};

enum vr_status {
	VR_PASS,
	VR_FAIL,
	VR_SKIP,
	VR_INFO,
};

struct verify_blob {
	const char *name;
	uint8_t *data;
	size_t len;
};

struct vr_item {
	char id[8];
	enum vr_status status;
	char msg[256];
};

struct verify_req {
	enum verify_mode mode;
	enum cfg_taal ta;
	int ta_set;
	int dump;
	int verbose;
	int json;

	struct verify_blob hdr;
	struct verify_blob in;
	struct verify_blob img[VR_MAX_IMG];
	int num_img;

	int flash_base_set;
	uint64_t flash_base;
	int xip_set;
	uint64_t xip_base;
	uint64_t xip_size;
	uint32_t hdr_size;

	int srk_hash_set;
	uint8_t srk_hash[VR_HASH_LEN];
	int revoke_set;
	uint32_t revoke_mask;
	int num_pub;
	struct srk_table_t pub[VR_MAX_PUB];

	struct vr_item *items;
	int num_items;
	int cap_items;
	int num_fail;
	int img_hash_set;
	uint8_t img_hash[VR_HASH_LEN];
	int srkh_set;
	uint8_t srkh[VR_HASH_LEN];
	int error;
};

enum csf_kind {
	CSF_ESBC,
	CSF_ISBC,
	CSF_PBI,
};

struct csf_hdr_view {
	enum csf_kind kind;
	int ta30;
	uint8_t barker[BARKER_LEN];
	uint32_t srk_tbl_off;
	uint8_t num_srk;
	uint8_t srk_sel;
	uint8_t misc_flags;
	uint8_t uid_flags;
	uint32_t psign;
	uint32_t sign_len;
	uint64_t img_addr;
	uint32_t img_len;
	uint32_t ie_key_sel;
	uint32_t sg_off;
	uint32_t sg_entries;
	uint64_t entry_point;
	uint32_t fsl_uid[MAX_NUM_FSL_UID];
	uint32_t oem_uid[MAX_NUM_OEM_UID];
};

struct srk_view {
	uint32_t num;
	const uint8_t *tbl;
	size_t len;
};

struct sg_entry_view {
	uint32_t len;
	uint32_t target;
	uint64_t src;
};

struct vr_key {
	int index;
	const uint8_t *modulus;
	const uint8_t *exponent;
	uint32_t mod_len;
};

/* Common check identifiers, mapped to per mode ids */
enum vr_common_check {
	CK_BARKER,
	CK_NUM_SRK,
	CK_SRK_SEL,
	CK_REVOKED,
	CK_KEY_LEN,
	CK_SIGN_LEN,
	CK_SIG_LT_MOD,
	CK_SRKH,
	CK_SIGNATURE,
	CK_BOUNDS,
	CK_MODULUS,
	CK_PUB,
	CK_MAX
};

/* verify_common.c */
void vr_report(struct verify_req *r, const char *id, enum vr_status st,
	       const char *fmt, ...);
int vr_load_file(struct verify_blob *b, const char *name);
void vr_free_blob(struct verify_blob *b);
int vr_rd32(const uint8_t *p, size_t len, uint64_t off, uint32_t *v);
int vr_in_range(size_t len, uint64_t off, uint64_t n);
int vr_parse_u64(const char *s, uint64_t *v);
int vr_parse_hex(const char *s, uint8_t *out, size_t n);
void vr_hex(char *dst, const uint8_t *p, size_t n);
void vr_print_report(struct verify_req *r);
int vr_exit_code(struct verify_req *r);

int csf_parse_hdr(const uint8_t *p, size_t len, enum csf_kind kind, int ta30,
		  struct csf_hdr_view *h);
void csf_dump_hdr(const struct csf_hdr_view *h);
int srk_view_init(struct srk_view *s, const uint8_t *buf, size_t len,
		  uint64_t off, uint32_t num);
uint32_t srk_key_len(const struct srk_view *s, int i);
const uint8_t *srk_key(const struct srk_view *s, int i);
void srk_dump(const struct srk_view *s);
void srk_hash(const struct srk_view *s, uint8_t *hash);
int sg_parse(const uint8_t *p, size_t len, uint64_t off, uint32_t n,
	     int ta30, struct sg_entry_view *sg);
void sg_dump(const struct sg_entry_view *sg, uint32_t n);

int vr_check_barker(struct verify_req *r, const char *id,
		    const struct csf_hdr_view *h);
int vr_check_srk(struct verify_req *r, const char *const ids[CK_MAX],
		 const struct csf_hdr_view *h, const uint8_t *buf, size_t len,
		 uint64_t base, struct srk_view *srk, struct vr_key *key);
int vr_check_signature(struct verify_req *r, const char *id,
		       const uint8_t *hash, const uint8_t *sig,
		       uint32_t sign_len, const struct vr_key *key,
		       const char *what);
void vr_report_flags(struct verify_req *r, const char *id,
		     const struct csf_hdr_view *h);

/* verify_esbc_ta_3_x.c, verify_isbc_ta_3_x.c, verify_pbi_ta_3_x.c */
int verify_esbc_ta_3_x(struct verify_req *r, int ta30);
int verify_isbc_ta_3_x(struct verify_req *r, int ta30);
int verify_isbc_buffers(struct verify_req *r, int ta30, const char *what,
			const uint8_t *hdr, size_t hdr_len,
			const struct verify_blob *img, int num_img,
			struct csf_hdr_view *out_hdr, struct srk_view *out_srk,
			struct sg_entry_view *out_sg);
int verify_pbi_ta_3_x(struct verify_req *r, int ta30);
int verify_pbl_ta_3_x(struct verify_req *r, int ta30);

/* PBI command stream of the TA 3.x service processor, as libqoriq-rcw walks it */
struct pbi_cmd {
	uint32_t idx;
	uint32_t word;
	rcw_pbi_op_t op;
	uint32_t nargs;
	uint32_t arg[3];
};

struct pbi_view {
	rcw_pbl_report_t rep;
	struct pbi_cmd *cmds;
	int ncmd;
	int cap;
	int oom;
	int sec_hdr_idx;
	int csf_ptr_set;
	uint32_t csf_ptr;
	int stop_idx;
	int nblk;
};

int pbi_decode(const uint8_t *buf, size_t len, struct pbi_view *v);
void pbi_free(struct pbi_view *v);
void pbi_dump(const uint8_t *buf, size_t len, const struct pbi_view *v);
int pbi_parse_sec_hdr(const uint8_t *buf, size_t len, const struct pbi_view *v,
		      int ta30, struct csf_hdr_view *h, uint64_t *hdr_off);
int verify_pbi_stream(struct verify_req *r, int ta30, const uint8_t *buf,
		      size_t len, struct pbi_view *v, struct csf_hdr_view *h,
		      struct srk_view *srk);

#endif
