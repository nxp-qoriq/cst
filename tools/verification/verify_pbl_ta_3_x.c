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

#include <verify.h>

#define PBL_MAX_HDR_EXTENT	0x100000
#define PBL_COPY_FROM_MEMORY	0x00

struct mem_seg {
	uint64_t dst;
	uint64_t size;
	uint64_t file_off;
	uint64_t avail;
	uint32_t word;
	uint32_t mem_src;
	int from_memory;
};

struct mem_model {
	const uint8_t *file;
	size_t file_len;
	struct mem_seg *seg;
	int nseg;
	uint64_t win_base;
	uint64_t win_size;
};

/***************************************************************************
 * Function	:	mem_source
 * Return	:	index of the block copy that last wrote the byte,
 *			-1 for the boot device window, -2 for nothing,
 *			-3 for a block copy from memory
 ***************************************************************************/
static int mem_source(const struct mem_model *m, uint64_t a, uint8_t *byte)
{
	int i;

	for (i = m->nseg - 1; i >= 0; i--) {
		const struct mem_seg *s = &m->seg[i];

		if (a >= s->dst && a - s->dst < s->size) {
			if (s->from_memory)
				return -3;
			if (a - s->dst >= s->avail)
				return -2;
			*byte = m->file[s->file_off + (a - s->dst)];
			return i;
		}
	}
	if (a >= m->win_base && a - m->win_base < m->win_size &&
	    a - m->win_base < m->file_len) {
		*byte = m->file[a - m->win_base];
		return -1;
	}
	return -2;
}

static int mem_read(const struct mem_model *m, uint64_t addr, uint64_t n,
		    uint8_t *out, uint64_t *missing)
{
	uint64_t p;

	if (n > UINT64_MAX - addr) {
		*missing = addr;
		return -1;
	}
	for (p = 0; p < n; p++) {
		if (mem_source(m, addr + p, &out[p]) < -1) {
			*missing = addr + p;
			return -1;
		}
	}
	return 0;
}

static void mem_describe(const struct mem_model *m, uint64_t addr, char *buf,
			 size_t buflen)
{
	uint8_t b;
	int src = mem_source(m, addr, &b);

	if (src >= 0)
		snprintf(buf, buflen, "block copy at word %u from PBL offset 0x%llx",
			 m->seg[src].word,
			 (unsigned long long)(m->seg[src].file_off + (addr - m->seg[src].dst)));
	else if (src == -1)
		snprintf(buf, buflen, "the boot device window at PBL offset 0x%llx",
			 (unsigned long long)(addr - m->win_base));
	else if (src == -3)
		snprintf(buf, buflen, "a block copy from memory, content unknown");
	else
		snprintf(buf, buflen, "nothing");
}

/***************************************************************************
 * Function	:	pbl_build_model
 * Description	:	X2: simulate the PBI block copies over the PBL file,
 *			along the path libqoriq-rcw walked
 ***************************************************************************/
static int pbl_build_model(struct verify_req *r, const struct pbi_view *v,
			   struct mem_model *m)
{
	int i, bad = 0, past = 0, nmem = 0;

	if (v->rep.pbi == RCW_ERR_PBI_CONDITIONAL) {
		vr_report(r, "X2", VR_FAIL,
			  "conditional jump at word %u: the path taken depends on hardware state, not simulated",
			  v->ncmd ? v->cmds[v->ncmd - 1].idx : 0);
		return -1;
	}

	m->file = r->in.data;
	m->file_len = r->in.len;
	m->nseg = 0;
	m->seg = calloc(v->nblk ? v->nblk : 1, sizeof(*m->seg));
	if (m->seg == NULL)
		return -1;
	if (r->xip_set) {
		m->win_base = r->xip_base;
		m->win_size = r->xip_size;
	} else {
		m->win_base = r->flash_base;
		m->win_size = r->in.len;
	}

	for (i = 0; i < v->ncmd; i++) {
		const struct pbi_cmd *c = &v->cmds[i];
		struct mem_seg *s = &m->seg[m->nseg];

		if (c->op != RCW_PBI_BLOCKCOPY)
			continue;
		if ((uint64_t)c->arg[1] + c->arg[2] > 0x100000000ULL) {
			vr_report(r, "X2", VR_FAIL,
				  "block copy at word %u: destination 0x%08x + 0x%x wraps",
				  c->idx, c->arg[1], c->arg[2]);
			bad = 1;
			continue;
		}
		s->word = c->idx;
		s->dst = c->arg[1];
		s->size = c->arg[2];
		if (c->arg[0] < r->flash_base ||
		    c->arg[0] - r->flash_base >= r->in.len) {
			if ((c->word & 0xff) == PBL_COPY_FROM_MEMORY) {
				s->mem_src = c->arg[0];
				s->from_memory = 1;
				vr_report(r, "X2", VR_INFO,
					  "block copy at word %u: 0x%llx bytes from memory 0x%08x to 0x%llx, content unknown",
					  c->idx, (unsigned long long)s->size,
					  s->mem_src, (unsigned long long)s->dst);
				m->nseg++;
				nmem++;
				continue;
			}
			vr_report(r, "X2", VR_FAIL,
				  "block copy at word %u: source 0x%08x outside the PBL (flash base 0x%llx, 0x%zx bytes)",
				  c->idx, c->arg[0],
				  (unsigned long long)r->flash_base, r->in.len);
			bad = 1;
			continue;
		}
		s->file_off = c->arg[0] - r->flash_base;
		s->avail = r->in.len - s->file_off;
		if (s->avail > s->size)
			s->avail = s->size;
		if (s->avail < s->size) {
			vr_report(r, "X2", VR_INFO,
				  "block copy at word %u: the last 0x%llx of 0x%llx bytes lie past the end of the PBL file (erased flash)",
				  c->idx, (unsigned long long)(s->size - s->avail),
				  (unsigned long long)s->size);
			past = 1;
		}
		vr_report(r, "X2", VR_INFO,
			  "block copy at word %u: 0x%llx bytes from PBL offset 0x%llx to 0x%llx",
			  c->idx, (unsigned long long)s->size,
			  (unsigned long long)s->file_off,
			  (unsigned long long)s->dst);
		m->nseg++;
	}
	if (bad)
		return -1;
	vr_report(r, "X2", VR_PASS, "%d block copies simulated from the PBL%s",
		  m->nseg - nmem, past ? ", some end past the file" : "");
	return 0;
}

static uint64_t isbc_hdr_extent(const struct csf_hdr_view *h)
{
	uint64_t e = VR_CSF_HDR_SIZE, t;

	if (h->num_srk && h->num_srk <= VR_MAX_SRK) {
		t = (uint64_t)h->srk_tbl_off + h->num_srk * VR_SRK_ENTRY_SIZE;
		if (t > e)
			e = t;
	}
	if (h->sg_entries && h->sg_entries <= VR_MAX_IMG) {
		t = (uint64_t)h->sg_off + h->sg_entries * VR_SG_ENTRY_SIZE;
		if (t > e)
			e = t;
	}
	t = (uint64_t)h->psign + h->sign_len;
	if (t > e)
		e = t;
	return e;
}

static void pbl_dump_memory(const struct mem_model *m, const struct pbi_view *v,
			    int ta30)
{
	struct csf_hdr_view h;
	struct srk_view srk;
	struct sg_entry_view sg[VR_MAX_IMG];
	uint8_t first[VR_CSF_HDR_SIZE], *hdr;
	uint64_t extent, missing;
	int i;

	printf("Memory written by the PBI (flash base 0x%llx, device window 0x%llx + 0x%llx):\n",
	       (unsigned long long)(m->win_base), (unsigned long long)m->win_base,
	       (unsigned long long)m->win_size);
	for (i = 0; i < m->nseg; i++) {
		if (m->seg[i].from_memory) {
			printf("  0x%08llx - 0x%08llx from memory 0x%08x (word %u), content unknown\n",
			       (unsigned long long)m->seg[i].dst,
			       (unsigned long long)(m->seg[i].dst + m->seg[i].size - 1),
			       m->seg[i].mem_src, m->seg[i].word);
			continue;
		}
		printf("  0x%08llx - 0x%08llx from PBL offset 0x%llx (word %u)%s\n",
		       (unsigned long long)m->seg[i].dst,
		       (unsigned long long)(m->seg[i].dst + m->seg[i].size - 1),
		       (unsigned long long)m->seg[i].file_off, m->seg[i].word,
		       m->seg[i].avail < m->seg[i].size ? ", tail past the file" : "");
	}
	if (!v->csf_ptr_set) {
		printf("No Boot1 CSF header pointer\n");
		return;
	}
	printf("Boot1 CSF header pointer 0x%08x\n", v->csf_ptr);
	if (mem_read(m, v->csf_ptr, VR_CSF_HDR_SIZE, first, &missing) != 0) {
		printf("  header byte 0x%llx is not written\n",
		       (unsigned long long)missing);
		return;
	}
	csf_parse_hdr(first, sizeof(first), CSF_ISBC, ta30, &h);
	csf_dump_hdr(&h);
	extent = isbc_hdr_extent(&h);
	if (extent > PBL_MAX_HDR_EXTENT) {
		printf("  header extent 0x%llx implausible\n",
		       (unsigned long long)extent);
		return;
	}
	hdr = malloc(extent);
	if (hdr == NULL)
		return;
	if (mem_read(m, v->csf_ptr, extent, hdr, &missing) != 0) {
		printf("  header byte 0x%llx is not written\n",
		       (unsigned long long)missing);
	} else {
		if (srk_view_init(&srk, hdr, extent, h.srk_tbl_off, h.num_srk) == 0)
			srk_dump(&srk);
		if (sg_parse(hdr, extent, h.sg_off, h.sg_entries, ta30, sg) == 0) {
			sg_dump(sg, h.sg_entries);
			for (i = 0; i < (int)h.sg_entries; i++) {
				char from[96];

				mem_describe(m, sg[i].src, from, sizeof(from));
				printf("  SG %d first byte written by %s\n", i + 1,
				       from);
			}
		}
	}
	free(hdr);
}

int verify_pbl_ta_3_x(struct verify_req *r, int ta30)
{
	struct pbi_view v;
	struct csf_hdr_view ph, h, ih;
	struct srk_view psrk, isrk;
	struct sg_entry_view sg[VR_MAX_IMG];
	struct verify_blob img[VR_MAX_IMG];
	char img_name[VR_MAX_IMG][48];
	struct mem_model m;
	uint8_t first[VR_CSF_HDR_SIZE], *hdr = NULL;
	uint64_t extent, missing;
	int pbi_ret, i, populated = 1, ep_in = -1, ret = SUCCESS;

	memset(&m, 0, sizeof(m));
	memset(img, 0, sizeof(img));
	memset(&isrk, 0, sizeof(isrk));
	memset(&ih, 0, sizeof(ih));
	if (r->in.data == NULL) {
		fprintf(stderr, "cst_verify: pbl needs --pbl\n");
		return FAILURE;
	}
	if (!r->flash_base_set) {
		fprintf(stderr, "cst_verify: pbl needs --flash-base (0x20000000 for FlexSPI NOR, 0x1000 for SD)\n");
		return FAILURE;
	}

	if (r->dump) {
		verify_pbi_ta_3_x(r, ta30);
		if (pbi_decode(r->in.data, r->in.len, &v) == 0 &&
		    pbl_build_model(r, &v, &m) == 0)
			pbl_dump_memory(&m, &v, ta30);
		free(m.seg);
		pbi_free(&v);
		return SUCCESS;
	}

	pbi_ret = verify_pbi_stream(r, ta30, r->in.data, r->in.len, &v, &ph,
				    &psrk);
	if (v.rep.envelope != RCW_OK || v.cmds == NULL ||
	    (v.rep.pbi != RCW_OK && v.rep.pbi != RCW_ERR_PBI_CONDITIONAL)) {
		vr_report(r, "X1", VR_FAIL,
			  "the PBI command stream cannot be decoded, no cross check possible");
		goto out;
	}
	vr_report(r, "X1", pbi_ret == 0 ? VR_PASS : VR_FAIL,
		  pbi_ret == 0 ? "the signed PBI verifies" :
		  "the signed PBI does not verify, see the P checks");

	if (pbl_build_model(r, &v, &m) != 0)
		goto out;

	if (!v.csf_ptr_set) {
		vr_report(r, "X3", VR_FAIL,
			  "no Boot1 CSF header pointer command in the PBI");
		goto out;
	}
	if (mem_read(&m, v.csf_ptr, VR_CSF_HDR_SIZE, first, &missing) != 0) {
		vr_report(r, "X3", VR_FAIL,
			  "Boot1 CSF header at 0x%08x: byte 0x%llx is not written by a block copy from the PBL nor inside the boot device window",
			  v.csf_ptr, (unsigned long long)missing);
		goto out;
	}
	csf_parse_hdr(first, sizeof(first), CSF_ISBC, ta30, &h);
	extent = isbc_hdr_extent(&h);
	if (extent > PBL_MAX_HDR_EXTENT) {
		vr_report(r, "X3", VR_FAIL,
			  "Boot1 CSF header at 0x%08x: fields reach 0x%llx bytes past it, implausible",
			  v.csf_ptr, (unsigned long long)extent);
		goto out;
	}
	hdr = malloc(extent);
	if (hdr == NULL) {
		ret = FAILURE;
		goto out;
	}
	if (mem_read(&m, v.csf_ptr, extent, hdr, &missing) != 0) {
		vr_report(r, "X3", VR_FAIL,
			  "Boot1 CSF header at 0x%08x: byte 0x%llx of its tables is not written by a block copy from the PBL nor inside the boot device window",
			  v.csf_ptr, (unsigned long long)missing);
		goto out;
	}
	{
		char from[96];

		mem_describe(&m, v.csf_ptr, from, sizeof(from));
		vr_report(r, "X3", VR_PASS,
			  "Boot1 CSF header at 0x%08x (0x%llx bytes with its tables) written by %s",
			  v.csf_ptr, (unsigned long long)extent, from);
	}

	if (h.sg_entries == 0 || h.sg_entries > VR_MAX_IMG ||
	    sg_parse(hdr, extent, h.sg_off, h.sg_entries, ta30, sg) != 0) {
		vr_report(r, "X5", VR_SKIP,
			  "SG table unusable, see the I checks");
		populated = 0;
		verify_isbc_buffers(r, ta30, "Boot1 header in memory", hdr,
				    extent, img, 0, NULL, NULL, NULL);
		vr_report(r, "X4", VR_FAIL, "the Boot1 header does not verify");
		goto out;
	}
	for (i = 0; i < (int)h.sg_entries; i++) {
		char from[96];

		img[i].data = malloc(sg[i].len ? sg[i].len : 1);
		if (img[i].data == NULL) {
			ret = FAILURE;
			goto out;
		}
		img[i].len = sg[i].len;
		snprintf(img_name[i], sizeof(img_name[i]), "SG %d at 0x%llx",
			 i + 1, (unsigned long long)sg[i].src);
		img[i].name = img_name[i];
		if (mem_read(&m, sg[i].src, sg[i].len, img[i].data, &missing) != 0) {
			vr_report(r, "X5", VR_FAIL,
				  "SG %d: 0x%x bytes at 0x%llx: byte 0x%llx is not written by a block copy from the PBL nor inside the boot device window",
				  i + 1, sg[i].len, (unsigned long long)sg[i].src,
				  (unsigned long long)missing);
			populated = 0;
			continue;
		}
		mem_describe(&m, sg[i].src, from, sizeof(from));
		vr_report(r, "X5", VR_INFO, "SG %d: 0x%x bytes at 0x%llx written by %s",
			  i + 1, sg[i].len, (unsigned long long)sg[i].src, from);
	}
	if (!populated) {
		vr_report(r, "X4", VR_SKIP,
			  "SG regions missing, the Boot1 header is not verified against memory");
		goto entry;
	}
	vr_report(r, "X5", VR_PASS, "%u SG regions fully written", h.sg_entries);

	if (verify_isbc_buffers(r, ta30, "Boot1 header in memory", hdr, extent,
				img, h.sg_entries, &ih, &isrk, sg) == 0)
		vr_report(r, "X4", VR_PASS,
			  "the Boot1 header verifies against the memory the PBI writes");
	else
		vr_report(r, "X4", VR_FAIL,
			  "the Boot1 header does not verify against the memory the PBI writes, see the I checks");

entry:
	for (i = 0; i < (int)h.sg_entries; i++) {
		if (img[i].data == NULL || !populated)
			continue;
		if (h.entry_point >= sg[i].src &&
		    h.entry_point - sg[i].src < sg[i].len)
			ep_in = i + 1;
	}
	if (ep_in > 0)
		vr_report(r, "X6", VR_PASS,
			  "entry point 0x%llx inside the written SG region %d",
			  (unsigned long long)h.entry_point, ep_in);
	else
		vr_report(r, "X6", VR_FAIL,
			  "entry point 0x%llx is not inside a written SG region",
			  (unsigned long long)h.entry_point);

	if (psrk.tbl && h.num_srk && h.num_srk <= VR_MAX_SRK &&
	    srk_view_init(&isrk, hdr, extent, h.srk_tbl_off, h.num_srk) == 0) {
		if (isrk.len == psrk.len &&
		    memcmp(isrk.tbl, psrk.tbl, psrk.len) == 0)
			vr_report(r, "X7", VR_PASS,
				  "the PBI and Boot1 headers carry the same SRK table");
		else
			vr_report(r, "X7", VR_FAIL,
				  "the PBI and Boot1 headers carry different SRK tables, one SRKH cannot match both");
	} else {
		vr_report(r, "X7", VR_SKIP, "SRK tables not comparable");
	}

out:
	for (i = 0; i < VR_MAX_IMG; i++)
		free(img[i].data);
	free(hdr);
	free(m.seg);
	pbi_free(&v);
	return ret;
}
