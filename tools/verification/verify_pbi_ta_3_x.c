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
#include <crypto_utils.h>

#define RCW_WORDS		(RCW_PBL_PBI_OFFSET / 4)
#define PBI_START		RCW_PBL_PBI_OFFSET

static const char *stop_name(rcw_pbi_op_t op)
{
	return op == RCW_PBI_CRC_STOP ? "CRC and stop" : "stop";
}

static void pbi_visit(const rcw_pbi_cmd_t *rc, size_t off, void *arg)
{
	struct pbi_view *v = arg;
	struct pbi_cmd *c;
	uint32_t k;

	if (v->oom)
		return;
	if (v->ncmd == v->cap) {
		int cap = v->cap ? 2 * v->cap : 64;
		struct pbi_cmd *p = realloc(v->cmds, cap * sizeof(*p));

		if (p == NULL) {
			v->oom = 1;
			return;
		}
		v->cmds = p;
		v->cap = cap;
	}
	c = &v->cmds[v->ncmd++];
	memset(c, 0, sizeof(*c));
	c->idx = RCW_WORDS + (uint32_t)(off / 4);
	c->word = rc->word;
	c->op = rc->op;
	c->nargs = (uint32_t)rc->nargs;
	for (k = 0; k < rc->nargs && k < 3; k++)
		c->arg[k] = rc->args[k];

	switch (rc->op) {
	case RCW_PBI_LOAD_SEC_HDR:
		if (v->sec_hdr_idx < 0)
			v->sec_hdr_idx = c->idx;
		break;
	case RCW_PBI_LOAD_CSF_PTR:
		v->csf_ptr_set = 1;
		v->csf_ptr = c->arg[0];
		break;
	case RCW_PBI_BLOCKCOPY:
		v->nblk++;
		break;
	case RCW_PBI_STOP:
	case RCW_PBI_CRC_STOP:
		v->stop_idx = c->idx;
		break;
	default:
		break;
	}
}

/***************************************************************************
 * Function	:	pbi_decode
 * Arguments	:	buf, len - the PBL file
 * Return	:	0, or -1 when the command table cannot be allocated
 * Description	:	libqoriq-rcw reads the RCW envelope and walks the PBI
 *			commands the BootROM executes: v->rep is its verdict,
 *			v->cmds the commands walked
 ***************************************************************************/
int pbi_decode(const uint8_t *buf, size_t len, struct pbi_view *v)
{
	memset(v, 0, sizeof(*v));
	v->sec_hdr_idx = -1;
	v->stop_idx = -1;
	rcw_pbl_verify(buf, len, 1, pbi_visit, v, &v->rep);
	return v->oom ? -1 : 0;
}

void pbi_free(struct pbi_view *v)
{
	free(v->cmds);
	v->cmds = NULL;
}

void pbi_dump(const uint8_t *buf, size_t len, const struct pbi_view *v)
{
	const rcw_pbl_report_t *rep = &v->rep;
	const rcw_pbi_check_t *chk = &rep->chk;
	char line[RCW_PBI_SOURCE_MAX];
	rcw_pbi_cmd_t rc;
	uint64_t off;
	int i;

	printf("RCW: load command 0x%08x, PBI length %u words, SB_EN %d, checksum 0x%08x (computed 0x%08x)\n",
	       rep->pbl.load_rcw_cmd, rep->pbl.pbi_length, rep->pbl.sb_en,
	       rep->pbl.checksum, rep->pbl.checksum_computed);
	printf("PBI commands:\n");
	for (i = 0; i < v->ncmd; i++) {
		const struct pbi_cmd *c = &v->cmds[i];

		off = (uint64_t)c->idx * 4;
		if (rcw_pbi_decode(buf + off, len - off, 1, &rc) == RCW_OK)
			rcw_pbi_to_source(&rc, line, sizeof(line));
		else
			line[0] = '\0';
		printf("  word %4u: %08x %s\n", c->idx, c->word, line);
	}
	switch (rep->pbi) {
	case RCW_ERR_BAD_BINARY:
		printf("  word %4u: unknown command 0x%08x, decoding stopped\n",
		       RCW_WORDS + (uint32_t)(chk->end / 4), chk->cmd.word);
		break;
	case RCW_ERR_TRUNCATED:
		printf("  stream truncated at word %u\n",
		       RCW_WORDS + (uint32_t)(chk->end / 4));
		break;
	case RCW_ERR_PBI_OVERRUN:
		printf("  word %4u: command runs past the PBI length\n",
		       RCW_WORDS + (uint32_t)(chk->end / 4));
		break;
	case RCW_ERR_PBI_LENGTH:
		printf("  no stop command at the PBI length (word %u)\n",
		       RCW_WORDS + (uint32_t)(chk->len / 4) - 2);
		break;
	case RCW_ERR_PBI_JUMP:
	case RCW_ERR_PBI_NO_CONDITION:
		printf("  word %4u: %s\n", RCW_WORDS + (uint32_t)(chk->end / 4),
		       rcw_strerror(rep->pbi));
		break;
	case RCW_ERR_PBI_CONDITIONAL:
		printf("  word %4u: conditional jump, the path beyond it is not walked\n",
		       RCW_WORDS + (uint32_t)(chk->end / 4));
		break;
	default:
		if (chk->end < chk->len)
			printf("  words %u to %u after the stop are not executed\n",
			       RCW_WORDS + (uint32_t)(chk->end / 4),
			       RCW_WORDS + (uint32_t)(chk->len / 4) - 1);
		break;
	}
	if (chk->stop_op == RCW_PBI_CRC_STOP)
		printf("  CRC 0x%08x (computed 0x%08x)\n", chk->crc, chk->crc_computed);
}

int pbi_parse_sec_hdr(const uint8_t *buf, size_t len, const struct pbi_view *v,
		      int ta30, struct csf_hdr_view *h, uint64_t *hdr_off)
{
	if (v->sec_hdr_idx < 0)
		return -1;
	*hdr_off = (uint64_t)(v->sec_hdr_idx + 1) * 4;
	if (!vr_in_range(len, *hdr_off, VR_CSF_HDR_SIZE))
		return -1;
	return csf_parse_hdr(buf + *hdr_off, len - *hdr_off, CSF_PBI, ta30, h);
}

static const char *const pbi_ids[CK_MAX] = {
	[CK_BARKER] = "P2",
	[CK_NUM_SRK] = "P2",
	[CK_SRK_SEL] = "P2",
	[CK_REVOKED] = "P10",
	[CK_KEY_LEN] = "P9",
	[CK_SIGN_LEN] = "P9",
	[CK_SIG_LT_MOD] = "P9",
	[CK_SRKH] = "P7",
	[CK_SIGNATURE] = "P3",
	[CK_BOUNDS] = "P11",
	[CK_MODULUS] = "P9",
	[CK_PUB] = "P8",
};

/***************************************************************************
 * Function	:	verify_pbi_stream
 * Arguments	:	buf, len - the PBL file
 *			v - decoded PBI, to be released with pbi_free()
 *			h, srk - the PBI security header and its SRK table
 * Return	:	0 when every check ran, -1 when a check stopped them
 * Description	:	Replay the BootROM validation of the RCW and PBI
 ***************************************************************************/
int verify_pbi_stream(struct verify_req *r, int ta30, const uint8_t *buf,
		      size_t len, struct pbi_view *v, struct csf_hdr_view *h,
		      struct srk_view *srk)
{
	struct vr_key key;
	const rcw_pbl_report_t *rep = &v->rep;
	const rcw_pbi_check_t *chk = &rep->chk;
	uint64_t hdr_off, pbi_end;
	uint32_t i, nwrite = 0, nacs = 0, nother = 0, last;
	uint8_t ctx[CRYPTO_HASH_CTX_SIZE];
	uint8_t hash[VR_HASH_LEN];

	memset(h, 0, sizeof(*h));
	memset(srk, 0, sizeof(*srk));
	if (pbi_decode(buf, len, v) != 0) {
		vr_report(r, "P1", VR_FAIL, "cannot allocate the command table");
		return -1;
	}
	if (rep->envelope == RCW_ERR_TRUNCATED) {
		vr_report(r, "P1", VR_FAIL, "%zu bytes, shorter than the RCW", len);
		return -1;
	}
	if (!rep->preamble_ok) {
		vr_report(r, "P1", VR_FAIL,
			  "RCW preamble 0x%08x, expected 0x%08x", rep->word0,
			  RCW_PBL_PREAMBLE);
		return -1;
	}
	if (!rep->load_rcw_ok) {
		vr_report(r, "P1", VR_FAIL, "load RCW command 0x%08x unknown",
			  rep->word1);
		return -1;
	}
	if (rep->envelope != RCW_OK) {
		vr_report(r, "P1", VR_FAIL, "RCW envelope: %s",
			  rcw_strerror(rep->envelope));
		return -1;
	}
	pbi_end = (uint64_t)PBI_START + chk->len;
	if (rep->pbl.pbi_length < 2 || pbi_end > len) {
		vr_report(r, "P1", VR_FAIL,
			  "PBI length %u words ends at 0x%llx in a %zu byte file",
			  rep->pbl.pbi_length, (unsigned long long)pbi_end, len);
		return -1;
	}
	if (rep->has_checksum && !rep->checksum_ok) {
		vr_report(r, "P1", VR_FAIL,
			  "RCW checksum 0x%08x, computed 0x%08x", rep->pbl.checksum,
			  rep->pbl.checksum_computed);
		return -1;
	}
	vr_report(r, "P1", VR_PASS,
		  "RCW preamble, load command 0x%08x%s, PBI length %u words",
		  rep->pbl.load_rcw_cmd,
		  rep->has_checksum ? " with valid checksum" : "",
		  rep->pbl.pbi_length);
	vr_report(r, "P1", VR_INFO,
		  rep->pbl.sb_en ? "SB_EN set in the RCW" :
		  "SB_EN clear in the RCW, the BootROM verifies only when the ITS fuse is set");

	if (rep->pbi == RCW_ERR_BAD_BINARY) {
		vr_report(r, "P6", VR_FAIL,
			  "unknown or reserved PBI command 0x%08x at word %u, cannot delimit the stream",
			  chk->cmd.word, RCW_WORDS + (uint32_t)(chk->end / 4));
		return -1;
	}
	if (rep->pbi == RCW_ERR_TRUNCATED || rep->pbi == RCW_ERR_PBI_OVERRUN) {
		vr_report(r, "P6", VR_FAIL,
			  "PBI command at word %u runs past PBI length",
			  RCW_WORDS + (uint32_t)(chk->end / 4));
		return -1;
	}
	if (rep->pbi == RCW_ERR_PBI_JUMP || rep->pbi == RCW_ERR_PBI_NO_CONDITION) {
		vr_report(r, "P6", VR_FAIL, "%s at word %u: %s",
			  rcw_pbi_op_name(chk->cmd.op),
			  RCW_WORDS + (uint32_t)(chk->end / 4), rcw_strerror(rep->pbi));
		return -1;
	}
	for (i = 0; i < (uint32_t)v->ncmd; i++) {
		const struct pbi_cmd *c = &v->cmds[i];

		switch (c->op) {
		case RCW_PBI_CCSR_WRITE:
			nwrite++;
			if ((c->word & 0x0ffffff8) == 0x01e00400)
				vr_report(r, "P6", VR_INFO,
					  "word %u: CCSR write 0x%08x to 0x%07x (boot location pointer)",
					  c->idx, c->arg[0], c->word & 0x0fffffff);
			break;
		case RCW_PBI_ALTCFG_WRITE:
			nacs++;
			break;
		case RCW_PBI_BLOCKCOPY:
			vr_report(r, "P6", VR_INFO,
				  "word %u: block copy type 0x%02x, 0x%x bytes from 0x%08x to 0x%08x",
				  c->idx, c->word & 0xff, c->arg[2], c->arg[0],
				  c->arg[1]);
			break;
		case RCW_PBI_LOAD_CSF_PTR:
			vr_report(r, "P6", VR_INFO,
				  "word %u: Boot1 CSF header pointer 0x%08x", c->idx,
				  c->arg[0]);
			break;
		case RCW_PBI_JUMP:
			nother++;
			vr_report(r, "P6", VR_INFO,
				  "word %u: jump forward 0x%x bytes to word %u",
				  c->idx, c->arg[0], c->idx + c->arg[0] / 4);
			break;
		case RCW_PBI_JUMP_COND:
			nother++;
			vr_report(r, "P6", VR_INFO,
				  "word %u: conditional jump forward 0x%x bytes to word %u when the condition is 0x%08x, the path beyond it is not walked",
				  c->idx, c->arg[0], c->idx + c->arg[0] / 4,
				  c->arg[1]);
			break;
		case RCW_PBI_LOAD_SEC_HDR:
		case RCW_PBI_STOP:
		case RCW_PBI_CRC_STOP:
			break;
		default:
			nother++;
			break;
		}
	}
	vr_report(r, "P6", VR_PASS,
		  "%d PBI commands decoded: %u CCSR writes, %u AltConfig writes, %d block copies, %u others",
		  v->ncmd, nwrite, nacs, v->nblk, nother);

	last = RCW_WORDS + (uint32_t)((chk->len - RCW_PBL_TERMINATOR_BYTES) / 4);
	if (rep->pbi != RCW_OK && rep->pbi != RCW_ERR_PBI_CONDITIONAL) {
		if (!rep->terminated)
			vr_report(r, "P5", VR_FAIL,
				  "no stop command within PBI length");
		else
			vr_report(r, "P5", VR_FAIL,
				  "stop command at word %d ends execution, but the PBI length does not end on a stop command (word %u)",
				  v->stop_idx, last);
		return -1;
	}
	if (rep->pbi == RCW_OK && chk->end < chk->len)
		vr_report(r, "P5", VR_INFO,
			  "stop command at word %d ends execution, words %u to %u are not executed",
			  v->stop_idx, RCW_WORDS + (uint32_t)(chk->end / 4),
			  RCW_WORDS + (uint32_t)(chk->len / 4) - 1);
	vr_report(r, "P5", VR_PASS, "%s command at word %u ends the PBI",
		  stop_name(chk->stop_op), last);

	if (v->sec_hdr_idx != RCW_WORDS) {
		vr_report(r, "P2", VR_FAIL,
			  "first PBI command is %s, expected load security header",
			  rcw_pbi_op_name(v->cmds[0].op));
		return -1;
	}
	if (pbi_parse_sec_hdr(buf, len, v, ta30, h, &hdr_off) != 0) {
		vr_report(r, "P2", VR_FAIL, "security header does not fit");
		return -1;
	}
	vr_report_flags(r, "P2", h);
	if (vr_check_barker(r, pbi_ids[CK_BARKER], h) != 0)
		return -1;
	if (h->misc_flags & 0x40) {
		vr_report(r, "P2", VR_FAIL,
			  "B01 flag set, the BootROM expects it clear in a PBI header");
		return -1;
	}
	if (h->misc_flags & 0x01) {
		vr_report(r, "P2", VR_FAIL,
			  "IE key extension flag set, not supported");
		return -1;
	}
	vr_report(r, "P2", VR_PASS, "load security header first, B01 clear");

	if (hdr_off + h->srk_tbl_off < pbi_end ||
	    hdr_off + h->psign < pbi_end) {
		vr_report(r, pbi_ids[CK_BOUNDS], VR_FAIL,
			  "SRK table or signature overlaps the PBI commands ending at 0x%llx",
			  (unsigned long long)pbi_end);
		return -1;
	}
	if (vr_check_srk(r, pbi_ids, h, buf, len, hdr_off, srk, &key) != 0)
		return -1;

	if (chk->stop_op == RCW_PBI_CRC_STOP) {
		if (!rep->crc_ok) {
			vr_report(r, "P4", VR_FAIL, "PBI CRC 0x%08x, computed 0x%08x",
				  chk->crc, chk->crc_computed);
			return -1;
		}
		vr_report(r, "P4", VR_PASS, "PBI CRC 0x%08x", chk->crc);
	} else {
		vr_report(r, "P4", VR_SKIP, "stop command without CRC");
	}

	crypto_hash_init(ctx);
	crypto_hash_update(ctx, (void *)(buf + PBI_START), chk->len);
	crypto_hash_update(ctx, (void *)srk->tbl, srk->len);
	crypto_hash_final(hash, ctx);
	return vr_check_signature(r, pbi_ids[CK_SIGNATURE], hash,
				  buf + hdr_off + h->psign, h->sign_len, &key,
				  "PBI commands and SRK table");
}

static void pbi_dump_all(struct verify_req *r, int ta30)
{
	struct pbi_view v;
	struct csf_hdr_view h;
	struct srk_view srk;
	uint64_t hoff;

	printf("PBL %s (%zu bytes)\n", r->in.name, r->in.len);
	if (pbi_decode(r->in.data, r->in.len, &v) != 0) {
		printf("  cannot allocate the command table\n");
		return;
	}
	if (v.rep.envelope != RCW_OK) {
		printf("  %s\n", v.rep.envelope == RCW_ERR_TRUNCATED ?
		       "file too short for an RCW" : !v.rep.preamble_ok ?
		       "no RCW preamble" : "no load RCW command");
		return;
	}
	pbi_dump(r->in.data, r->in.len, &v);
	if (pbi_parse_sec_hdr(r->in.data, r->in.len, &v, ta30, &h, &hoff) == 0) {
		printf("PBI security header at 0x%llx\n",
		       (unsigned long long)hoff);
		csf_dump_hdr(&h);
		if (srk_view_init(&srk, r->in.data, r->in.len,
				  hoff + h.srk_tbl_off, h.num_srk) == 0)
			srk_dump(&srk);
		else
			printf("  SRK table outside the file\n");
	} else {
		printf("  no load security header command\n");
	}
	pbi_free(&v);
}

int verify_pbi_ta_3_x(struct verify_req *r, int ta30)
{
	struct pbi_view v;
	struct csf_hdr_view h;
	struct srk_view srk;

	if (r->in.data == NULL) {
		fprintf(stderr, "cst_verify: pbi needs --pbl\n");
		return FAILURE;
	}

	if (r->dump) {
		pbi_dump_all(r, ta30);
		return SUCCESS;
	}

	verify_pbi_stream(r, ta30, r->in.data, r->in.len, &v, &h, &srk);
	pbi_free(&v);
	return SUCCESS;
}
