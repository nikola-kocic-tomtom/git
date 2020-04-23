 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
		if (rec->cnt > index->cnt) {
				lcs->begin1 = as;
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,

		chain_len = 0;
out:
		struct record *next;
	} **records, /* an occurrence */

continue_scan:

	if (!(index.line_map = (struct record **) xdl_malloc(sz)))
			while (ae < LINE_END(1) && be < LINE_END(2)
	xdl_cha_free(&index->rcha);
			rc = rec->cnt;
				  line1, count1, line2, count2);
			return -1;
		unsigned int ptr, cnt;
				bs--;
{

		rec = *rec_chain;
 * Redistribution and use in source and binary forms, with or
			rec = rec->next;
	unsigned int ptr, tbl_idx;

		return 0;
int xdl_do_histogram_diff(mmfile_t *file1, mmfile_t *file2,

	struct histindex index;
struct region {
	if (LINE_END(1) >= MAX_PTR)
	}
				rec->cnt = XDL_MIN(MAX_CNT, rec->cnt + 1);
				/* cap rec->cnt at MAX_CNT */
			should_break = 0;
	return ret;
		if (!(rec = xdl_cha_alloc(&index->rcha)))
			    xpp->flags);
	index.rcha.head = NULL;
				lcs->end2 = be;
			result = 0;
		as = rec->ptr;
	xrecord_t *r1, xrecord_t *r2)
				 * it onto the front of the existing element
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
static inline void free_index(struct histindex *index)
						line1, lcs.begin1 - line1,
					should_break = 1;
		rec->cnt = 1;

	index.max_chain_length = 64;
	return r1->ha == r2->ha &&
 *   written permission.
}
			env->xdf2.rchg[line2++ - 1] = 1;
		goto cleanup;
	chastore_t rcha;

	xpparam_t const *xpp, xdfenv_t *env)
 *   products derived from this software without specific prior
				index->has_common = CMP(index, 1, rec->ptr, 2, b_ptr);
				env->xdf1.rchg[line1++ - 1] = 1;

	/* in case of early xdl_cha_free() */
		return 0;
	lcs_found = find_lcs(xpp, env, &lcs, line1, count1, line2, count2);
#include "xinclude.h"
 * - Redistributions in binary form must reproduce the above
}
 *   names of its contributors may be used to endorse or promote
			as = np;
		return 0;
			if (CMP(index, 1, rec->ptr, 1, ptr)) {
		return -1;
	if (index.has_common && index.max_chain_length < index.cnt)
#define MAX_CNT	UINT_MAX
		rec->ptr = ptr;
	index.cnt = index.max_chain_length + 1;
			 * result = histogram_diff(xpp, env,
	struct record *rec = index->records[TABLE_HASH(index, 2, b_ptr)];
	else
	sz *= sizeof(struct record *);
			if (!index->has_common)
				goto continue_scan;
		     has_common;
			line1 = lcs.end1 + 1;
		goto cleanup;
		env->xdf1.dstart + 1, env->xdf1.dend - env->xdf1.dstart + 1,
		     key_shift,

static int try_lcs(struct histindex *index, struct region *lcs, int b_ptr,
				lcs->begin2 = bs;
#define REC(env, s, l) \
				as--;

	if (lcs_found < 0)

 * and other copyright owners as documented in JGit's IP log.
 * conditions are met:
	unsigned int cnt,
	if (xdl_prepare_env(file1, file2, xpp, env) < 0)
			while (count2--)


}
			chain_len++;
	sz = index.records_size = 1 << index.table_bits;
	xdl_free(index->records);

 *

	unsigned int as, ae, bs, be, np, rc;
			if (np == 0)
				break;
#define CNT(index, ptr) \
		 * This is the first time we have ever seen this particular
 * Copyright (C) 2010, Google Inc.
{
 * accompanies this distribution, is reproduced below, and is
		LINE_MAP(index, ptr) = rec;
			}
					rc = XDL_MIN(rc, CNT(index, ae));
	XDL_HASHLONG((REC(index->env, side, line))->ha, index->table_bits)
				ae++;

	int lcs_found;
		tbl_idx = TABLE_HASH(index, 1, ptr);
			np = NEXT_PTR(index, as);

 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	memset(index.line_map, 0, sz);
		 * element in the sequence. Construct a new chain for it.

				env->xdf2.rchg[line2++ - 1] = 1;
 * without modification, are permitted provided that the following
			count1 = LINE_END(1) - lcs.end1;
			if (result)
 * All rights reserved.
				if (np == 0) {

			ae = as;
			*/
	unsigned int begin2, end2;
	return xdl_fall_back_diff(env, &xpparam,
	xpparam_t const *xpp;
		for (;;) {
	  **line_map; /* map of line to record chain */

				 * ptr is identical to another element. Insert

 *
			}
 *
}
	index.xpp = xpp;
	xpparam_t xpparam;
 * - Redistributions of source code must retain the above copyright
		     ptr_shift;
static int histogram_diff(xpparam_t const *xpp, xdfenv_t *env,
		while(count2--)
		b_ptr = try_lcs(&index, lcs, b_ptr, line1, count1, line2, count2);
	sz *= sizeof(unsigned int);
{
/*
			count2 = LINE_END(2) - lcs.end2;
			return -1;
{
		/*
 */

 * under the terms of the Eclipse Distribution License v1.0 which
}
	result = -1;

	for (ptr = LINE_END(1); line1 <= ptr; ptr--) {
};
	sz = index.line_map_size;
				}

			goto redo;

				&& CMP(index, 1, as - 1, 2, bs - 1)) {
			bs = b_ptr;
				goto out;
#define LINE_END_PTR(n) (*line##n + *count##n - 1)
{
				be++;
	int b_ptr;
 * - Neither the name of the Eclipse Foundation, Inc. nor the
 * available at http://www.eclipse.org/org/documents/edl-v10.php

	return 0;
			be = bs;
}
	struct region lcs;
		}

		xdl_recmatch(r1->ptr, r1->size, r2->ptr, r2->size,
		goto out;
			env->xdf1.rchg[line1++ - 1] = 1;
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	free_index(&index);
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
static int cmp_recs(xpparam_t const *xpp,

	return b_next;
				rec->ptr = ptr;
	}
			result = histogram_diff(xpp, env,
		rec->next = *rec_chain;
 *   with the distribution.
#define MAX_PTR	UINT_MAX
	else if (lcs_found)
	int result;
	if (!(index.next_ptrs = (unsigned int *) xdl_malloc(sz)))
		while (rec) {
	index.records = NULL;



		ret = 0;

			if (b_next <= be)
				/*

		return -1;
	if (count1 <= 0 && count2 <= 0)
		index->has_common = 1;
#define LINE_END(n) (line##n + count##n - 1)
				 * chain.
	index.line_map = NULL;
	int line1, int count1, int line2, int count2)

	else {

				if (1 < rc)
				np = NEXT_PTR(index, np);
			 *            lcs.end2 + 1, LINE_END(2) - lcs.end2);
			}
	return result;

static int find_lcs(xpparam_t const *xpp, xdfenv_t *env,
 *   copyright notice, this list of conditions and the following
#define TABLE_HASH(index, side, line) \

		int line1, int count1, int line2, int count2)
		if (lcs.begin1 == 0 && lcs.begin2 == 0) {
{
	int line1, int count1, int line2, int count2)
	(cmp_recs(i->xpp, REC(i->env, s1, l1), REC(i->env, s2, l2)))
		     line_map_size;
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
	for (b_ptr = line2; b_ptr <= LINE_END(2); )
			 *            lcs.end1 + 1, LINE_END(1) - lcs.end1,
		if (chain_len == index->max_chain_length)

				index->cnt = rc;
	if (!(index.records = (struct record **) xdl_malloc(sz)))
 *   disclaimer in the documentation and/or other materials provided
		}
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
	(index->next_ptrs[(ptr) - index->ptr_shift])
		    int line1, int count1, int line2, int count2)
	int sz, ret = -1;
 *
			continue;
{
			}
			continue;
					rc = XDL_MIN(rc, CNT(index, as));
	memset(index.next_ptrs, 0, sz);
	unsigned int *next_ptrs;

	index.table_bits = xdl_hashbits(count1);
		*rec_chain = rec;
#define CMP_ENV(xpp, env, s1, l1, s2, l2) \


					break;
};
	if (scanA(&index, line1, count1))

	index.env = env;
		     records_size,
				break;
			 * but let's optimize tail recursion ourself:

	} else if (!count2) {
				&& CMP(index, 1, ae + 1, 2, be + 1)) {
}
		goto cleanup;
		goto cleanup;
static int scanA(struct histindex *index, int line1, int count1)
				LINE_MAP(index, ptr) = rec;
	unsigned int table_bits,

		env->xdf2.dstart + 1, env->xdf2.dend - env->xdf2.dstart + 1);
	memset(&index, 0, sizeof(index));
			}
#define CMP(i, s1, l1, s2, l2) \
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
	return histogram_diff(xpp, env,
	for (; rec; rec = rec->next) {
			while (np <= ae) {
			if (should_break)
			if (lcs->end1 - lcs->begin1 < ae - as || rc < index->cnt) {

#define LINE_MAP(i, a) (i->line_map[(a) - i->ptr_shift])
 * This program and the accompanying materials are made available
		    struct region *lcs,
	((LINE_MAP(index, ptr))->cnt)
	}
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER

			/*
	if (!count1) {
			line2 = lcs.end2 + 1;
	unsigned int max_chain_length,

				 */
				b_next = be + 1;
	xdfenv_t *env;


	memset(index.records, 0, sz);
		}
 *
		 */

	}
		while(count1--)
		ret = 1;
	unsigned int chain_len;
struct histindex {
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
	index.ptr_shift = line1;
	memset(&lcs, 0, sizeof(lcs));
			while (line1 < as && line2 < bs
	(env->xdf##s.recs[l - 1])
		; /* no op */
	xpparam.flags = xpp->flags & ~XDF_DIFF_ALGORITHM_MASK;
redo:
		result = fall_back_to_classic_diff(xpp, env, line1, count1, line2, count2);
				if (1 < rc)
		rec_chain = index->records + tbl_idx;
	struct record **rec_chain, *rec;
	unsigned int b_next = b_ptr + 1;

static int fall_back_to_classic_diff(xpparam_t const *xpp, xdfenv_t *env,
				NEXT_PTR(index, ptr) = rec->ptr;
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
	xdl_free(index->line_map);
			while (count1--)
						line2, lcs.begin2 - line2);

	if (xdl_cha_init(&index.rcha, sizeof(struct record), count1 / 4 + 1) < 0)
	int should_break;
 *
}

	sz = index.line_map_size = count1;
#define NEXT_PTR(index, ptr) \
	(cmp_recs(xpp, REC(env, s1, l1), REC(env, s2, l2)))
 *
	unsigned int begin1, end1;
cleanup:
 *   notice, this list of conditions and the following disclaimer.
	xdl_free(index->next_ptrs);

		if (!CMP(index, 1, as, 2, b_ptr))

	struct record {
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
	/* lines / 4 + 1 comes from xprepare.c:xdl_prepare_ctx() */
{

		} else {
				lcs->end1 = ae;
		goto cleanup;

		}
	sz *= sizeof(struct record *);
