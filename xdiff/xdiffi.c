 * the group can be slid down. Similarly, if the last line in a group is equal
		} while (groupsize != g.end - g.start);
				spl->i2 = i2;
	dd2.nrec = xe->xdf2.nreff;
	if (off1 == lim1) {
			     flags));
			 * for the two splits to define a "score" for each
	 */
	}
	 * -1 if there is no such line)?
			if (best > 0) {

				return ec;
			fbest = fbest1 = -1;
static int get_indent(xrecord_t *rec)
	 * How many consecutive lines above the split are blank?
		m->indent = -1;
		do {
		 * avoid extra conditions in the check inside the core loop.
{
	/* The line contains only whitespace. */
		return -1;
		return -1;
	xenv.snake_cnt = XDL_SNAKE_CNT;
		return xdl_do_histogram_diff(mf1, mf2, xpp, xe);
		/*
	} else {
	if (!group_next(xdfo, &go))

	long i1, i2, l1, l2;
	}
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	if (g->start > 0 &&
 * and corpus described in
	/*
#define TOTAL_BLANK_WEIGHT (-30)
}
		 * The group is currently shifted as far down as possible, so
		}
	 */
		return -1;
			kvdb[d] = i1;
		if (fmax < dmax)
				if (v > XDL_K_HEUR * ec && v > best &&
{

			ignore = xdl_blankline(rec[i]->ptr, rec[i]->size, flags);
			g->start--;
static void score_add_split(const struct split_measurement *m, struct split_score *s)
{
 */
 * Note that loops that are testing for changed lines in xdf->rchg do not need
#define XDL_SNAKE_CNT 20
	     xdemitconf_t const *xecfg, xdemitcb_t *ecb) {
		else

	 * Shrink the box by walking through each diagonal snake (SW and NE).
			 * a match yet:
		 * Enough is enough. We spent too much time here and now we
				    off1 + xenv->snake_cnt <= i1 && i1 < lim1 &&
	 */
	kvdf[fmid] = off1;
		 * each direction. If it bumps into any other changes, merge
 * human-readable text, and also ensures that the output of get_indent fits
		 * Now shift the change up and then down as far as possible in

/*
	next:
			while (1) {
		xch->ignore = ignore;
				}

				if (group_previous(xdfo, &go))
			 */
			 * another between the end of the group and the
	 * The index of the first changed line in the group, or the index of

 * groups will usually be empty.
				dd = d > fmid ? d - fmid: fmid - d;
 * output value at MAX_INDENT.
 */
			/*


			for (; i1 > off1 && i2 > off2 && ha1[i1 - 1] == ha2[i2 - 1]; i1--, i2--);
	} else {
			if (!(xch = xdl_add_change(cscr, i1, i2, l1 - i1, l2 - i2))) {
			 * a badness "score" for each split, and add the scores
 * search and to return a suboptimal point.
				}
/*
			for (; shift <= g.end; shift++) {
		}
			break;

	unsigned long const *ha1 = dd1->ha, *ha2 = dd2->ha;
static void xdl_mark_ignorable(xdchange_t *xscr, xdfenv_t *xe, long flags)
		/*
	exit(1);
		for (d = bmax; d >= bmin; d -= 2) {
 * integer math.
	m->pre_indent = -1;
			--bmax;
					best_shift = shift;
			}
		      long *kvdf, long *kvdb, int need_min, xdpsplit_t *spl,
	group_init(xdf, &g);
/*
				return ec;
static int group_slide_down(xdfile_t *xdf, struct xdlgroup *g, long flags)
					xdl_bug("match disappeared");
			ignore = xdl_blankline(rec[i]->ptr, rec[i]->size, flags);
			long shift, best_shift = -1;
	long i;
			return ret;
					fbest1 = i1;
static int recs_match(xrecord_t *rec1, xrecord_t *rec2, long flags)
	int cmp_indents = ((s1->effective_indent > s2->effective_indent) -
 * If g can be slid toward the end of the file, do so, and if it bumps into a
	for (i1 = xe->xdf1.nrec, i2 = xe->xdf2.nrec; i1 >= 0 || i2 >= 0; i1--, i2--)
 * into a previous group, expand this group to include it. Return 0 on success


 * If a line is indented more than this, get_indent() just returns this value.
		 *
			 * line up with the last group of changes from the
	for (i = 0; i < rec->size; i++) {
			while (g.end > best_shift) {
	if (xenv.mxcost < XDL_MAX_COST_MIN)
		 */
					break;
		rec = &xe->xdf1.recs[xch->i1];
		xdl_bug("group sync broken at end of file");
			 * that this line is the start of a block.
	/*
 *  License as published by the Free Software Foundation; either
				     xch->i2, xche->i2 + xche->chg2 - xch->i2,

				RELATIVE_DEDENT_WITH_BLANK_PENALTY :
	for (; off1 < lim1 && off2 < lim2 && ha1[lim1 - 1] == ha2[lim2 - 1]; lim1--, lim2--);

	g->start = g->end = 0;

	if (!(kvd = (long *) xdl_malloc((2 * ndiags + 2) * sizeof(long)))) {
#define POST_BLANK_WEIGHT 6
							spl->i1 = i1;
 * If more than this number of consecutive blank rows are found, just return
		if (need_min)


			g->end++;

	/*
/*
		/*
/*
				    score_cmp(&score, &best_score) <= 0) {
 * Return the amount of indentation of the specified line, treating TAB as 8
		return -1;
	if (g->end < xdf->nrec &&
			return -1;
 * using this algorithm, so a little bit of heuristic is needed to cut the
/*
					end_matching_other = g.end;
		 */
			 */
				end_matching_other = g.end;
#define XDL_HEUR_MIN_COST 256
			s->penalty += any_blanks ?
					best_score.effective_indent = score.effective_indent;

		 * The line is indented more than its predecessor.
		m->pre_blank += 1;

		 */
/*
int xdl_diff(mmfile_t *mf1, mmfile_t *mf2, xpparam_t const *xpp,
	} else {
		return 0;
		xdl_free_env(xe);

	} else if (m->pre_indent == -1) {
	xch->chg1 = chg1;

			 */
 *
 *
 * This also helps in finding joinable change groups and reducing the diff
#define END_OF_FILE_PENALTY 21
				if (group_slide_up(xdf, &g, flags))
}
				i2 = i1 - d;
	/*
		m->pre_indent = get_indent(xdf->recs[i]);
			if (kvdb[d - 1] < kvdb[d + 1])
			continue;
}
static xdchange_t *xdl_add_change(xdchange_t *xscr, long i1, long i2, long chg1, long chg2) {

					xdl_bug("best shift unreached");
			RELATIVE_INDENT_WITH_BLANK_PENALTY :

	xdl_free_env(&xe);
}

			}
			 * group to align with a group of changed lines in the
		if (xecfg->hunk_func(xch->i1, xche->i1 + xche->chg1 - xch->i1,
				spl->i2 = bbest - bbest1;
 * If g can be slid toward the beginning of the file, do so, and if it bumps
				}

		if (xdl_split(ha1, off1, lim1, ha2, off2, lim2, kvdf, kvdb,

 * columns. Return -1 if line is empty or contains only whitespace. Clamp the
		if (group_next(xdf, &g))
			     rec2->ptr, rec2->size,
	 * If one dimension is empty, then all records on the other one must
				i2 = i1 - d;
			rchg1[rindex1[off1]] = 1;


 * of lines that was inserted or deleted from the corresponding version of the

	/*

 * if g cannot be slid down.
{
/* Characteristics measured about a hypothetical split position. */
		 * maybe the previous block didn't have a block terminator).
 */
			cscr = xch;
 *  This library is distributed in the hope that it will be useful,
 * The empirically-determined weight factors used by score_split() below.
}
		xdl_free_script(xscr);
}
		else
			if ((lim1 + lim2) - bbest < fbest - (off1 + off2)) {
{
		g->end++;
				RELATIVE_OUTDENT_PENALTY;
		if (m->pre_indent != -1)
		}
			}

			for (d = fmax; d >= fmin; d -= 2) {
#include "xinclude.h"
		 * opposite direction because (max - min) must be a power of
		      xdalgoenv_t *xenv) {

		int ignore = 1;
		if (m->post_indent != -1)
 * If the first line in a group is equal to the line following the group, then
	if (xdl_prepare_env(mf1, mf2, xpp, xe) < 0) {
		 */
				i2 = i1 - d;
}


		 * we got a good snake, we sample current diagonals to see
		if (g.end == earliest_end) {
	 */
/* Penalty if there are no non-blank lines before the split */
}
		 diffdata_t *dd2, long off2, long lim2,
	/*
	long ec, d, i1, i2, prev1, best, dd, v, k;
		 * We need to extend the diagonal "domain" by one. If the next
	m->pre_blank = 0;
static int group_slide_up(xdfile_t *xdf, struct xdlgroup *g, long flags)
		if (xpp->flags & XDF_IGNORE_BLANK_LINES)
		xdl_free_env(&xe);
int xdl_do_diff(mmfile_t *mf1, mmfile_t *mf2, xpparam_t const *xpp,
		m->post_indent = get_indent(xdf->recs[i]);
				     ecb->priv) < 0)
		return -1;

 * Also see that project if you want to improve the weights based on, for
			}
		}
		if (rchg1[i1 - 1] || rchg2[i2 - 1]) {
	 * including the line immediately after the split:

 */

	dd2.rchg = xe->xdf2.rchg;
		 * If the group is empty in the to-be-compacted file, skip it:
	return 0;
			return -1;

 */
}
				spl->min_hi = 0;
		;
	kvdb = kvdf + ndiags;
	xch->ignore = 0;
			if (odd && bmin <= d && d <= bmax && kvdb[d] <= i1) {
	if (g->end == xdf->nrec)
	 * How much is the nearest non-blank line above the split indented (or
#define XDL_MAX_COST_MIN 256

	 */
			 kvdf, kvdb, (xpp->flags & XDF_NEED_MINIMAL) != 0, &xenv) < 0) {

	long start;

			}
		 * Also we initialize the external K value to -1 so that we can


			 * other file that it can align with.
		 */
		 * them.
				    off1 < i1 && i1 <= lim1 - xenv->snake_cnt &&

			/*
				got_snake = 1;


#define RELATIVE_OUTDENT_PENALTY 24
	long earliest_end, end_matching_other;
 *  Lesser General Public License for more details.
			if (g.end - groupsize - 1 > shift)
					for (k = 0; ha1[i1 + k] == ha2[i2 + k]; k++)
 * See "An O(ND) Difference Algorithm and its Variations", by Eugene Myers.
#define INDENT_WEIGHT 60
		return xdl_do_patience_diff(mf1, mf2, xpp, xe);
			prev1 = i1;
/* Multiplier for the number of blank lines after the split */

 * its successor
	m->post_indent = -1;
		rec = &xe->xdf2.recs[xch->i2];
				v = (lim1 - i1) + (lim2 - i2) - dd;
}
	} else if (off2 == lim2) {
	 */
					xdl_bug("group sync broken sliding up");
							best = v;
			for (l2 = i2; rchg2[i2 - 1]; i2--);
 * also ensures that the output of score_split fits in an int.
	if (m->indent != -1)
	/* Penalty for this split (smaller is preferred). */
		}
		m->indent = get_indent(xdf->recs[split]);
				got_snake = 1;
			} else {
	/* Penalties based on nearby blank lines: */
			xdl_bug("group sync broken moving to next group");
		xdl_free(kvd);
void xdl_free_script(xdchange_t *xscr) {
 * this value. This avoids requiring O(N^2) work for pathological cases, and
			for (best = 0, d = fmax; d >= fmin; d -= 2) {
 * Compute a badness score for the hypothetical split whose measurements are
			for (d = bmax; d >= bmin; d -= 2) {
 */
							spl->i2 = i2;
		if (m->post_blank == MAX_BLANKS) {
	}
 * (marking changed lines) is done in the two boundary reaching checks.

 * following group, expand this group to include it. Return 0 on success or -1
/* Penalty if there are no non-blank lines after the split */
				spl->min_hi = 1;
		m->end_of_file = 1;
	return 0;
			while (go.end == go.start) {
		xrecord_t **rec;
			ret += 8 - ret % 8;
		long *rindex2 = dd2->rindex;
	long dmin = off1 - lim2, dmax = lim1 - off2;


		/*
		 * avoid extra conditions in the check inside the core loop.
			break;
	int indent;
	s->penalty += TOTAL_BLANK_WEIGHT * total_blank;
		for (; off1 < lim1; off1++)
			i2 = i1 - d;
			 * Indent heuristic: a group of pure add/delete lines
	/*
		 * freedom to produce a more intuitive diff.
				spl->min_lo = 0;
		 */
	}
					i1 = off2 + d, i2 = off2;
} xdpsplit_t;
		return -1;
				score_add_split(&m, &score);
 * file). We consider there to be such a group at the beginning of the file, at
struct split_score {
}

 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
}


		 */


 * We only consider whether the sum of the effective indents for splits are

		 */
 * starting from (lim1, lim2). If the K values on the same diagonal crosses
		xdpsplit_t spl;
 * Larger values means that the position is a less favorable place to split.

	int post_blank, total_blank, indent, any_blanks;
	 */
 *
		 * the heuristics below only have to handle upwards shifts.
				v = (i1 - off1) + (i2 - off2) - dd;

	char *rchg1 = xe->xdf1.rchg, *rchg2 = xe->xdf2.rchg;
 */
					bbest = i1 + i2;
				struct split_score score = {0, 0};
	kvdb[bmid] = lim1;
 * How far do we slide a hunk at most?

	xdchange_t *xch;
 *  modify it under the terms of the GNU Lesser General Public
	for (; off1 < lim1 && off2 < lim2 && ha1[off1] == ha2[off2]; off1++, off2++);
 * all of these weight/penalty values by the same factor wouldn't change the
				i1 = kvdb[d + 1] - 1;
	int end_of_file;
		 * collect the furthest reaching path using the (i1 + i2)

		} else {
	xdchange_t *xch;
	while (1) {
				if (fbest < i1 + i2) {

					xdl_bug("group sync broken sliding to blank line");
			 * position that the group can be shifted to. Then we
static inline int group_previous(xdfile_t *xdf, struct xdlgroup *g)
	for (g->end = g->start; xdf->rchg[g->end]; g->end++)
	} else {
		xdf->rchg[g->end++] = 1;

 */
 * Note that scores are only ever compared against each other, so multiplying

	return (rec1->ha == rec2->ha &&
		if (m->pre_blank == MAX_BLANKS) {

		 * two.
		if (ef(&xe, xscr, ecb, xecfg) < 0) {
			if (!odd && fmin <= d && d <= fmax && i1 <= kvdf[d]) {
			      need_min, &spl, xenv) < 0) {
	g->end = g->start - 1;
	int post_indent;
	if (xdl_recs_cmp(&dd1, 0, dd1.nrec, &dd2, 0, dd2.nrec,
		if (got_snake && ec > xenv->heur_min) {
 * returns the furthest point of reach. We might encounter expensive edge cases
	    recs_match(xdf->recs[g->start - 1], xdf->recs[g->end - 1], flags)) {
		}
 */
	 * How many lines after the line following the split are blank?
		long *rindex1 = dd1->rindex;
				}
	 */
	dd1.nrec = xe->xdf1.nreff;
	}
struct xdlgroup {
		else if (c == '\t')
	while (xdf->rchg[g->end])
	/* -1 if s1.effective_indent < s2->effective_indent, etc. */
			break;
			s->penalty += any_blanks ?
		return -1;
		if (bmax < dmax)
		 * measure is a function of the distance from the diagonal

}
 * Rule: "Divide et Impera" (divide & conquer). Recursively split the box in
	if (xdl_change_compact(&xe.xdf1, &xe.xdf2, xpp->flags) < 0 ||

	}
		if (!XDL_ISSPACE(c))
	 * Set initial diagonal values for both forward and backward path.
/*
}
			--fmax;
	if (!(xch = (xdchange_t *) xdl_malloc(sizeof(xdchange_t))))
			      xdemitconf_t const *xecfg)
			 * "before" context and the start of the group, and
		else
	} else if (indent > m->pre_indent) {
			while (!group_slide_up(xdf, &g, flags))

/*
				spl->i1 = bbest1;
/*
	 * Trivial. Collects "groups" of changes and creates an edit script.
		if (!xch)
static int score_cmp(struct split_score *s1, struct split_score *s2)
			RELATIVE_INDENT_PENALTY;
{
		/*
	if (XDF_DIFF_ALG(xpp->flags) == XDF_HISTOGRAM_DIFF)
			kvdf[d] = i1;
}
							break;
	int ret = 0;
		s->penalty += any_blanks ?
			for (; i1 < lim1 && i2 < lim2 && ha1[i1] == ha2[i2]; i1++, i2++);
 * Move g to describe the next (possibly empty) group in xdf and return 0. If g
		} else if (flags & XDF_INDENT_HEURISTIC) {
				if (i1 + i2 < bbest) {
/*
	 * How much is the nearest non-blank line after the line following the
		 * it interesting.
 */
							spl->i1 = i1;
		 * The line is indented less than its predecessor. It could be
 * stored in m. The weight factors were determined empirically using the tools
	xdfenv_t xe;

			/*
	xdl_free(kvd);
typedef struct s_xdpsplit {
			 * The following line is indented more. So it is likely

		 * No additional adjustments needed.
		xenv.mxcost = XDL_MAX_COST_MIN;


	 * favored):
		/*
	int post_blank;
static int xdl_call_hunk_func(xdfenv_t *xe, xdchange_t *xscr, xdemitcb_t *ecb,
	    xdl_build_script(&xe, &xscr) < 0) {

/*
			++fmin;
	 * if the line is blank):
				shift = g.end - INDENT_HEURISTIC_MAX_SLIDING;
static inline int group_next(xdfile_t *xdf, struct xdlgroup *g)
				spl->i1 = i1;
	int pre_blank;

				spl->min_lo = spl->min_hi = 1;

	/*
				RELATIVE_DEDENT_PENALTY;
 */
				}
			kvdf[++fmax + 1] = -1;
 *     https://github.com/mhagger/diff-slider-tools
#define INDENT_HEURISTIC_MAX_SLIDING 100

	 * A place to accumulate penalty factors (positive makes this index more
	int penalty;
				i1 = kvdb[d];
#define XDL_LINE_MAX (long)((1UL << (CHAR_BIT * sizeof(long) - 1)) - 1)

			end_matching_other = -1;

	 * group, end is equal to start.
	}

			}

	fprintf(stderr, "BUG: %s\n", msg);
	post_blank = (m->indent == -1) ? 1 + m->post_blank : 0;
				i2 = i1 - d;
/*
{
				i1 = XDL_MIN(kvdf[d], lim1);
#define RELATIVE_OUTDENT_WITH_BLANK_PENALTY 17

		/*
		 */
	dd1.ha = xe->xdf1.ha;
				if (group_slide_up(xdf, &g, flags))
 */
							best = v;
/* Multiplier for the number of blank lines around the split */


						if (k == xenv->snake_cnt) {
			/* no shifting was possible */
	 * How much is the line immediately following the split indented (or -1
			else
		for (d = fmax; d >= fmin; d -= 2) {
 * group_slide_down() and group_slide_up().
	return 0;
 * Basically considers a "box" (off1, off2, lim1, lim2) and scan from both
	/*
 * heuristic's behavior. Still, we need to set that arbitrary scale *somehow*.

	return 0;
			m->pre_indent = 0;
	 */


/*
 */
{

 *
				dd = d > bmid ? d - bmid: bmid - d;
			}
}
		s->penalty += START_OF_FILE_PENALTY;
			 * This is this highest that this group can be shifted.
		}
 * determine the better of two scores.
			return MAX_INDENT;
/*
	long fmid = off1 - off2, bmid = lim1 - lim2;
{
		xdl_recmatch(rec1->ptr, rec1->size,
#define RELATIVE_INDENT_WITH_BLANK_PENALTY 10
	*xscr = cscr;
		/* No additional adjustments needed. */

			struct split_score best_score;
 * Penalties applied if the line is indented less than both its predecessor and
			return -1;
		if (bmin > dmin)
	}
	} else {
	xdchange_t *xscr;
/*
}
 * within an int.
		 */
 * If g is already at the beginning of the file, do nothing and return -1.
			rchg2[rindex2[off2]] = 1;
	 */
	/*
int xdl_change_compact(xdfile_t *xdf, xdfile_t *xdfo, long flags) {
				if (go.end > go.start)
 *  Copyright (C) 2003	Davide Libenzi
}
	dd1.rchg = xe->xdf1.rchg;
			/* Shift the group backward as much as possible: */
 * Move g to describe the previous (possibly empty) group in xdf and return 0.
	}

				return ec;
			xdl_free_script(xscr);
		 * also be the start of a new block (e.g., an "else" block, or
		 * opposite direction because (max - min) must be a power of
 * adjusted relative to each other with sufficient precision despite using

}
			 * Keep track of the last "end" index that causes this

 *  This library is free software; you can redistribute it and/or
struct split_measurement {
		}
	/*

			if (best > 0) {
#define RELATIVE_DEDENT_WITH_BLANK_PENALTY 17
			}
		 * values exits the box boundaries we need to change it in the
	 * split indented (or -1 if there is no such line)?
				spl->i1 = i1;
			goto next;
			 * aesthetically better and some are worse. We compute
				spl->min_hi = 1;
				i1 = kvdf[d];
		 * If the group can be shifted, then we can possibly use this
/*
		 * measure.
		}
	xch->i2 = i2;

			if (i1 - prev1 > xenv->snake_cnt)
#define RELATIVE_DEDENT_PENALTY 23
	}
			for (best = 0, d = bmax; d >= bmin; d -= 2) {
					bbest1 = i1;
		 * two.
{
			/* Now shift the group forward as far as possible: */
				if (best_shift == -1 ||
		 * the block terminator of the previous block, but it could
					for (k = 1; ha1[i1 - k] == ha2[i2 - k]; k++)
		 *
		xdfenv_t *xe) {
 *  LibXDiff by Davide Libenzi ( File Differential Library )
 * Fill m with information about a hypothetical split of xdf above line split.
			 * That was probably the end of a block.
	 * Is the split at the end of the file (aside from any blank lines)?
	for (xch = xscr; xch; xch = xch->next) {
				 kvdf, kvdb, spl.min_lo, xenv) < 0 ||
		return NULL;
static void group_init(xdfile_t *xdf, struct xdlgroup *g)
	kvdf = kvd;
	long end;

#define RELATIVE_INDENT_PENALTY (-4)
}
		if (ret >= MAX_INDENT)

			 */
		 * if some of them have reached an "interesting" path. Our
 *
	for (i = split - 1; i >= 0; i--) {
				spl->min_lo = 0;
		m->end_of_file = 0;
	emit_func_t ef = xecfg->hunk_func ? xdl_call_hunk_func : xdl_emit_diff;
	if (XDF_DIFF_ALG(xpp->flags) == XDF_PATIENCE_DIFF)
	 */
#define START_OF_FILE_PENALTY 1
		} else if (end_matching_other != -1) {
		if (m->post_indent != -1 && m->post_indent > indent) {
				 kvdf, kvdb, spl.min_hi, xenv) < 0) {
		xdf->rchg[--g->end] = 0;
			bbest = bbest1 = XDL_LINE_MAX;
		int got_snake = 0;
/*
		for (i = 0; i < xch->chg2 && ignore; i++)

	if (xscr) {

			if (go.end > go.start)
			}
	while ((xch = xscr) != NULL) {
 *
	return 0;
				i1 = kvdb[d - 1];
static long xdl_split(unsigned long const *ha1, long off1, long lim1,
			return -1;
		 * Try to distinguish those cases based on what comes next:
		    xdl_recs_cmp(dd1, spl.i1, lim1, dd2, spl.i2, lim2,
		char c = rec->ptr[i];
				if (group_slide_down(xdf, &g, flags))
	int min_lo, min_hi;
 */
		if (ec >= xenv->mxcost) {
 * the end of the file, and between any two unchanged lines, though most such
	int effective_indent;
				xdl_free_script(cscr);
	}


		}
 *  License along with this library; if not, see
			 * other file. -1 indicates that we haven't found such
	}


		for (i = 0; i < xch->chg1 && ignore; i++)
}
#define MAX_BLANKS 20
		while (xdf->rchg[g->start - 1])

		 * Also we initialize the external K value to -1 so that we can
		 * edit cost times a magic factor (XDL_K_HEUR) we consider
 * value is multiplied by the following weight and combined with the penalty to



			}
			xdl_mark_ignorable(xscr, &xe, xpp->flags);
	xch->i1 = i1;
	 * algorithm.
int xdl_recs_cmp(diffdata_t *dd1, long off1, long lim1,
				spl->i2 = i2;
	    recs_match(xdf->recs[g->start], xdf->recs[g->end], flags)) {
			break;
		indent = m->indent;
	for (g->start = g->end; xdf->rchg[g->start - 1]; g->start--)
				if (group_next(xdfo, &go))
		}
				shift = g.end - groupsize - 1;

		/*
				if (group_previous(xdfo, &go))

	}
 * size.
		/*
					best_score.penalty = score.penalty;
		xdf->rchg[--g->start] = 1;
				i1 = kvdf[d + 1];
		xdf->rchg[g->start++] = 0;
				if (lim2 < i2)
	if (g->start == 0)

		/*
		xscr = xscr->next;
			m->post_indent = 0;
	dd1.rindex = xe->xdf1.rindex;
			}
	any_blanks = (total_blank != 0);
			kvdb[++bmax + 1] = XDL_LINE_MAX;
		for (; off2 < lim2; off2++)
	return 0;
	if (m->end_of_file)
	 * One is to store the forward path and one to store the backward path.
		xche = xdl_get_hunk(&xch, xecfg);




				spl->min_lo = spl->min_hi = 1;
				    off2 < i2 && i2 <= lim2 - xenv->snake_cnt) {
	 */
		if (g.end == g.start)
	long i;
	 */
		 */
		;
	xdalgoenv_t xenv;
		 *
				measure_split(xdf, shift - groupsize, &m);
 * index bounding since the array is prepared with a zero at position -1 and N.
	long bmin = bmid, bmax = bmid;

		xdl_free_env(xe);
 * Initialize g to point at the first group in xdf.

 * Penalties applied if the line is indented more than its predecessor

 *  Davide Libenzi <davidel@xmailserver.org>
	}
};
			if (g.end - INDENT_HEURISTIC_MAX_SLIDING > shift)
						if (k == xenv->snake_cnt - 1) {
			ret += 1;
		 * The line has the same indentation level as its predecessor.

	 * The index of the first unchanged line after the group. For an empty
	return -1;
 *  You should have received a copy of the GNU Lesser General Public
	}
	if (split >= xdf->nrec) {
 * Represent a group of changed lines in an xdfile_t (i.e., a contiguous group
				spl->min_lo = 1;

	for (ec = 1;; ec++) {
 * is already at the end of the file, do nothing and return -1.
		if (xdl_recs_cmp(dd1, off1, spl.i1, dd2, off2, spl.i2,
		}
			 * implies two splits, one between the end of the

 * This avoids having to do absurd amounts of work for data that are not
			  struct split_measurement *m)
	/*
	group_init(xdfo, &go);
			 * Record its end index:
			++bmin;

			 */
 *  <http://www.gnu.org/licenses/>.
		indent = m->post_indent;
				RELATIVE_OUTDENT_WITH_BLANK_PENALTY :
 * the forward diagonal starting from (off1, off2) and the backward diagonal
		spl.i1 = spl.i2 = 0;
		xdl_free(xch);
			break;
	m->post_blank = 0;
 */
		 * Divide ...
						}

	s->effective_indent += indent;
		/*
	/*
		 long *kvdf, long *kvdb, int need_min, xdalgoenv_t *xenv) {
			}

			i2 = i1 - d;
			earliest_end = g.end;
	}
		 * ... et Impera.
		long i;
	 * Allocate and setup K vectors to be used by the differential
	if (m->pre_indent == -1 && m->pre_blank == 0)
		char *rchg2 = dd2->rchg;
				spl->i1 = fbest1;
			groupsize = g.end - g.start;
				spl->min_hi = 0;
 */
	total_blank = m->pre_blank + post_blank;
	return INDENT_WEIGHT * cmp_indents + (s1->penalty - s2->penalty);
	/* The effective indent of this split (smaller is preferred). */

	 *
{

		/* Move past the just-processed group: */

		/* No additional adjustments needed. */
			 */
 *
#define XDL_K_HEUR 4
	long i1, i2;
	}
		      unsigned long const *ha2, long off2, long lim2,
					xdl_bug("group sync broken sliding to match");
 */
 */
				i1 = XDL_MAX(off1, kvdb[d]);
	if (indent == -1) {
	return 0;
	s->penalty += POST_BLANK_WEIGHT * post_blank;

	/*
 * Penalties applied if the line is indented less than its predecessor but not

				    off2 + xenv->snake_cnt <= i2 && i2 < lim2) {

 * less than its successor
	 * Set post_blank to the number of blank lines following the split,

				spl->min_lo = 1;

	for (i = split + 1; i < xdf->nrec; i++) {
		 * If the edit cost is above the heuristic trigger and if
			 * beginning of the "after" context. Some splits are
	if (xdl_do_diff(mf1, mf2, xpp, &xe) < 0) {
			}

static void measure_split(const xdfile_t *xdf, long split,
		while (xdf->rchg[g->end])
				score_add_split(&m, &score);
			 * Move the possibly merged group of changes back to

	}
		if (group_next(xdfo, &go))
	ndiags = xe->xdf1.nreff + xe->xdf2.nreff + 3;
	dd2.ha = xe->xdf2.ha;
#define MAX_INDENT 200
	}
				struct split_measurement m;
		 * We need to extend the diagonal "domain" by one. If the next
	for (xch = xscr; xch; xch = xche->next) {
			kvdf[--fmin - 1] = -1;
	xdchange_t *cscr = NULL, *xch;

 */
	 * be obviously changed.
	 * the unchanged line above which the (empty) group is located.
				measure_split(xdf, shift, &m);

			 * pick the shift with the lowest score.
			/*

/*
					xdl_bug("group sync broken sliding down");
		/*

					fbest = i1 + i2;
		 */
	xenv.mxcost = xdl_bogosqrt(ndiags);
			if (prev1 - i1 > xenv->snake_cnt)
	long fmin = fmid, fmax = fmid;

	xch->chg2 = chg2;
};

	/* Note that the effective indent is -1 at the end of the file: */
				if (i2 < off2)
		char *rchg1 = dd1->rchg;
							break;
	    xdl_change_compact(&xe.xdf2, &xe.xdf1, xpp->flags) < 0 ||
			}
			/*
	int pre_indent;
	xenv.heur_min = XDL_HEUR_MIN_COST;
/*
	g->start = g->end + 1;
 * to the line preceding the group, then the group can be slid up. See
	dd2.rindex = xe->xdf2.rindex;
static void xdl_bug(const char *msg)
};
 * In practice, these numbers are chosen to be large enough that they can be

 * Move back and forward change groups for a consistent and pretty diff output.
	return 0;
	 */
			shift = earliest_end;
			   (s1->effective_indent < s2->effective_indent));

		return 0;
 * less than (-1), equal to (0), or greater than (+1) each other. The resulting
		s->penalty += END_OF_FILE_PENALTY;
int xdl_build_script(xdfenv_t *xe, xdchange_t **xscr) {
			/*
	long odd = (fmid - bmid) & 1;

	kvdf += xe->xdf2.nreff + 1;
		m->post_blank += 1;
			long fbest, fbest1, bbest, bbest1;
{
					i1 = lim2 + d, i2 = lim2;
			xdl_free_env(&xe);
				if (group_previous(xdfo, &go))
				return ec;
/*
 */
		if (fmin > dmin)
			return ec;
	diffdata_t dd1, dd2;
			prev1 = i1;
	xch->next = xscr;


 *
			if (kvdf[d - 1] >= kvdf[d + 1])
	long ndiags;
			for (l1 = i1; rchg1[i1 - 1]; i1--);

	} else if (indent == m->pre_indent) {
			kvdb[--bmin - 1] = XDL_LINE_MAX;
 * example, a larger or more diverse corpus.
		 * corner (i1 + i2) penalized with the distance from the

	long *kvd, *kvdf, *kvdb;
 */
	/*
{
		else if (c == ' ')
 *
	kvdb += xe->xdf2.nreff + 1;
	xdchange_t *xch;
		else

		 * mid diagonal itself. If this value is above the current
				i1 = kvdf[d - 1] + 1;

	 */
							spl->i2 = i2;
	struct xdlgroup g, go;
	else
						}

		/* ignore other whitespace characters */
 *  version 2.1 of the License, or (at your option) any later version.
				spl->i2 = fbest - fbest1;
		return -1;
				return -1;
		 * values exits the box boundaries we need to change it in the
	xdchange_t *xch, *xche;

 * or -1 if g cannot be slid up.
			else
				if (v > XDL_K_HEUR * ec && v > best &&
			break;
		return -1;
 * sub-boxes by calling the box splitting function. Note that the real job
 *
	long groupsize;
	return xch;
