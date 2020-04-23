		if (!result->ptr) {
			return -1;
		/* The only line has no eol */
		if (!dest) {
		return -1;
			if (xdl_append_merge(&c, 0,
	for (; m; m = m->next) {
 */
	xrecord_t **rec1 = xe1->xdf2.recs + i1;
	}
			chg0 = xscr2->chg1;
				i0 -= off;
			if (xdl_append_merge(&c, 1,
				xscr1->chg2 != xscr2->chg2 ||
			rec2[i]->ptr, rec2[i]->size, flags);
} xdmerge_t;
			xdl_cleanup_merge(changes);
			if (xdl_append_merge(&c, 2,
			}
	/* Match post-images' preceding, or first, lines' end-of-line style */
			xscr2 = xscr2->next;
		m = xdl_malloc(sizeof(xdmerge_t));
		xscr2 = xscr2->next;
				if (dest)
		chg2 = xscr2->chg2;
	    xdl_change_compact(&xe1.xdf2, &xe1.xdf1, xpp->flags) < 0 ||
			chg2 = xscr2->i2 + xscr2->chg2 - i2;
{

			} else
		size += marker_size + 1 + needs_cr + marker2_size;
		 * This probably does not work outside git, since
			size += marker_size + 1 + needs_cr + marker3_size;
			+ xe2->xdf2.recs[m->i2 + m->chg2 - 1]->size - t2.ptr;
		end = next_m->i1;
	if (needs_cr)
				return -1;
		}
		    (end - begin > 3 &&
 * as conflicting, too.
{

			m->mode = 0;
	 * These point at the preimage; of course there is just one
				size++;
	m->chg2 = next_m->i2 + next_m->chg2 - m->i2;
			continue;
	if (add_nl) {
						  size, i, style, m, dest,
				 xdmerge_t *m, char *dest, int style,

		}
		m->chg1 = i1 + chg1 - m->i1;
	xrecord_t **recs;
}
			m = m2;
		i1 = xscr1->i1 + xscr1->chg1;
			m = next_m;
		/* let's handle just the conflicts */
 *  version 2.1 of the License, or (at your option) any later version.
			      dest ? dest + size : NULL);
				return -1;
			      xdmerge_t *m, char *dest, int marker_size)
			return 1;
	xdl_free_script(xscr2);
		if (!next_m)

	return 0;
		if (xdl_change_compact(&xe.xdf1, &xe.xdf2, xpp->flags) < 0 ||
	return count;
				size += xdl_recs_copy(xe1, m->i1, m->chg1, needs_cr, (m->mode & 2),
		xdmerge_t *next_m = m->next;
static int xdl_recs_copy(xdfenv_t *xe, int i, int count, int needs_cr, int add_nl, char *dest)
 *
{
	 * 0 = conflict,
	while (xscr1 && xscr2) {

	xdmerge_t *next_c;
}
			if (marker3_size) {
				      result->ptr, style, marker_size);
		size += marker_size;
					xscr1->chg2, xpp->flags)) {
			dest[size++] = '\r';
	long i1, i2;
			      const char *name3,
				i2 += off;
				     i0, chg0, i1, chg1, i2, chg2)) {

		dest[size++] = '\n';
 * level == 1: mark overlapping changes as conflict only if not identical
		xscr1 = xscr1->next;
			changes = c;
}
	while (xscr1) {
			xscr = xscr->next;
			    long i2, long chg2)


			if (off > 0) {
			count++;
{
		size += marker_size;
			}
	/*
			return -1;
}
				xscr1->chg1 != xscr2->chg1 ||
	    xdl_build_script(&xe1, &xscr1) < 0) {
	 * overlap, lines before i1 in the postimage of side #1 appear
		memcpy(result->ptr, mf2->ptr, mf2->size);
	if (!i)
	}
			continue;

 * if the lines are moved into the conflicts.
		xdl_fill_merge_buffer(xe1, name1, xe2, name2,

 * Returns 1 if the i'th line ends in CR/LF (if it is the last line and
	xrecord_t **rec2 = xe2->xdf2.recs + i2;
		xdl_free_script(x);
{
		xdl_free_env(&xe1);
		}
				i1 -= off;
			m->mode = favor;
}
						      dest ? dest + size : NULL);
/*
	int needs_cr;

}
			/* If this happens, the changes are identical. */

	int marker1_size = (name1 ? strlen(name1) + 1 : 0);
						  marker_size);
		m->next = NULL;
		needs_cr = is_eol_crlf(&xe1->xdf1, 0);
		m->i1 = i1;
		next_c = c->next;
			continue;
static int xdl_fill_merge_buffer(xdfenv_t *xe1, const char *name1,
int xdl_merge(mmfile_t *orig, mmfile_t *mf1, mmfile_t *mf2,
		if (xscr2->i1 + xscr2->chg1 < xscr1->i1) {
	m->next = next_m->next;
	int count = 0;
		/* All lines before the last *must* end in LF */
				xdl_free_script(x);
	}
		if (m->mode)
		}
				xdl_cleanup_merge(changes);
			      dest ? dest + size : NULL);
	}
{
			i0 = xscr1->i1;
	} else if (!xscr2) {
		t2.size = xe2->xdf2.recs[m->i2 + m->chg2 - 1]->ptr
}
				xe->xdf2.recs[i]->size))
		      lines_contain_alnum(xe1, begin, end - begin)))) {
				chg1 -= ffo;
	struct s_xdmerge *next;
		t1.ptr = (char *)xe1->xdf2.recs[m->i1]->ptr;
			xdmerge_t *m2 = xdl_malloc(sizeof(xdmerge_t));
		size += marker_size;

		return 0;
		needs_cr = is_eol_crlf(&xe2->xdf2, m->i2 ? m->i2 - 1 : 0);
	}
	int i;
	xdmerge_t *m = *merge;
			xdl_free_env(&xe);

	if (!xscr1) {
		return -1;
			/* conflict */
		     (!simplify_if_no_alnum ||
		chg1 = xscr1->chg2;
		changes = c;
		m->chg1 = xscr->chg1;
static int xdl_orig_copy(xdfenv_t *xe, int i, int count, int needs_cr, int add_nl, char *dest)
	for (;;) {
			size += marker1_size;
	const char *const ancestor_name = xmp->ancestor;
 *  Davide Libenzi <davidel@xmailserver.org>
	int size = 0;
			size++;
	     xdl_simplify_non_conflicts(xe1, changes,
	xdmerge_t *next_m = m->next;
			int ffo = off + xscr1->chg1 - xscr2->chg1;
			}
	int mode;
				     i0, chg0, i1, chg1, i2, chg2)) {
 */
		result->size = mf1->size;
						  ancestor_name,
	long chg0;
		while (xscr->next) {
}

	int status;
		if (level == XDL_MERGE_MINIMAL || xscr1->i1 != xscr2->i1 ||
		if (xdl_do_diff(&t1, &t2, xpp, &xe) < 0)
			m->i2 = xscr->i2 + i2;
}
			if (dest)
	 */
static int lines_contain_alnum(xdfenv_t *xe, int i, int chg)
	for (i = 0; i < line_count; i++) {

			chg2 = xscr2->chg2;
		xdl_free_env(&xe1);
		if (!result)
			dest[size] = ' ';
		m->chg2 = i2 + chg2 - m->i2;
			chg1 = xscr1->i2 + xscr1->chg2 - i1;
			int off = xscr1->i1 - xscr2->i1;
			size += xdl_recs_copy(xe1, i, m->i1 - i, 0, 0,
		 * more aggressive than XDL_MERGE_EAGER.
	if (count < 1)
			      dest ? dest + size : NULL);
		return result;
	const char *const name1 = xmp->file1;
			if (!m2) {
#include "xinclude.h"

		i2 = xscr2->i1 + xscr2->chg1;
		mmfile_t t1, t2;
}
	 * how side #1 wants to change the common ancestor; if there is no
			file->recs[i]->ptr[size - 2] == '\r';
	return 0;
		} else

		if (isalnum((unsigned char)*(ptr++)))
{
{
		if (needs_cr)
		result->size = size;
	if (xdl_change_compact(&xe1.xdf1, &xe1.xdf2, xpp->flags) < 0 ||
		/* no sense refining a conflict when one side is empty */
	if (!changes)
 * lines. Try hard to show only these few lines as conflicting.
			if (ffo < 0) {
			return 1;
		if (favor && !m->mode)
			(*merge)->next = m;
	for (i = 0; i < count; size += recs[i++]->size)
	size += xdl_recs_copy(xe1, i, m->i1 - i, 0, 0,
				 const char *ancestor_name,
	xpparam_t const *xpp = &xmp->xpp;
			m->mode = 4;
		memcpy(result->ptr, mf1->ptr, mf1->size);
		begin = m->i1 + m->chg1;
		/* Last line; ends in LF; Is it CR/LF? */
static int xdl_do_merge(xdfenv_t *xe1, xdchange_t *xscr1,
		 */

				chg2 += ffo;
 *  You should have received a copy of the GNU Lesser General Public
	return size;
			if (needs_cr) {
					XDL_MERGE_ZEALOUS < level) < 0)) {
 *  License along with this library; if not, see
			return -1;
			m->mode = 0;
	if (m && (i1 <= m->i1 + m->chg1 || i2 <= m->i2 + m->chg2)) {

static int fill_conflict_hunk(xdfenv_t *xe1, const char *name1,
			xdl_merge_two_conflicts(m);
	    xdl_change_compact(&xe2.xdf2, &xe2.xdf1, xpp->flags) < 0 ||
			changes = c;
		i0 = xscr2->i1;
			m->chg2 = xscr->chg2;
			chg0 = xscr1->chg1;
			return -1;
}
		}
{
	for (size = i = 0; m; m = m->next) {
	xdl_free_env(&xe1);
 *  License as published by the Free Software Foundation; either
			memcpy(dest + size + 1, name1, marker1_size - 1);
	m->chg1 = next_m->i1 + next_m->chg1 - m->i1;
			+ xe1->xdf2.recs[m->i1 + m->chg1 - 1]->size - t1.ptr;
		int i1 = m->i1, i2 = m->i2;


	return 0;

 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
		return -1;
	 * 3 = no conflict, take both.
	xdl_free_env(&xe2);
					     i0, chg0, i1, chg1, i2, chg2)) {
{
	/* Postimage from side #1 */
		/*
		}
 * it appears simpler -- because it takes up less (or as many) lines --
 * level == 3: analyze non-identical changes for minimal conflict set, but
			    long i0, long chg0,
	}
		chg0 = xscr1->chg1;
		memset(dest + size, '=', marker_size);
}
 * -1 if the line ending cannot be determined.

	/*
		size += marker_size + 1 + needs_cr;

			}
	int style = xmp->style;
	int size, i;
		m->mode = mode;
	if (!file->nrec)
		xdfenv_t xe;
		xdl_free_env(&xe2);
			}
		int line_count, long flags)
{
		xdfenv_t *xe2, xdchange_t *xscr2,
	free(next_m);
		int size = xdl_fill_merge_buffer(xe1, name1, xe2, name2,
			i0 = xscr2->i1;
		t2.ptr = (char *)xe2->xdf2.recs[m->i2]->ptr;

	 * 1 = no conflict, take first,
		} else {
	}
		result->ptr = xdl_malloc(mf1->size);
 * returns < 0 on error, == 0 for no conflicts, else number of conflicts
	}
		i2 = xscr2->i2;
 * Sometimes, changes are not quite identical, but differ in only a few
		return -1;
	int marker2_size = (name2 ? strlen(name2) + 1 : 0);
	return status;
	return xdl_cleanup_merge(changes);
		i1 = xscr2->i1 + xe1->xdf2.nrec - xe1->xdf1.nrec;
		chg2 = xscr1->chg1;
		if (i1 >= i2)

			      xdfenv_t *xe2, const char *name2,
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
				return -1;
		if (!xscr) {
 *  This library is free software; you can redistribute it and/or
		return -1;
	if (xdl_change_compact(&xe2.xdf1, &xe2.xdf2, xpp->flags) < 0 ||
	} else {

/*
			chg2 = xscr1->chg1;
			else
{
	result->ptr = NULL;
		memset(dest + size, '>', marker_size);
			changes = c;
			m->chg1 = xscr->chg1;
			xdl_cleanup_merge(changes);
	int needs_cr = is_cr_needed(xe1, xe2, m);

			size += marker2_size;
 *
		return size > 1 &&

		memset(dest + size, '<', marker_size);
		return -1;
		else if (m->mode & 3) {
static void xdl_merge_two_conflicts(xdmerge_t *m)
	} else {
	const char *const name2 = xmp->file2;
		if (xscr1->i1 + xscr1->chg1 < xscr2->i1) {
{
				xdl_cleanup_merge(changes);
 *  modify it under the terms of the GNU Lesser General Public
	return needs_cr < 0 ? 0 : needs_cr;
		if (i2 >= i1)
		result->ptr = xdl_malloc(size);

			size = fill_conflict_hunk(xe1, name1, xe2, name2,

	xdmerge_t *changes, *c;

	}
	if (needs_cr)
static int xdl_append_merge(xdmerge_t **merge, int mode,
	}
				 int favor,
	return (size = file->recs[i - 1]->size) > 1 &&
 *  This library is distributed in the hope that it will be useful,

				 xdfenv_t *xe2, const char *name2,
	 * 2 = no conflict, take second.
			dest[size++] = '\r';

	xdl_free_script(xscr1);
		xpparam_t const *xpp)


	if (!m)
	for (; chg; chg--, i++)
	if (!dest) {
				dest[size] = ' ';
					xe2, xscr2->i2,
			xscr1 = xscr1->next;
				return -1;
	if (marker_size <= 0)
	if (result) {
	}
			i2 = xscr2->i2;
			file->recs[i]->ptr[size - 1] == '\n')
		if (!changes)
			}
			dest[size++] = '\r';
				int needs_cr = is_cr_needed(xe1, xe2, m);
			i1 = xscr1->i2;
	 * preimage, that is from the shared common ancestor.
		 * "diff3 -m" output does not make sense for anything
	size += xdl_recs_copy(xe1, i, xe1->xdf2.nrec - i, 0, 0,
				      dest ? dest + size : NULL);
		int marker_size = xmp->marker_size;
			xdl_cleanup_merge(changes);
		i = recs[count - 1]->size;

		if (c->mode == 0)
	xdfenv_t xe1, xe2;
			result++;
 * This function merges m and m->next, marking everything between those hunks
			dest[size] = ' ';
 *  <http://www.gnu.org/licenses/>.

{
 *
	return xdl_recs_copy_0(1, xe, i, count, needs_cr, add_nl, dest);
		    xdl_build_script(&xe, &xscr) < 0) {
	 */

			size += marker_size;
		if (!changes)
	/* Before conflicting part */
	if (i < file->nrec - 1)
	if (xdl_do_diff(orig, mf2, xpp, &xe2) < 0) {
/*
			memcpy(dest + size + 1, name2, marker2_size - 1);
	/* were there conflicts? */
 * level == 2: analyze non-identical changes for minimal conflict set
		if (m->mode == 0)
static int is_cr_needed(xdfenv_t *xe1, xdfenv_t *xe2, xdmerge_t *m)
	/* refine conflicts */
	if (!dest) {
	if (!dest) {

	xpparam_t const *xpp = &xmp->xpp;
		m->chg0 = chg0;
					     i0, chg0, i1, chg1, i2, chg2)) {
 *  Copyright (C) 2003-2006 Davide Libenzi, Johannes E. Schindelin
	}
			continue;
		if (XDL_MERGE_EAGER < level)
	return xdl_recs_copy_0(0, xe, i, count, needs_cr, add_nl, dest);
	 * These point at the respective postimages.  E.g. <i1,chg1> is
 */
	/* Determine eol from second-to-last line */
		xdl_free_env(&xe);
				size += xdl_recs_copy(xe2, m->i2, m->chg2, 0, 0,

		xdl_free_script(xscr1);
		xdl_cleanup_merge(changes);
		/* Shared preimage */

	/* If still undecided, use LF-only */
			/* Before conflicting part */
}
	c = changes = NULL;
static int xdl_merge_cmp_lines(xdfenv_t *xe1, int i1, xdfenv_t *xe2, int i2,
		} else {
	while (size--)

	}
	return size;
		}
	recs = (use_orig ? xe->xdf1.recs : xe->xdf2.recs) + i;
		if (!changes)
		m->i0 = i0;
	/* Postimage from side #2 */
		*merge = m;
static int xdl_cleanup_merge(xdmerge_t *c)
		if (marker1_size) {
			return result;
/*
		i0 = xscr1->i1;
 * If there are less than 3 non-conflicting lines between conflicts,
					dest[size] = '\r';
			      int size, int i, int style,
						 ancestor_name,
		if (needs_cr)
 *  Lesser General Public License for more details.
}
		if (needs_cr)
	}

		if (m->mode != 0 || next_m->mode != 0 ||
				dest[size++] = '\r';
 *
			    long i1, long chg1,

			chg0 = xscr1->i1 + xscr1->chg1 - i0;
	long i0;
				size += marker3_size;
				      &xe2, xscr2,
{
static int xdl_refine_conflicts(xdfenv_t *xe1, xdfenv_t *xe2, xdmerge_t *m,
		if (xdl_append_merge(&c, 1,
		if (*merge)
 * has no eol, the preceding line, if any), 0 if it ends in LF-only, and
			xscr1 = xscr1->next;
			/* Postimage from side #1 */
		xmparam_t const *xmp, mmbuffer_t *result)
		free(c);
			}

		xmparam_t const *xmp, mmbuffer_t *result)
	    (xdl_refine_conflicts(xe1, xe2, changes, xpp) < 0 ||
static int is_eol_crlf(xdfile_t *file, int i)
 */
		}
}

		i1 = xscr1->i2;
			chg1 = xscr1->chg2;
	xdchange_t *xscr1, *xscr2;
static int line_contains_alnum(const char *ptr, long size)
				xdl_free_env(&xe);
			if (m->mode & 2)
	} else {
typedef struct s_xdmerge {

			xdl_free_env(&xe);
			i2 = xscr2->i2 - xscr2->i1 + xscr1->i1;
		i = m->i1 + m->chg1;
						 marker_size);
			/* Postimage from side #2 */
 *
}
	}
	while (xscr2) {
		result->ptr = xdl_malloc(mf2->size);
		xdchange_t *xscr, *x;
 */
		xdl_free_env(&xe1);
				chg0 -= ffo;
		dest[size++] = '\n';
		if (i == 0 || recs[count - 1]->ptr[i - 1] != '\n') {
		}
	}
		size += marker_size + 1 + needs_cr + marker1_size;
		m->chg2 = xscr->chg2;
		if (xdl_append_merge(&c, 2,
						 favor, changes, NULL, style,
			memcpy(dest + size, recs[i]->ptr, recs[i]->size);
			i1 = xscr1->i2;
					      dest ? dest + size : NULL);
	return 0;
		x = xscr;
		if (!m)
			chg1 = xscr2->chg1;
		dest[size++] = '\n';
	size += xdl_recs_copy(xe2, m->i2, m->chg2, needs_cr, 1,
		int result = xdl_recmatch(rec1[i]->ptr, rec1[i]->size,
		if (line_contains_alnum(xe->xdf2.recs[i]->ptr,
			i1 = xscr1->i2 - xscr1->i1 + xscr2->i1;
					     i0, chg0, i1, chg1, i2, chg2)) {
static int xdl_simplify_non_conflicts(xdfenv_t *xe1, xdmerge_t *m,
{
}
	}
			m->i1 = xscr->i1 + i1;
		if (m->chg1 == 0 || m->chg2 == 0)
		m->i1 = xscr->i1 + i1;
		int begin, end;
			if (m->mode & 1) {
			return -1;

			return -1;
	for (; c; c = next_c) {
 *             treat hunks not containing any letter or number as conflicting
	    xdl_build_script(&xe2, &xscr2) < 0) {
				 int marker_size)
	if (xdl_do_diff(orig, mf1, xpp, &xe1) < 0) {
		chg0 = xscr2->chg1;
	return 0;
				      ancestor_name, favor, changes,
	status = 0;
			file->recs[i]->ptr[size - 2] == '\r';
/*
				xdl_merge_cmp_lines(xe1, xscr1->i2,
	size += xdl_recs_copy(xe1, m->i1, m->chg1, needs_cr, 1,
		/*
	return size;
	if (style == XDL_MERGE_DIFF3) {
			      dest ? dest + size : NULL);
		m->chg1 = chg1;
			memset(dest + size, '|', marker_size);
	} else {
				      xmp, result);
		}
	if ((size = file->recs[i]->size) &&
		}
				memcpy(dest + size + 1, name3, marker3_size - 1);
 * level == 0: mark all overlapping changes as conflict
		}
{
	int favor = xmp->favor;
	}
	if (style == XDL_MERGE_DIFF3) {
 *
		}
		m->chg0 = i0 + chg0 - m->i0;
	result->size = 0;

	/*
		/* Cannot determine eol style from empty file */
		return (size = file->recs[i]->size) > 1 &&
			i2 = xscr2->i2;
				xdl_cleanup_merge(changes);
	 * in the merge result as a region touched by neither side.
	}
		m->i2 = i2;
		t1.size = xe1->xdf2.recs[m->i1 + m->chg1 - 1]->ptr
		marker_size = DEFAULT_CONFLICT_MARKER_SIZE;
						      dest ? dest + size : NULL);
	 */
		size += xdl_orig_copy(xe1, m->i0, m->chg0, needs_cr, 1,
			dest[size++] = '\n';
	/* output */
	int i0, i1, i2, chg0, chg1, chg2;
			m2->next = m->next;
/*
	/* Look at pre-image's first line, unless we already settled on LF */
	}
		chg1 = xscr2->chg1;
		if (marker2_size) {
		result->size = mf2->size;
			level = XDL_MERGE_EAGER;
	int level = xmp->level;
	}
		 * we have a very simple mmfile structure.
		return -1;
		if (dest)
			continue;

			return -1;
		status = xdl_do_merge(&xe1, xscr1,
		m->i2 = xscr->i2 + i2;
 */
			i0 = xscr1->i1;
	}
		 */
			continue;
			}
	long size;
		file->recs[i - 1]->ptr[size - 2] == '\r';
		}
		    xdl_change_compact(&xe.xdf2, &xe.xdf1, xpp->flags) < 0 ||
	int marker3_size = (name3 ? strlen(name3) + 1 : 0);
	int result = 0;
	needs_cr = is_eol_crlf(&xe1->xdf2, m->i1 ? m->i1 - 1 : 0);
	} else {
	long chg1, chg2;
		m->chg2 = chg2;
		i2 = xscr1->i1 + xe2->xdf2.nrec - xe2->xdf1.nrec;

		if (mode != m->mode)
	if (XDL_MERGE_ZEALOUS <= level &&
 *  LibXDiff by Davide Libenzi ( File Differential Library )
				dest[size] = '\n';
static int xdl_recs_copy_0(int use_orig, xdfenv_t *xe, int i, int count, int needs_cr, int add_nl, char *dest)

			m->next = m2;
				      int simplify_if_no_alnum)
			if (needs_cr)
			xscr2 = xscr2->next;
