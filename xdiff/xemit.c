	char dummy[1];


			   char *buf, long sz)
			 * its new end.

	long len = xdl_get_rec(xdf, ri, &rec);
		if (xecfg->flags & XDL_EMIT_FUNCCONTEXT) {
		 * Emit current hunk header.
		if (len >= 0) {
		    xch->i1 - (xchp->i1 + xchp->chg1) >= max_ignorable)
	long len = xdl_get_rec(xdf, ri, &rec);



		xch = xchp->next;
				 * a whole function was added.
					xchp = xchp->next;
				s2 = XDL_MAX(s2 - (s1 - fs1), 0);
{

	const char *rec;
						goto post_context_calculation;
		  xdemitconf_t const *xecfg) {

		}
					xch = xchp;
		 */
 * inside the differential hunk according to the specified configuration.
		return def_ff(rec, len, buf, sz, xecfg->find_func_priv);
int xdl_emit_diff(xdfenv_t *xe, xdchange_t *xscr, xdemitcb_t *ecb,

	}

	long size, psize = strlen(pre);
 */
			if (fe1 < 0)
				func_line->len = len;
			long fe1 = get_func_line(xe, xecfg, NULL,

}

	lxch = *xscr;
		}
				}
 * Also advance xscr if the first changes must be discarded.
	xdchange_t *xch, *xchp, *lxch;
	return 0;
{


 *  <http://www.gnu.org/licenses/>.
			}

				 * ignored change?
				e1 = fe1;
					return -1;
			 */
		} else if (lxch != xchp &&
	unsigned long ignored = 0; /* number of ignored blank lines */
		 * Emit post-context.
			if (fs1 < 0)
			for (; s1 < xch->i1 && s2 < xch->i2; s1++, s2++)
	long max_ignorable = xecfg->ctxlen;
			 */
			 * Removes lines from the first file.

				/* If so, show it after all. */
			if (xche->next) {
			len--;
					goto pre_context_calculation;
static int is_func_rec(xdfile_t *xdf, xdemitconf_t const *xecfg, long ri)
		lctx = XDL_MIN(lctx, xe->xdf1.nrec - (xche->i1 + xche->chg1));

 *  Lesser General Public License for more details.

	return -1;

			for (s1 = xch->i1; s1 < xch->i1 + xch->chg1; s1++)
				 * pre-image.
				/*
static long get_func_line(xdfenv_t *xe, xdemitconf_t const *xecfg,
		return len;
			(isalpha((unsigned char)*rec) || /* identifier? */
		 */
	if (xdl_emit_diffrec(rec, size, pre, psize, ecb) < 0) {
				 */
			if (xdl_emit_record(&xe->xdf2, s2, " ", ecb) < 0)
				i1 = xe->xdf1.nrec - 1;
			ignored = 0;
	return xecfg->find_func(rec, len, buf, sz, xecfg->find_func_priv);

			if (fe1 > e1) {
				 * Did we extend context upwards into an
			if (func_line)
				    get_func_line(xe, xecfg, NULL, l, e1) < 0) {
 post_context_calculation:

				if (xdl_emit_record(&xe->xdf2, s2, " ", ecb) < 0)
			   xch->i1 + ignored - (lxch->i1 + lxch->chg1) > max_common) {
	long l, size, step = (start > limit) ? -1 : 1;
		return NULL;
				 */

			len = sz;
	}
		if (!xch)
				fs1 = 0;
			 * Merge previous with current change atom.
		 * Emit pre-context.
	*rec = xdf->recs[ri]->ptr;
			 * Overlap with next change?  Then include it
		} else {

}
				s1 = fs1;
 *
			lxch = xch;
		if (distance < max_ignorable && (!xch->ignore || lxch == xchp)) {
 *  version 2.1 of the License, or (at your option) any later version.
		lctx = xecfg->ctxlen;
				return -1;
				}
	if (*xscr == NULL)
			 *rec == '$')) { /* identifiers from VMS and other esoterico */
 *
		if (xch == NULL ||
			ignored = 0;
		for (s1 = xch->i1, s2 = xch->i2;; xch = xch->next) {
					xche = xche->next;
				 * Otherwise get more context from the
	return xdf->recs[ri]->size;
						 xe->xdf1.nrec);
 *  Davide Libenzi <davidel@xmailserver.org>
			s2 = xch->i2 + xch->chg2;
	if (!xecfg->find_func)
			       !is_func_rec(&xe->xdf1, xecfg, fs1 - 1))
				e2 = XDL_MIN(e2 + (fe1 - e1), xe->xdf2.nrec);
		} else if (distance < max_ignorable && xch->ignore) {
	long max_common = 2 * xecfg->ctxlen + xecfg->interhunkctxlen;
	char const *rec;
			 */
 */

			long fs1, i1 = xch->i1;
	}
					return -1;
static long match_func_rec(xdfile_t *xdf, xdemitconf_t const *xecfg, long ri,
			lxch = xch;

			s1 = xch->i1 + xch->chg1;
				if (xdl_emit_record(&xe->xdf1, s1, "-", ecb) < 0)
					i2++;

				fs1--;
			return l;
};
				if (xchp != xch) {
			ignored += xch->chg2;

				       xchp->i2 + xchp->chg2 <= s2)
		long len = match_func_rec(&xe->xdf1, xecfg, l, buf, size);

			*xscr = xch;
		if (xdl_emit_hunk_hdr(s1 + 1, e1 - s1, s2 + 1, e2 - s2,
	}
	for (l = start; l != limit && 0 <= l && l < xe->xdf1.nrec; l += step) {

	return 0;
		len--;

	return !len;

			 * in the current hunk and start over to find
				return -1;
 *  Copyright (C) 2003	Davide Libenzi

	if (len > 0 &&
	for (xch = xscr; xch; xch = xche->next) {


			}
	size = xdl_get_rec(xdf, ri, &rec);
			if (fs1 < s1) {
/*
	buf = func_line ? func_line->buf : dummy;
 *
 *
		xche = xdl_get_hunk(&xch, xecfg);
	}
	long len;
{
#include "xinclude.h"
		return -1;
				      func_line.buf, func_line.len, ecb) < 0)
	/* remove ignorable changes that are too far before other changes */
				if (l - xecfg->ctxlen <= e1 ||
			get_func_line(xe, xecfg, &func_line,
		/*
		}
pre_context_calculation:
 *  This library is free software; you can redistribute it and/or
	size = func_line ? sizeof(func_line->buf) : sizeof(dummy);
			for (s2 = xch->i2; s2 < xch->i2 + xch->chg2; s2++)
				 * We don't need additional context if
				if (xdl_emit_record(&xe->xdf2, s2, "+", ecb) < 0)
						 xche->i1 + xche->chg1,

				/*
			/*
	while (len > 0 && XDL_ISSPACE(*rec)) {
{
				fe1 = xe->xdf1.nrec;
		}
			return -1;
			if (i1 >= xe->xdf1.nrec) {
			/*
		rec++;
}
		} else if (!xch->ignore) {

		for (s2 = xche->i2 + xche->chg2; s2 < e2; s2++)
 *  You should have received a copy of the GNU Lesser General Public
 *  LibXDiff by Davide Libenzi ( File Differential Library )
 *  This library is distributed in the hope that it will be useful,

static long def_ff(const char *rec, long len, char *buf, long sz, void *priv)
				/*
}
		if (len > sz)
		if (xecfg->flags & XDL_EMIT_FUNCCONTEXT) {

static int is_empty_rec(xdfile_t *xdf, long ri)
					if (is_func_rec(&xe->xdf2, xecfg, i2))
		s1 = XDL_MAX(xch->i1 - xecfg->ctxlen, 0);
}
xdchange_t *xdl_get_hunk(xdchange_t **xscr, xdemitconf_t const *xecfg)
			}

	const char *rec;
}
	struct func_line func_line = { 0 };
		/*
			funclineprev = s1 - 1;
struct func_line {
				       xchp->i1 + xchp->chg1 <= s1 &&
		}
		if (distance > max_common)
			/*
		for (; s2 < xch->i2; s2++)
	}

	xdchange_t *xch, *xche;
}
		e2 = xche->i2 + xche->chg2 + lctx;
				      s1 - 1, funclineprev);
		xdchange_t *xchp = xch;
		lctx = XDL_MIN(lctx, xe->xdf2.nrec - (xche->i2 + xche->chg2));
					goto post_context_calculation;

 *  License along with this library; if not, see
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
			 */
		 */
}
			ignored += xch->chg2;
			break;
			while (fe1 > 0 && is_empty_rec(&xe->xdf1, fe1 - 1))
				}
				long l = XDL_MIN(xche->next->i1,
		if (xecfg->flags & XDL_EMIT_FUNCNAMES) {
 *
}
		/*
			if (xdl_emit_record(&xe->xdf2, s2, " ", ecb) < 0)
 * Starting at the passed change atom, find the latest change atom to be included
	}
				while (i2 < xe->xdf2.nrec) {
						 xe->xdf1.nrec - 1);
			if (xch == xche)
			break;

	return -1;
	long funclineprev = -1;

		memcpy(buf, rec, len);
			fs1 = get_func_line(xe, xecfg, NULL, i1, -1);
	for (xchp = *xscr; xchp && xchp->ignore; xchp = xchp->next) {
		s2 = XDL_MAX(xch->i2 - xecfg->ctxlen, 0);
	for (xchp = *xscr, xch = xchp->next; xch; xchp = xch, xch = xch->next) {
		e1 = xche->i1 + xche->chg1 + lctx;
	long s1, s2, e1, e2, lctx;
					return -1;
				long i2 = xch->i2;
			 *rec == '_' || /* also identifier? */
		while (0 < len && isspace((unsigned char)rec[len - 1]))
static long xdl_get_rec(xdfile_t *xdf, long ri, char const **rec) {
				break;

		long distance = xch->i1 - (xchp->i1 + xchp->chg1);
			}

	char buf[80];

static int xdl_emit_record(xdfile_t *xdf, long ri, char const *pre, xdemitcb_t *ecb) {
				while (xchp != xch &&
			break;
		}


			/*
 *  License as published by the Free Software Foundation; either
			while (fs1 > 0 && !is_empty_rec(&xe->xdf1, fs1 - 1) &&
{
			/* Appended chunk? */
				 */
	return lxch;
/*
	return match_func_rec(xdf, xecfg, ri, dummy, sizeof(dummy)) >= 0;


	char *buf, dummy[1];
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  modify it under the terms of the GNU Lesser General Public
{

			 * Adds lines from the second file.
				fe1--;
			  struct func_line *func_line, long start, long limit)
