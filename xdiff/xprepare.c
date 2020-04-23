		cf->rchash[hi] = rcrec;
	line = rec->ptr;
 *  You should have received a copy of the GNU Lesser General Public
	return 0;
 *
	long *rindex;
	xdf->nreff = 0;
			}
			rdis1++;
		dis1[i] = (nm == 0) ? 0: (nm >= mlim) ? 2: 1;
static void xdl_free_ctx(xdfile_t *xdf);
	if (XDF_DIFF_ALG(xpp->flags) != XDF_HISTOGRAM_DIFF)
	for (i = 0, lim = XDL_MIN(xdf1->nrec, xdf2->nrec); i < lim;
			    xdl_classify_record(pass, cf, rhash, hbits, crec) < 0)
	}
	long idx;
			xdf1->rchg[i] = 1;
	xdf1->nreff = nreff;
	memset(dis, 0, xdf1->nrec + xdf2->nrec + 2);
		xdl_free_ctx(&xe->xdf1);
	}
		goto abort;
	dis2 = dis1 + xdf1->nrec + 1;
		rcrec->len1 = rcrec->len2 = 0;
		goto abort;
	long flags;
	 * performance penalties in case of big files.

	long r, rdis0, rpdis0, rdis1, rpdis1;
	xdlclassifier_t cf;
			xdf1->rindex[nreff] = i;

	recs2 = xdf2->recs;
		    (dis2[i] == 2 && !xdl_clean_mmatch(dis2, i, xdf2->dstart, xdf2->dend))) {
	}
	}


	if (!(cf->rchash = (xdlclass_t **) xdl_malloc(cf->hsize * sizeof(xdlclass_t *)))) {
	if (XDF_DIFF_ALG(xpp->flags) == XDF_HISTOGRAM_DIFF)

				return -1;
			recs[nrec++] = crec;
static int xdl_clean_mmatch(char const *dis, long i, long s, long e) {
	if (i - s > XDL_SIMSCAN_WINDOW)
	long enl1, enl2, sample;


	     i <= xdf2->dend; i++, recs++) {
	hi = (long) XDL_HASHLONG(rec->ha, hbits);
	cf->alloc = size;
		return -1;
	long hi;

	 * Limits the window the is examined during the similar-lines
	cf->count = 0;



			crec->size = (long) (cur - prev);
	dis1 = dis;

	for (r = 1, rdis0 = 0, rpdis0 = 1; (i - r) >= s; r++) {
	if (rdis1 == 0)

	return rpdis1 * XDL_KPDIS_RUN < (rpdis1 + rdis1);
	 * If the run before the line 'i' found only multimatch lines, we

	enl2 = xdl_guess_lines(mf2, sample) + 1;

	long count;

		rcrec->line = line;
 * might be potentially discarded if they happear in a run of discardable.
 *
static int xdl_trim_ends(xdfile_t *xdf1, xdfile_t *xdf2) {
	if ((cur = blk = xdl_mmfile_first(mf, &bsize)) != NULL) {

	xdl_free(rindex);
 *  This library is free software; you can redistribute it and/or
		hsize = 1 << hbits;
		    (dis1[i] == 2 && !xdl_clean_mmatch(dis1, i, xdf1->dstart, xdf1->dend))) {
		xdl_free(cf->rchash);
		}
	    (XDF_DIFF_ALG(xpp->flags) != XDF_HISTOGRAM_DIFF) &&
	}
		else if (dis[i + r] == 2)
	struct s_xdlclass *next;




			goto abort;
#define XDL_KPDIS_RUN 4
static int xdl_optimize_ctxs(xdlclassifier_t *cf, xdfile_t *xdf1, xdfile_t *xdf2);
		goto abort;
					rec->ptr, rec->size, cf->flags))
		xdl_free_classifier(&cf);
	 * scan. The loops below stops when dis[i - r] == 1 (line that


 *  License along with this library; if not, see

}

			break;
	long alloc;

	if (xdl_prepare_ctx(2, mf2, enl2, xpp, &cf, &xe->xdf2) < 0) {

	 * return 0 and hence we don't make the current line (i) discarded.
	}
	xdf->ha = ha;
	     i++, recs1++, recs2++)
			hav = xdl_hash_record(&cur, top, xpp->flags);
	recs = NULL;
		return -1;
}
	xdl_free_ctx(&xe->xdf2);
	unsigned int hbits;



static void xdl_free_classifier(xdlclassifier_t *cf) {
	unsigned long hav;
	rpdis1 += rpdis0;
		} else
	hi = (long) XDL_HASHLONG(rec->ha, cf->hbits);
typedef struct s_xdlclassifier {
		xdl_cha_free(&cf->ncha);
		xdl_free_classifier(&cf);
	 * (nrecs) will be updated correctly anyway by

	char const *blk, *cur, *top, *prev;
}
int xdl_prepare_env(mmfile_t *mf1, mmfile_t *mf2, xpparam_t const *xpp,

	xdl_cha_free(&cf->ncha);
}
		cf->rcrecs[rcrec->idx] = rcrec;

	long len1, len2;


	 * xdl_prepare_ctx().
	unsigned long ha;
	 * current line (i) is already a multimatch line.
			       unsigned int hbits, xrecord_t *rec) {
	for (rcrec = cf->rchash[hi]; rcrec; rcrec = rcrec->next)
		e = i + XDL_SIMSCAN_WINDOW;
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
	recs1 = xdf1->recs + xdf1->nrec - 1;

}

	 */

	if (!rcrec) {
	xdlclass_t **rcrecs;
} xdlclassifier_t;
		return 0;
		  ? XDL_GUESS_NLINES2 : XDL_GUESS_NLINES1);
	if (XDF_DIFF_ALG(xpp->flags) != XDF_HISTOGRAM_DIFF &&
				recs = rrecs;
/*

 *  Davide Libenzi <davidel@xmailserver.org>
	return 0;
		} else
			if ((XDF_DIFF_ALG(xpp->flags) != XDF_HISTOGRAM_DIFF) &&


	ha = NULL;
	if ((mlim = xdl_bogosqrt(xdf1->nrec)) > XDL_MAX_EQLIMIT)
	 * table (rhash) won't be filled up/grown. The number of lines
	xdlclass_t *rcrec;
	 * Note that we always call this function with dis[i] > 1, so the
		    xdfenv_t *xe) {
	 * proceed all the way to the extremities by causing huge
	xdf1->dend = xdf1->nrec - i - 1;
	if (!(rchg = (char *) xdl_malloc((nrec + 2) * sizeof(char))))
	xrecord_t **recs1, **recs2;
	}
 */
	return -1;

}
	rhash = NULL;
	return 0;
	xdl_free(ha);
	rec->next = rhash[hi];


	if (xdl_trim_ends(xdf1, xdf2) < 0 ||
 */
static int xdl_init_classifier(xdlclassifier_t *cf, long size, long flags);
	for (r = 1, rdis1 = 0, rpdis1 = 1; (i + r) <= e; r++) {
#define XDL_SIMSCAN_WINDOW 100
#define XDL_GUESS_NLINES2 20
#define XDL_GUESS_NLINES1 256
	 * have no match (dis[j] == 0) or have multiple matches (dis[j] > 1).
		if (!(rhash = (xrecord_t **) xdl_malloc(hsize * sizeof(xrecord_t *))))
		rcrec->size = rec->size;
static int xdl_cleanup_records(xdlclassifier_t *cf, xdfile_t *xdf1, xdfile_t *xdf2) {

			cf->rcrecs = rcrecs;
	nrec = 0;
	char *dis, *dis1, *dis2;
typedef struct s_xdlclass {

		rcrec->next = cf->rchash[hi];

	}
	if ((mlim = xdl_bogosqrt(xdf2->nrec)) > XDL_MAX_EQLIMIT)
		}
static int xdl_classify_record(unsigned int pass, xdlclassifier_t *cf, xrecord_t **rhash,
	rchg = NULL;
	xdl_cha_free(&xdf->rcha);
 * matches on the other file. Also, lines that have multiple matches


				xdl_recmatch(rcrec->line, rcrec->size,
		s = i - XDL_SIMSCAN_WINDOW;
 *  LibXDiff by Davide Libenzi ( File Differential Library )
		rcrec->idx = cf->count++;
	xdf2->nreff = nreff;
	    xdl_init_classifier(&cf, enl1 + enl2 + 1, xpp->flags) < 0)
			nreff++;
	xdl_free(cf->rcrecs);
	xdl_free(xdf->rchg - 1);
	memset(rchg, 0, (nrec + 2) * sizeof(char));
	 * thus a poorer estimate of the number of lines, as the hash

	return 0;
	xdl_free(cf->rchash);
	(pass == 1) ? rcrec->len1++ : rcrec->len2++;
	xdl_free(rchg);
 */
	xdl_free_ctx(&xe->xdf1);
		xdl_free_ctx(&xe->xdf1);
			if (nrec >= narec) {
	unsigned int hbits;

		xdl_free_classifier(&cf);
		return 0;
	for (i = xdf1->dstart, recs = &xdf1->recs[xdf1->dstart]; i <= xdf1->dend; i++, recs++) {

	xdf2->dend = xdf2->nrec - i - 1;
	if (!(cf->rcrecs = (xdlclass_t **) xdl_malloc(cf->alloc * sizeof(xdlclass_t *)))) {
		rcrec = cf->rcrecs[(*recs)->ha];
	}
	}

static int xdl_prepare_ctx(unsigned int pass, mmfile_t *mf, long narec, xpparam_t const *xpp,

		if (dis2[i] == 1 ||




	memset(&cf, 0, sizeof(cf));
		goto abort;
			rpdis0++;
		if (cf->count > cf->alloc) {
	rhash[hi] = rec;
		rcrec = cf->rcrecs[(*recs)->ha];
static int xdl_prepare_ctx(unsigned int pass, mmfile_t *mf, long narec, xpparam_t const *xpp,
	for (lim -= i, i = 0; i < lim; i++, recs1--, recs2--)
	 */
	cf->hsize = 1 << cf->hbits;
	 */
}
	return 0;
		if (!dis[i + r])

#define XDL_MAX_EQLIMIT 1024
	sample = (XDF_DIFF_ALG(xpp->flags) == XDF_HISTOGRAM_DIFF
		if (rcrec->ha == rec->ha &&
			}
static void xdl_free_ctx(xdfile_t *xdf) {

	xdf->rchg = rchg + 1;
static int xdl_init_classifier(xdlclassifier_t *cf, long size, long flags) {

	rdis1 += rdis0;
			xdf1->ha[nreff] = (*recs)->ha;
	 */
			nreff++;
			rpdis1++;
	/*
				goto abort;
static int xdl_optimize_ctxs(xdlclassifier_t *cf, xdfile_t *xdf1, xdfile_t *xdf2) {
	     i <= xdf1->dend; i++, recs++) {
	if (!(ha = (unsigned long *) xdl_malloc((nrec + 1) * sizeof(unsigned long))))
	}
static int xdl_classify_record(unsigned int pass, xdlclassifier_t *cf, xrecord_t **rhash,
	    xdl_optimize_ctxs(&cf, &xe->xdf1, &xe->xdf2) < 0) {
			rdis0++;

	char *rchg;
			crec->ptr = prev;
			if (!(crec = xdl_cha_alloc(&xdf->rcha)))
		goto abort;
 *  License as published by the Free Software Foundation; either
	    xdl_cleanup_records(cf, xdf1, xdf2) < 0) {
	/*
			crec->ha = hav;
	if (xdl_cha_init(&cf->ncha, sizeof(xdlclass_t), size / 4 + 1) < 0) {
	xdf->dstart = 0;
		return -1;
	return 0;
		else
		rcrec->ha = rec->ha;
	xdf1->dstart = xdf2->dstart = i;

	}
		hbits = xdl_hashbits((unsigned int) narec);
/*

}
		nm = rcrec ? rcrec->len1 : 0;
		memset(rhash, 0, hsize * sizeof(xrecord_t *));
				narec *= 2;

	long nrec, hsize, bsize;
	xdl_cha_free(&xdf->rcha);
	/*

}
 *
	if ((XDF_DIFF_ALG(xpp->flags) != XDF_PATIENCE_DIFF) &&
	xdlclass_t *rcrec;
	long hsize;
	xdlclass_t **rcrecs;

		nm = rcrec ? rcrec->len2 : 0;
		xdl_cha_free(&cf->ncha);
	cf->flags = flags;
} xdlclass_t;

	long i, nm, nreff, mlim;
	return 0;
	long size;

	xdlclass_t **rchash;

	unsigned long *ha;
			if (!(rcrecs = (xdlclass_t **) xdl_realloc(cf->rcrecs, cf->alloc * sizeof(xdlclass_t *)))) {
	enl1 = xdl_guess_lines(mf1, sample) + 1;
	 * Scans the lines before 'i' to find a run of lines that either

 * Early trim initial and terminal matching records.
			cf->alloc *= 2;
		if ((*recs1)->ha != (*recs2)->ha)
			xdf2->rchg[i] = 1;
			   xdlclassifier_t *cf, xdfile_t *xdf) {
	xdf->rhash = rhash;
	if (!(recs = (xrecord_t **) xdl_malloc(narec * sizeof(xrecord_t *))))
	rindex = NULL;
		if ((*recs1)->ha != (*recs2)->ha)
 *
	char const *line;
static int xdl_clean_mmatch(char const *dis, long i, long s, long e);
	long i, lim;

	xdl_free(recs);
	xrecord_t **recs, **rrecs;

 *  This library is distributed in the hope that it will be useful,

	 * We want to discard multimatch lines only when they appear in the
	xdf->nrec = nrec;
	}
 *  Copyright (C) 2003  Davide Libenzi
void xdl_free_env(xdfenv_t *xe) {
	if (xdl_prepare_ctx(1, mf1, enl1, xpp, &cf, &xe->xdf1) < 0) {
	recs2 = xdf2->recs + xdf2->nrec - 1;
		}
	if (e - i > XDL_SIMSCAN_WINDOW)
		if (dis1[i] == 1 ||
		xdl_free_classifier(&cf);
static int xdl_trim_ends(xdfile_t *xdf1, xdfile_t *xdf2);
				if (!(rrecs = (xrecord_t **) xdl_realloc(recs, narec * sizeof(xrecord_t *))))
			xdf2->rindex[nreff] = i;
	xdl_free(dis);
	}

 *  <http://www.gnu.org/licenses/>.

	 * If the run after the line 'i' found only multimatch lines, we


 *  Lesser General Public License for more details.
	cf->hbits = xdl_hashbits((unsigned int) size);
			       unsigned int hbits, xrecord_t *rec);
	/*
		return -1;
			xdf2->ha[nreff] = (*recs)->ha;
					goto abort;
			break;
	for (nreff = 0, i = xdf2->dstart, recs = &xdf2->recs[xdf2->dstart];
#include "xinclude.h"
		return -1;
	if (!(dis = (char *) xdl_malloc(xdf1->nrec + xdf2->nrec + 2))) {
	}
		else if (dis[i - r] == 2)
	xdl_free(xdf->ha);

	xdf->hbits = hbits;
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
				goto abort;
		if (!(rcrec = xdl_cha_alloc(&cf->ncha))) {
			break;

			return -1;
static int xdl_cleanup_records(xdlclassifier_t *cf, xdfile_t *xdf1, xdfile_t *xdf2);
	}
	 * has no match), but there are corner cases where the loop

	for (nreff = 0, i = xdf1->dstart, recs = &xdf1->recs[xdf1->dstart];

	recs1 = xdf1->recs;
	xdl_free(xdf->recs);

		dis2[i] = (nm == 0) ? 0: (nm >= mlim) ? 2: 1;
	 * return 0 and hence we don't make the current line (i) discarded.

	xrecord_t **recs;


 *
			break;
		for (top = blk + bsize; cur < top; ) {
		if (!dis[i - r])
		xdl_free_ctx(&xe->xdf2);
	xdf->rindex = rindex;
	xdf->recs = recs;
			break;
	xdl_free(xdf->rindex);
	/*
 * Try to reduce the problem complexity, discard records that have no
}
	chastore_t ncha;
 *  modify it under the terms of the GNU Lesser General Public
	memset(cf->rchash, 0, cf->hsize * sizeof(xdlclass_t *));
			prev = cur;
		return -1;

		return -1;
/*
	xdl_free(xdf->rhash);
	 */
		mlim = XDL_MAX_EQLIMIT;
}
	 * middle of runs with nomatch lines (dis[j] == 0).
	rec->ha = (unsigned long) rcrec->idx;
		return -1;

		return -1;
	for (i = xdf2->dstart, recs = &xdf2->recs[xdf2->dstart]; i <= xdf2->dend; i++, recs++) {


	xdf->dend = nrec - 1;
	if (!(rindex = (long *) xdl_malloc((nrec + 1) * sizeof(long))))
	 * For histogram diff, we can afford a smaller sample size and

			   xdlclassifier_t *cf, xdfile_t *xdf);
static void xdl_free_classifier(xdlclassifier_t *cf);
	else {
		hbits = hsize = 0;
abort:
	xrecord_t **rhash;
		else
	char const *line;

	xdl_free(rhash);
	if (xdl_cha_init(&xdf->rcha, sizeof(xrecord_t), narec / 4 + 1) < 0)
		mlim = XDL_MAX_EQLIMIT;

 *  version 2.1 of the License, or (at your option) any later version.
	xrecord_t *crec;
	if (rdis0 == 0)
	}
