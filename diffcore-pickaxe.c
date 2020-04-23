		return !regexec_buf(regexp, two->ptr, two->size,
			kwsprep(kws);
			struct kwsmatch kwsm;


	int ret;
#include "kwset.h"
struct diffgrep_cb {

{
	return ret;
		     struct diff_options *o,
	regmatch_t regmatch;

		    has_non_ascii(needle)) {
		/* Showing the whole changeset if needle exists */
		for (i = 0; i < q->nr; i++) {
			cnt++;
	struct userdiff_driver *textconv_one = NULL;
		} else {
			}
		return;
		while (sz && *data &&
static int pickaxe_match(struct diff_filepair *p, struct diff_options *o,
			if (pickaxe_match(p, o, regexp, kws, fn))
	} else {
				       ? tolower_trans_tbl : NULL);

		}
		 * the empty outq at the end of this function, but
	}
			int cflags = REG_NEWLINE | REG_ICASE;
	if (line[0] != '+' && line[0] != '-')
	struct diffgrep_cb *data = priv;
	return ecbdata.hit;

				    1, &regmatch, 0);
};
			basic_regex_quote_buf(&sb, needle);
		       struct diff_options *o,
	mf1.size = fill_textconv(o->repo, textconv_one, p->one, &mf1.ptr);
}
		for (i = 0; i < q->nr; i++) {
	return cnt;
			size_t offset = kwsexec(kws, data, sz, &kwsm);
		}
			struct diff_filepair *p = q->queue[i];
static void pickaxe(struct diff_queue_struct *q, struct diff_options *o,
#include "quote.h"
			(DIFF_FILE_VALID(p->two) &&
	if (o->flags.allow_textconv) {
		/* Showing only the filepairs that has the needle */
static void regcomp_or_die(regex_t *regex, const char *needle, int cflags)
				 &regmatch, 0);
		}

	data->hit = !regexec_buf(data->regexp, line + 1, len - 1, 1,
	data = mf->ptr;
			kws = kwsalloc(o->pickaxe_opts & DIFF_PICKAXE_IGNORE_CASE
#include "xdiff-interface.h"
	 */
	regmatch_t regmatch;
	ret = fn(DIFF_FILE_VALID(p->one) ? &mf1 : NULL,
		for (i = 0; i < q->nr; i++)
static int has_changes(mmfile_t *one, mmfile_t *two,
				diff_q(&outq, p);
			strbuf_release(&sb);
	 * because a pair is an exact rename with different textconv attributes
	if (opts & (DIFF_PICKAXE_REGEX | DIFF_PICKAXE_KIND_G)) {
	unsigned int one_contains = one ? contains(one, regexp, kws) : 0;
}
	const char *data;
	const char *needle = o->pickaxe;

		textconv_one = get_textconv(o->repo, p->one);
	kwset_t kws = NULL;
		return 0;
#include "commit.h"

#include "diffcore.h"
	diff_free_filespec_data(p->two);
		regexp = &regex;
 * Copyright (C) 2005 Junio C Hamano
	if (regexp) {
	if (xdi_diff_outf(one, two, discard_hunk_line, diffgrep_consume,
			struct diff_filepair *p = q->queue[i];
			data += regmatch.rm_eo;
	 * the pattern appears on added/deleted lines.
	/*
				break;
static void diffgrep_consume(void *priv, char *line, unsigned long len)

static unsigned int contains(mmfile_t *mf, regex_t *regexp, kwset_t kws)
	unsigned int two_contains = two ? contains(two, regexp, kws) : 0;

	ecbdata.regexp = regexp;
			data += offset + kwsm.size[0];
	}
	struct diffgrep_cb ecbdata;
	ecbdata.hit = 0;
	 * for each side, which might generate different content).
void diffcore_pickaxe(struct diff_options *o)

			kwsincr(kws, needle, strlen(needle));
	unsigned long sz;
	/* ignore unmerged */
static int diff_grep(mmfile_t *one, mmfile_t *two,
			cflags |= REG_ICASE;
		return 0;

	if (textconv_one)
		 */
		return !regexec_buf(regexp, one->ptr, one->size,
		regfree(regexp);
			regexp = &regex;
		       !regexec_buf(regexp, data, sz, 1, &regmatch, flags)) {

		/*
		return 0;
			diff_free_filepair(q->queue[i]);
	sz = mf->size;
}
		       regex_t *regexp, kwset_t kws)
	} else { /* Classic exact string match */
			sz -= offset + kwsm.size[0];
	cnt = 0;
		free(mf2.ptr);
		if (o->pickaxe_opts & DIFF_PICKAXE_IGNORE_CASE)
	mmfile_t mf1, mf2;

typedef int (*pickaxe_fn)(mmfile_t *one, mmfile_t *two,
				sz--;
{
	int err = regcomp(regex, needle, cflags);

	return one_contains != two_contains;
		regerror(err, regex, errbuf, 1024);
			struct strbuf sb = STRBUF_INIT;
		if (o->pickaxe_opts & DIFF_PICKAXE_IGNORE_CASE &&
	if (err) {



}
	 */

 */


	}
	 * same and don't even have to load the blobs. Unless textconv is in
	struct userdiff_driver *textconv_two = NULL;
		int flags = 0;
			  &ecbdata, &xpp, &xecfg))
	if (!two)
}
	    ((!textconv_one && diff_filespec_is_binary(o->repo, p->one)) ||
	}
	int i;
		return  (DIFF_FILE_VALID(p->one) &&
	memset(&xpp, 0, sizeof(xpp));
	if (regexp)
		 DIFF_FILE_VALID(p->two) ? &mf2 : NULL,
	memset(&xecfg, 0, sizeof(xecfg));
		 o, regexp, kws);
		 */
}
		}


	} else if (opts & DIFF_PICKAXE_KIND_S) {
	if (textconv_two)
	if (!o->pickaxe[0])
	if (kws)
		kwsfree(kws);
			cnt++;
		die("invalid regex: %s", errbuf);
		return 0;
	}
		 * Otherwise we will clear the whole queue by copying
	     (!textconv_two && diff_filespec_is_binary(o->repo, p->two))))
				diff_free_filepair(p);
			 regex_t *regexp, kwset_t kws, pickaxe_fn fn)
	xpparam_t xpp;
			regcomp_or_die(&regex, sb.buf, cflags);
	xdemitconf_t xecfg;
	if (!one)
		 * NEEDSWORK: we should have a way to terminate the
	mf2.size = fill_textconv(o->repo, textconv_two, p->two, &mf2.ptr);
		     regex_t *regexp, kwset_t kws)
			 oidset_contains(o->objfind, &p->one->oid)) ||

	if ((o->pickaxe_opts & DIFF_PICKAXE_KIND_G) &&
			 oidset_contains(o->objfind, &p->two->oid));
		return;
	if (!DIFF_FILE_VALID(p->one) && !DIFF_FILE_VALID(p->two))
			else
		 * first clear the current entries in the queue.
		free(mf1.ptr);
	xecfg.interhunkctxlen = o->interhunkcontext;
	DIFF_QUEUE_CLEAR(&outq);
			if (offset == -1)
	return;
			if (sz && *data && regmatch.rm_so == regmatch.rm_eo) {
	/*
}
#include "diff.h"

			flags |= REG_NOTBOL;

	    !o->flags.text &&
				    1, &regmatch, 0);
	struct diff_queue_struct outq;

{
				data++;

		/*
		    regex_t *regexp, kwset_t kws, pickaxe_fn fn)
	}
			if (pickaxe_match(p, o, regexp, kws, fn))

	diff_free_filespec_data(p->one);
		regmatch_t regmatch;
	if (o->objfind) {
		int cflags = REG_EXTENDED | REG_NEWLINE;
/*
		}

	unsigned int cnt;
		char errbuf[1024];
		textconv_two = get_textconv(o->repo, p->two);
	regex_t *regexp;
	if (textconv_one == textconv_two && diff_unmodified_pair(p))
}
		 * caller early.
{
		/* The POSIX.2 people are surely sick */

		while (sz) {
 * Copyright (C) 2010 Google Inc.
	int hit;
				return; /* do not munge the queue */
	 * play, _and_ we are using two different textconv filters (e.g.,
		return 0;
{
{
	*q = outq;
		regcomp_or_die(&regex, needle, cflags);
	regex_t regex, *regexp = NULL;
	pickaxe(&diff_queued_diff, o, regexp, kws,
		(opts & DIFF_PICKAXE_KIND_G) ? diff_grep : has_changes);
	if (data->hit)
	if (o->pickaxe_opts & DIFF_PICKAXE_ALL) {

	 * If we have an unmodified pair, we know that the count will be the
	 * We have both sides; need to run textual diff and see if
	free(q->queue);
#include "cache.h"
{


			sz -= regmatch.rm_eo;
	xecfg.ctxlen = o->context;
			  struct diff_options *o,
	int opts = o->pickaxe_opts;
			  regex_t *regexp, kwset_t kws);
{
