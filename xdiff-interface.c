}
	struct xdiff_emit_state *priv = priv_;
	char *ap = a->size ? a->ptr + a->size : a->ptr;
	struct stat st;
	a->size -= trimmed - recovered;
#include "xdiff/xutils.h"
			regfree(&regs->array[i].re);
	if (stat(filename, &st))
		consume_one(priv, priv->remainder.buf, priv->remainder.len);

{

	regmatch_t pmatch[2];
static int xdiff_out_hunk(void *priv_,

struct xdiff_emit_state {
				return -1;

	while (result > 0 && (isspace(line[result - 1])))
	if (priv->remainder.len) {
		if (ap[recovered++] == '\n')
#include "xdiff/xemit.h"
	for (i = 0; i < regs->nr; i++) {
		else
	struct xdiff_emit_state *priv = priv_;
#include "config.h"
struct ff_regs {
			continue;
	}
int xdi_diff_outf(mmfile_t *mf1, mmfile_t *mf2,
		if (!strcmp(value, "diff3"))
	return 0;
		value = ep ? ep + 1 : NULL;
	struct ff_regs *regs;
	state.line_fn = line_fn;
	sz = xsize_t(st.st_size);
	return xdl_hash_record(&s, s + len, flags);
	FILE *f;
			strbuf_add(&priv->remainder, mb[i].ptr, mb[i].size);
{
		if (regcomp(&reg->re, expression, cflags))

#include "xdiff-interface.h"
		consume_one(priv, priv->remainder.buf, priv->remainder.len);
	memcpy(buffer, line, result);
		return -1;
{
		if (!value)

{
	ptr->size = size;
			  long new_begin, long new_nr,
	int i;
	if (regs->nr <= i)
	char *ep;
		      func, funclen);
		 */
	b->size -= trimmed - recovered;
		trimmed += blk;
	}
	state.consume_callback_data = consume_callback_data;
{
 * but end on a complete line.
	fclose(f);
void discard_hunk_line(void *priv,
	}
	while (recovered < trimmed)
}
		ep = memchr(s, '\n', size);
		bp -= blk;

	if (!priv->line_fn)
		if (!value)
		size -= this_size;
	for (i = 0; i < regs->nr; i++) {

			    value, var);
	enum object_type type;

	}
	return xdl_recmatch(l1, s1, l2, s2, flags);
	return 0;
		result = buffer_size;
			die("'%s' is not a boolean", var);
	memset(&ecb, 0, sizeof(ecb));
		else
			value++;
		return -1;
	}
	state.hunk_fn = hunk_fn;
		size = FIRST_FEW_BYTES;
			if (reg->negate)
			git_xmerge_style = XDL_MERGE_DIFF3;
}
	}
		strbuf_reset(&priv->remainder);
	if (mf1->size > MAX_XDIFF_SIZE || mf2->size > MAX_XDIFF_SIZE)
	if (oideq(oid, &null_oid)) {
}
}
	ptr->ptr = read_object_file(oid, &type, &size);
			break;
		strbuf_reset(&priv->remainder);
 * Trim down common substring at the end of the buffers,
	while (size) {
		return 0;
			  const char *func, long funclen)
{
		int i;
		return 0;
			len--;
	}
		unsigned long this_size;
		priv->line_fn(priv->consume_callback_data, s, this_size);
int read_mmfile(mmfile_t *ptr, const char *filename)
#include "xdiff/xtypes.h"
	}
		ptr->size = 0;
static void consume_one(void *priv_, char *s, unsigned long size)
		xecfg->find_func = NULL;
		return error("Could not read %s", filename);
	for (i = 0; i < nbuf; i++) {
			die("Last expression must not be negated: %s", value);
{
	int result;

		ptr->ptr = xstrdup("");
	mmfile_t b = *mf2;
}
	strbuf_release(&state.remainder);
static long ff_regexp(const char *line, long len,
	char *bp = b->size ? b->ptr + b->size : b->ptr;
	return result;
{
	i = pmatch[1].rm_so >= 0 ? 1 : 0;
			break;
	if (hunk_fn)
		struct ff_reg *reg = regs->array + i;
		if (ep)
	xecfg->find_func = ff_regexp;
		/*
		char *buffer = NULL;
#include "xdiff/xdiffi.h"
	regs = xecfg->find_func_priv = xmalloc(sizeof(struct ff_regs));

	if (FIRST_FEW_BYTES < size)
	long trimmed = 0, recovered = 0;

	memset(&state, 0, sizeof(state));
		for (i = 0; i < regs->nr; i++)
}
		else if (!strcmp(value, "merge"))
	struct xdiff_emit_state *priv = priv_;
}
{
		result--;

};
{
	if (!strcmp(var, "merge.conflictstyle")) {

}
void xdiff_clear_find_func(xdemitconf_t *xecfg)
	ALLOC_ARRAY(regs->array, regs->nr);
int git_xmerge_config(const char *var, const char *value, void *cb)
	if (result > buffer_size)
		  void *consume_callback_data,
		fclose(f);
	result = pmatch[i].rm_eo - pmatch[i].rm_so;
	return 0;
		this_size = (ep == NULL) ? size : (ep - s + 1);
 */
int xdiff_compare_lines(const char *l1, long s1,

	strbuf_init(&state.remainder, 0);

/*
	xdiff_emit_hunk_fn hunk_fn;
}

	const int blk = 1024;
	ret = xdi_diff(mf1, mf2, xpp, xecfg, &ecb);
	int i;
}
#include "cache.h"

	}
#define FIRST_FEW_BYTES 8000




			expression = buffer = xstrndup(value, ep - value);


}
		return error_errno("Could not stat %s", filename);
	if (xecfg->find_func) {
	for (i = 0, regs->nr = 1; value[i]; i++)
		regex_t re;
		ep = strchr(value, '\n');
	if (priv->remainder.len)
		s += this_size;
		if (!priv->remainder.len) {
	unsigned long size;

	return git_default_config(var, value, cb);
{
		  xpparam_t const *xpp, xdemitconf_t const *xecfg)

	long smaller = (a->size < b->size) ? a->size : b->size;
	struct xdiff_emit_state state;
	int i;
	ecb.out_line = xdiff_outf;
			  long old_begin, long old_nr,
unsigned long xdiff_hash_string(const char *s, size_t len, long flags)
	}

		die("unable to read blob object %s", oid_to_hex(oid));
		}
	return ret;
int buffer_is_binary(const char *ptr, unsigned long size)
		      old_begin, old_nr, new_begin, new_nr,
			git_xmerge_style = 0;
	while (blk + trimmed <= smaller && !memcmp(ap - blk, bp - blk, blk)) {
	size_t sz;
	struct strbuf remainder;

		if (len > 1 && line[len-2] == '\r')
			die("unknown style '%s' given for '%s'",
{

{
		struct ff_regs *regs = xecfg->find_func_priv;
	xdemitcb_t ecb;
#include "xdiff/xmacros.h"
}

			len -= 2;
		       long ob, long on, long nb, long nn,
		return error_errno("Could not open %s", filename);
		const char *ep, *expression;
		ecb.out_hunk = xdiff_out_hunk;
			const char *l2, long s2, long flags)
		}
		else
			consume_one(priv, mb[i].ptr, mb[i].size);

	if ((f = fopen(filename, "rb")) == NULL)
	ptr->size = sz;
		if (mb[i].ptr[mb[i].size-1] != '\n') {
		ap -= blk;
static void trim_common_tail(mmfile_t *a, mmfile_t *b)
	if (!xecfg->ctxlen && !(xecfg->flags & XDL_EMIT_FUNCCONTEXT))
		if (value[i] == '\n')
		 * Please update _git_checkout() in
		return;
		int negate;
		struct ff_reg *reg = regs->array + i;
};
	void *consume_callback_data;
			regs->nr++;
	int ret;
}
	priv->hunk_fn(priv->consume_callback_data,
			expression = value;
	ptr->ptr = xmalloc(sz ? sz : 1);
void xdiff_set_find_func(xdemitconf_t *xecfg, const char *value, int cflags)
int xdi_diff(mmfile_t *mf1, mmfile_t *mf2, xpparam_t const *xpp, xdemitconf_t const *xecfg, xdemitcb_t *xecb)
	if (len > 0 && line[len-1] == '\n') {
		strbuf_add(&priv->remainder, mb[i].ptr, mb[i].size);
void read_mmblob(mmfile_t *ptr, const struct object_id *oid)
	ecb.priv = &state;

	return xdl_diff(&a, &b, xpp, xecfg, xecb);
		free(regs->array);
		}
	mmfile_t a = *mf1;


	struct ff_regs *regs = priv;
{
	if (sz && fread(ptr->ptr, sz, 1, f) != 1) {
	struct ff_reg {
	/* Exclude terminating newline (and cr) from matching */
		xecfg->find_func_priv = NULL;
			BUG("mismatch between line count and parsing");
			continue;
	} *array;
}
		  xdiff_emit_line_fn line_fn,
	xdiff_emit_line_fn line_fn;
		char *buffer, long buffer_size, void *priv)
		free(regs);
#include "object-store.h"


{
}
		 * git-completion.bash when you add new merge config

		free(buffer);

		if (reg->negate && i == regs->nr - 1)
			/* Incomplete line */
int git_xmerge_style = -1;
			die("Invalid regexp to look for hunk header: %s", expression);
		       const char *func, long funclen)
	int nr;
	line += pmatch[i].rm_so;

		  xdiff_emit_hunk_fn hunk_fn,
		BUG("xdiff emitted hunk in the middle of a line");
		/* we have a complete line */
		trim_common_tail(&a, &b);
	return !!memchr(ptr, 0, size);
	}
		if (!regexec_buf(&reg->re, line, len, 2, pmatch, 0)) {
		if (*value == '!')
	if (!ptr->ptr || type != OBJ_BLOB)
static int xdiff_outf(void *priv_, mmbuffer_t *mb, int nbuf)
{
		reg->negate = (*value == '!');
