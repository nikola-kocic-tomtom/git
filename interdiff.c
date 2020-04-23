	diff_setup_done(&opts);
	diffcore_std(&opts);
	diff_flush(&opts);

#include "commit.h"
void show_interdiff(struct rev_info *rev, int indent)
#include "cache.h"

	diff_tree_oid(rev->idiff_oid1, rev->idiff_oid2, "", &opts);
	strbuf_addchars(&prefix, ' ', indent);

#include "interdiff.h"
	opts.output_prefix = idiff_prefix_cb;
	opts.output_format = DIFF_FORMAT_PATCH;
	opts.output_prefix_data = &prefix;
	return data;
static struct strbuf *idiff_prefix_cb(struct diff_options *opt, void *data)
	memcpy(&opts, &rev->diffopt, sizeof(opts));
{
}
	struct strbuf prefix = STRBUF_INIT;
#include "revision.h"
}

{
	struct diff_options opts;

	strbuf_release(&prefix);
