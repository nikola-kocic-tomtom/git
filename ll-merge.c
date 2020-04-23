	create_temp(orig, temp[0], sizeof(temp[0]));
	git_config(read_merge_config, NULL);
			name = default_ll_merge;
	if (!strcmp("recursive", key))
	close(fd);
				path, name1, name2);
	xsnprintf(temp[3], sizeof(temp[3]), "%d", marker_size);
	 */
			  mmbuffer_t *result,
	}
	     const char *path,
	 */
		 *

	ll_merge_fn fn;
		*ll_user_merge_tail = fn;

{
		switch (opts->variant) {
			   mmbuffer_t *result,
	}
	return marker_size;
	driver = find_ll_merge_driver(ll_driver_name);
	if (opts->renormalize) {

		return git_config_string(&default_ll_merge, var, value);
 bad:

	int status, fd, i;
		if (!strcmp(ll_merge_drv[i].name, name))
			   int marker_size);
	o = *opts;
			   int marker_size)

	    buffer_is_binary(orig->ptr, orig->size) ||
	xmp.file1 = name1;

	return &ll_merge_drv[LL_TEXT_MERGE];
	for (fn = ll_user_merge; fn; fn = fn->next)
		if (!default_ll_merge)
	struct ll_merge_driver *fn;
	if (check->items[1].value) {
{
		ll_user_merge_tail = &(fn->next);
{
	memset(&xmp, 0, sizeof(xmp));
	char *cmdline;
#define LL_TEXT_MERGE 1
		default:
	const char *name;
	/* default to the 3-way */
		 *    %L - conflict marker length

		result->size = 0;
	sq_quote_buf(&path_sq, path);
	xmp.xpp.flags = opts->xdl_opts;
			   const char *path,
		name = merge_attr;
	if (fn->cmdline == NULL)
			   mmfile_t *src1, const char *name1,

	for (i = 0; i < 3; i++)
{
	const struct ll_merge_driver *driver;

		 * file named by %A, and signal that it has done with zero exit
			   mmfile_t *orig, const char *orig_name,

		free(mm->ptr);

	stolen->ptr = NULL;
	    src1->size > MAX_XDIFF_SIZE ||
	if (check->items[0].value) {
	 * We are not interested in anything but "merge.<name>.variable";
	if (!strcmp(var, "merge.default"))
static int ll_ext_merge(const struct ll_merge_driver *fn,
	strbuf_release(&path_sq);
	create_temp(src1, temp[1], sizeof(temp[1]));
	git_check_attr(istate, path, check);
		xmp.marker_size = marker_size;
			const struct ll_merge_options *opts,
#include "xdiff-interface.h"
	if (fstat(fd, &st))
			   const char *path,
		fn->name = xmemdupz(name, namelen);
{
	if (!merge_attributes)
}
	dict[1].placeholder = "A"; dict[1].value = temp[1];
	assert(opts);
	fd = open(temp[1], O_RDONLY);
		unlink_or_warn(temp[i]);
	const char *args[] = { NULL, NULL };
		FREE_AND_NULL(result->ptr);

	return xdl_merge(orig, src1, src2, &xmp, result);
static int ll_binary_merge(const struct ll_merge_driver *drv_unused,
				       src2, name2,
#include "quote.h"
	if (ll_user_merge_tail)
	dict[0].placeholder = "O"; dict[0].value = temp[0];
typedef int (*ll_merge_fn)(const struct ll_merge_driver *,
	create_temp(src2, temp[2], sizeof(temp[2]));
	status = run_command_v_opt(args, RUN_USING_SHELL);
	if (parse_config_key(var, "merge", &name, &namelen, &key) < 0 || !name)


		if (marker_size <= 0)


	result->size = 0;
{
	int i;
			  opts, marker_size);
/*
	if (marker_size > 0)
	result->ptr = stolen->ptr;
			break;
 */
	static const struct ll_merge_options default_opts;

			   mmfile_t *src2, const char *name2,
	if (!check)
 */
	assert(opts);
				       opts, marker_size);

	{ "union", "built-in union merge", ll_union_merge },
		 *    %B - temporary file name for the other branches' version.
	}
		 * tokens and is given to the shell:
	int marker_size = DEFAULT_CONFLICT_MARKER_SIZE;
		case XDL_MERGE_FAVOR_OURS:
	result->ptr = xmallocz(result->size);
	const char *key, *name;
			/* fallthru */
	struct ll_merge_options o;
		return git_config_string(&fn->description, var, value);
}
	 * The tentative merge result is the common ancestor for an
	if (!strcmp("driver", key)) {
		marker_size += opts->extra_marker_size;
	initialize_ll_merge();
		goto close_bad;
		fn = xcalloc(1, sizeof(struct ll_merge_driver));
	 */
	     struct index_state *istate,
		mm->size = strbuf.len;

	xmp.ancestor = orig_name;
	if (!strcmp("name", key))
	if (write_in_full(fd, src->ptr, src->size) < 0)
	{ "text", "built-in 3-way text merge", ll_xdl_merge },
			const char *path,
	int marker_size = DEFAULT_CONFLICT_MARKER_SIZE;
}
		mm->ptr = strbuf_detach(&strbuf, NULL);

#define LL_UNION_MERGE 2
static int ll_xdl_merge(const struct ll_merge_driver *drv_unused,

			const char *path,
}
{
 */

static struct attr_check *load_merge_attributes(void)
	if (opts->extra_marker_size) {
	struct stat st;
		if (!strcmp(fn->name, name))
}
			  mmfile_t *orig, const char *orig_name,
 * Low level 3-way in-core file merge.

}
		return &ll_merge_drv[LL_BINARY_MERGE];
				       path,
	}
 * User defined low-level merge driver support.
			mmfile_t *orig, const char *orig_name,
		else

	 * internal merge.  For the final merge, it is "ours" by
			stolen = src1;
	dict[2].placeholder = "B"; dict[2].value = temp[2];

		case XDL_MERGE_FAVOR_THEIRS:
static void create_temp(mmfile_t *src, char *path, size_t len)
	const char *name;
			   const struct ll_merge_options *opts,

			return fn;
			warning("Cannot merge binary files: %s (%s vs. %s)",
	return ll_xdl_merge(drv_unused, result, path_unused,
		opts = &default_opts;
	if (fd < 0)
		if (!value)
		if (marker_size <= 0)
}
#include "cache.h"
			const struct ll_merge_options *opts,
		die("custom merge driver %s lacks command line.", fn->name);
		marker_size = atoi(check->items[0].value);

		merge_attributes = attr_check_initl("merge", "conflict-marker-size", NULL);
	 * after seeing merge.<name>.var1.
		return;
	result->size = stolen->size;
		 * status.
	/*
		normalize_file(ours, path, istate);
	if (!fn) {

static struct ll_merge_driver *ll_user_merge, **ll_user_merge_tail;
	args[0] = cmd.buf;
	ll_driver_name = check->items[0].value;
	}
			  const struct ll_merge_options *opts,
	const char *ll_driver_name = NULL;

			marker_size = DEFAULT_CONFLICT_MARKER_SIZE;
		 *    %A - temporary file name for our version.
	if (opts->virtual_ancestor) {
};
	if (!opts)

		 * merge.<name>.driver specifies the command line:
			   mmfile_t *src1, const char *name1,
static struct attr_check *merge_attributes;
	struct ll_merge_driver *fn;
	for (fn = ll_user_merge; fn; fn = fn->next)

#include "config.h"
		normalize_file(theirs, path, istate);
	for (i = 0; i < ARRAY_SIZE(ll_merge_drv); i++)
			   mmfile_t *src2, const char *name2,
	if (ATTR_TRUE(merge_attr))
			   mmfile_t *orig, const char *orig_name,
	struct strbuf path_sq = STRBUF_INIT;

};
				       src1, name1,
 * Built-in low-levels
	     mmfile_t *theirs, const char *their_label,
	struct strbuf strbuf = STRBUF_INIT;

	}
	strbuf_expand(&cmd, fn->cmdline, strbuf_expand_dict_cb, &dict);
		 *	command-line
/*
	    buffer_is_binary(src2->ptr, src2->size)) {
	}
	xmparam_t xmp;
	result->size = st.st_size;
	int fd;
	else if (ATTR_UNSET(merge_attr)) {
		if (driver->recursive)
		 * The external merge driver should write the results in the
		fn->fn = ll_ext_merge;
	attr_check_free(merge_attributes);
	 * "merge.summary", "merge.tool", and "merge.verbosity".
		return git_config_string(&fn->recursive, var, value);
static const struct ll_merge_driver *find_ll_merge_driver(const char *merge_attr)
		 *
		/*
		 */
 * merge.default and merge.driver configuration items
	dict[4].placeholder = "P"; dict[4].value = path_sq.buf;
{
	}
			driver = find_ll_merge_driver(driver->recursive);
			mmfile_t *src1, const char *name1,

	xsnprintf(path, len, ".merge_file_XXXXXX");
	 * With -Xtheirs or -Xours, we have cleanly merged;
	}
#define LL_BINARY_MERGE 0
		 *    %P - the original path (safely quoted for the shell)

{
 * Copyright (c) 2007 Junio C Hamano
			mmbuffer_t *result,
	if (renormalize_buffer(istate, path, mm->ptr, mm->size, &strbuf)) {
			  mmfile_t *src2, const char *name2,
			mmbuffer_t *result,
#include "run-command.h"
}
	 * default but -Xours/-Xtheirs can tweak the choice.
		return 0;
	 * Find existing one as we might be processing merge.<name>.var2
	char temp[4][50];
	xmp.favor = opts->variant;
		 *    %O - temporary file name for the merge base.
void reset_merge_attributes(void)
	return (opts->variant ? 0 : 1);
		xmp.style = git_xmerge_style;
struct ll_merge_driver;
		 *
	}
		die_errno("unable to write temp-file");
		marker_size = atoi(check->items[1].value);
	     mmfile_t *ancestor, const char *ancestor_label,
		normalize_file(ancestor, path, istate);

	{ "binary", "built-in binary merge", ll_binary_merge },
	/*
			mmfile_t *src2, const char *name2,
	     mmfile_t *ours, const char *our_label,
			return &ll_merge_drv[i];
	result->ptr = NULL;
	} else {
	ll_user_merge_tail = &ll_user_merge;
			int marker_size)
	fd = xmkstemp(path);
	strbuf_release(&cmd);
	o.variant = XDL_MERGE_FAVOR_UNION;
		 *
	}
	 * otherwise we got a conflict.
		if (!strncmp(fn->name, name, namelen) && !fn->name[namelen])
	assert(opts);
}
struct ll_merge_driver {
				       orig, orig_name,
	close(fd);
			stolen = src2;
	merge_attributes = NULL;
	/*
	 * especially, we do not want to look at variables such as
	dict[5].placeholder = NULL; dict[5].value = NULL;
	const char *recursive;
static int ll_union_merge(const struct ll_merge_driver *drv_unused,
 */
		 * The command-line will be interpolated with the following
	if (opts->virtual_ancestor) {
int ll_merge(mmbuffer_t *result_buf,
		check = attr_check_initl("conflict-marker-size", NULL);
			break;
			mmfile_t *orig, const char *orig_name,

		return &ll_merge_drv[LL_TEXT_MERGE];
/*


	mmfile_t *stolen;
 *
			  int marker_size)
		goto bad;
static int read_merge_config(const char *var, const char *value, void *cb)
		}
	    buffer_is_binary(src1->ptr, src1->size) ||
			mmfile_t *src2, const char *name2,
	}
			int marker_size)
			return &ll_merge_drv[LL_TEXT_MERGE];
	else

{

static void initialize_ll_merge(void)
	    src2->size > MAX_XDIFF_SIZE ||
	else if (ATTR_FALSE(merge_attr))
	int namelen;
	     const struct ll_merge_options *opts)
	if (orig->size > MAX_XDIFF_SIZE ||
static const char *default_ll_merge;
#include "ll-merge.h"
	struct ll_merge_driver *next;
static struct ll_merge_driver ll_merge_drv[] = {
	git_check_attr(istate, path, check);
			    &o, marker_size);

	struct strbuf cmd = STRBUF_INIT;
	return status;
 close_bad:
			  ours, our_label, theirs, their_label,
	return driver->fn(driver, result_buf, path, ancestor, ancestor_label,
	const char *description;
	struct attr_check *check = load_merge_attributes();

		return 0;
	/*
	xmp.level = XDL_MERGE_ZEALOUS;
	dict[3].placeholder = "L"; dict[3].value = temp[3];
	if (git_xmerge_style >= 0)
{
			return error("%s: lacks value", var);
}
}

			  mmfile_t *src1, const char *name1,
	assert(opts);
	/* Use union favor */
			  const char *path_unused,
			   mmbuffer_t *result,

int ll_merge_marker_size(struct index_state *istate, const char *path)
			break;
}
	static struct attr_check *check;
	return merge_attributes;
static void normalize_file(mmfile_t *mm, const char *path, struct index_state *istate)
/*
		fn->cmdline = xstrdup(value);
			mmfile_t *src1, const char *name1,
	return 0;
			marker_size = DEFAULT_CONFLICT_MARKER_SIZE;
	if (read_in_full(fd, result->ptr, result->size) != result->size) {
	struct strbuf_expand_dict_entry dict[6];
#include "attr.h"

{
		return ll_binary_merge(drv_unused, result,
			   const struct ll_merge_options *opts,

	 */
	xmp.file2 = name2;
			    orig, NULL, src1, NULL, src2, NULL,
		stolen = orig;
}
{
