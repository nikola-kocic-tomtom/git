	int diffsize;
		struct patch_util *util = b->items[i].util, *other;
		      "^.?@@ (.*)$", REG_EXTENDED }
	free(b2a);
		struct patch_util *util = a->items[i].util;
			i++;
		if (i < a->nr && a_util->matching < 0) {
	spec->is_stdin = 1;
			if (current_filename && p[2])
{
			output_pair_header(diffopt, patch_no_width,
}
			strbuf_addstr(&buf, " ## ");
			strbuf_addstr(&buf, line + 1);
	diff_flush(diffopt);
	int patch_no_width = decimal_width(1 + (a->nr > b->nr ? a->nr : b->nr));
			 * A completely blank (not ' \n', which is context)
		len = find_end_of_line(line, size);

	cp.git_cmd = 1;

			p = strstr(p, "@@");

	else
	return data;
	fwrite(buf->buf, buf->len, 1, diffopt->file);
			in_header = 1;
				strbuf_addstr(&buf, p + 2);
	if (!res && read_patches(range2, &branch2, other_arg))
		for (j = b->nr; j < n; j++)
}
	if (other_arg)
			"--no-abbrev-commit",
				strbuf_addstr(&buf, " ## Commit message ##\n");
		for (i = a->nr; i < n; i++)
	/* For the search for an exact match */
	int i = 0, j = 0;
		       struct diff_options *diffopt)
							  DEFAULT_ABBREV)));
		opts.flags.dual_color_diffed_diffs = dual_color;
	/* Now try to find exact matches in b */
			 */
	}

	xpparam_t pp = { 0 };

			if (p)
	if (!eol)
				error(_("could not parse commit '%s'"), p);
	cp.no_stdin = 1;

	struct diff_filespec *spec = alloc_filespec(name);
		for (j = b->nr; j < n; j++)
				strbuf_addf(&buf, " (mode change %06o => %06o)",
		status = '!';

		const char *p;
				util->diff_offset = buf.len;
	fill_filespec(spec, &null_oid, 0, 0100644);
		strbuf_addf(buf, " %*s:  %s", patch_no_width, "-", dashes->buf);
	strbuf_release(&dashes);
#include "diffcore.h"
		pp_commit_easy(CMIT_FMT_ONELINE, commit, buf);
		get_correspondences(&branch1, &branch2, creation_factor);
	struct object_id oid;
		if (status == '!')
	for (i = 0; i < b->nr; i++) {
{
	free(current_filename);
	struct string_list branch1 = STRING_LIST_INIT_DUP;
	 * We assume the user is really more interested in the second argument
	spec->size = strlen(p);
	 * them once we have shown all of their predecessors in the LHS.
	(*(int *)data)++;
			strbuf_addch(&buf, '-');
		/* Show unmatched LHS commit whose predecessors were shown. */

		   get_filespec("a", a), get_filespec("b", b));
	mmfile_t mf1, mf2;
	if (status == '!')
	mf2.ptr = (char *)b;
				finish_command(&cp);
			"--no-prefix",
			strbuf_addch(&buf, '+');
		c = util->matching < 0 ?
				strbuf_addch(&buf, '\n');
			continue;
				strbuf_add(&buf, line, p - line + 1);

			else
		opts.output_prefix_data = &indent;
			strbuf_addf(buf, "%s%s", color_reset, color);
}
		color = color_commit;
{
			cost[i + n * j] = c;
	int matching;



	int n = a->nr + b->nr;
	cfg.ctxlen = 3;
	/* the index of the matching item in the other branch, or -1 */
			line[len - 1] = '\n';
			int linenr = 0;

		return -1;
			struct patch_util *b_util = b->items[j].util;
		}
	free(cost);
		status = '=';

		hashmap_entry_init(&util->e, strhash(util->diff));
		return size;
}
	return res;

			/*
	diff_queue(&diff_queued_diff,
			 * line is not valid in a diff.  We skip it
			       int patch_no_width,
	argv_array_pushl(&cp.args, "log", "--no-color", "-p", "--no-merges",
				strbuf_addstr(&buf, " ## Metadata ##\n");
	string_list_clear(&branch1, 1);
#include "linear-assignment.h"
					   b->items[j].string, diffopt);
			output_pair_header(diffopt, patch_no_width,
				p = line + len - 2;
		    const struct argv_array *other_arg)
	error(_("failed to generate diff"));
				strlen(find_unique_abbrev(oid,
		} else if (line[0] == '#') {
			cost[i + n * j] = c;
		opts.flags.suppress_hunk_header_line_count = 1;
		/* Show unmatched RHS commits. */

};
			len = parse_git_diff_header(&root, &linenr, 0, line,

	diffcore_std(diffopt);
		status = '>';
				c = diffsize(a_util->diff, b_util->diff);
{

			struct patch patch = { 0 };
			util->matching = -1;
				strbuf_addstr(&buf, "\n\n");
			"--reverse", "--date-order", "--decorate=no",
	if (status == '!')

		util->i = i;

			strbuf_addch(&buf, ' ');

		}
}
			if (a_util->matching == j)
				string_list_clear(list, 1);
	 * ("newer" version). To that end, we print the output in the order of
	/*


};

	}

		if (diffopt)
		struct patch_util *a_util, *b_util;
		return -1;
		c = a_util->matching < 0 ?
				strbuf_addf(&buf, "%s (deleted)", patch.old_name);
	strbuf_release(&buf);
			cost[i + n * j] = c;
	if (!xdi_diff_outf(&mf1, &mf2,
	ALLOC_ARRAY(cost, st_mult(n, n));
{
		for (j = 0; j < b->nr; j++) {
			}
	if (strbuf_read(&contents, cp.out, 0) < 0) {
	for (i = 0; i < a->nr; i++)
	spec->should_munmap = 0;
			strbuf_addstr(&buf, "@@");

				current_filename = xstrdup(patch.old_name);
	return eol + 1 - buffer;

#include "argv-array.h"
 * as struct object_id (will need to be free()d).
			if (other->matching >= 0)
static void patch_diff(const char *a, const char *b,

		util->i = i;
}
			if (!(diffopt->output_format & DIFF_FORMAT_NO_OUTPUT))
			 * (e.g. will not be confusing when debugging)

			else
	return COST_MAX;
		return count;
		if (skip_prefix(line, "commit ", &p)) {
	int i, shown;

	int res = 0;
	}
	if (!b_util)
					p--;
	} else {
{
	size = contents.len;
		/* Show matching LHS/RHS pair. */
	argv_array_push(&cp.args, range);
#include "cache.h"
			b_util->matching = i;

			/*
{
	int i;
		string_list_append(list, buf.buf)->util = util;
	size_t size;
		status = '<';
{
			continue;
						    len, size, &patch);
	}
	}
			continue;
			  const char *funcline, long funclen)
	size_t diff_offset;
}

	ALLOC_ARRAY(b2a, n);
	strbuf_release(&buf);
			else if (patch.is_rename)
			NULL);
		} else if (skip_prefix(line, "@@ ", &p)) {

		}
	return strcmp(a->diff, keydata ? keydata : b->diff);
				strbuf_addf(&buf, "%s => %s", patch.old_name, patch.new_name);
		res = error(_("could not parse log for '%s'"), range1);
		output(&branch1, &branch2, &opts);
				current_filename = xstrdup(patch.new_name);
	hashmap_free(&map);
			free(current_filename);
			strbuf_addch(&buf, ' ');
		strbuf_addf(buf, "%s%s", color_reset, color_new);
		while (i < a->nr && a_util->shown)
	 * commits that are no longer in the RHS into a good place, we place
static int read_patches(const char *range, struct string_list *list,
			other->matching = i;
		} else if (!line[0])
	struct commit *commit;
		struct diff_options opts;
		strbuf_addf(buf, " %*d:  %s", patch_no_width, b_util->i + 1,
		else

		struct patch_util *a_util = a->items[i].util;
	const char *color;

			diff_setup(&opts);
static void output_pair_header(struct diff_options *diffopt,

	}
	int *cost, c, *a2b, *b2a;
	int in_header = 1;

		}

		color = color_new;
			if (util) {
				patch_diff(a->items[b_util->matching].string,
		color = color_commit;

				strbuf_release(&buf);
			if (patch.is_new > 0)

			 * silently, because this neatly handles the blank
	ALLOC_ARRAY(a2b, n);
	compute_assignment(n, n, cost, a2b, b2a);
				free(util);
}

			struct strbuf root = STRBUF_INIT;
				/* strip the trailing colon */
 * Reads the patches into a string list, with the `util` field being populated
#include "hashmap.h"
int show_range_diff(const char *range1, const char *range2,
					   &buf, &dashes, NULL, b_util);
 */
			j++;
		color = color_old;
				strbuf_addf(&buf, " ## %.*s ##\n",

			if (patch.is_delete > 0)
			a_util->matching = a2b[i];
			else
		}
			} else if (starts_with(line, "Notes") &&

				int creation_factor)
				   line[strlen(line) - 1] == ':') {
			b_util = ++j < b->nr ? b->items[j].util : NULL;
		opts.output_prefix = output_prefix_cb;
struct patch_util {
	 */
			}
	*eol = '\0';
		while (j < b->nr && b_util->matching < 0) {
	free(a2b);

			}
		/* Skip all the already-shown commits from the LHS. */
	hashmap_init(&map, (hashmap_cmp_fn)patch_util_cmp, NULL, 0);
static size_t find_end_of_line(char *buffer, unsigned long size)
					    (int)(strlen(line) - 1), line);
			if (!util->diff_offset)
			else if (patch.is_delete > 0)
	strbuf_addf(buf, "%s\n", color_reset);
}
		if (a2b[i] >= 0 && a2b[i] < b->nr) {
	while (i < a->nr || j < b->nr) {
	}
			struct patch_util *a_util = a->items[i].util;
	strbuf_reset(buf);
#include "userdiff.h"
	struct patch_util *util = NULL;
		return error_errno(_("could not start `log`"));

	} else if (strcmp(a_util->patch, b_util->patch)) {
#include "pretty.h"


static void output(struct string_list *a, struct string_list *b,

		if (other) {

	/* First, add the patches of a to a hash map */
		struct patch_util *util = b->items[j].util;
	mf1.ptr = (char *)a;
			  const struct patch_util *b, const char *keydata)
				strbuf_addf(&buf, "%s (new)", patch.new_name);
			 * Choose indicators that are not used anywhere
		}
{
	struct hashmap_entry e;
static struct userdiff_driver section_headers = {
	if (util)
}
		util->patch = b->items[i].string;
		util->diff = util->patch + util->diff_offset;
	for (i = 0; i < a->nr; i++) {

			   &pp, &cfg))
	.funcname = { "^ ## (.*) ##$\n"
	} else if (!a_util) {

	for (i = a->nr; i < n; i++)
			const struct argv_array *other_arg)
				die(_("could not parse git header '%.*s'"), (int)len, line);
	const char *diff, *patch;
	cp.out = -1;
		hashmap_add(&map, &util->e);
	struct strbuf buf = STRBUF_INIT, dashes = STRBUF_INIT;
			   diffsize_hunk, diffsize_consume, &count,
			util->matching = other->i;
		} else if (in_header) {
#include "run-command.h"
		diff_setup_done(&opts);
			if (patch.new_mode && patch.old_mode &&

static struct strbuf *output_prefix_cb(struct diff_options *opt, void *data)
	spec->driver = &section_headers;
			"--output-indicator-new=>",
			strbuf_addch(&buf, '\n');
		if (!opts.output_format)
		    const struct diff_options *diffopt,
	strbuf_addstr(buf, status == '!' ? color_old : color);
	if (start_command(&cp))
			if (len < 0)
		}
				strbuf_addf(&buf, " %s:", current_filename);
	if (commit) {
			 * separator line between commits in git-log
		find_exact_matches(&branch1, &branch2);
			    find_unique_abbrev(&a_util->oid, DEFAULT_ABBREV));
		else if (line[0] == '>') {
	struct strbuf buf = STRBUF_INIT, contents = STRBUF_INIT;
	if (read_patches(range1, &branch1, other_arg))

	 * the RHS (the `b` parameter). To put the LHS (the `a` parameter)

static void find_exact_matches(struct string_list *a, struct string_list *b)
		strbuf_addf(buf, "%s%s", color_reset, color);

			strbuf_addstr(&buf, line);
	char *line, *current_filename = NULL;

	char *eol = memchr(buffer, '\n', size);

	struct child_process cp = CHILD_PROCESS_INIT;
	spec->data = (char *)p;
			"--output-indicator-context=#",
	xdemitconf_t cfg = { 0 };

}

			a_util->shown = 1;
static struct diff_filespec *get_filespec(const char *name, const char *p)
		util->diffsize++;
	for (i = 0; i < a->nr; i++) {
	struct hashmap map;
	const char *color_reset = diff_get_color_opt(diffopt, DIFF_RESET);

	strbuf_addch(buf, status);


	struct string_list branch2 = STRING_LIST_INIT_DUP;
	string_list_clear(&branch2, 1);
static int patch_util_cmp(const void *dummy, const struct patch_util *a,
				strbuf_addstr(&buf, patch.new_name);
	mf1.size = strlen(a);

		} else {
			a_util = ++i < a->nr ? a->items[i].util : NULL;
			cost[i + n * j] = 0;
			       struct strbuf *dashes,
				strbuf_reset(&buf);
		error_errno(_("could not read `log` output"));
					   &buf, &dashes, a_util, b_util);
				while (isspace(*p) && p >= line)
		util->patch = a->items[i].string;
	mf2.size = strlen(b);
			"--output-indicator-old=<",
		strbuf_addch(buf, ' ');
			       struct patch_util *b_util)
		finish_command(&cp);
#include "string-list.h"
				strbuf_release(&contents);
	if (!a_util)
			strbuf_addstr(&buf, line + 1);
}
	int count = 0;
		strbuf_addf(buf, "%*s:  %s ", patch_no_width, "-", dashes->buf);
		strbuf_addstr(&indent, "    ");
		strbuf_release(&indent);
			} else if (starts_with(line, "    ")) {
			continue;
{
{
}
		other = hashmap_remove_entry(&map, util, e, NULL);
				BUG("already assigned!");
			 * else in diffs, but still look reasonable
	int offset, len;

			 */
			if (starts_with(line, "Author: ")) {
	const char *color_new = diff_get_color_opt(diffopt, DIFF_FILE_NEW);
		strbuf_addch(&buf, '\n');
			 * output.
		if (starts_with(line, "diff --git")) {
	if (!res) {

			    find_unique_abbrev(&b_util->oid, DEFAULT_ABBREV));
	if (finish_command(&cp))
	const char *color_commit = diff_get_color_opt(diffopt, DIFF_COMMIT);
	for (j = 0; j < b->nr; j++) {
		strbuf_addchars(dashes, '-',
	return 0;
	char status;
			strbuf_addstr(&buf, " ##");
	}
			struct patch_util *b_util = b->items[a2b[i]].util;
	diffsize_consume(data, NULL, 0);
			a_util->diffsize * creation_factor / 100 : COST_MAX;
	struct object_id *oid = a_util ? &a_util->oid : &b_util->oid;
	commit = lookup_commit_reference(the_repository, oid);
			else if (a_util->matching < 0 && b_util->matching < 0)

		argv_array_pushv(&cp.args, other_arg->argv);
			opts.output_format = DIFF_FORMAT_PATCH;
		b_util = j < b->nr ? b->items[j].util : NULL;
					    patch.old_mode, patch.new_mode);
		    int creation_factor, int dual_color,
		res = error(_("could not parse log for '%s'"), range2);
static int diffsize(const char *a, const char *b)
				strbuf_addstr(&buf, line);
{
			output_pair_header(diffopt, patch_no_width,

			    patch.old_mode != patch.new_mode)

			strbuf_addstr(&buf, line + 1);
		a_util = i < a->nr ? a->items[i].util : NULL;
				strbuf_addstr(&buf, "\n\n");
			memcpy(&opts, diffopt, sizeof(opts));
		struct strbuf indent = STRBUF_INIT;


	else
			util = xcalloc(sizeof(*util), 1);
		line[len - 1] = '\0';
					   &buf, &dashes, a_util, NULL);
#include "range-diff.h"
		   struct diff_options *diffopt)
#include "apply.h"
				string_list_append(list, buf.buf)->util = util;

static void diffsize_consume(void *data, char *line, unsigned long len)
	if (!dashes->len)
			in_header = 0;
	}
static void diffsize_hunk(void *data, long ob, long on, long nb, long nn,
	return spec;
			util->diffsize * creation_factor / 100 : COST_MAX;
	strbuf_release(&contents);
		opts.flags.suppress_diff_headers = 1;
/*
	for (offset = 0; size > 0; offset += len, size -= len, line += len) {
#include "xdiff-interface.h"
	line = contents.buf;
			       struct patch_util *a_util,
				return -1;
	}
	const char *color_old = diff_get_color_opt(diffopt, DIFF_FILE_OLD);
static void get_correspondences(struct string_list *a, struct string_list *b,
		hashmap_entry_init(&util->e, strhash(util->diff));
			a_util = a->items[b_util->matching].util;
{
				c = COST_MAX;
	int i, j;


		util->diff = util->patch + util->diff_offset;

		if (j < b->nr) {
		} else if (line[0] == '<') {
#include "commit.h"

		}
		strbuf_addf(buf, "%*d:  %s ", patch_no_width, a_util->i + 1,
				c = 0;


			       struct strbuf *buf,

{
			if (get_oid(p, &util->oid)) {
	if (!b_util) {
}


