#include "tag.h"
		} else {



	return 0;

	if (get_mode(name1, &mode1) || get_mode(name2, &mode2))
	diff_setup_done(&revs->diffopt);

	diff_flush(&revs->diffopt);
{
	if (argc != 2) {

			if (i1 == p1.nr)
	if (queue_diff(&revs->diffopt, paths[0], paths[1]))
	/*
				  "compare two paths outside a working tree"));
			/* 1 is file that is deleted */
			p = prefix_filename(prefix, p);
	int mode1 = 0, mode2 = 0;

		d2 = noindex_filespec(name2, mode2);
{
	strbuf_addstr(path, tail ? tail + 1 : file);
 * "diff --no-index" support
{
				       revs->diffopt.parseopts);
	if (name == file_from_standard_input)
			     diff_no_index_usage, 0);
		const char *p = argv[argc - 2 + i];

	revs->diffopt.flags.relative_name = 1;
			else if (i2 == p2.nr)
	int i, no_index;
	unsigned int isdir0, isdir1;
			strbuf_addstr(&buffer2, name2);
	s = alloc_filespec(name);
		strbuf_release(&buffer1);
static int get_mode(const char *path, int *mode)
static int queue_diff(struct diff_options *o,
	struct strbuf buf = STRBUF_INIT;
		populate_from_stdin(s);
				strbuf_addstr(&buffer2, p2.items[i2++].string);
	}
	revs->diffopt.flags.no_index = 1;
		if (!is_dot_or_dotdot(e->d_name))

{
		return -1;
/* append basename of F to D */
#include "builtin.h"
}
			mode2 = 0;

			d2 = noindex_filespec(NULL, 0);
	if (!path || !strcmp(path, "/dev/null"))


				n1 = NULL;
{
		}
	 */
		/* emit that file */
			}
	}
		diff_queue(&diff_queued_diff, d1, d2);

			else {
#include "dir.h"
}
	return 0;

#include "commit.h"
			strbuf_complete(&buffer2, '/');
 * is bolted onto the diff callchain.

		d1 = noindex_filespec(name1, mode1);


				n1 = buffer1.buf;
			 * path that is "-", spell it as "./-".

		return 1;
#include "diffcore.h"
	} else {
	strbuf_addstr(path, dir);
			 * stdin should be spelled as "-"; if you have
 * Copyright (c) 2007 by Johannes Schindelin
	 * 0 = no changes, 1 = changes, else error
		/* and then let the entire directory be created or deleted */
	struct dirent *e;
		usage_with_options(diff_no_index_usage, options);
		if (name1 && read_directory_contents(name1, &p1))
		  int argc, const char **argv)
	strbuf_addch(path, '/');
	 * The return code for --no-index imitates diff(1):

	else if (lstat(path, &st))
		OPT_END(),
	s->data = strbuf_detach(&buf, &size);
	isdir0 = is_directory(path[0]);
	FREE_AND_NULL(options);
#ifdef GIT_WINDOWS_NATIVE
	s->is_stdin = 1;
		}
		struct string_list p2 = STRING_LIST_INIT_DUP;
			warning(_("Not a git repository. Use --no-index to "
			mode1 = 0;
		struct diff_filespec *d1, *d2;
	closedir(dir);
int diff_no_index(struct rev_info *revs,
{
		return ret;
	DIR *dir;
	fixup_paths(paths, &replacement);
		struct strbuf buffer1 = STRBUF_INIT;
	}
		strbuf_release(&buffer2);
	return s;
	s->size = size;
		path[0] = replacement->buf;
#include "blob.h"
			int comp;
		else if (prefix)

	if (isdir0) {
		append_basename(replacement, path[0], path[1]);


		*mode = create_ce_mode(0666);
}
 * Note that we append the basename of F to D/, so "diff a/b/file D"
				comp = -1;
	const char *tail = strrchr(file, '/');


		struct strbuf buffer2 = STRBUF_INIT;
		string_list_clear(&p1, 0);
				n2 = NULL;
		*mode = st.st_mode;
			strbuf_complete(&buffer1, '/');
}

static const char file_from_standard_input[] = "-";
		return error_errno("error while reading from stdin");
			else {
/*
}
	diff_set_mnemonic_prefix(&revs->diffopt, "1/", "2/");
#include "revision.h"
				comp = strcmp(p1.items[i1].string, p2.items[i2].string);
	diffcore_std(&revs->diffopt);
	if (!revs->diffopt.output_format)
	struct option no_index_options[] = {
		if (S_ISDIR(mode1)) {
		if (name1) {
			if (comp > 0)
		struct string_list p1 = STRING_LIST_INIT_DUP;
 * Copyright (c) 2008 by Junio C Hamano
#include "parse-options.h"
		if (o->flags.reverse_diff) {
			strbuf_addstr(&buffer1, name1);
 * This should be "(standard input)" or something, but it will
#include "diff.h"

	else if (path == file_from_standard_input)
#include "cache.h"
	setup_diff_pager(&revs->diffopt);
static void append_basename(struct strbuf *path, const char *dir, const char *file)
	return 0;
	revs->max_count = -2;

				strbuf_addstr(&buffer1, p1.items[i1++].string);
	size_t size = 0;
			else
	struct strbuf replacement = STRBUF_INIT;

		name = "/dev/null";
			d1 = noindex_filespec(NULL, 0);
	for (i = 0; i < 2; i++) {

 */
		OPT_BOOL_F(0, "no-index", &no_index, "",
	s->should_munmap = 0;

		paths[i] = p;
	revs->diffopt.flags.exit_with_status = 1;
	struct diff_filespec *s;
}
		append_basename(replacement, path[1], path[0]);
			strbuf_setlen(&buffer2, len2);
	options = parse_options_concat(no_index_options,

			name1 = NULL;
	isdir1 = is_directory(path[1]);
			}
			SWAP(mode1, mode2);
			SWAP(name1, name2);
			/*
		size_t len1 = 0, len2 = 0;
		}
{

		}
	else
			return -1;
	    path[1] == file_from_standard_input)
	struct option *options;
	if (mode1 && mode2 && S_ISDIR(mode1) != S_ISDIR(mode2)) {
		revs->diffopt.output_format = DIFF_FORMAT_PATCH;
		int i1, i2, ret = 0;
	NULL
	revs->diffopt.skip_stat_unmatch = 1;
	N_("git diff --no-index [<options>] <path> <path>"),
		string_list_clear(&p2, 0);
			 */

		}
		return error("Could not open directory %s", path);
	if (path[0] == file_from_standard_input ||
		if (!strcmp(p, "-"))
#include "log-tree.h"

	} else {


	};
	if (isdir0 == isdir1)
			d1 = noindex_filespec(name1, mode1);
		*mode = 0;

	if (!(dir = opendir(path)))
		return;
/*
	s->should_free = 1;
/*
			string_list_insert(list, e->d_name);
		return;
			p = file_from_standard_input;
 * DWIM "diff D F" into "diff D/F F" and "diff F D" into "diff F D/F"
		return 0;
		return error("Could not access '%s'", path);
	while ((e = readdir(dir)))
}
		path->len--;
	const char *prefix = revs->prefix;
static const char * const diff_no_index_usage[] = {

		diff_queue(&diff_queued_diff, d1, d2);

		*mode = 0;
			if (comp < 0)
			string_list_clear(&p1, 0);
	}
			return -1;
 */
};
		path[1] = replacement->buf;
static struct diff_filespec *noindex_filespec(const char *name, int mode)
				comp = 1;
	else if (!strcasecmp(path, "nul"))
		if (implicit_no_index)

	return diff_result_code(&revs->diffopt, 0);
			d2 = noindex_filespec(name2, mode2);
 */
	if (S_ISDIR(mode1) || S_ISDIR(mode2)) {
		      const char *name1, const char *name2)
}
			strbuf_setlen(&buffer1, len1);
	if (strbuf_read(&buf, 0, 0) < 0)
			const char *n1, *n2;
static int read_directory_contents(const char *path, struct string_list *list)
	revs->diffopt.prefix = prefix;
			len2 = buffer2.len;
		for (i1 = i2 = 0; !ret && (i1 < p1.nr || i2 < p2.nr); ) {
static void fixup_paths(const char **path, struct strbuf *replacement)
			   PARSE_OPT_NONEG | PARSE_OPT_HIDDEN),
	struct stat st;
	const char *paths[2];


		  int implicit_no_index,

		if (name2 && read_directory_contents(name2, &p2)) {
 * becomes "diff a/b/file D/file", not "diff a/b/file D/a/b/file".
			name2 = NULL;
			/* 2 is file that is created */
			ret = queue_diff(o, n1, n2);

	fill_filespec(s, &null_oid, 0, mode);
	if (!name)
		if (name2) {
#include "color.h"

	}
			len1 = buffer1.len;

				n2 = buffer2.buf;
		struct diff_filespec *d1, *d2;
		}
	argc = parse_options(argc, argv, revs->prefix, options,
	while (path->len && path->buf[path->len - 1] == '/')
	strbuf_release(&replacement);
static int populate_from_stdin(struct diff_filespec *s)
 * probably expose many more breakages in the way no-index code
#endif
{

#include "string-list.h"
