#include "quote.h"
/*
#define LS_SHOW_TREES 4
		if (spec[len] && spec[len] != '/')
		/*

		die("not a tree object");
	 * show_recursive() rolls its own matching code and is
		OPT_SET_INT(0, "full-name", &chomp_prefix,
	return !!read_tree_recursive(the_repository, tree, "", 0, 0,
	if (argc < 1)
	parse_pathspec(&pathspec, PATHSPEC_ALL_MAGIC &
 * Copyright (C) Linus Torvalds, 2005
				if (oid_object_info(the_repository, oid, &size) == OBJ_BAD)
	if (!tree)
			       find_unique_abbrev(oid, abbrev));
	}
			LS_SHOW_TREES),
			retval = READ_TREE_RECURSIVE;
#define LS_NAME_ONLY 8
				unsigned long size;

		ls_options |= LS_SHOW_TREES;
			LS_NAME_ONLY),

			if (!strcmp(type, blob_type)) {
#include "pathspec.h"
}
	if (!pathspec.nr)
		ls_tree_prefix = prefix = NULL;
		die("Not a valid object name %s", argv[0]);
}
	for (i = 0; i < pathspec.nr; i++) {
		} else
#include "cache.h"
	strbuf_setlen(base, baselen);
			continue;

	if (full_tree) {
	 * cannot be lifted until it is converted to use
}
	/*
		OPT_BIT('d', NULL, &ls_options, N_("only show trees"),
	ls_tree_prefix = prefix;
static struct pathspec pathspec;
	}
#include "blob.h"
			    N_("use full path names"), 0),
			    N_("terminate entries with NUL byte"), 0),
			if (!(ls_options & LS_SHOW_TREES))

	if (prefix && *prefix)

		const char *spec = pathspec.items[i].match;
	pathspec.has_wildcard = 0;

			       find_unique_abbrev(oid, abbrev),
				  ~(PATHSPEC_FROMTOP | PATHSPEC_LITERAL),

#include "parse-options.h"
int cmd_ls_tree(int argc, const char **argv, const char *prefix)
	const struct option ls_tree_options[] = {
	NULL
	return retval;
	strbuf_addstr(base, pathname);
#include "builtin.h"
		       PATHSPEC_PREFER_CWD,
		int len, speclen;
#include "commit.h"
	if (get_oid(argv[0], &oid))
		 */
		OPT_SET_INT('z', NULL, &line_termination,
#define LS_RECURSIVE 1
	int i, full_tree = 0;

static int ls_options;
			    "(implies --full-name)")),
			continue;
		}
	if (S_ISGITLINK(mode)) {
		OPT_END()

	if (ls_options & LS_RECURSIVE)
		return 1;
			retval = READ_TREE_RECURSIVE;
		if (show_recursive(base->buf, base->len, pathname)) {
					xsnprintf(size_text, sizeof(size_text),
		 *
static int line_termination = '\n';
		return 0;
		chomp_prefix = 0;
		return 0;
		OPT__ABBREV(&abbrev),
		 * Something similar to this incomplete example:
		type = tree_type;
			printf("%06o %s %s %7s\t", mode, type,
	for (i = 0; i < pathspec.nr; i++)
		const char *pathname, unsigned mode, int stage, void *context)
		if (speclen <= len)
	} else if (S_ISDIR(mode)) {
			continue;
			LS_SHOW_SIZE),
	if ( (LS_TREE_ONLY|LS_RECURSIVE) ==
 *
 * GIT - The information manager from hell
	struct tree *tree;
	 * generally ignorant of 'struct pathspec'. The magic mask
		if (strncmp(base, spec, baselen))
		chomp_prefix = strlen(prefix);
static const  char * const ls_tree_usage[] = {
			} else
			 N_("list entire tree; not just current directory "
		OPT_BIT(0, "name-status", &ls_options, N_("list only filenames"),
	int i;
	baselen = base->len;
		len = strlen(pathname);
				     &pathspec, show_tree, NULL);
	const char *type = blob_type;
			char size_text[24];
static int show_recursive(const char *base, int baselen, const char *pathname)
	argc = parse_options(argc, argv, prefix, ls_tree_options,


#include "tree.h"
				   stdout, line_termination);
					xsnprintf(size_text, sizeof(size_text),
			printf("%06o %s %s\t", mode, type,
		type = commit_type;
		speclen = strlen(spec);
	if (!(ls_options & LS_NAME_ONLY)) {
{
			LS_RECURSIVE),
			LS_TREE_ONLY),
	else if (ls_options & LS_TREE_ONLY)
};
		OPT_BOOL(0, "full-tree", &full_tree,
				return retval;
		spec += baselen;
		OPT_BIT('r', NULL, &ls_options, N_("recurse into subtrees"),

static int show_tree(const struct object_id *oid, struct strbuf *base,
	int baselen;
		       prefix, argv + 1);
#define LS_SHOW_SIZE 16

		OPT_BIT('l', "long", &ls_options, N_("include object size"),
		if (memcmp(pathname, spec, len))
		if (ls_options & LS_SHOW_SIZE) {
						  "%"PRIuMAX, (uintmax_t)size);
	return 0;
		OPT_BIT(0, "name-only", &ls_options, N_("list only filenames"),
	 * match_pathspec() or tree_entry_interesting()
	tree = parse_tree_indirect(&oid);
{
	write_name_quoted_relative(base->buf,
static const char *ls_tree_prefix;
{
#include "config.h"
			continue;
	};
	}
#include "object-store.h"
	}
	struct object_id oid;
	 */
		pathspec.items[i].nowildcard_len = pathspec.items[i].len;
	int retval = 0;
	/* -d -r should imply -t, but -d by itself should not have to. */
						  "BAD");
	git_config(git_default_config, NULL);
static int abbrev;
			     ls_tree_usage, 0);
				   chomp_prefix ? ls_tree_prefix : NULL,
		 *
			       size_text);
static int chomp_prefix;
				xsnprintf(size_text, sizeof(size_text), "-");
		usage_with_options(ls_tree_usage, ls_tree_options);
	    ((LS_TREE_ONLY|LS_RECURSIVE) & ls_options))
				else
		 *
		if (show_subprojects(base, baselen, pathname))
	N_("git ls-tree [<options>] <tree-ish> [<path>...]"),
		OPT_BIT('t', NULL, &ls_options, N_("show trees when recursing"),
			LS_NAME_ONLY),
		 * Maybe we want to have some recursive version here?

#define LS_TREE_ONLY 2
		return 1;
 */
