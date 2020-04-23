#include "tree.h"
int cmd_read_tree(int argc, const char **argv, const char *cmd_prefix)
	BUG_ON_OPT_NEG(unset);

		init_tree_desc(t+i, tree->buffer, tree->size);
		printf("(missing)\n");
/*

				 trees[0]);
		OPT_BOOL(0, "empty", &read_empty,
		{ OPTION_STRING, 0, "prefix", &opts.prefix, N_("<subdirectory>/"),
	if (opts.reset || opts.merge || opts.prefix) {
		die("more than one --exclude-per-directory given.");
	 */
			opts.head_idx = 1;


static int debug_merge(const struct cache_entry * const *stages,
}

	for (i = 0; i < argc; i++) {
	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);
	 *

	struct unpack_trees_options opts;
#include "lockfile.h"
		die("I cannot read more than %d trees", MAX_UNPACK_TREES);
#include "resolve-undo.h"

	 * When reading only one tree (either the most basic form,
		die("passing trees as arguments contradicts --empty");
		OPT_BOOL('i', NULL, &opts.index_only,
	const struct option read_tree_options[] = {
			struct unpack_trees_options *o)
{
			die("you must specify at least one tree to merge");
	printf("* %d-way merge\n", o->merge_size);
	if (!nr_trees && !read_empty && !opts.merge)
#include "submodule.h"
	struct tree *tree;
	int prefix_set = 0;
#include "submodule-config.h"
{
		{ OPTION_CALLBACK, 0, "recurse-submodules", NULL,
	 * mode.

		       ce->ce_mode, ce_stage(ce), ce->name,
			die("Not a valid object name %s", arg);
	 * here; we are merely interested in reusing the
		  PARSE_OPT_NONEG },
		  N_("write resulting index to <file>"),
#include "config.h"
static void debug_stage(const char *label, const struct cache_entry *ce,
	return 0;
static int read_empty;
		OPT_END()
static int index_output_cb(const struct option *opt, const char *arg,
			opts.head_idx = stage - 2;
{
		parse_tree(tree);
	return 0;
	}
#include "cache.h"
			    PARSE_OPT_OPTARG, option_parse_recurse_submodules_worktree_updater },
			break;
	opts = (struct unpack_trees_options *)opt->value;
	tree = parse_tree_indirect(oid);
#include "dir.h"
{
};
		  N_("read the tree into the index under <subdirectory>/"),
	int i;
	}
	};
	if (!strcmp(var, "submodule.recurse"))
		else
		OPT_BOOL('m', NULL, &opts.merge,
		die("unable to write new index file");
			opts.fn = twoway_merge;
	 * NEEDSWORK
static int git_read_tree_config(const char *var, const char *value, void *cb)
		}
			 N_("update working tree with merge result")),
	prefix_set = opts.prefix ? 1 : 0;
		case 3:

{
	struct unpack_trees_options *opts;
	else
		{ OPTION_CALLBACK, 0, "exclude-per-directory", &opts,

	/* We do not need to nor want to do read-directory
			break;
	opts.src_index = &the_index;
}
			 N_("perform a merge in addition to a read")),
		die("Which one? -m, --reset, or --prefix?");
		OPT_BOOL(0, "trivial", &opts.trivial_merges_only,
		case 2:
		char buf[24];
	}
	if (opts.merge) {
		  N_("allow explicitly ignored files to be overwritten"),
		switch (stage - 1) {
	int i, stage = 0;
			 N_("don't check the working tree after merging")),
				 the_repository->index,
			break;
		  N_("gitignore"),
		opts.fn = debug_merge;
#include "object.h"
		OPT__QUIET(&opts.quiet, N_("suppress feedback messages")),
	if (!ce)
			 N_("3-way merge if no file level merging required")),
	if (opts->dir)
	if (nr_trees >= MAX_UNPACK_TREES)
		die("%s is meaningless without -m, --reset, or --prefix",
	else if (nr_trees > 0 && read_empty)
	BUG_ON_OPT_NEG(unset);
	 * destroy all index entries because we still need to preserve
{
static int nr_trees;
				    int unset)
	if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK))
		OPT__VERBOSE(&opts.verbose_update, N_("be verbose")),
	struct lock_file lock_file = LOCK_INIT;
		stage++;
	return 0;
		return -1;
	 */
		const char *arg = argv[i];
			 N_("same as -m, but discard unmerged entries")),
static int exclude_per_directory_cb(const struct option *opt, const char *arg,
	if (nr_trees == 1 && !opts.prefix)
		die("-u and -i at the same time makes no sense");

			break;
	if ((opts.dir && !opts.update))
		printf("(conflict)\n");
#include "parse-options.h"
	return 0;
		case 1:
			    "checkout", "control recursive updating of submodules",
		stage = opts.merge = 1;
			    N_("only empty the index")),
static struct tree *trees[MAX_UNPACK_TREES];
			 N_("skip applying sparse checkout filter")),
			 N_("debug unpack-trees")),
	opts->dir = dir;
		if (list_tree(&oid) < 0)
	 * "-m ent" or "--reset ent" form), we can obtain a fully
	return 0;
	opts.head_idx = -1;
		       struct unpack_trees_options *o)

#include "unpack-trees.h"
		{ OPTION_CALLBACK, 0, "index-output", NULL, N_("file"),
	struct object_id oid;

	/*
	set_alternate_index_output(arg);
	cache_tree_free(&active_cache_tree);
	 * what came from the tree.
			opts.fn = opts.prefix ? bind_merge : oneway_merge;

	if (1 < opts.merge + opts.reset + prefix_set)
 * GIT - The information manager from hell

	dir->flags |= DIR_SHOW_IGNORED;
	printf("%s ", label);
	 * certain information such as index version or split-index
			     read_tree_usage, 0);

	 * The old index should be read anyway even if we're going to

 *



}
}
	NULL
	if (!tree)
	if (unpack_trees(nr_trees, t, &opts))
		OPT_BOOL('u', NULL, &opts.update,
	return git_default_config(var, value, cb);

	 * valid cache-tree because the index must match exactly
}

		return 0; /* do not write the index out */
		if (read_cache_unmerged() && (opts.prefix || opts.merge))
	/*
	for (i = 1; i <= o->merge_size; i++) {
		if (stage - 1 >= 3)

	if (opts.debug_unpack)
	if (opts.merge && !opts.index_only)
	}
#define USE_THE_INDEX_COMPATIBILITY_MACROS
			die(_("You need to resolve your current index first"));
		OPT_BOOL(0, "no-sparse-checkout", &opts.skip_sparse_checkout,
			opts.fn = threeway_merge;
{
		OPT__DRY_RUN(&opts.dry_run, N_("don't update the index or the work tree")),
			opts.initial_checkout = is_cache_unborn();
	N_("git read-tree [(-m [--trivial] [--aggressive] | --reset | --prefix=<prefix>) [-u [--exclude-per-directory=<gitignore>] | -i]] [--no-sparse-checkout] [--index-output=<file>] (--empty | <tree-ish1> [<tree-ish2> [<tree-ish3>]])"),
		return git_default_submodule_config(var, value, cb);
		warning("read-tree: emptying the index with no arguments is deprecated; use --empty");

		if (get_oid(arg, &oid))
		default:
			die("failed to unpack tree object %s", arg);
		OPT_BOOL(0, "reset", &opts.reset,
	 * per directory ignore stack mechanism.
				 int unset)
	struct dir_struct *dir;
	for (i = 0; i < nr_trees; i++) {
#include "builtin.h"
 */
	struct tree_desc t[MAX_UNPACK_TREES];
	debug_stage("index", stages[0], o);
		case 0:
	if (opts.debug_unpack || opts.dry_run)
static const char * const read_tree_usage[] = {
		setup_work_tree();

		  PARSE_OPT_NONEG, index_output_cb },

	else if (ce == o->df_conflict_entry)
	if (1 < opts.index_only + opts.update)

		OPT_BOOL(0, "debug-unpack", &opts.debug_unpack,
		       oid_to_hex(&ce->oid));
	}
	trees[nr_trees++] = tree;
 * Copyright (C) Linus Torvalds, 2005
		struct tree *tree = trees[i];

		xsnprintf(buf, sizeof(buf), "ent#%d", i);
	git_config(git_read_tree_config, NULL);
	opts.dst_index = &the_index;
}
			 N_("3-way merge in presence of adds and removes")),
		printf("%06o #%d %s %.8s\n",
#include "tree-walk.h"

	if ((opts.update || opts.index_only) && !opts.merge)
		return 128;

static int list_tree(struct object_id *oid)
		  PARSE_OPT_NONEG, exclude_per_directory_cb },
	memset(&opts, 0, sizeof(opts));
#include "cache-tree.h"
	dir->exclude_per_dir = arg;
		OPT_GROUP(N_("Merging")),
	 */
		prime_cache_tree(the_repository,

	dir = xcalloc(1, sizeof(*opts->dir));

		debug_stage(buf, stages[i], o);

	resolve_undo_clear();
		die("--exclude-per-directory is meaningless unless -u");
		    opts.update ? "-u" : "-i");
		OPT_BOOL(0, "aggressive", &opts.aggressive,
}
	argc = parse_options(argc, argv, cmd_prefix, read_tree_options,

