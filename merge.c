	struct unpack_trees_options opts;

		argv_array_push(&args, merge_argument(j->item));

		init_tree_desc(t+i, trees[i]->buffer, trees[i]->size);
	struct tree_desc t[MAX_UNPACK_TREES];
	argv_array_clear(&args);

	ret = run_command_v_opt(args.argv, RUN_GIT_CMD);
{

	trees[nr_trees] = parse_tree_indirect(head);
	for (j = remotes; j; j = j->next)
		rollback_lock_file(&lock_file);

	if (!trees[nr_trees++]) {
	if (repo_read_index(r) < 0)
		return -1;
	resolve_undo_clear_index(r->index);
#include "cache.h"
#include "tree-walk.h"
	return oid_to_hex(commit ? &commit->object.oid : the_hash_algo->empty_tree);
	if (overwrite_ignore) {
	setup_unpack_trees_porcelain(&opts, "merge");
	argv_array_push(&args, head_arg);

	discard_index(r->index);
			  int overwrite_ignore)
	}
	struct commit_list *j;
		      const char **xopts, struct commit_list *common,
		opts.dir = &dir;
	memset(&t, 0, sizeof(t));
	}

	opts.head_idx = 1;
	memset(&opts, 0, sizeof(opts));
{
	return 0;
	for (i = 0; i < nr_trees; i++) {
#include "diffcore.h"
	struct argv_array args = ARGV_ARRAY_INIT;

		die(_("failed to read the cache"));
		memset(&dir, 0, sizeof(dir));


		clear_unpack_trees_porcelain(&opts);
	opts.fn = twoway_merge;
	opts.update = 1;
	if (unpack_trees(nr_trees, t, &opts)) {

		dir.flags |= DIR_SHOW_IGNORED;
		argv_array_pushf(&args, "--%s", xopts[i]);
	init_checkout_metadata(&opts.meta, NULL, remote, NULL);

	struct tree *trees[MAX_UNPACK_TREES];
int checkout_fast_forward(struct repository *r,
	clear_unpack_trees_porcelain(&opts);

	if (write_locked_index(r->index, &lock_file, COMMIT_LOCK))
		rollback_lock_file(&lock_file);
	return ret;
static const char *merge_argument(struct commit *commit)
#include "unpack-trees.h"
	opts.src_index = r->index;
	if (repo_hold_locked_index(r, &lock_file, LOCK_REPORT_ON_ERROR) < 0)
	int i, ret;
		parse_tree(trees[i]);
#include "lockfile.h"
}
	struct dir_struct dir;
		rollback_lock_file(&lock_file);
int try_merge_command(struct repository *r,
		setup_standard_excludes(&dir);
	for (j = common; j; j = j->next)
		return error(_("unable to write new index file"));
#include "commit.h"
	refresh_index(r->index, REFRESH_QUIET, NULL, NULL, NULL);
	memset(&trees, 0, sizeof(trees));
		      const char *strategy, size_t xopts_nr,
	argv_array_push(&args, "--");
	opts.verbose_update = 1;
	int i, nr_trees = 0;
#include "resolve-undo.h"
		return -1;
		argv_array_push(&args, merge_argument(j->item));
	opts.merge = 1;
		return -1;
	argv_array_pushf(&args, "merge-%s", strategy);
#include "diff.h"
	if (!trees[nr_trees++]) {
}
	struct lock_file lock_file = LOCK_INIT;
	opts.dst_index = r->index;
			  const struct object_id *head,
		      const char *head_arg, struct commit_list *remotes)
	trees[nr_trees] = parse_tree_indirect(remote);
	}
			  const struct object_id *remote,

#include "dir.h"
	for (i = 0; i < xopts_nr; i++)
	}
}
{
	}
#include "run-command.h"
		return -1;

