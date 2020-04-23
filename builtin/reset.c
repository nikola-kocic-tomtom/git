
		delete_ref(NULL, "ORIG_HEAD", old_orig, 0);

	int i;
			if (read_from_tree(&pathspec, &oid, intent_to_add))
	} else if (old_orig)
{


			int flags = quiet ? REFRESH_QUIET : REFRESH_IN_PORCELAIN;
}

	ret = 0;
	}
	N_("git reset [-q] [--pathspec-from-file [--pathspec-file-nul]] [<tree-ish>]"),
		die(_("%s reset is not allowed in a bare repository"),
	 * git reset [-opts] <tree> -- [<paths>...]

		die(_("Cannot do a %s reset in the middle of a merge."),
		} else {
				err = reset_index(ref, &oid, MIXED, quiet);

			if (!quiet && get_git_work_tree()) {
	unborn = !strcmp(rev, "HEAD") && get_oid("HEAD", &oid);
	return update_ref_status;
#include "diff.h"
	 */
	N_("git reset [-q] [<tree-ish>] [--] <pathspec>..."),
#include "unpack-trees.h"
				if (advice_reset_quiet_warning && t_delta_in_ms > REFRESH_INDEX_DELAY_WARNING_IN_MS) {
		if (!ce)
{
						"use '--quiet' to avoid this.  Set the config setting reset.quiet to true\n"
};
			continue;
			rev = *argv++;
	struct object_id oid;
				return 1;
	int patch_mode = 0, pathspec_file_nul = 0, unborn;
				t_begin = getnanotime();
		/* fallthrough */
	N_("mixed"), N_("soft"), N_("hard"), N_("merge"), N_("keep"), NULL
			die(_("Cannot do %s reset with paths."),
		struct diff_filespec *one = q->queue[i]->one;
	for (i = 0; i < nr; i++)
#include "submodule.h"
		struct lock_file lock = LOCK_INIT;
	 *
		OPT_PATHSPEC_FROM_FILE(&pathspec_from_file),
}
			verify_filename(prefix, argv[0], 1);
		tree = parse_tree_indirect(&oid);
		if (get_oid_treeish(rev, &oid))
}
{
#include "diffcore.h"
enum reset_type { MIXED, SOFT, HARD, MERGE, KEEP, NONE };
	opts.merge = 1;
			return error(_("You do not have a valid HEAD."));
	if (reset_type == MIXED && is_bare_repository())
		ce = make_cache_entry(&the_index, one->mode, &one->oid, one->path,
	if (reset_type != SOFT && (reset_type != MIXED || get_git_work_tree()))
#include "parse-options.h"
			die(_("Failed to resolve '%s' as a valid tree."), rev);

static void print_new_head_line(struct commit *commit)
			  struct object_id *tree_oid,
				N_("reset HEAD, index and working tree"), MERGE),
	if (is_merge() || unmerged_cache())
	/* git reset tree [--] paths... can be used to
			   UPDATE_REFS_MSG_ON_ERR);
			int err;
		if (!commit)

			    "reset", "control recursive updating of submodules",

	N_("git reset [--mixed | --soft | --hard | --merge | --keep] [-q] [<commit>]"),
}
	if (unpack_trees(nr, desc, &opts))

	if (pathspec.nr) {
		if (reset_type == HARD && !update_ref_status && !quiet)
 *
	int i, nr = 0;
		}
		struct tree *tree;

		add_cache_entry(ce, ADD_CACHE_OK_TO_ADD | ADD_CACHE_OK_TO_REPLACE);
	if (unborn) {
#include "cache-tree.h"
#include "branch.h"
				    prefix, pathspec_from_file, pathspec_file_nul);
	struct strbuf buf = STRBUF_INIT;
			remove_file_from_cache(one->path);

	diffcore_std(&opt);
	 * the index file to the tree object we are switching to. */

				N_("reset HEAD but keep local changes"), KEEP),
#define REFRESH_INDEX_DELAY_WARNING_IN_MS (2 * 1000)
				die(_("Could not reset index file to revision '%s'."), rev);
	int intent_to_add = *(int *)data;

	/* Soft reset does not touch the index file nor the working tree
	struct object_id unused;
	const struct option options[] = {
				uint64_t t_begin, t_delta_in_ms;
		/* Any resets without paths update HEAD to the head being
	if (!pathspec.nr)

		opts.fn = twoway_merge;
			  int intent_to_add)
			 * Ok, argv[0] looks like a commit/tree; it should not
}
	}
	init_checkout_metadata(&opts.meta, ref, oid, NULL);
		OPT_END()
	} else if (!pathspec.nr && !patch_mode) {

}
	clear_pathspec(&opt.pathspec);

			argv += 2;
{

	nr++;
	opts.fn = oneway_merge;
			 * be a filename.
			die(_("make_cache_entry failed for path '%s'"),
	if (buf.len > 0)
		       PATHSPEC_PREFER_FULL |

			/* Otherwise we treat this as a filename */
#include "object.h"
	update_ref_status = update_ref(msg.buf, "HEAD", oid, orig, 0,
	int reset_type = NONE, update_ref_status = 0, quiet = 0;
	struct pathspec pathspec;
		find_unique_abbrev(&commit->object.oid, DEFAULT_ABBREV));
static const char * const git_reset_usage[] = {
					      _("Unstaged changes after reset:"));
		 * can not be a tree
		if (patch_mode)


}
		*old_orig = NULL, oid_old_orig;
#include "lockfile.h"
	}
}
		OPT_PATHSPEC_FILE_NUL(&pathspec_file_nul),
		commit = lookup_commit_reference(the_repository, &oid);
						N_("reset HEAD and index"), MIXED),

	}
	struct tree *tree;
	else
 * Based on git-reset.sh, which is
		trace2_cmd_mode("path");
		setup_work_tree();
	 * git reset [-opts] <paths>...
		hold_locked_index(&lock, LOCK_DIE_ON_ERROR);
		if (is_missing) {
		strbuf_addf(sb, "%s: %s", rla, action);
		set_reflog_message(&msg, "updating ORIG_HEAD", NULL);
	if (!quiet)
	if (do_diff_cache(tree_oid, &opt))
	return ret;
		die(_("index file corrupt"));
	opts.src_index = &the_index;
	if (argv[0]) {
			argv++; /* reset to HEAD, possibly with paths */
	opt.format_callback = update_index_from_diff;
			       const char *rev)
		prime_cache_tree(the_repository, the_repository->index, tree);
	}
	if (reset_type == SOFT || reset_type == KEEP)
	putchar('\n');
		trace2_cmd_mode(reset_type_names[reset_type]);

		else if ((!argv[1] && !get_oid_committish(argv[0], &unused)) ||
	struct object_id *orig = NULL, oid_orig,

	if (!pathspec.nr && !unborn) {
		parse_pathspec_file(&pathspec, 0,
		}
	argc = parse_options(argc, argv, prefix, options, git_reset_usage,
		free((void *)desc[i].buffer);
	opt.flags.override_submodule_config = 1;
	const char *rev = "HEAD";
		break;
static inline int is_merge(void)
#include "tree.h"
static void update_index_from_diff(struct diff_queue_struct *q,
		    _(reset_type_names[reset_type]));
				       UPDATE_REFS_MSG_ON_ERR);
		OPT_SET_INT(0, "merge", &reset_type,
	opt.output_format = DIFF_FORMAT_CALLBACK;
			warning(_("--mixed with paths is deprecated; use 'git reset -- <paths>' instead."));
	if (reset_type == KEEP) {
}
	} else {
			    PARSE_OPT_OPTARG, option_parse_recurse_submodules_worktree_updater },
	opt.format_callback_data = &intent_to_add;


	memset(&opt, 0, sizeof(opt));
	if (reset_type == MIXED || reset_type == HARD) {
				    PATHSPEC_PREFER_FULL,
	set_reflog_message(&msg, "updating HEAD", rev);
		OPT_BOOL('p', "patch", &patch_mode, N_("select hunks interactively")),
		remove_branch_state(the_repository, 0);
		OPT_SET_INT(0, "mixed", &reset_type,
 * Copyright (c) 2005, 2006 Linus Torvalds and Junio C Hamano
						PARSE_OPT_KEEP_DASHDASH);
				t_delta_in_ms = (getnanotime() - t_begin) / 1000000;
	};
				refresh_index(&the_index, flags, NULL, NULL,
	if (reset_type != SOFT) {
	if (read_cache() < 0)

		struct object_id head_oid;
 *
				      0, 0);


	for (i = 0; i < q->nr; i++) {
		}
	return !access(git_path_merge_head(the_repository), F_OK);
			die(_("--pathspec-from-file is incompatible with pathspec arguments"));
	if (intent_to_add && reset_type != MIXED)
out:
			dwim_ref(rev, strlen(rev), &dummy, &ref);
		OPT_SET_INT(0, "keep", &reset_type,
		if (reset_type == MIXED) {
{
	return 0;
	if (!fill_tree_descriptor(the_repository, desc + nr, oid)) {
#include "pretty.h"
			die(_("Failed to resolve '%s' as a valid revision."), rev);
	if (!get_oid("HEAD", &oid_orig)) {
			rev = argv[0];
		opts.update = 1;

	int update_ref_status;

		       const char **argv, const char *prefix,
	}
			}
		update_ref(msg.buf, "ORIG_HEAD", orig, old_orig, 0,
		update_ref_status = reset_refs(rev, &oid);
		int is_missing = !(one->mode && !is_null_oid(&one->oid));
{
		die(_("-N can only be used with --mixed"));

		opts.verbose_update = 1;
	opts.dst_index = &the_index;
		OPT_SET_INT(0, "hard", &reset_type,

		       const char **rev_ret)
	pp_commit_easy(CMIT_FMT_ONELINE, commit, &buf);
		old_orig = &oid_old_orig;
			die(_("--pathspec-from-file is incompatible with --patch"));
		if (reset_type == MIXED)
			if (reset_type == KEEP && !err)
			    one->path);
			free(ref);
					_(reset_type_names[reset_type]));
	NULL

		} else {
		} else if (argv[1] && !strcmp(argv[1], "--")) {
 */

			char *ref = NULL;
static int reset_refs(const char *rev, const struct object_id *oid)
			 (argv[1] && !get_oid_treeish(argv[0], &unused))) {
 * Copyright (c) 2007 Carlos Rica
		opts.reset = 1;
	if (!get_oid("ORIG_HEAD", &oid_old_orig))

		OPT_SET_INT(0, "soft", &reset_type, N_("reset only HEAD"), SOFT),
		error(_("Failed to find tree of %s."), oid_to_hex(oid));
			the_index.updated_skipworktree = 1;
	struct unpack_trees_options opts;
	diff_flush(&opt);
	parse_args(&pathspec, argv, prefix, patch_mode, &rev);
static void parse_args(struct pathspec *pathspec,
	}
static const char *reset_type_names[] = {
	const char *rev, *pathspec_from_file = NULL;
		if (is_missing && !intent_to_add) {
	parse_pathspec(pathspec, 0,
};
		       (patch_mode ? PATHSPEC_PREFIX_ORIGIN : 0),

	 * git reset [-opts] <tree> [<paths>...]
	/*
		if (!strcmp(argv[0], "--")) {
		strbuf_addf(sb, "reset: %s", action);

	default:
		if (reset_type != NONE)
	read_cache_unmerged();
			set_object_name_for_intent_to_add_entry(ce);
		if (!fill_tree_descriptor(the_repository, desc + nr, &head_oid))
	if (pathspec.nr)
			ce->ce_flags |= CE_INTENT_TO_ADD;
#include "submodule-config.h"

		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
			die(_("Could not write new index file."));
	switch (reset_type) {
static void set_reflog_message(struct strbuf *sb, const char *action,
		if (pathspec.nr)
	if (reset_type == NONE)

		    _(reset_type_names[reset_type]));
			if (ref && !starts_with(ref, "refs/"))


		return git_default_submodule_config(var, value, cb);
	N_("git reset --patch [<tree-ish>] [--] [<pathspec>...]"),
				ref = NULL;
	struct strbuf msg = STRBUF_INIT;
			die(_("--patch is incompatible with --{hard,mixed,soft}"));
static int reset_index(const char *ref, const struct object_id *oid, int reset_type, int quiet)
#include "builtin.h"
	 * git reset [-opts] [<rev>]

static int git_reset_config(const char *var, const char *value, void *cb)
						"to make this the default.\n"), t_delta_in_ms / 1000.0);
{


static int read_from_tree(const struct pathspec *pathspec,
			/*
		oidcpy(&oid, the_hash_algo->empty_tree);
		{ OPTION_CALLBACK, 0, "recurse-submodules", NULL,
	opts.head_idx = 1;
static void die_if_unmerged_cache(int reset_type)
	 * Possible arguments are:

		tree = parse_tree_indirect(oid);
	if (pathspec_from_file) {


	}
			verify_non_filename(prefix, argv[0]);
		orig = &oid_orig;
	return update_ref_status;
		struct diff_options *opt, void *data)
		die_if_unmerged_cache(reset_type);
			print_new_head_line(lookup_commit_reference(the_repository, &oid));
	opt.repo = the_repository;

	const char *rla = getenv("GIT_REFLOG_ACTION");
		return run_add_interactive(rev, "--patch=reset", &pathspec);
			return error(_("Failed to find tree of HEAD."));
	 * git reset [-opts] -- [<paths>...]

	copy_pathspec(&opt.pathspec, pathspec);
	}
			struct object_id dummy;
				N_("record only the fact that removed paths will be added later")),
	strbuf_release(&msg);
		if (write_locked_index(&the_index, &lock, COMMIT_LOCK))
		oidcpy(&oid, &commit->object.oid);
	if (patch_mode) {
		die(_("--pathspec-file-nul requires --pathspec-from-file"));
		return 1;
	 * At this point, argv points immediately after [-opts].
		/*
	 * at all, but requires them in a good order.  Other resets reset
		if (get_oid_committish(rev, &oid))

	strbuf_reset(sb);
	}
	case KEEP:
			die(_("Could not parse object '%s'."), rev);
		 * has to be unambiguous. If there is a single argument, it
		trace2_cmd_mode("patch-interactive");
		 * switched to, saving the previous head in ORIG_HEAD before. */
		if (get_oid("HEAD", &head_oid))
}
	return git_default_config(var, value, cb);
		reset_type = MIXED; /* by default */
			err = reset_index(ref, &oid, reset_type, quiet);
				N_("reset HEAD, index and working tree"), HARD),

	 * affecting the working tree nor HEAD. */
	}
		printf(" %s", buf.buf);
	 *
		       prefix, argv);
		}
		else if (reset_type != NONE)
	} else if (pathspec_file_nul) {
		 */
		goto out;
		struct commit *commit;
				}
			if (err)
		opts.update = 1;
	if (!strcmp(var, "submodule.recurse"))

	case MERGE:
		OPT_BOOL('N', "intent-to-add", &intent_to_add,
	else
		struct cache_entry *ce;
 * "git reset" builtin command
			die(_("Could not parse object '%s'."), rev);
 *
	*rev_ret = rev;
		oidcpy(&oid, &tree->object.oid);
	struct diff_options opt;
	printf(_("HEAD is now at %s"),
	strbuf_release(&buf);

		/* reset on unborn branch: treat as reset to empty tree */
	memset(&opts, 0, sizeof(opts));
/*
#include "config.h"
	int intent_to_add = 0;
}
		if (!tree)
	case HARD:
	struct tree_desc desc[2];
		 * Otherwise, argv[0] could be either <rev> or <paths> and
	int ret = -1;
{
		       int patch_mode,


#define USE_THE_INDEX_COMPATIBILITY_MACROS
{
	 * load chosen paths from the tree into the index without

					printf(_("\nIt took %.2f seconds to enumerate unstaged changes after reset.  You can\n"
	if (rla)
{
		nr++;
int cmd_reset(int argc, const char **argv, const char *prefix)
#include "tag.h"
	git_config_get_bool("reset.quiet", &quiet);
		}
{
	git_config(git_reset_config, NULL);
		strbuf_addf(sb, "reset: moving to %s", rev);
		goto out;
#include "refs.h"
#include "run-command.h"
	}
			 */
	else if (rev)
