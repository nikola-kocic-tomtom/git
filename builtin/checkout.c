
				die(_("invalid reference: %s"), arg);
	 * matches the pathspec and could just stamp

	int implicit_detach;
	if (old_branch_info.path)
}
#include "lockfile.h"
	const char *old_desc, *reflog_msg;
	if (opts->new_orphan_branch && opts->orphan_from_empty_tree) {
	 *   (a) If <something> is a commit, that is to
		if (opts->checkout_index < 0)
		if (!opts->quiet) {
	 * for all args, expanding wildcards, and exit
			       NULL);
	for (pos = 0; pos < active_nr; pos++)
	setup_branch_path(new_branch_info);
	int writeout_stage;
			work = write_in_core_index_as_tree(the_repository);
	if (!ce)
		die(_("cannot switch branch while cherry-picking\n"
{


		    arg);
	int ret;
			patch_mode = "--patch=worktree";
		OPT_SET_INT_F('3', "theirs", &opts->writeout_stage,
	int flag, writeout_error = 0;
		if (ce->ce_flags & CE_MATCHED) {
					strbuf_release(&err);
	free(theirs.ptr);
		struct cache_entry *old = active_cache[pos];
}
static int checkout_branch(struct checkout_opts *opts,

					fprintf(stderr, _("Switched to a new branch '%s'\n"), new_branch_info->name);
		die(_("a branch is expected, got '%s'"), ref);

	}
		"Warning: you are leaving %d commits behind, "
		ce->ce_flags |= CE_MATCHED;
		die(_("Cannot switch branch to a non-commit '%s'"),
			Q_(
		if (opts->accept_pathspec && !strcmp(argv[i], "--")) {

	if (write_object_file(result_buf.ptr, result_buf.size, blob_type, &oid))
	opts.implicit_detach = 1;

	return 0;
			return ret;
		die(_("-p and --overlay are mutually exclusive"));
	ps_matched = xcalloc(opts->pathspec.nr, 1);
			die(_("You are on a branch yet to be born"));
	else
	strbuf_branchname(&buf, branch->name, INTERPRET_BRANCH_LOCAL);

	 *   (d) Otherwise :
	opts.overlay_mode = 0;
			o.ancestor = old_branch_info->name;
	struct strbuf sb = STRBUF_INIT;
static void setup_new_branch_info_and_source_tree(
			       &info->oid,
					return;
static int merge_working_tree(const struct checkout_opts *opts,
	if (stage == 2)
	 *   <ref> must be a valid tree, everything after the '--' must be
	struct tree **source_tree = &opts->source_tree;
	opts.dst_index = &the_index;
	if (opts->discard_changes) {
	 * all that is left is pathspecs.
	}
	int has_dash_dash = 0;
			return 0;
					warning(_("path '%s' is unmerged"), ce->name);
	/*
		}

	free(prevopts);

	unsigned seen = 0;
			       prefix, argv);

		    (flag & REF_ISSYMREF) && is_null_oid(&rev))
		    !opts->patch_mode)	/* patch mode is special */
/*
		*source_tree = get_commit_tree(new_branch_info->commit);
};
	    opts->writeout_stage)
	return 0;
	}
							opts);
{
		opts->ignore_unmerged_opt = "--force";

	trace2_cmd_mode("unborn");
	return 0;

		"not connected to\n"
		if (get_oid_mb(opts->from_treeish, &rev))
		char *head_ref = resolve_refdup("HEAD", 0, NULL, &flag);
	options = add_checkout_path_options(&opts, options);
		OPT_END()

						       &nr_checkouts, opts->overlay_mode);
#include "config.h"


{
		OPT_BOOL_F(0, "overwrite-ignore", &opts->overwrite_ignore,
		 * a commit, or an attempt to use case (1) with an
	 *
	/* "checkout -m path" to recreate conflicted state */
		else

	if (!reflog_msg)
	opts.dwim_new_local_branch = 1;
#include "diff.h"
	struct checkout_opts *opts,
	opts.checkout_index = -2;    /* default on */
	opts.checkout_index = -1;    /* default off */
		 * Accept "git checkout foo", "git checkout foo --"
	struct object_id oid;
		return 1;
	 */
#include "tree-walk.h"
	struct object_id threeway[3];
					      nr_checkouts),
	options = add_common_switch_branch_options(&opts, options);

	struct object_id *rev,
	/* Now we are committed to check them out */
		/*
			 * tree-ish, which means we should remove it
#include "merge-recursive.h"
			opts->checkout_index = 0;
		const char *argv0 = argv[0];

	 *       if <something> is A...B (missing A or B means HEAD but you can
		if (strcmp(name, ce->name))
	if (opts->discard_changes && opts->merge)
{
	   a commit exists. */
		if (skip_prefix(ref, "refs/remotes/", &ref))
	/*
		struct object_id rev;
		die(_("paths cannot be used with switching branches"));
			ce->ce_flags |= CE_REMOVE | CE_WT_REMOVE;
		errs |= checkout_worktree(opts, new_branch_info);
						       NULL, &nr_checkouts);
			    argv[0]);

		else
		if (!stage || strcmp(path, ce->name))
			pos = skip_same_name(ce, pos) - 1;
		const char *patch_mode;
			ret = merge_trees(&o,
			discard_cache_entry(ce);
{
	argcount++;
			else if (opts->merge)
		if (lost < ORPHAN_CUTOFF)
	NULL,
	free(ps_matched);
		}
	int len;
{
			ret = reset_tree(new_tree,
		; /* skip */
		if (!read_ref_full("HEAD", 0, &rev, &flag) &&

		OPT_STRING('c', "create", &opts.new_branch, N_("branch"),
			"Please use -- (and optionally --no-guess) to disambiguate"),
			error(_("you need to resolve your current index first"));
	 * NEEDSWORK:
	if (opts->accept_pathspec && opts->accept_ref)
	return newopts;
	opts.only_merge_on_switching_branches = 0;
	 */
	}
	for (i = 0; i < argc; i++) {

		/*
	 */
	struct object_id oid;
			"If you want to keep them by creating a new branch, "
	}
static const char * const switch_branch_usage[] = {
		tree = parse_tree_indirect(old_branch_info->commit ?
static void report_tracking(struct branch_info *new_branch_info)
		oidcpy(rev, &branch_rev);
		/*
	int count_checkout_paths;
	struct object_id rev;
	while ((c = get_revision(revs)) != NULL) {
		}
			old->ce_flags |= CE_UPDATE;
	while (pos < active_nr &&
			      N_("checkout their version for unmerged files"),
	}
	if (!opts->checkout_worktree && !opts->checkout_index)

{

		opts->merge = 1; /* implied */
		return;

	char *to_free;
			die(_("unable to write new index file"));

	init_checkout_metadata(&opts.meta, info->refname,
			patch_mode = "--patch=checkout";
	int nr_checkouts = 0, nr_unmerged = 0;
	 * If this is a ref, resolve it; otherwise, look up the OID for our
	    (new_branch_info->path || (!opts->force_detach && !strcmp(new_branch_info->name, "HEAD"))))
	int force_detach;
struct checkout_opts {
			die(_("--pathspec-from-file is incompatible with --patch"));
	}

	else if (dash_dash_pos >= 2)
			if (opts->new_branch_log &&
		pp_commit_easy(CMIT_FMT_ONELINE, commit, sb);

			return switch_unborn_to_new_branch(opts);
		const char *pathname, unsigned mode, int stage, void *context)
		else
		if (more == 1)
	free(ancestor.ptr);
		 * Do not complain the most common case
	if (opts->track != BRANCH_TRACK_UNSPECIFIED)
}
			opts->show_progress = 0;
	const char *path = ce->name;
	if (advice_detached_head)
			describe_one_orphan(&sb, last);
			 N_("ignore unmerged entries")),
	 * (it also writes the merge result to the object database even
	else if (dash_dash_pos == 1)
			 N_("do not limit pathspecs to sparse entries only")),
							ps_matched,
	opts.fn = oneway_merge;
#define USE_THE_INDEX_COMPATIBILITY_MACROS
	    !new_branch_info->name &&
	int num_matches = 0;
	}
		if (opts->new_orphan_branch) {
{
		 * refresh. But it's a bit tricker to do...

				       int could_be_checkout_paths)
			struct tree *work;
					    char *ps_matched,
		"any of your branches:\n\n"
			     "If you'd like to always have checkouts of an ambiguous <name> prefer\n"
	int can_switch_when_in_progress;

		cache_tree_update(&the_index, WRITE_TREE_SILENT | WRITE_TREE_REPAIR);
	int show_progress;
		if (opts->source_tree)
	    !opts->force_detach)
	rev.diffopt.flags = opts->flags;
	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);
		parse_tree(new_tree);
	 *   The first argument must not be ambiguous.
		}
	memcpy(ce->name, base->buf, base->len);
					 struct option *prevopts)
		die(_("Unable to add merge result for '%s'"), path);
	strbuf_release(&msg);

	unsigned mode = 0;
		if (!new_branch_info->commit)

		die(_("'%s' cannot be used with switching branches"),
			 N_("second guess 'git checkout <no-such-branch>' (default)")),
				error(_("path '%s' is unmerged"), ce->name);
	int orphan_from_empty_tree;
	/* we can't end up being in (2) anymore, eat the argument */

			    options, switch_branch_usage);
		 *
		return 1;
			"this may be a good time\nto do so with:\n\n"
	strbuf_release(&branch_ref);
		die(_("neither '%s' or '%s' is specified"),

			 * whether the merge flag was used.
	memset(&new_branch_info, 0, sizeof(new_branch_info));
	if (!opts->accept_pathspec && !opts->accept_ref)
static void die_expecting_a_branch(const struct branch_info *branch_info)
 * We are about to leave commit that was at the tip of a detached
		refresh_cache(REFRESH_QUIET);
		memset(&topts, 0, sizeof(topts));
	state.force = 1;
	 * match_pathspec() for _all_ entries when
		if (ret) {
		}
			opts->checkout_index = -opts->checkout_index - 1;
	 */
					 const struct object_id *oid,
	N_("git checkout [<options>] [<branch>] -- <file>..."),
	if (opts->force_detach && opts->new_branch)
			/*
	repo_init_revisions(the_repository, &rev, NULL);
						opts->new_orphan_branch, err.buf);
					fprintf(stderr, _("Already on '%s'\n"),
	    !opts->new_branch &&
		else if (!nr_unmerged || nr_checkouts)
						struct option *prevopts)
				exit(128);
}
	git_config(git_checkout_config, opts);
			return ret;
			setup_standard_excludes(topts.dir);
	struct strbuf branch_ref = STRBUF_INIT;
			if (!ce_stage(ce))

	}
						     ps_matched,
			 */
	strbuf_addch(sb, '\n');
				errs = 1;

	} else {
			} else {
			char *refname;
	memset(&opts, 0, sizeof(opts));
			if (old_branch_info->path && !strcmp(new_branch_info->path, old_branch_info->path)) {
	opts.ignore_unmerged_opt = "--ignore-unmerged";
	if (opts->merge)
			    opts->checkout_worktree, opts->checkout_index);
					  old_tree);
	 *  2) git checkout -- [<paths>]
}
		/* 2-way merge to the new branch */
}
		last = c;
			free(path_to_free);

			BUG("'switch --orphan' should never accept a commit as starting point");
		oidcpy(&threeway[stage - 1], &ce->oid);

		opts->ignore_unmerged = 1;
	 * ps_matched yet. Once it can, we can avoid calling
		if (new_branch_info->name)
			if (!old_branch_info->commit)
			describe_detached_head(_("HEAD is now at"), new_branch_info->commit);
				       new_branch_info->commit ?
	opts.empty_pathspec_ok = 1;
	if (opts->new_orphan_branch) {
	die(_("a branch is expected, got '%s'"), branch_info->name);
	if (!opts->discard_changes && !opts->quiet && new_branch_info->commit)
	 *       remote-tracking branch.
		return READ_TREE_RECURSIVE;
}
	oidcpy(&ce->oid, oid);
	       !strcmp(active_cache[pos]->name, ce->name)) {
static void mark_ce_for_checkout_no_overlay(struct cache_entry *ce,
			 */


			dash_dash_pos = i;
	if (opts->patch_mode)
	opts.accept_ref = 1;
	 * work-tree format and writes out which only allows it for a
			  const struct checkout *state, int *nr_checkouts,
static void orphaned_commit_warning(struct commit *old_commit, struct commit *new_commit)
	}

		fprintf(stderr, "%s %s... %s\n", msg,
	add_pending_oid(cb_data, refname, oid, UNINTERESTING);
#include "checkout.h"
		}
	if (remote && could_be_checkout_paths) {
			   N_("which tree-ish to checkout from")),
	if (state.cherry_pick_in_progress)
			    options, restore_usage);

	resolve_undo_clear();
	setup_revisions(0, NULL, &revs, NULL);
	FREE_AND_NULL(options);
			     usagestr, parseopt_flags);
	 */
		 * "git checkout tree-ish -- path", but this entry
		struct tree *tree;
	if (ORPHAN_CUTOFF < lost) {
	argc--;
		 */
#include "submodule.h"
	 *   (c) Otherwise, if "--" is present, treat it like case (1).
		init_tree_desc(&trees[0], tree->buffer, tree->size);
		    !(argc == 2 && has_dash_dash) &&
			   oid_to_hex(old_commit ? &old_commit->object.oid : &null_oid),
};
	}
	if (!opts->can_switch_when_in_progress)
			 * We update the index fully, then write the
				strbuf_release(&err);
	opts.empty_pathspec_ok = 0;

#include "xdiff-interface.h"
	} else {
	int do_merge = 1;
			BUG("either flag must have been set, worktree=%d, index=%d",
	ce->ce_mode = create_ce_mode(mode);
static const char *parse_remote_branch(const char *arg,
			BRANCH_TRACK_EXPLICIT),
	struct option *newopts = parse_options_concat(prevopts, options);
				int ret;

		if (opts->force_detach)
	 *       - if it's a reference, treat it like case (1)
	 *
	 *
			  &ours, "ours", &theirs, "theirs",
			if (has_dash_dash)
	const char *remote = unique_tracking_name(arg, rev, &num_matches);
				if (opts->new_branch_force)
	ret = checkout_main(argc, argv, prefix, &opts,
	argc = parse_options(argc, argv, prefix, options,
	    !opts->new_branch &&
		 *	git checkout branch
	return ret;
	strbuf_release(&sb);
static int reset_tree(struct tree *tree, const struct checkout_opts *o,
	state.refresh_cache = 1;

		return error(_("path '%s' does not have their version"), ce->name);
static int check_stages(unsigned stages, const struct cache_entry *ce, int pos)

		return error(_("path '%s' does not have necessary versions"), path);
		topts.update = 1;
			old_desc ? old_desc : "(invalid)", new_branch_info->name);
				fprintf(stderr, _("Switched to branch '%s'\n"),
static struct option *add_common_options(struct checkout_opts *opts,
	 */

			      3, PARSE_OPT_NONEG),
{

		if (opts->new_branch_force)
		    "--staged", "--worktree");
		die_if_some_operation_in_progress();
	return newopts;
	repo_init_revisions(the_repository, &revs, NULL);

	 *
	int checkout_index;
		OPT_PATHSPEC_FROM_FILE(&opts->pathspec_from_file),
	 *       or <something> is not a path, no -t or -b was given, and
	strbuf_addstr(sb, "  ");
			     "one remote, e.g. the 'origin' remote, consider setting\n"
}
					   the_hash_algo->empty_tree);
		/*

		    "--[no]-overlay");
	 */
static int add_pending_uninteresting_ref(const char *refname,
		}
		    "--merge", "--conflict", "--staged");
	fputs(sb.buf, stdout);

{
	opts.accept_pathspec = 0;
			topts.dir = xcalloc(1, sizeof(*topts.dir));


		opts->new_branch = opts->new_orphan_branch;
		ce->ce_flags |= CE_MATCHED;
		if (opts->track != BRANCH_TRACK_UNSPECIFIED)
	int quiet;
		setup_branch_path(new_branch_info);
			if (old_branch_info->name == NULL) {
				continue;

#include "unpack-trees.h"
			/* Do more real merge */
			find_unique_abbrev(&commit->object.oid, DEFAULT_ABBREV), sb.buf);
	const char *name = ce->name;
}
	struct object_id oid; /* The object ID of the commit being checked out. */
		add_pending_oid(&revs, "HEAD",
{
		die(_("cannot switch branch while rebasing\n"
	}
				errs |= checkout_stage(opts->writeout_stage,
	if (state.rebase_interactive_in_progress || state.rebase_in_progress)
	clear_commit_marks_all(ALL_REV_FLAGS);
	 * non-commit, but just in case.
}
	repo_hold_locked_index(the_repository, &lock_file, LOCK_DIE_ON_ERROR);
}
								 could_be_checkout_paths);
	struct option *options;

		    opts->ignore_unmerged_opt);
		    "--ours", "--theirs", "--staged");
				else
			    options, checkout_usage);
		lost),
	void *path_to_free;
	 *
			     "checkout.defaultRemote=origin in your config."));
		opts->from_treeish = "HEAD";
	free(prevopts);
	char *refname; /* The full name of the ref being checked out. */
static void update_refs_for_switch(const struct checkout_opts *opts,
				errs |= check_stages((1<<2) | (1<<3), ce, pos);
	    !read_ref(new_branch_info->path, &branch_rev))
		pp_commit_easy(CMIT_FMT_ONELINE, commit, &sb);
			      struct branch_info *new_branch_info,

		 * NEEDSWORK: if --worktree is not specified, we
}

int cmd_checkout(int argc, const char **argv, const char *prefix)
{
	struct object_id rev;
	const char *new_branch_force;

	if (!new_branch_info->commit) {
	 * -b/-B/--orphan is being used.
			 */
		pos++;
		free(result_buf.ptr);

	int empty_pathspec_ok;
static void mark_ce_for_checkout_overlay(struct cache_entry *ce,
		new_tree = parse_tree_indirect(the_hash_algo->empty_tree);
		if (!recover_with_dwim) {

	struct strbuf msg = STRBUF_INIT;
static int switch_branches(const struct checkout_opts *opts,
		show_local_changes(&new_branch_info->commit->object, &opts->diff_options);

			check_filename(opts->prefix, arg);
	/*
	len = base->len + strlen(pathname);
};
				}
	strbuf_addf(&branch_ref, "refs/heads/%s", opts->new_branch);
static int read_tree_some(struct tree *tree, const struct pathspec *pathspec)
	options = add_common_switch_branch_options(&opts, options);
			/*
	int new_branch_log;
		die(_("internal error in revision walk"));
		suggest_reattach(old_commit, &revs);
	/*
	 *
			 * from the index and the working tree.
	remove_scheduled_dirs();
	}
		orphaned_commit_warning(old_branch_info.commit, new_branch_info->commit);
{
	if (!opts->checkout_worktree && !opts->from_treeish)
		if (opts->checkout_worktree < 0)
	if (opts->new_branch)
	 * Either this entry came from the tree-ish we are
			"If you want to keep it by creating a new branch, "
	old_desc = old_branch_info->name;
		argc--;

	if (!strcmp(new_branch_info->name, "HEAD") && !new_branch_info->path && !opts->force_detach) {
#include "tree.h"
	struct rev_info rev;
	int dash_dash_pos;
#include "remote.h"

				int dwim_new_local_branch_ok,

			die_if_checked_out(new_branch_info->path, 1);
#define ORPHAN_CUTOFF 4
	read_mmblob(&ours, &threeway[1]);
		topts.verbose_update = opts->show_progress;
	return errs;
	/*
	}
	int checkout_worktree;
				return 1;
			  state->istate, NULL);
			opts->track == BRANCH_TRACK_UNSPECIFIED &&
		if (ce_stage(active_cache[pos]) == stage)
	}
	} else {
int cmd_switch(int argc, const char **argv, const char *prefix)
		return error(_("path '%s' does not have all necessary versions"),
	int force;
		die(_("'%s' cannot be used with %s"),
	}
	 * From here on, new_branch will contain the branch to be checked out,
		die(_("unable to write new index file"));
}

{
	status = ll_merge(&result_buf, path, &ancestor, "base",
	if (opts->new_branch_log)
			recover_with_dwim = 0;
	opts.accept_ref = 0;
		 * even if there happen to be a file called 'branch';
		pos++;
					 writeout_error, new_branch_info);
		OPT_BOOL('l', NULL, &opts.new_branch_log, N_("create reflog for new branch")),
	memset(&old_branch_info, 0, sizeof(old_branch_info));
	opts.src_index = &the_index;
				else

	head = lookup_commit_reference_gently(the_repository, &rev, 1);
	ce->ce_flags = create_ce_flags(0) | CE_UPDATE;
		die(_("'%s' cannot be used with updating paths"),

}
		"%s\n",
						      opts, &rev,
						       ce, pos,
						      DEFAULT_ABBREV));
	if (ce_path_match(&the_index, ce, &opts->pathspec, ps_matched))
			strbuf_release(&sb);

		argc -= n;


{
		if (opts->only_merge_on_switching_branches)

	} else if (opts->accept_pathspec) {
		die(_("'%s' cannot be used with switching branches"),
		update_ref(msg.buf, "HEAD", &new_branch_info->commit->object.oid, NULL,
	memset(&opts, 0, sizeof(opts));
		if (unmerged_cache()) {
				arg = remote;
		die(_("only one reference expected, %d given."), dash_dash_pos);
			opts->new_branch);
			} else {
		return;
	struct branch_info old_branch_info;

	struct branch *branch = branch_get(new_branch_info->name);
			       opts->patch_mode ? PATHSPEC_PREFIX_ORIGIN : 0,
#include "resolve-undo.h"
	N_("git checkout [<options>] <branch>"),
		      "or \"git worktree add\"."));

		do_merge = 1;
}
			 * normalization (or clean+smudge rules) is
		struct unpack_trees_options topts;
					    const struct checkout_opts *opts)


	if (strcmp(buf.buf, branch->name))
			die(_("only one reference expected"));
	}
	 * If it comes from the tree-ish, we already know it
		return 128;
	return pos;
	}
		return run_add_interactive(new_branch_info->name, patch_mode, &opts->pathspec);

		if (opts->overlay_mode)

	struct checkout_opts opts;


		parse_commit_or_die(new_branch_info->commit);
			   PARSE_OPT_NOCOMPLETE),
		branch->name = xstrdup(buf.buf);
			      "checking out of the index."));
	if (opts->source_tree && !(ce->ce_flags & CE_UPDATE))
	N_("git switch [<options>] [<branch>]"),
		arg, num_matches);
		else if (opts->checkout_index && !opts->checkout_worktree)
	ret = checkout_main(argc, argv, prefix, &opts,
{
	 * to the write_entry() machinery that massages the contents to
	branch->path = strbuf_detach(&buf, NULL);
		skip_prefix(argv0, "remotes/", &argv0);
	 * Make sure all pathspecs participated in locating the paths
	    !new_branch_info->path)
			       info->commit ? &info->commit->object.oid : &info->oid,
{
			       NULL);
				      opts->track);
			strbuf_addf(&sb, _(" ... and %d more.\n"), more);
			return 0;
	opts.update = worktree;
	} else {

	opts.head_idx = -1;
			 N_("throw away local modifications")),
	opts.can_switch_when_in_progress = 0;
			struct merge_options o;
		return 0;
	opts.implicit_detach = 0;
	enum branch_track track;


	int overlay_mode;
					 opts, 1,
	 *       and there is a tracking branch whose name is <something>
	 *       omit at most one side), and if there is a unique merge base
		OPT_PATHSPEC_FILE_NUL(&opts->pathspec_file_nul),
	if (!has_dash_dash) {	/* case (3).(d) -> (1) */
		return 0;

			   N_("create and switch to a new branch")),
			return 1;
			struct strbuf sb = STRBUF_INIT;
			patch_mode = "--patch=reset";
		init_checkout_metadata(&topts.meta, new_branch_info->refname,
	 * "git restore --staged --source HEAD"
	for_each_ref(add_pending_uninteresting_ref, &revs);
static struct option *add_checkout_path_options(struct checkout_opts *opts,
					      "Updated %d paths from the index",
		opts->new_branch = opts->new_branch_force;
				      opts->new_branch_force ? 1 : 0,
		int could_be_checkout_paths = !has_dash_dash &&
			die(_("you must specify path(s) to restore"));
#include "advice.h"
	NULL,
		new_branch_info->commit = old_branch_info.commit;
		if (ce->ce_mode == old->ce_mode &&
	return git_xmerge_config(var, value, NULL);
	}
	read_mmblob(&ancestor, &threeway[0]);

	if (opts->checkout_index < 0 || opts->checkout_worktree < 0)
	if (state.bisect_in_progress)
	static char *ps_matched;
		      struct branch_info *info)
			if (ret)
			/*
#include "wt-status.h"

	 * convenient shortcut: "git restore --staged" equals
		 * Try to give more helpful suggestion.
}
	reflog_msg = getenv("GIT_REFLOG_ACTION");
	for (pos = 0; pos < active_nr; pos++) {
		}
		opts.only_merge_on_switching_branches = 1;
		 * index to avoid the next (potentially costly)
	add_cache_entry(ce, ADD_CACHE_OK_TO_ADD | ADD_CACHE_OK_TO_REPLACE);
	default:
	 * remote branches, erroring out for invalid or ambiguous cases.

			if (opts->ignore_unmerged) {
			   N_("create/reset and checkout a branch")),
				      opts->new_branch_force ? 1 : 0,
		int flag;



		 */
		unlink_entry(ce);
	int lost = 0;

			die(_("a branch is expected, got remote branch '%s'"), ref);
{
}
			fprintf_ln(stderr, Q_("Updated %d path from %s",
	 *
		if (opts->checkout_index < 0)
				errs |= checkout_entry(ce, &state,
		OPT_BOOL('m', "merge", &opts->merge, N_("perform a 3-way merge with the new branch")),
		die(_("-b, -B and --orphan are mutually exclusive"));

	opts.checkout_worktree = -2; /* default on */
		new_branch_info->name = opts->new_branch;
	discard_cache_entry(ce);
	 *   a path.
		if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK))
	if (opts->force && opts->merge)

}
	return newopts;
	if (state.revert_in_progress)
				   nr_unmerged);
	if (!parse_commit(commit))
			   struct branch_info *new_branch_info)

	remove_marked_cache_entries(&the_index, 1);
	 * entry in place. Whether it is UPTODATE or not, checkout_entry will
#include "builtin.h"

			die(_("--pathspec-from-file is incompatible with --detach"));
		die(_("cannot switch branch while merging\n"
					fprintf(stderr, _("Can not do reflog for '%s': %s\n"),
	if (!active_cache_tree)
{
	}
			      int *writeout_error)
	}
	if (old_branch_info.path)
	if ((stages & seen) != stages)
							 &old_branch_info->commit->object.oid,
			 * the two-tree unpack we already tried and failed.
	if (get_oid_mb(arg, rev)) {
			die(_("'%s' cannot be used with '%s'"), "--detach", "-t");
	if (!opts->implicit_detach &&
		/* Nothing to do. */
		OPT_BOOL('S', "staged", &opts.checkout_index,
#include "dir.h"
			if (!ce_stage(ce)) {
		return checkout_paths(opts, &new_branch_info);
	opts.accept_pathspec = 1;
	 * merge.renormalize set, too
			die(_("a branch is expected, got tag '%s'"), ref);
	options = add_checkout_path_options(&opts, options);
				errs |= check_stage(opts->writeout_stage, ce, pos, opts->overlay_mode);



	setup_new_branch_info_and_source_tree(new_branch_info, opts, rev, arg);
#include "refs.h"
	/*
{
static const char * const checkout_usage[] = {
		int n = parse_branchname_arg(argc, argv, dwim_ok,
	/*
	opts.only_merge_on_switching_branches = 1;

			if (old_branch_info->path &&


			     name);
	 *
		argv += n;
			if (!opts->merge)
	struct checkout state = CHECKOUT_INIT;
	state.istate = &the_index;
		    advise(_("If you meant to check out a remote tracking branch on, e.g. 'origin',\n"
	options = parse_options_dup(switch_options);
		return 0;
{
static int checkout_stage(int stage, const struct cache_entry *ce, int pos,
		OPT_BOOL(0, "discard-changes", &opts.discard_changes,
		 * We return 0 nevertheless, as the index is all right
			return argcount;
	dash_dash_pos = -1;
	if (print_sha1_ellipsis()) {
	free(path_to_free);
			      struct branch_info *old_branch_info,
		new_branch_info->name = "(empty)";
		if (opts->quiet)
		checkout_index = 1;
		 * is in the original index but is not in tree-ish

	 * checked out in this checkout
			}
		die(_("cannot switch branch while reverting\n"
		stage = ce_stage(ce);
		 * Either case (3) or (4), with <something> not being

		die(_("make_cache_entry failed for path '%s'"), path);
		      "Consider \"git cherry-pick --quit\" "
	for (pos = 0; pos < active_nr; pos++) {
	return argcount;
	 *       between A and B, A...B names that merge base.
	 *       switch to the branch or detach HEAD at it.  As a special case,
				      "the following files:\n%s"), sb.buf);
		if (!opts->pathspec.nr)

			die(_("unable to update HEAD"));
		return git_default_submodule_config(var, value, NULL);
	 *       in one and only one remote (or if the branch exists on the
}
	if (report_path_error(ps_matched, &opts->pathspec)) {
static void describe_one_orphan(struct strbuf *sb, struct commit *commit)
	 *   - If it's only a path, treat it like case (2).

	wt_status_get_state(the_repository, &state, 0);

	else
	if (opts->track != BRANCH_TRACK_UNSPECIFIED && !opts->new_branch) {
		die(_("'%s' cannot be used with '%s'"), "--discard-changes", "--merge");
		    opts->accept_pathspec)
			   N_("conflict style (merge or diff3)")),
		struct object_id rev;
			  int overlay_mode)
	if (pos >= 0) {
}
		}
	struct option options[] = {
	 * case 3: git checkout <something> [--]
		setup_unpack_trees_porcelain(&topts, "checkout");
	}
	 * There is absolutely no reason to write this as a blob object
	opts.switch_branch_doing_nothing_is_ok = 0;
	options = add_common_options(&opts, options);
static int checkout_main(int argc, const char **argv, const char *prefix,

			   changed ? "1" : "0", NULL);
				&new_commit->object.oid,

	int pos;
	opts.orphan_from_empty_tree = 1;
				struct strbuf err = STRBUF_INIT;
	const char *path; /* The full name of a real branch */
		Q_(
	if (opts->checkout_worktree && !opts->checkout_index && !opts->source_tree)
	struct option switch_options[] = {
		topts.merge = 1;
	opts.accept_pathspec = 1;
{
	 *
					new_branch_info->name);
			 * give up or do a real merge, depending on
		if (nr_unmerged)
				recover_with_dwim = 0;
			     const struct branch_info *info)
		 * anything to this entry at all.
	struct checkout_opts *opts, struct option *prevopts)
		OPT__FORCE(&opts->force, N_("force checkout (throw away local modifications)"),
			   N_("restore the index")),
		free(head_ref);
	}

	int status;
}
	}
}
	if (!opts->accept_pathspec) {
	old_branch_info.path = path_to_free = resolve_refdup("HEAD", 0, &rev, &flag);
	       !strcmp(active_cache[pos]->name, ce->name)) {
		die_expecting_a_branch(new_branch_info);
		return 0;
				if (!opts->quiet)

	const char *prefix;
						     opts);
		die(_("'%s' cannot be used with switching branches"),
#include "cache-tree.h"
				delete_reflog(old_branch_info->path);
	int i;
		has_dash_dash = 1; /* case (3) or (1) */
{

	const char *new_orphan_branch;

		if (argc)
	 * when it may contain conflicts).
	while (pos < active_nr &&

	}
	return status;
			die(_("git checkout: --ours/--theirs, --force and --merge are incompatible when\n"
		return error(_("index file corrupt"));
		if (!argv0 || !argv0[1])
		 * and more importantly we have made best efforts to

		      "or \"git worktree add\"."));
		/* fallthrough */
			add_files_to_cache(NULL, NULL, 0);
		fprintf(stderr,

				struct object_id *rev)
	if (!opts->switch_branch_doing_nothing_is_ok &&

	}
	if (opts->new_orphan_branch)
			!opts->patch_mode &&
			 * Without old_branch_info->commit, the below is the same as
static void suggest_reattach(struct commit *commit, struct rev_info *revs)
	read_ref_full("HEAD", 0, &rev, NULL);

		die(_("reference is not a tree: %s"), arg);
	    }
	 * case 2: git checkout -- [<paths>]
	struct lock_file lock_file = LOCK_INIT;
}
	int overwrite_ignore;
	/*

static int checkout_paths(const struct checkout_opts *opts,
	 * do the right thing.
	int dwim_new_local_branch;
			init_merge_options(&o, the_repository);
			      N_("checkout our version for unmerged files"),
		old_branch_info.path = NULL;
				errs |= checkout_merged(pos, &state,
			    PARSE_OPT_OPTARG, option_parse_recurse_submodules_worktree_updater },
		OPT_BOOL(0, "ignore-skip-worktree-bits", &opts->ignore_skipworktree,
	}

			die(_("--track needs a branch name"));
	while (pos < active_nr) {


			if (ret < 0)


			die(_("invalid path specification"));
		free(ps_matched);
		new_branch_info->name = "HEAD";
	return errs;
}
	opts->overwrite_ignore = 1;
		OPT_STRING(0, "orphan", &opts->new_orphan_branch, N_("new-branch"), N_("new unparented branch")),
			mode = create_ce_mode(ce->ce_mode);
				*new_branch = arg;
	if (opts->checkout_index >= 0 || opts->checkout_worktree >= 0) {

	 * NEEDSWORK: re-create conflicts from merges with
					      NULL, nr_checkouts);
	const char *arg)

		else
{
static int git_checkout_config(const char *var, const char *value, void *cb)
	FREE_AND_NULL(options);
		    "--detach", "-b/-B/--orphan");
			    advice_detached_head && !opts->force_detach)
	return switch_branches(opts, new_branch_info);
		}

	struct diff_options diff_options;
	int ret = 0;

	return status;
				      opts->new_branch, new_branch_info->name,
{
		OPT_STRING(0, "conflict", &opts->conflict_style, N_("style"),
	mmfile_t ancestor, ours, theirs;
	add_pending_object(&revs, object, oid_to_hex(&object->oid));
			     "\n"
	if (opts->new_branch) {
			die(_("--pathspec-from-file is incompatible with pathspec arguments"));
static int post_checkout_hook(struct commit *old_commit, struct commit *new_commit,
			 * Unpack couldn't do a trivial merge; either
	struct option restore_options[] = {
		OPT_END()
	/* Clean up objects used, as they will be reused. */
		if (opts->accept_pathspec && !opts->empty_pathspec_ok &&


	int branch_exists;
		else
	}
	int argcount = 0;
	    !opts->force_detach &&
	read_mmblob(&theirs, &threeway[2]);
#include "submodule-config.h"
		active_cache_tree = cache_tree();
			} else {
	FREE_AND_NULL(options);
	};
	if (opts->merge && opts->patch_mode)
		OPT_BOOL('W', "worktree", &opts.checkout_worktree,
				      opts->new_branch_log,
	if (opts->force) {
	if (argc && opts->accept_ref) {
		fprintf(stderr, "%s %s %s\n", msg,
		checkout_index = opts->checkout_index;


		topts.fn = twoway_merge;
	memcpy(ce->name + base->len, pathname, len - base->len);
			o.branch1 = new_branch_info->name;
		"any of your branches:\n\n"
		    opts->ignore_unmerged_opt, "-m");
		else if (!opts->checkout_index && opts->checkout_worktree)
		/* not a commit */
		      "or \"git worktree add\"."));
		/*
		old_desc = oid_to_hex(&old_branch_info->commit->object.oid);
	if (argc == 3 && !strcmp(argv[1], "-b")) {
		strbuf_insertstr(&msg, 0, reflog_msg);

			opts->show_progress = isatty(2);
	 * to be checked out.
	if (new_branch_info->name && !new_branch_info->commit)
					      "Updated %d paths from %s",
	if (opts->overlay_mode != -1)
	if (!overlay_mode)

		die(_("You are on a branch yet to be born"));
static int switch_unborn_to_new_branch(const struct checkout_opts *opts)
static void die_if_some_operation_in_progress(void)
	 *

{
			find_unique_abbrev(&commit->object.oid, DEFAULT_ABBREV));
			ret = reset_tree(new_tree,
			die(_("could not resolve %s"), opts->from_treeish);
	/* update the index with the given tree's info
	if (new_commit)

	};
	opts.checkout_worktree = -2; /* default on */
		OPT_END()
				return ret;
		if (argc > 1)
	if (dwim_ref(branch_info->name, strlen(branch_info->name), &oid, &to_free) == 1) {
		OPT_BOOL(0, "overlay", &opts.overlay_mode, N_("use overlay mode (default)")),
			pos = skip_same_name(ce, pos) - 1;
	if (!remote && num_matches > 1) {
		if (create_symref("HEAD", new_branch_info->path, msg.buf) < 0)
	 * CE_MATCHED to it from update_some(). But we still
					      "Recreated %d merge conflicts",

		die(_("--pathspec-file-nul requires --pathspec-from-file"));
	 *
		if (opts->checkout_worktree < 0)
		struct tree_desc trees[2];

	ce = make_empty_cache_entry(&the_index, len);
			   N_("update ignored files (default)"),
	if (!opts->new_branch)
	struct wt_status_state state;
			}
				    0,
	struct cache_entry *ce = active_cache[pos];
			describe_one_orphan(&sb, c);
			strbuf_release(&o.obuf);

	}
		return;
	if (opts->new_orphan_branch && opts->orphan_from_empty_tree) {
			      int changed)
	if (!opts->source_tree)                   /* case (1): want a tree */
	}
	} else {
			   REF_NO_DEREF, UPDATE_REFS_DIE_ON_ERR);
			 * a pain; plumb in an option to set
 * HEAD.  If it is not reachable from any ref, this is the last chance
		die(_("'%s' must be used when '%s' is not specified"),
				       struct object_id *rev,
	int parseopt_flags = 0;
	return remote;
	if (!strcmp(arg, "-"))
	}
{
		argv++;
	 *       short-hand to fork local <something> from that

			struct strbuf old_commit_shortname = STRBUF_INIT;
		 */

	/* Any unmerged paths? */
				   nr_checkouts,
		"Warning: you are leaving %d commit behind, "
		struct object_id rev;
	new_branch_info->commit = lookup_commit_reference_gently(the_repository, rev, 1);
	struct cache_entry *ce;
	 * expression.  Failure here is okay.
	} else if (opts->pathspec_file_nul) {

		if (ce->ce_flags & CE_MATCHED) {

		struct checkout_opts *opts = cb;
				return 1;

		pos++;
	memset(&state, 0, sizeof(state));
	NULL,
	struct option *newopts = parse_options_concat(prevopts, options);
#include "ll-merge.h"
	strbuf_add_unique_abbrev(sb, &commit->object.oid, DEFAULT_ABBREV);
	int pos;
			o.branch2 = "local";
	struct branch_info *new_branch_info,
	parse_tree(tree);
	const char *ignore_unmerged_opt;
						       &state,
		if (new_branch_info->commit)
	if (!opts->quiet)

	case 0:
		if (!opts->quiet) {
			break;
 * for the user to do so without resorting to reflog.
		return error(_("path '%s' does not have their version"), ce->name);
static int checkout_merged(int pos, const struct checkout *state, int *nr_checkouts)
	int ret;
	 * This case should never happen because we already die() on
		if (opts->new_branch && argc == 1)

	int accept_ref;
	if (dash_dash_pos == 0)
	    die(_("'%s' matched multiple (%d) remote tracking branches"),
	 *   (b) If <something> is _not_ a commit, either "--" is present
	} else {
	if (!opts->quiet && !old_branch_info.path && old_branch_info.commit && new_branch_info->commit != old_branch_info.commit)
}
	int ignore_other_worktrees;
			free(refname);
		return checkout_branch(opts, &new_branch_info);
	return run_hook_le(NULL, "post-checkout",

	 * cache entry.  The code in write_entry() needs to be refactored
	 *
	if (opts->checkout_worktree)
	if (!parse_commit(commit))
		OPT_END()
		    "--ours/--theirs");
	int ignore_skipworktree;
		const char *ref = to_free;
	 * case 1: git checkout <ref> -- [<paths>]
						      opts->from_treeish);
			 * when branches have different end-of-line
	if (opts->patch_mode || opts->pathspec.nr)
		handle_ignore_submodules_arg(&opts->diff_options, value);
	struct commit *c, *last = NULL;
		int more = lost - ORPHAN_CUTOFF;
	struct tree_desc tree_desc;

	if (opts->new_branch_force)
		if (!opts->source_tree)
		fprintf(stderr, _("Switched to a new branch '%s'\n"),
	struct option options[] = {
	 * including "last branch" syntax and DWIM-ery for names of
		repo_get_oid_committish(the_repository, branch->name, &branch->oid);
		OPT_BOOL('p', "patch", &opts->patch_mode, N_("select hunks interactively")),
	trace2_cmd_mode(opts->patch_mode ? "patch" : "path");
				o.ancestor = old_commit_shortname.buf;
	if (opts->ignore_unmerged && opts->patch_mode)
			die(_("'%s' cannot take <start-point>"), "--orphan");
	if ((!!opts->new_branch + !!opts->new_branch_force + !!opts->new_orphan_branch) > 1)
			do_merge = 0;
	init_tree_desc(&tree_desc, tree->buffer, tree->size);
	ce->ce_namelen = len;
				/* DWIMmed to create local branch, case (3).(b) */
	       !strcmp(active_cache[pos]->name, ce->name))

		clear_unpack_trees_porcelain(&topts);
		}
	int ret;
	init_checkout_metadata(&state.meta, info->refname,
		BUG("make up your mind, you need to take _something_");
	opts.can_switch_when_in_progress = 1;
		 * should save stat info of checked out files in the
		opts->discard_changes = 1;
			      2, PARSE_OPT_NONEG),
			die(_("'%s' is not a commit and a branch '%s' cannot be created from it"),
		argv0 = strchr(argv0, '/');
		/* Give ngettext() the count */
		report_tracking(new_branch_info);
					fprintf(stderr, _("Reset branch '%s'\n"),
	}
	if (!opts->ignore_skipworktree && ce_skip_worktree(ce))
		 */
		{ OPTION_CALLBACK, 0, "recurse-submodules", NULL,
	}
	if (opts->pathspec.nr)
	 * if not null the branch is detached because it's already
static void setup_branch_path(struct branch_info *branch)
		      "Consider \"git am --quit\" "
			old_tree = get_commit_tree(old_branch_info->commit);
	const char *pathspec_from_file;

	opts.dwim_new_local_branch = 1;

				UNINTERESTING);

				    prefix, opts->pathspec_from_file, opts->pathspec_file_nul);
		opts->new_branch = argv0 + 1;
	if (read_cache_preload(&opts->pathspec) < 0)
		OPT_STRING('B', NULL, &opts.new_branch_force, N_("branch"),
			if (!ref_exists(old_branch_info->path) && reflog_exists(old_branch_info->path))
	int errs = 0;
			refname = mkpathdup("refs/heads/%s", opts->new_orphan_branch);
{
static const char * const restore_usage[] = {

	while (pos < active_nr) {

};
		OPT_BOOL(0, "ignore-unmerged", &opts.ignore_unmerged,
		 * them.
			 */
		*source_tree = parse_tree_indirect(rev);
	 *
#include "revision.h"
static int skip_same_name(const struct cache_entry *ce, int pos)
		 */
		if (opts->source_tree && !(ce->ce_flags & CE_UPDATE))


	if (opts->pathspec_from_file) {
		 * checked out to the working tree.  We will not do
		topts.src_index = &the_index;
		return error(_("path '%s' does not have our version"), ce->name);
		 * User ran 'git checkout -b <branch>' and expects

	int merge;
			o.verbosity = 0;
	opts.merge = 1;
		 * and "git switch foo" as candidates for dwim.
	strbuf_splice(&buf, 0, 0, "refs/heads/", 11);
		 */
	else
					  new_tree,
		OPT_STRING('C', "force-create", &opts.new_branch_force, N_("branch"),

	}
	}
		ce = active_cache[pos];
		opts->track = git_branch_track;
	ce = make_transient_cache_entry(mode, &oid, path, 2);
	if (new_branch_info->path && !opts->force_detach && !opts->new_branch &&
	free(ours.ptr);
			mark_ce_for_checkout_no_overlay(active_cache[pos],
	struct object *object = &old_commit->object;
	} else if (!opts->accept_ref && opts->from_treeish) {
	int accept_pathspec;
	options = parse_options_dup(restore_options);
				validate_new_branchname(opts->new_branch, &buf, 0);
	if (prepare_revision_walk(&revs))
		read_tree_some(opts->source_tree, &opts->pathspec);
			 N_("do not check if another worktree is holding the given ref")),
			 * branch, leaving the working tree as the
	if (ce_path_match(&the_index, ce, &opts->pathspec, ps_matched)) {
#include "commit.h"
	if (!new_branch_info->name) {
	if (!format_tracking_info(branch, &sb, AHEAD_BEHIND_FULL))
	}
		"%s\n",
	ce->ce_flags &= ~CE_MATCHED;
			 * tree from the index, then merge the new
			/* The plural version */
	if (opts->source_tree)
	if (state.merge_in_progress)
{
		skip_prefix(argv0, "refs/", &argv0);

	 *       - else: fail.
	/* --track without -b/-B/--orphan should DWIM */
			 * entries in the index.
}
		      "or \"git worktree add\"."));
			create_branch(the_repository,
				struct branch_info *new_branch_info,
	struct strbuf sb = STRBUF_INIT;
	if (opts->conflict_style) {
			    pathspec, update_some, NULL);
		ret = reset_tree(new_tree, opts, 1, writeout_error, new_branch_info);
				ret = safe_create_reflog(refname, 1, &err);
		skip_prefix(old_branch_info.path, "refs/heads/", &old_branch_info.name);
 */
					 opts, 0,
		 * the same behavior as 'git switch -c <branch>'.
	struct pathspec pathspec;
		      "Consider \"git revert --quit\" "
#include "parse-options.h"
	 * opts->source_tree != NULL.

	return 0;
	int only_merge_on_switching_branches;
	 * Handle
	else
	}
			struct tree *old_tree;
		die(_("a branch is expected, got commit '%s'"), branch_info->name);
static void show_local_changes(struct object *head,
	 */
	if (opts->overlay_mode == 1 && opts->patch_mode)
							 DEFAULT_ABBREV);
		else
		return error(_("path '%s': cannot merge"), path);

{
		      "Consider \"git merge --quit\" "
	if (starts_with(var, "submodule."))
	    if (advice_checkout_ambiguous_remote_branch_name) {
		arg = "@{-1}";
	 * case 4: git checkout <something> <paths>
		OPT_BOOL('d', "detach", &opts->force_detach, N_("detach HEAD at named commit")),
	while (++pos < active_nr &&
			}

	int checkout_index;
	memset(threeway, 0, sizeof(threeway));
		if (opts->pathspec.nr)
		git_xmerge_config("merge.conflictstyle", opts->conflict_style, NULL);
}
		die(_("Cannot update paths and switch to branch '%s' at the same time."),

	if (errs)
	 * This is to save new stat info.
		    oideq(&ce->oid, &old->oid)) {
	struct strbuf sb = STRBUF_INIT;
		struct strbuf buf = STRBUF_INIT;
			opts->checkout_worktree = 0;
		OPT_BOOL(0, "progress", &opts->show_progress, N_("force progress reporting")),

	if (do_merge) {

	struct unpack_trees_options opts;
	char *conflict_style;
	};
	 *   - else: fail.
		remove_marked_cache_entries(&the_index, 1);

		lost++;
	struct strbuf buf = STRBUF_INIT;
		      "Consider \"git rebase --quit\" "
			 N_("second guess 'git switch <no-such-branch>'")),
			" git branch <new-branch-name> %s\n\n",
			} else if (opts->new_branch) {
	diff_setup_done(&rev.diffopt);
		int dwim_ok =

}
#include "branch.h"
{
	/*
	errs |= post_checkout_hook(head, head, 0);
}
		int flag;
	strbuf_addch(sb, ' ');
	if (!overlay_mode) {
	options = add_common_options(&opts, options);
	 */
	mmbuffer_t result_buf;
	    !opts->ignore_other_worktrees) {
			 */
	struct branch_info new_branch_info;
	else

		ce = active_cache[pos];
}
		 * it would be extremely annoying.
	if (!new_branch_info->commit && opts->new_branch) {
		ret = merge_working_tree(opts, &old_branch_info, new_branch_info, &writeout_error);
				       &new_branch_info->oid, NULL);

	}
	 * Allow updating the index when checking out from the index.
				continue;
static void describe_detached_head(const char *msg, struct commit *commit)
		 * or does not match the pathspec; it will not be
			opts->checkout_worktree = -opts->checkout_worktree - 1;

	}
	if (opts->writeout_stage)
		die(_("'%s' cannot be used with '%s'"), "-f", "-m");
	struct object_id branch_rev;
		    opts->new_branch);
			die(_("'%s' cannot be used with '%s'"), "--orphan", "-t");
		if (ret == -1) {
	if (!(old_commit->object.flags & UNINTERESTING))
			 * branch as the base. Then we reset the index
	struct tree *new_tree;
		parse_commit_or_die(new_branch_info->commit);
static int check_stage(int stage, const struct cache_entry *ce, int pos,
	int errs = 0;
	} else if (opts->force_detach || !new_branch_info->path) {	/* No longer on any branch. */
		if (stage == 2)
		has_dash_dash = 1; /* helps disambiguate */
			    !should_autocreate_reflog(refname)) {
	status = create_symref("HEAD", branch_ref.buf, "checkout -b");
		old_branch_info.commit = lookup_commit_reference_gently(the_repository, &rev, 1);
}
				if (opts->branch_exists)
	/*
		topts.dst_index = &the_index;

struct branch_info {

		opts.switch_branch_doing_nothing_is_ok = 0;
	int switch_branch_doing_nothing_is_ok;
}
		if (opts->force_detach)
		if (recover_with_dwim) {


static int update_some(const struct object_id *oid, struct strbuf *base,
	/*
	N_("git restore [<options>] [--source=<branch>] <file>..."),
			if (opts->writeout_stage)
			   N_("create and checkout a new branch")),
		return error(_("path '%s' does not have our version"), ce->name);
	opts.accept_ref = 1;
		 */

			die(_("missing branch name; try -b"));
			topts.dir->flags |= DIR_SHOW_IGNORED;
	if (opts->checkout_index && !opts->checkout_worktree &&
	 *   everything after the '--' must be paths.

	struct tree *source_tree;
		OPT_BOOL(0, "guess", &opts.dwim_new_local_branch,
	UNLEAK(opts);
	trace2_cmd_mode("branch");

	fprintf(stderr,
	return 0;
		 * new_branch && argc > 1 will be caught later.
	const char *new_branch;
	};
		"not connected to\n"
	opts.overlay_mode = -1;
			 * o.renormalize?
	options = add_common_options(&opts, options);
	return ret || writeout_error;
	if (!opts->from_treeish && opts->checkout_index && !opts->checkout_worktree)
			 struct checkout_opts *opts, struct option *options,
	 */
			lost),
			} else if (opts->writeout_stage) {

		    (!(flag & REF_ISSYMREF) || strcmp(head_ref, new_branch_info->path)))
		if (opts->patch_mode)
	update_refs_for_switch(opts, &old_branch_info, new_branch_info);
	 * Extract branch name from command line arguments, so
			       is_null_oid(&info->oid) ? &tree->object.oid :
		rollback_lock_file(&lock_file);
static struct option *add_common_switch_branch_options(
		OPT_STRING('s', "source", &opts.from_treeish, "<tree-ish>",
}
	struct lock_file lock_file = LOCK_INIT;
		const struct cache_entry *ce = active_cache[pos];
	 * need ps_matched and read_tree_recursive (and
		 * we should auto-create the branch, case (3).(b).
	struct option *newopts = parse_options_concat(prevopts, options);
							&nr_unmerged);
		die(_("'%s' cannot be used with '%s'"),
				struct checkout_opts *opts,
	pos = cache_name_pos(ce->name, ce->ce_namelen);

			 * merged version, but skipping unmerged
static int checkout_worktree(const struct checkout_opts *opts,
	errs |= finish_delayed_checkout(&state, &nr_checkouts);
			 * branch with the current tree, with the old
				detach_advice(new_branch_info->name);
			break;
	new_branch_info->name = arg;

		die(_("'%s' cannot be used with updating paths"), "--detach");
};
	};

	 * eventually tree_entry_interesting) cannot fill
		parse_pathspec(&opts->pathspec, 0,
		sb.buf);

		OPT_STRING('b', NULL, &opts.new_branch, N_("branch"),
			mark_ce_for_checkout_overlay(active_cache[pos],
	if (read_cache_preload(NULL) < 0)
	int patch_mode;
		strbuf_release(&buf);
	int discard_changes;
			die(_("reference is not a tree: %s"), opts->from_treeish);
	int ret;
	case -2:
		    new_branch_info->name);

	struct option *options = NULL;
		if (opts->overwrite_ignore) {
					 writeout_error, new_branch_info);
	struct option options[] = {
		die(_("cannot switch branch in the middle of an am session\n"
		die(_("'%s' or '%s' cannot be used with %s"),

			if (repo_index_has_changes(the_repository, old_tree, &sb))
	 */
		unmerge_marked_index(&the_index);
					 int flags, void *cb_data)
	ce->ce_flags &= ~CE_MATCHED;
		OPT_SET_INT_F('2', "ours", &opts->writeout_stage,
	if (state.am_in_progress)
}

	/*
		       int overlay_mode)
				if (ret) {
		*writeout_error = 1;
		return 0;
	if (opts->ignore_unmerged && opts->merge)
		die(_("'%s' could be both a local file and a tracking branch.\n"
		int recover_with_dwim = dwim_new_local_branch_ok;

	struct commit *head;
		new_tree = get_commit_tree(new_branch_info->commit);
		if (!(argc == 1 && !has_dash_dash) &&
	} else if (opts->track == BRANCH_TRACK_UNSPECIFIED)
	    new_branch_info->name &&

	if (argc) {
	if (status < 0 || !result_buf.ptr) {
	char *checkout;

		if (skip_prefix(ref, "refs/tags/", &ref))
		}
	if (!(flag & REF_ISSYMREF))
			/*
	}
	if (S_ISDIR(mode))

	const char *arg;
	if (!opts->ignore_skipworktree && ce_skip_worktree(ce))
	options = parse_options_dup(checkout_options);
			}
	int pos;
	 * to allow us to feed a <buffer, size, mode> instead of a cache
		    "--worktree", "--source");


		argcount++;
		/* The singular version */

{
	memset(&opts, 0, sizeof(opts));
			 * (but not the working tree) to the new
	if (!opts->quiet &&
				   struct branch_info *new_branch_info)
		return error(_("index file corrupt"));
						new_branch_info->name);
	}
int cmd_restore(int argc, const char **argv, const char *prefix)
	else
			   oid_to_hex(new_commit ? &new_commit->object.oid : &null_oid),
			fprintf_ln(stderr, Q_("Updated %d path from the index",

			   N_("create/reset and switch to a branch")),
	if (opts->count_checkout_paths) {
	const char *from_treeish;
	}
}
				strbuf_add_unique_abbrev(&old_commit_shortname,
			   PARSE_OPT_NOCOMPLETE),
	const char **new_branch = &opts->new_branch;
	int status;
	if (!dwim_ref(branch->name, strlen(branch->name), &branch->oid, &branch->refname))
	 * and new_branch_force and new_orphan_branch will tell us which one of

#include "object-store.h"
}
{
			die(_("git checkout: --detach does not take a path argument '%s'"),
	 * entry.  Such a refactoring would help merge_recursive as well
		OPT_BOOL(0, "ignore-other-worktrees", &opts->ignore_other_worktrees,

		}
			       info->commit ? &info->commit->object.oid :
	else
				   struct branch_info *old_branch_info,
		topts.quiet = opts->merge && old_branch_info->commit;

	arg = argv[0];
#include "blob.h"
			!opts->new_branch;
	 *       remote named in checkout.defaultRemote), then this is a
	struct option *options;
		parseopt_flags = PARSE_OPT_KEEP_DASHDASH;
					 char *ps_matched,
				   find_unique_abbrev(&opts->source_tree->object.oid,
	if (opts->checkout_index && !opts->checkout_worktree &&
				return ret;
	opts.switch_branch_doing_nothing_is_ok = 1;
			opts->branch_exists =
	ret = checkout_main(argc, argv, prefix, &opts,

		    !ce_intent_to_add(old) &&
			       const struct diff_options *opts)
	}
		/*
		parse_pathspec_file(&opts->pathspec, 0,
			find_unique_abbrev(&commit->object.oid, DEFAULT_ABBREV), sb.buf);
			     "    git checkout --track origin/<name>\n"
{
	rev.diffopt.output_format |= DIFF_FORMAT_NAME_STATUS;
			   N_("restore the working tree (default)")),
			 * NEEDSWORK: carrying over local changes
		}
			 * In overlay mode, but the path is not in
			break;
			/* Give ngettext() the count */
		new_branch_info->commit = NULL;
				       &new_branch_info->commit->object.oid :
		    "--patch");
	};
	 *       - else if it's a path, treat it like case (2)
		return 1; /* case (2) */
{
	opts.skip_unmerged = !worktree;
	if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK))
					free(refname);

	 * checking the paths out of, or we are checking out
					      nr_unmerged),

	if (opts->patch_mode) {
		 */
			BUG("'switch --orphan' should never accept a commit as starting point");
	if (opts->force_detach)
		 * It's likely an error, but we need to find out if
	const char *name; /* The short name used */

			"this may be a good time\nto do so with:\n\n"

		die(_("'%s' cannot be used with updating paths"), "--track");
			opts->branch_exists = validate_branchname(opts->new_branch, &buf);
	 *  3) git checkout <something> [<paths>]
					      nr_checkouts),
	free(prevopts);
	 *
{
	 * of the index.
						new_branch_info->name);
		seen |= (1 << ce_stage(ce));
	struct checkout_opts opts;
	memset(&opts, 0, sizeof(opts));
	if (!cache_tree_fully_valid(active_cache_tree))
				die(_("cannot continue with staged changes in "
			const char *remote = parse_remote_branch(arg, rev,

	struct commit *commit; /* The named commit */
		      int worktree, int *writeout_error,
	return ret;
	struct option checkout_options[] = {
	if (stage == 2)
	/*
#include "run-command.h"
		if (opts->track != BRANCH_TRACK_UNSPECIFIED)
	free(result_buf.ptr);
	status = checkout_entry(ce, state, NULL, nr_checkouts);
	/* I think we want full paths, even if we're in a subdirectory. */
		topts.initial_checkout = is_cache_unborn();
	if (opts->show_progress < 0) {
	strbuf_release(&sb);
			strbuf_release(&old_commit_shortname);
		die(_("'%s' or '%s' cannot be used with %s"),
	int ignore_unmerged;
		tree = new_tree;

	if (!strcmp(var, "diff.ignoresubmodules")) {
	    opts->merge)
	run_diff_index(&rev, 0);
		if (old_branch_info->path && old_branch_info->name) {
			}
	opts.verbose_update = o->show_progress;
				      opts->quiet,
			if (remote) {
		init_tree_desc(&trees[1], tree->buffer, tree->size);
	int pathspec_file_nul;
{
			" git branch <new-branch-name> %s\n\n",
	}


			  const struct branch_info *new_branch_info)
		warning(_("you are switching branch while bisecting"));
		strbuf_addf(&msg, "checkout: moving from %s to %s",
	struct checkout_opts opts;
		lost,
{
	else
		int stage;
		 * update paths in the work tree, and we cannot revert
			fprintf_ln(stderr, Q_("Recreated %d merge conflict",
		      "or \"git worktree add\"."));
	 *   - If it's *only* a reference, treat it like case (1).

	}


		OPT__QUIET(&opts->quiet, N_("suppress progress reporting")),
		if (ce_stage(active_cache[pos]) == stage)
			    "checkout", "control recursive updating of submodules",
		 * invalid ref.
			} else if (opts->merge) {

	ret = post_checkout_hook(old_branch_info.commit, new_branch_info->commit, 1);
	opts->track = BRANCH_TRACK_UNSPECIFIED;
	if (!old_desc && old_branch_info->commit)
			return checkout_entry(active_cache[pos], state,
}
	object->flags &= ~UNINTERESTING;
		OPT_END()
	}
		/* The plural version */
}
	read_tree_recursive(the_repository, tree, "", 0, 0,
	opts.overlay_mode = -1;
		if (head_ref &&
{
	} else if (opts->force_detach) {
		ret = unpack_trees(2, trees, &topts);
			 const char * const usagestr[])
				   nr_checkouts);
		/*
		if (!argc || !strcmp(argv0, "--"))
			verify_non_filename(opts->prefix, arg);

	add_pending_object(&rev, head, NULL);
	if (opts->pathspec.nr) {
	if (opts->new_branch) {
		OPT_SET_INT('t', "track",  &opts->track, N_("set upstream info for new branch"),
			/* The singular version */
	enable_delayed_checkout(&state);
		die(_("'%s' cannot be used with updating paths"), "-l");
	return ret;
		pos++;
	 */
	if (is_null_oid(&threeway[1]) || is_null_oid(&threeway[2]))
		/*
					fprintf(stderr, _("Switched to and reset branch '%s'\n"), new_branch_info->name);

	/* "new_commit" can be NULL when checking out from the index before
		die(_("missing branch or commit argument"));
		describe_detached_head(_("Previous HEAD position was"), old_commit);
	argv++;
			     "\n"
		if (opts->orphan_from_empty_tree && new_branch_info->name)
	 */
	struct rev_info revs;
	strbuf_release(&sb);
		if (opts->checkout_index && opts->checkout_worktree)
	    !opts->new_branch_force &&

	remove_branch_state(the_repository, !opts->quiet);
	if (branch_info->commit)
	 *
				argv[0], opts->new_branch);
	 *  1) git checkout <tree> -- [<paths>]
		struct cache_entry *ce = active_cache[pos];
	opts->show_progress = -1;
		setup_new_branch_info_and_source_tree(&new_branch_info,
static int parse_branchname_arg(int argc, const char **argv,
		if (ret)
	if (!argc)
		OPT_END()
	opts.reset = 1;
					     &new_branch_info, opts, &rev);
			recover_with_dwim = 0;
			if (ret)
	 * and create a phony cache entry.  This hack is primarily to get
			}

					  work,
		if (1 < !!opts->writeout_stage + !!opts->force + !!opts->merge)
	switch (unpack_trees(1, &tree_desc, &opts)) {

		topts.head_idx = -1;
	 */
		OPT_BOOL(0, "guess", &opts.dwim_new_local_branch,
	if (!check_refname_format(new_branch_info->path, 0) &&
	} else
		return;
					   &old_branch_info->commit->object.oid :
	opts.orphan_from_empty_tree = 0;
		OPT_BOOL(0, "overlay", &opts.overlay_mode, N_("use overlay mode")),
		BUG("these flags should be non-negative by now");

			opts->dwim_new_local_branch &&
		if (!has_dash_dash && !no_wildcard(arg))
	if (checkout_index) {
	opts->count_checkout_paths = !opts->quiet && !has_dash_dash;
	} else if (new_branch_info->path) {	/* Switch branches. */
			/*

}

		die(_("'%s' cannot be used with %s"), "--merge", "--patch");
			   struct branch_info *new_branch_info)

	opts->prefix = prefix;
			     "you can do so by fully qualifying the name with the --track option:\n"
		new_branch_info->path = NULL; /* not an existing branch */
	 * with any non-zero return code.
	 * If the entry is the same as the current index, we can leave the old
					 const struct checkout_opts *opts)

