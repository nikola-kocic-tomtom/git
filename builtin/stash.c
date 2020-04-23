
	argv_array_push(&cp.args, "reset");
	}
			fprintf_ln(stderr, _("Cannot save the current status"));
		return -1;

			 struct strbuf *untracked_files)
};
}
	   "          [-u|--include-untracked] [-a|--all] [-m|--message <message>]\n"
		o.branch1 = "Version stash was based on";
static void add_pathspecs(struct argv_array *args,

	head_short_sha1 = find_unique_abbrev(&head_commit->object.oid,
	old_repo_index_file = the_repository->index_file;
		ret = -1;
	 */
					 "--quiet", "-d", NULL);

		printf_ln(_("Saved working directory and index state %s"),
	}


	argc = parse_options(argc, argv, prefix, options,
			 N_("include untracked files in stash")),

 * > 0 if there are untracked files
	}
	struct object_id b_tree;
	struct child_process cp = CHILD_PROCESS_INIT;
			 N_("stash in patch mode")),
	set_alternate_index_output(NULL);

			if (!quiet)
	argc = parse_options(argc, argv, prefix, options, git_stash_usage,
			ce_path_match(&the_index, active_cache[i], ps,
				fprintf_ln(stderr, _("Cannot remove "
				goto done;
	}
	diff_tree_oid(&info.b_commit, &info.w_commit, "", &rev.diffopt);
		ret = -1;
	switch (ret) {
	rev.diffopt.flags.recursive = 1;

			if (run_command(&cp)) {
		goto done;
	int is_stash_ref;
		OPT_BOOL('k', "keep-index", &keep_index,


	struct object_id u_tree;

	} else if (pathspec_file_nul) {
	for (i = 0; i < ps->nr; i++)
			     PARSE_OPT_STOP_AT_NON_OPTION);
		OPT_END()
	if (!stash_msg)
				ret = -1;
	N_("git stash list [<options>]"),
}
			}
		ret = -1;
		goto done;
		if (ret < 0) {
			printf_ln(_("No local changes to save"));
		fprintf_ln(stderr, _("No branch name specified"));
			if (run_command(&cp)) {
		ret = -1;
	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);
	   "          [-u|--include-untracked] [-a|--all] [-m|--message <message>]\n"
#include "exec-cmd.h"
	if (!ref_exists(ref_stash))
	free_stash_info(&info);
			ret = -1;
			struct child_process cp = CHILD_PROCESS_INIT;
	struct option options[] = {
	}

	return ret;
 * The return value is:
			fprintf_ln(stderr, _("\"git stash store\" requires one "
 */
	   "          [--pathspec-from-file=<file> [--pathspec-file-nul]]\n"

	struct object_id obj;
			return -1;
	assert_stash_ref(&info);
{
	}
			       "unimplemented"));
	int ret = 0;
		}

	};
			     include_untracked);
	the_repository->index_file = old_repo_index_file;
	argv_array_push(&cp.args, "read-tree");
	struct stash_info info;
	} else {

	if (stash_msg)
static int save_stash(int argc, const char **argv, const char *prefix)
	result = run_diff_files(&rev, 0);
	strbuf_addf(&msg, "%s: %s ", branch_name, head_short_sha1);
			strbuf_addf(&refs_msg, " '%s'", argv[i]);
		return -1;

		strbuf_addstr(&info->revision, commit);
	if (pipe_command(&cp_upd_index, diff_output.buf, diff_output.len,


			     git_stash_branch_usage, 0);
		ret = do_drop_stash(&info, quiet);

				      ps_matched);
	}
	int flags = 0;

						     "worktree changes"));
	if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK))

	int pathspec_file_nul = 0;
			argv_array_pushl(&cp.args, "checkout", "--no-overlay",
			   N_("stash message")),
		} else {
	N_("git stash save [-p|--patch] [-k|--[no-]keep-index] [-q|--quiet]\n"
 */
			  stash_msg_buf.buf);
	argv_array_push(&cp.args, oid_to_hex(u_tree));
	const char *index_file;
static void assert_stash_ref(struct stash_info *info)
	if (run_command(&cp_read_tree)) {
	if (write_index_as_tree(&info->u_tree, &istate, stash_index_path.buf, 0,
	argc = parse_options(argc, argv, prefix, options,

	struct child_process cp = CHILD_PROCESS_INIT;
		ret = -1;
}
	if (!ret)
 * < 0 if there was an error
	struct pathspec ps;

	if (read_cache_preload(&rev.diffopt.pathspec) < 0) {


 */
};

		free_stash_info(&info);
	struct object_id dummy;
	struct argv_array args = ARGV_ARRAY_INIT;
				goto done;
	struct object_id u_commit;
		if (pipe_command(&cp, patch.buf, patch.len, NULL, 0, NULL, 0)) {
	if (argc > 1) {
	read_cache_preload(NULL);
static int do_clear_stash(void)
	const char *pathspec_from_file = NULL;
	}
	/* do_clear_stash if we just dropped the last stash entry */
	old_index_env = xstrdup_or_null(getenv(INDEX_ENVIRONMENT));

	int found = 0;
			 N_("stash in patch mode")),
	if (!quiet)
	struct child_process cp_reflog = CHILD_PROCESS_INIT;

		ret = -1;
		discard_cache();
	if (refresh_cache(REFRESH_QUIET))
			cp.git_cmd = 1;
		}
 * w_commit is set to the commit containing the working tree
static const char * const git_stash_clear_usage[] = {
			goto done;
	object_array_clear(&rev.pending);

	const char *commit = NULL;
}
	struct index_state istate = { NULL };
	struct commit_list *parents = NULL;
		argv_array_push(&cp.args, "status");
			ret = -1;
	init_revisions(&rev, prefix);
}
	rev.diffopt.output_format = DIFF_FORMAT_CALLBACK;
	struct tree *tree;
	if (untracked_commit_option)
	argc = parse_options(argc, argv, prefix, options,
	argv_array_pushl(&cp_reflog.args, "reflog", "delete", "--updateref",
{
	else if (!strcmp(argv[0], "drop"))
		int i;
		OPT__QUIET(&quiet, N_("quiet mode")),
	char *end_of_rev;
	ret = do_apply_stash(prefix, &info, index, quiet);
		break;
static const char * const git_stash_pop_usage[] = {
				argv_array_push(&cp_add.args, "--force");
		ret = do_apply_stash(prefix, &info, 1, 0);
	if (get_oid_with_context(the_repository,
				ret = -1;
}
#include "diffcore.h"
			if (!ps->nr)
				      &result);
	cp_upd_index.git_cmd = 1;

	 */
#include "unpack-trees.h"
	/* State of the working tree. */
	if (!strcmp(var, "stash.showpatch")) {
	struct option options[] = {
	if (reset_tree(&info->i_tree, 0, 0)) {
	if (pathspec_from_file) {
	branch_ref = resolve_ref_unsafe("HEAD", 0, NULL, &flags);
				fprintf_ln(stderr, _("Cannot save "
		OPT_END()
};
	}
#include "refs.h"
	prepare_fallback_ident("git stash", "git@stash");

		strbuf_insertf(stash_msg_buf, 0, "On %s: ", branch_name);

	bases[0] = &info->b_tree;
				  oid_to_hex(&info->w_commit));
	free_stash_info(&info);
	struct child_process cp = CHILD_PROCESS_INIT;
	 * API for resetting.
	NULL
	else

		if (ps->nr) {
}
	N_("git stash show [<options>] [<stash>]"),
 * It will return 1 if there were any changes and 0 if there were not.
	argv_array_pushv(&cp.args, argv);
		OPT_PATHSPEC_FILE_NUL(&pathspec_file_nul),
	struct stash_info info;
	 * buffer.
					     DEFAULT_ABBREV);
		}
	struct strbuf patch = STRBUF_INIT;
		ret = -1;
	return git_diff_basic_config(var, value, cb);
	struct strbuf symbolic = STRBUF_INIT;

	/* Find out what the user wants. */
#include "revision.h"
	int i;
	opts.head_idx = 1;
	 */
			 N_("include untracked files in stash")),

{
	const char *branch_ref = NULL;
	 * Reset is overall quite simple, however there is no current public
	discard_index(&istate);
		/* NUL-terminate: will be fed to update-index -z */
{

		head_commit = lookup_commit(the_repository, &info->b_commit);
	int quiet = 0;
			strbuf_addstr(untracked_files, ent->name);
			  int quiet)
	};
#include "config.h"
	if (run_command(&cp)) {
		ret = -1;
			if (!quiet)

	return 0;
				return error(_("could not generate diff %s^!."),
		for (i = 0; i < active_nr; i++)

					       "Try without --index."));
	} else if (strspn(commit, "0123456789") == strlen(commit)) {
	int include_untracked = 0;
		strbuf_addf(stash_msg_buf, "WIP on %s", msg.buf);
		return error(_("git stash clear with parameters is "
		if (index)
		goto done;



		}
	if (!commit) {
	cp.git_cmd = 1;
	struct child_process cp_upd_index = CHILD_PROCESS_INIT;
}
	}
			return -1;
		return -1;
	if (!include_untracked && ps->nr) {
	argv_array_pushl(&cp.args, "rev-parse", "--verify", "--quiet", NULL);
	struct option options[] = {
#include "run-command.h"
{
			struct strbuf out = STRBUF_INIT;
	/*

					 "-R", NULL);
	return found;
				argv_array_push(&cp_add.args, "-u");
	}
static int restore_untracked(struct object_id *u_tree)
	ret = do_push_stash(&ps, stash_msg, quiet, keep_index,

static int show_stat = 1;
	ret = run_command(&cp);
	 */
static const char * const git_stash_save_usage[] = {
}
				argv_array_push(&cp.args, "-x");

				struct strbuf files)

	}
		usage_with_options(git_stash_show_usage, options);
		goto done;
		goto done;
	struct strbuf stash_msg_buf = STRBUF_INIT;
	 * need to be added to avoid implementing too much reflog code here
		goto done;
	}
/*
	git_config(git_stash_config, NULL);
		strbuf_release(&refs_msg);
		fprintf_ln(stderr, _("Can't use --patch and --include-untracked"
	 * apply_all_patches would have to be updated to optionally take a
	struct option options[] = {


			    struct diff_options *options,
	 * `parents` will be empty after calling `commit_tree()`, so there is
	if (commit_tree(untracked_msg.buf, untracked_msg.len,
			    "you need it again."));
		OPT_STRING('m', "message", &stash_msg, N_("message"),


	}


		goto done;
	struct commit *head_commit = NULL;
	char *seen;
			die("subcommand wasn't specified; 'push' can't be assumed due to unexpected token '%s'",


	}
		OPT_BOOL(0, "index", &index,

			}
		goto done;
	struct object_id obj;
		for (i = 0; i < argc; i++)
	if (do_store_stash(&info.w_commit, stash_msg_buf.buf, 1)) {
	struct stash_info info;
{

	ret = do_create_stash(&ps, &stash_msg_buf, 0, 0, &info,
		ret = -1;
	return pipe_command(&cp, NULL, 0, out, 0, NULL, 0);
			 "--ignore-skip-worktree-entries",
	struct stash_info info;

	else if (!strcmp(argv[0], "push"))
		die(_("--pathspec-file-nul requires --pathspec-from-file"));
	struct strbuf revision;

	const char *head_short_sha1 = NULL;
	int result;
	int quiet = 0;
}
done:

	int keep_index = -1;
	const char *stash_msg = NULL;
	cp.git_cmd = 1;
	strbuf_release(&info->revision);
	discard_index(&istate);

	struct commit *result;
		argv_array_push(args, ps->items[i].original);
		return !!push_stash(0, NULL, prefix, 0);

					 "--cached", "--binary", "HEAD", "--",
	remove_path(stash_index_path.buf);
		      int push_assumed)

		}
	} else {
	}
	rev.abbrev = 0;
		return !!branch_stash(argc, argv, prefix);
		if (ps.nr)
	struct option options[] = {
{

	argc = parse_options(argc, argv, prefix, options,
			strbuf_release(&out);
			strbuf_addch(untracked_files, '\0');
	int max_len;
	 */
	if (has_index) {
	strbuf_release(&untracked_msg);
		if (!quiet)

	}
			argv++;
	return pipe_command(&cp, NULL, 0, out, 0, NULL, 0);
	}
	if (read_cache() < 0)
				 absolute_path(get_git_work_tree()));
			goto done;
	if (diff_result_code(&rev.diffopt, result)) {
	argv_array_pushl(&cp.args, "checkout-index", "--all", NULL);
 * = 0 if there are no changes.
}
					 NULL);
	argv_array_pushf(&cp.args, "%s^2^..%s^2", w_commit_hex, w_commit_hex);
		return error(_("%s: Could not drop stash entry"),
			     git_stash_store_usage,
	strbuf_init(&info->revision, 0);
	remove_path(stash_index_path.buf);
	char *old_index_env = NULL, *old_repo_index_file;
		if (argv[i][0] != '-')
		untracked_commit_option = 1;

	argv_array_push(&cp.args, branch);
		info->is_stash_ref = !strcmp(expanded_ref, ref_stash);
	if (commit_tree(stash_msg_buf->buf, stash_msg_buf->len, &info->w_tree,
	strbuf_release(&untracked_files);
		}
	    commit_tree(commit_tree_label.buf, commit_tree_label.len,
			/* NUL-terminate: will be fed to update-index -z */
		return 0;
			return -1;
done:
						     untracked_files))
}
{
			    &info, &patch, quiet)) {

		OPT_BOOL('u', "include-untracked", &include_untracked,
#include "rerere.h"
			else

};
{

			 NULL, 0)) {

}
	struct option options[] = {
	if (include_untracked) {
		ret = -1;
	argc = parse_options(argc, argv, prefix, options,
		OPT_STRING('m', "message", &stash_msg, "message",
		}
	if (include_untracked != INCLUDE_ALL_FILES)

	return ret;
	struct child_process cp = CHILD_PROCESS_INIT;
	int include_untracked = 0;

			       struct strbuf *untracked_files)
	 */
	int untracked_commit_option = 0;
			fprintf_ln(stderr, _("Index was not unstashed."));
		ret = -1;
			fprintf_ln(stderr, _("Did you forget to 'git add'?"));
	int has_u;

}
				fprintf_ln(stderr, _("Cannot save the current "
			cp.git_cmd = 1;
	read_cache_preload(NULL);

		if (reset_tree(&c_tree, 0, 1)) {
	int ret = 0;
	struct object_context dummy;
	struct argv_array stash_args = ARGV_ARRAY_INIT;
static const char * const git_stash_branch_usage[] = {
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
#define USE_THE_INDEX_COMPATIBILITY_MACROS
	    !git_env_bool("GIT_TEST_STASH_USE_BUILTIN", -1))
static struct strbuf stash_index_path = STRBUF_INIT;
	res = run_command(&cp);
};


	/* Even though --quiet is specified, rev-parse still outputs the hash */
		}
	struct strbuf untracked_msg = STRBUF_INIT;

	discard_index(&istate);
			      NULL, 0);
	 * converted together with update_index.
			goto done;
	cp.git_cmd = 1;
		return !!drop_stash(argc, argv, prefix);
	argv_array_pushf(&cp.env_array, "GIT_INDEX_FILE=%s",
		if (include_untracked && !ps->nr) {
		if (ret)
	if (include_untracked && get_untracked_files(ps, include_untracked,
	struct strbuf diff_output = STRBUF_INIT;
		break;
	}
		    (uintmax_t)pid);
			    N_("include ignore files"), 2),
	return ret;
	if (!check_changes(ps, include_untracked, &untracked_files)) {
	if (refresh_and_write_cache(REFRESH_QUIET, 0, 0) < 0) {
	NULL
	argv_array_pushl(&cp.args, "checkout", "-b", NULL);
	 * a fatal error when a reflog is empty, which we can not recover from.
			rev.diffopt.output_format = DIFF_FORMAT_DIFFSTAT;
		struct dir_entry *ent = dir.entries[i];
	if (pipe_command(&cp_diff_tree, NULL, 0, out_patch, 0, NULL, 0)) {
	return ret;
 * b_commit is set to the base commit
	strbuf_join_argv(&stash_msg_buf, argc - 1, ++argv, ' ');
};
	commit_list_insert(head_commit, &parents);
		setup_standard_excludes(&dir);
		argc = parse_options(argc, argv, prefix, options,
					 oid_to_hex(&info.i_tree), "--", NULL);
}
		if (report_path_error(ps_matched, ps)) {
		return -1;

			add_pathspecs(&cp_add.args, ps);
	int ret = 0;
		return -1;
{
			if (!include_untracked)
				goto done;
		strbuf_addstr(&stash_msg_buf, stash_msg);

static void add_diff_to_buf(struct diff_queue_struct *q,

	NULL
}

		commit_list_insert(lookup_commit(the_repository,
	}
			return -1;

	if (parse_tree(tree))
			   refs_msg.buf);
			if (run_command(&cp)) {
	struct strbuf untracked_files = STRBUF_INIT;

		error(_("'%s' is not a stash reference"), info->revision.buf);
	struct option options[] = {
		return 0;
{
	}
};
	memset(&ps, 0, sizeof(ps));

	const char *branch_name = "(no branch)";
		stash_msg = strbuf_join_argv(&stash_msg_buf, argc, argv, ' ');
	int ret;
		}
}
			argv_array_push(&cp_add.args, "--");
	seen = xcalloc(ps->nr, 1);
	opts.reset = reset;
};
			add_pathspecs(&cp.args, ps);
		if (!quiet)
	strbuf_addf(&stash_index_path, "%s.stash.%" PRIuMAX, index_file,
static int show_stash(int argc, const char **argv, const char *prefix)


				     PARSE_OPT_KEEP_DASHDASH);

				goto done;
	strbuf_release(&msg);
static const char * const git_stash_push_usage[] = {
	struct object_id i_tree;
	commit_list_insert(head_commit, &parents);
			struct child_process cp = CHILD_PROCESS_INIT;
		return error(_("unable to write new index file"));
	strbuf_release(&stash_msg_buf);
			  const struct pathspec *ps) {
	argv_array_push(&cp.args, oid_to_hex(&info.b_commit));


	memset(&dir, 0, sizeof(dir));
	const char *branch = NULL;
		ret = -1;
	cp_diff_tree.git_cmd = 1;
	};
	argv_array_pushl(&cp_read_tree.args, "read-tree", "HEAD", NULL);
		cp.dir = prefix;
{

static int check_changes(const struct pathspec *ps, int include_untracked,
				NULL)) {
	return 0;

			if (ret)
		if (show_patch)
	/* No initial commit. */
	argv_array_pushf(&cp_upd_index.env_array, "GIT_INDEX_FILE=%s",
		goto done;
	cp_reflog.git_cmd = 1;
		free_stash_info(info);
		return 0;

	cp.git_cmd = 1;
	return ret;
		return -1;
	opts.fn = oneway_merge;

		stash_msg = "Created via \"git stash store\".";
			     PARSE_OPT_KEEP_UNKNOWN);
		ret = 1;

		return 0;
{
	ret = run_command(&cp);
		int i;
	return ret;
				return error(_("conflicts in index."

	 * We need to run restore files from a given index, but without
	N_("git stash store [-m|--message <message>] [-q|--quiet] <commit>"),
		       prefix, argv);
	}
	}
		parse_pathspec_file(&ps, 0,
	if (argc) {
		free_stash_info(info);
			return 0;
			parents, &info->w_commit, NULL, NULL)) {
	char *expanded_ref;

		if (patch_mode)

	argc = setup_revisions(revision_args.argc, revision_args.argv, &rev, NULL);
	if (revision_args.argc == 1) {
	}
		strbuf_addstr(data, q->queue[i]->one->path);
	else if (!strcmp(argv[0], "show"))

	remove_path(stash_index_path.buf);
				strbuf_release(&out);
	 */
	argv_array_pushl(&cp.args, "update-index", "--add", "--stdin", NULL);
{
		if (!quiet)
}
				ret = -1;
		setenv(INDEX_ENVIRONMENT, old_index_env, 1);
						     "worktree state"));
	return ret;
		OPT_BOOL(0, "index", &index,
	if (!ret)
			   int include_untracked, int patch_mode,
	}
	N_("git stash apply [--index] [-q|--quiet] [<stash>]"),
			argv_array_push(&stash_args, argv[i]);
		goto done;
	read_cache_preload(NULL);
			has_index = 0;
	};
	N_("git stash [push [-p|--patch] [-k|--[no-]keep-index] [-q|--quiet]\n"
			if (diff_tree_binary(&out, &info->w_commit)) {
#include "parse-options.h"
	N_("git stash branch <branchname> [<stash>]"),
	commit_list_insert(lookup_commit(the_repository, &info->i_commit),
			add_pathspecs(&cp_diff.args, ps);
	int ret = 0;
	if (!info->is_stash_ref) {
	if (get_oid(ref_stash, &obj))
			rev.diffopt.output_format |= DIFF_FORMAT_PATCH;

	free_stash_info(&info);
#include "lockfile.h"
		goto done;
	/*
	argv_array_clear(&stash_args);
static int get_untracked_files(const struct pathspec *ps, int include_untracked,
	if (get_oidf(&info->b_commit, "%s^1", revision) ||
	add_pending_object(&rev, parse_object(the_repository, &info->b_commit),
				NULL)) {
	if (argc)


	argv_array_pushl(&cp_upd_index.args, "update-index",
	    get_oidf(&info->w_tree, "%s:", revision) ||
		if (!quiet)
	}
	struct object_id dummy;
static const char *ref_stash = "refs/stash";
		free_stash_info(info);
	struct unpack_trees_options opts;
	if (refresh_and_write_cache(REFRESH_QUIET, 0, 0)) {

	N_("git stash branch <branchname> [<stash>]"),
			 NULL, 0, NULL, 0)) {
	argv_array_push(&cp.args, "--");
		if (!quiet)
			     git_stash_clear_usage,
		return -1;
	int ret = 0;
		struct child_process cp = CHILD_PROCESS_INIT;
		return !!clear_stash(argc, argv, prefix);
	opts.merge = 1;
	struct tree_desc t[MAX_UNPACK_TREES];
{
	rev.diffopt.flags.quick = 1;
	if (get_stash_info(&info, argc, argv))
	NULL

	if (!check_changes_tracked_files(&ps))
{
	log_tree_diff_flush(&rev);

	if (write_cache_as_tree(&info->i_tree, 0, NULL) ||
		if (!quiet)
	struct child_process cp = CHILD_PROCESS_INIT;
	 * reflog does not provide a simple function for deleting refs. One will




 *
	result = run_diff_index(&rev, 1);

	int ret;
		goto done;
		if (get_newly_staged(&out, &c_tree)) {
	argv_array_push(&cp.args, c_tree_hex);
			}
		cp.git_cmd = 1;
{
		goto done;

		return -1;
		warning(_("the stash.useBuiltin support has been removed!\n"
	}
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
	if (ret)
	argv_array_push(&cp.args, ref_stash);
static const char * const git_stash_apply_usage[] = {
		show_patch = git_config_bool(var, value);
		return error(_("cannot apply a stash in the middle of a merge"));
	free(expanded_ref);
			    N_("include ignore files"), 2),

			     PARSE_OPT_KEEP_UNKNOWN);
	NULL


 * The return value of `check_changes_tracked_files()` can be:
	if (diff_result_code(&rev.diffopt, result)) {
	 * Update-index is very complicated and may need to have a public
static int reset_head(void)
}
#include "log-tree.h"
 * i_tree is set to the index tree

	opts.update = update;
	memset(&ps, 0, sizeof(ps));
	}
 * w_tree is set to the working tree
	copy_pathspec(&rev.prune_data, ps);
			found++;
	ret = get_stash_info(&info, stash_args.argc, stash_args.argv);
			if (run_command(&cp)) {
			fprintf_ln(stderr, _("Cannot initialize stash"));

{
	 */

static int clear_stash(int argc, const char **argv, const char *prefix)
	pp_commit_easy(CMIT_FMT_ONELINE, head_commit, &msg);

	if (!strcmp(var, "stash.usebuiltin")) {
	 * function exposed in order to remove this forking.
	else
	init_tree_desc(t, tree->buffer, tree->size);

		goto done;
		use_legacy_stash = !git_config_bool(var, value);
	rev.diffopt.format_callback = add_diff_to_buf;


			struct child_process cp = CHILD_PROCESS_INIT;
{
	else if (!strcmp(argv[0], "apply"))
		if (oideq(&info->b_tree, &info->i_tree) ||
	}
			if (write_cache_as_tree(&index_tree, 0, NULL))
			fprintf_ln(stderr, _("No changes selected"));
	strbuf_release(&symbolic);

	int i;
			fprintf_ln(stderr, _("Cannot update %s with %s"),
	}
		ret = 1;
	}



	else if (!strcmp(argv[0], "create"))
	strbuf_release(&diff_output);
	strbuf_release(&stash_msg_buf);
		OPT_END()
	cp.git_cmd = 1;
	if (argc)
	return ret;
		printf_ln(_("The stash entry is kept in case "
	if (get_stash_info(&info, argc - 1, argv + 1))
	int keep_index = -1;
		return !!create_stash(argc, argv, prefix);
	if (index) {

		force_assume = !strcmp(argv[0], "-p");
{
static int list_stash(int argc, const char **argv, const char *prefix)
		printf_ln("%s", oid_to_hex(&info.w_commit));
			fprintf_ln(stderr, _("You do not have "
		if (!quiet)


	 * Diff-tree would not be very hard to replace with a native function,
	};
			cp.git_cmd = 1;
	return ret;
	o.branch2 = "Stashed changes";
		keep_index = 1;
		unsetenv(INDEX_ENVIRONMENT);
			}
				 argv[0], quiet ? GET_OID_QUIETLY : 0, &obj,
		do_clear_stash();
		OPT_SET_INT('a', "all", &include_untracked,
		}
}
			goto done;
done:
	/*
		return -1;
static int pop_stash(int argc, const char **argv, const char *prefix)
{

	if (get_stash_info(&info, argc, argv))
	int ret = 0;
			 stash_index_path.buf);
			if (!quiet)

		 * Status is quite simple and could be replaced with calls to
	if (check_changes_tracked_files(ps))
			if (include_untracked == INCLUDE_ALL_FILES)
			cp.git_cmd = 1;
		goto done;
		return !!pop_stash(argc, argv, prefix);

			reset_head();

	N_("git stash list [<options>]"),


	argv_array_push(&cp_reflog.args, info->revision.buf);
	strbuf_add(&symbolic, revision, end_of_rev - revision);
	return pipe_command(&cp, out->buf, out->len, NULL, 0, NULL, 0);


static int apply_stash(int argc, const char **argv, const char *prefix)
			     git_stash_save_usage,
	/* Starting with argv[1], since argv[0] is "create" */
			   struct stash_info *info, struct strbuf *patch,
	pid_t pid = getpid();
			   N_("stash message")),
			     info->revision.buf);

			     git_stash_list_usage,

	struct child_process cp_upd_index = CHILD_PROCESS_INIT;
	int ret;
		return ret;
	NULL
	}
						     "the untracked files"));
}
}
	set_alternate_index_output(stash_index_path.buf);
	argv_array_pushl(&cp.args, "diff-index", "--cached", "--name-only",

	struct child_process cp = CHILD_PROCESS_INIT;
		ret = do_drop_stash(&info, 0);
	}
		else
				 absolute_path(get_git_dir()));
		return 0;

			argv_array_pushl(&cp.args, "clean", "--force",

			argv_array_pushl(&cp.args, "reset", "-q", "--", NULL);


			if (pipe_command(&cp_apply, out.buf, out.len, NULL, 0,
	int force_assume = 0;
		goto done;

			struct strbuf out = STRBUF_INIT;
		ret = -1;

	git_config(git_diff_ui_config, NULL);
	struct option options[] = {
	N_("git stash clear"),

 * u_tree is set to the untracked files tree
{
	struct stash_info info;
	int index = 0;
				    PATHSPEC_PREFER_FULL | PATHSPEC_PREFIX_ORIGIN,
			 "--rewrite", NULL);

	if (refresh_and_write_cache(REFRESH_QUIET, 0, 0))

			     PARSE_OPT_KEEP_UNKNOWN | PARSE_OPT_KEEP_DASHDASH);
	N_("git stash [push [-p|--patch] [-k|--[no-]keep-index] [-q|--quiet]\n"
		OPT_END()
		goto done;
				NULL)) {
	};
	else if (!strcmp(argv[0], "store"))

	int patch_mode = 0;
			discard_cache();
		OPT_STRING('m', "message", &stash_msg, "message",

	 * diff-index is very similar to diff-tree above, and should be
					 NULL, 0)) {
			 stash_index_path.buf);
	cp.git_cmd = 1;
}
	o.branch1 = "Updated upstream";
			    argv[0]);
	if (get_stash_info(&info, argc, argv))
static int do_push_stash(const struct pathspec *ps, const char *stash_msg, int quiet,
	struct child_process cp_read_tree = CHILD_PROCESS_INIT;
}
	struct index_state istate = { NULL };
	tree = parse_tree_indirect(i_tree);
			 "--remove", "--stdin", NULL);
			free_stash_info(info);
		rerere(0);
	ret = run_add_interactive(NULL, "--patch=stash", ps);

	argv_array_pushl(&cp_upd_index.args, "update-index", "-z", "--add",

	struct dir_struct dir;
		OPT_END()

		}
			struct child_process cp_apply = CHILD_PROCESS_INIT;
	else if (!strcmp(argv[0], "pop"))
	strbuf_release(&stash_msg_buf);
static const char * const git_stash_usage[] = {
	/*
	};

		return -1;
	/* Assume 'stash push' */
	if (patch_mode) {
	struct strbuf msg = STRBUF_INIT;
	if (argc != 1) {
	N_("git stash drop [-q|--quiet] [<stash>]"),
	}
	init_diff_ui_defaults();

/*
		printf_ln(_("Merging %s with %s"), o.branch1, o.branch2);
	add_head_to_pending(&rev);
	struct rev_info rev;


	parents = NULL;
	NULL
	strbuf_release(&commit_tree_label);

#include "merge-recursive.h"
		show_stat = git_config_bool(var, value);

			 "-z", "--add", "--remove", "--stdin", NULL);
		}

{
	for (i = 1; i < argc; i++) {
static int show_patch;
			   "");
				return error(_("could not save index tree"));
	const char *revision;
	 * This could easily be replaced by get_oid, but currently it will throw
{
/*
			    patch_mode, include_untracked);
static int reset_tree(struct object_id *i_tree, int update, int reset)
			read_cache();
	argv_array_pushl(&cp_diff_tree.args, "diff-tree", "-p", "HEAD",
	argv_array_pushf(&cp_read_tree.env_array, "GIT_INDEX_FILE=%s",
	else if (!strcmp(argv[0], "clear"))
			}
			argv_array_pushl(&cp_apply.args, "apply", "--index",
		info->is_stash_ref = 0;
	if (use_legacy_stash ||
		ret = -1;
	return !!push_stash(args.argc, args.argv, prefix, 1);
			strbuf_release(&out);

	if (argc) {
};
	if (patch_mode && keep_index == -1)
	if (info->has_u && restore_untracked(&info->u_tree))
static int apply_cached(struct strbuf *out)
{
	int nr_trees = 1;
		argv_array_pushf(&cp.env_array, GIT_WORK_TREE_ENVIRONMENT"=%s",
	}



	N_("git stash save [-p|--patch] [-k|--[no-]keep-index] [-q|--quiet]\n"


			}
	argc = parse_options(argc, argv, prefix, options,
 * The function will fill `untracked_files` with the names of untracked files
			 N_("attempt to recreate the index")),
	}
	if (o.verbosity >= 3)
	FREE_AND_NULL(old_index_env);
	clear_pathspec(&rev.prune_data);
		if (keep_index < 1) {
	 * Apply currently only reads either from stdin or a file, thus
		ret = 1;
			fprintf_ln(stderr, _("No stash entries found."));
{
done:
	}
		commit = argv[0];
		OPT__QUIET(&quiet, N_("quiet mode")),

	UNLEAK(rev);
			     git_stash_pop_usage, 0);
	if (!ret && info.is_stash_ref)
						 &info->u_commit),

	int patch_mode = 0;
		goto done;
	}


		goto done;
			die(_("--pathspec-from-file is incompatible with --patch"));

		}
	argv_array_pushf(&cp.args, "%s@{0}", ref_stash);
	argv_array_pushl(&cp.args, "log", "--format=%gd: %gs", "-g",
		       struct strbuf *out_patch, int quiet)
					     "index state"));
	info->has_u = !get_oidf(&info->u_tree, "%s^3:", revision);
	 * run_command to fork processes that will not interfere.
		ret = stash_patch(info, ps, patch, quiet);
		return !!store_stash(argc, argv, prefix);
			die(_("--pathspec-from-file is incompatible with pathspec arguments"));
	diff_setup_done(&rev.diffopt);
	struct rev_info rev;
		strbuf_addf(&info->revision, "%s@{%s}", ref_stash, commit);
	struct argv_array revision_args = ARGV_ARRAY_INIT;

	}

		ret = -1;
		return -1;
	}
	case 1:
				fprintf_ln(stderr, _("Cannot save the current "
	argv_array_pushf(&cp.env_array, "GIT_INDEX_FILE=%s",
	object_array_clear(&rev.pending);
	argc = parse_options(argc, argv, prefix, options,
	struct option options[] = {
		ret = -1;
static void free_stash_info(struct stash_info *info)
		cp.git_cmd = 1;
		rev.diffopt.output_format = DIFF_FORMAT_PATCH;
	N_("git stash clear"),
			&info->u_tree, NULL, &info->u_commit, NULL, NULL)) {

	return 0;
int cmd_stash(int argc, const char **argv, const char *prefix)
		if (!quiet)
	else
{
	}
		/* read back the result of update_index() back from the disk */
}
{
static int do_apply_stash(const char *prefix, struct stash_info *info,
	    get_oidf(&info->b_tree, "%s^1:", revision) ||
		OPT_END()
			}
	};

static const char * const git_stash_list_usage[] = {

	NULL
	if (!strcmp(var, "stash.showstat")) {
		return !!show_stash(argc, argv, prefix);
	rev.diffopt.format_callback_data = &diff_output;
	if (!check_changes(ps, include_untracked, &untracked_files)) {
			free(ps_matched);
		if (!quiet)
			argv_array_pushl(&cp_diff.args, "diff-index", "-p",
						     "worktree state"));
			ret = apply_cached(&out);
		ret = -1;
	return run_command(&cp);
	N_("git stash drop [-q|--quiet] [<stash>]"),
	if (old_index_env && *old_index_env)

			if (run_command(&cp_add)) {
	 * any options.

			struct child_process cp_add = CHILD_PROCESS_INIT;
	struct option options[] = {
	   "          [-u|--include-untracked] [-a|--all] [<message>]"),
	else if (*argv[0] != '-')
	} else {
	opts.src_index = &the_index;

		       REF_FORCE_CREATE_REFLOG,
			 N_("keep index")),
static int drop_stash(int argc, const char **argv, const char *prefix)
			  "See its entry in 'git help config' for details."));
{
static int create_stash(int argc, const char **argv, const char *prefix)

 */
	if (quiet)
			struct child_process cp = CHILD_PROCESS_INIT;
			free_stash_info(&info);

			argv_array_push(&cp_add.args, "add");


	cp_read_tree.git_cmd = 1;
		return -1;

	if (!reflog_exists(ref_stash) && do_clear_stash()) {
		if (reset_tree(&index_tree, 0, 0))
	if (!stash_msg_buf->len)
			 oid_to_hex(&info->w_tree), "--", NULL);

			if (!quiet)

	 */
	argv_array_push(&args, "push");
		if (save_untracked_files(info, &msg, untracked_files)) {
		ret = -1;
	opts.dst_index = &the_index;
		if (!quiet)
	if (update_ref(stash_msg, ref_stash, w_commit, NULL,
	return do_push_stash(&ps, stash_msg, quiet, keep_index, patch_mode,



		return 0;
			   &parents);
		 * wt_status in the future, but it adds complexities which may
#include "dir.h"
	const char *stash_msg = NULL;
	child_process_init(&cp);
	return res;
	free_stash_info(&info);
	   "          [--] [<pathspec>...]]"),
	ret = run_command(&cp_reflog);

			printf_ln(_("Dropped %s (%s)"), info->revision.buf,
	struct child_process cp = CHILD_PROCESS_INIT;
		free(ent);


done:
		run_command(&cp);
 * `untracked_files` will be filled with the names of untracked files.
	struct object_id i_commit;
			     PARSE_OPT_KEEP_DASHDASH);
	return !(ret == 0 || ret == 1);
}
		return error(_("could not restore untracked files from stash"));
	N_("git stash pop [--index] [-q|--quiet] [<stash>]"),
	max_len = fill_directory(&dir, the_repository->index, ps);
	for (i = 0; i < q->nr; i++) {
	}
			if (include_untracked == INCLUDE_ALL_FILES)
	struct rev_info rev;
	return pipe_command(&cp, out->buf, out->len, NULL, 0, NULL, 0);
	return do_clear_stash();
		return -1;
	struct object_id c_tree;
	if (oideq(&info->b_tree, &c_tree))

		struct strbuf refs_msg = STRBUF_INIT;
	 * The config settings are applied only if there are not passed

		if (!ref_exists(ref_stash)) {
	argv_array_pushl(&cp.args, "diff-tree", "--binary", NULL);
		diff_setup_done(&rev.diffopt);
		} else if (ret > 0) {
	free(seen);
	const char *c_tree_hex = oid_to_hex(c_tree);
		return -1;
			}

static int check_changes_tracked_files(const struct pathspec *ps)
			  int index, int quiet)
}
static int get_newly_staged(struct strbuf *out, struct object_id *c_tree)
	ret = dwim_ref(symbolic.buf, symbolic.len, &dummy, &expanded_ref);
	struct object_id b_commit;
	const char *w_commit_hex = oid_to_hex(w_commit);
					     "working tree state"));
	struct child_process cp = CHILD_PROCESS_INIT;
	}
	clear_pathspec(&rev.prune_data);
			 "--first-parent", "-m", NULL);
static int get_stash_info(struct stash_info *info, int argc, const char **argv)
		char *ps_matched = xcalloc(ps->nr, 1);

		argv_array_pushl(&cp.args, "apply", "-R", NULL);
	init_merge_options(&o, the_repository);
		goto done;
			argv_array_push(&revision_args, argv[i]);
		OPT_END()
		if (stash_working_tree(info, ps)) {


				   ref_stash, oid_to_hex(w_commit));
	 */
static int diff_tree_binary(struct strbuf *out, struct object_id *w_commit)
		OPT_PATHSPEC_FROM_FILE(&pathspec_from_file),
	} else {
	N_("git stash show [<options>] [<stash>]"),
				goto done;
	int quiet = 0;
		return -1;
	argc = parse_options(argc, argv, prefix, options,
	ret = do_drop_stash(&info, quiet);

done:
	struct object_id index_tree;
	struct child_process cp_diff_tree = CHILD_PROCESS_INIT;
{
				ret = -1;


		}
			 stash_index_path.buf);
				ret = -1;
	free(dir.ignored);
	default: /* Invalid or ambiguous */
/*
			goto done;
static int save_untracked_files(struct stash_info *info, struct strbuf *msg,



	int ret = 0;
		       UPDATE_REFS_MSG_ON_ERR)) {
	branch = argv[0];
	if (write_cache_as_tree(&c_tree, 0, NULL))
#include "cache-tree.h"
		return -1;
	if (!out_patch->len) {

#include "argv-array.h"
	int ret = 0;

		OPT_END()
		OPT_BOOL('p', "patch", &patch_mode,
		if (!quiet) {
			argc--;
static const char * const git_stash_show_usage[] = {
		goto done;
	else if (!strcmp(argv[0], "save"))
{
	return delete_ref(NULL, ref_stash, &obj, 0);
	cp.git_cmd = 1;


	cp.git_cmd = 1;
				     git_stash_push_usage,

	if (ret) {
		/*
}
					 "--no-recurse-submodules", NULL);
		strbuf_release(&out);
		goto done;
	parse_pathspec(&ps, 0, PATHSPEC_PREFER_FULL | PATHSPEC_PREFIX_ORIGIN,

	ret = merge_recursive_generic(&o, &c_tree, &info->w_tree, 1, bases,
					     ref_stash, argv[0]);

		} else if (push_assumed && !force_assume) {

				    prefix, pathspec_from_file, pathspec_file_nul);
 * i_commit is set to the commit containing the index tree
	 * no need to call `free_commit_list()`
	assert_stash_ref(&info);

			return -1;
	int ret;

		OPT_END()
		OPT_BOOL('u', "include-untracked", &include_untracked,



	if (flags & REF_ISSYMREF)
		remove_path(stash_index_path.buf);
}
	memset(&opts, 0, sizeof(opts));
	NULL
	int has_index = index;
	if (do_create_stash(ps, &stash_msg_buf, include_untracked, patch_mode,
			 stash_index_path.buf);
			      git_stash_usage, options);
#include "builtin.h"
#define INCLUDE_ALL_FILES 2
}
	const char *stash_msg = NULL;
	if (!rev.diffopt.output_format) {
	if (argc == 1)
		 * require more tests.
			    void *data)


	}
 *
		discard_cache();
		goto done;

	strbuf_addf(&untracked_msg, "untracked files on %s\n", msg->buf);

	return ret;

		goto done;
	}
	if (patch_mode && include_untracked) {
		OPT_SET_INT('a', "all", &include_untracked,
	return ret;
		return -1;
	return ret;
	if (run_diff_index(&rev, 0)) {
	if (get_oid("HEAD", &info->b_commit)) {
	assert_stash_like(info, revision);
	rev.diffopt.flags.ignore_submodules = 1;
			 int keep_index, int patch_mode, int include_untracked)
		OPT_END()

	revision = info->revision.buf;
	strbuf_addf(&commit_tree_label, "index on %s\n", msg.buf);
	};
		ret = -1;
		o.verbosity = 0;
 * = 0 if there are not any untracked files
		struct child_process cp = CHILD_PROCESS_INIT;
			strbuf_release(&out);
		return !!save_stash(argc, argv, prefix);
static int use_legacy_stash;

			     git_stash_drop_usage, 0);
		return -1;
			 N_("attempt to recreate the index")),

	/*
	argv_array_pushf(&cp_upd_index.env_array, "GIT_INDEX_FILE=%s",
	struct strbuf untracked_files = STRBUF_INIT;
	/*
			 stash_index_path.buf);
{
}
	/*
			fprintf_ln(stderr, _("Cannot save the current "
					     "the initial commit yet"));

			cp_apply.git_cmd = 1;


	} else {
	end_of_rev = strchrnul(revision, '@');
	} else {
	/*
		}

	copy_pathspec(&rev.prune_data, ps);
	int res;
	return run_command(&cp);
		strbuf_addch(data, '\0');
	clear_directory(&dir);
	struct object_id w_commit;

 * b_tree is set to the base tree
	read_cache_preload(NULL);
				 &dummy)) {
		OPT__QUIET(&quiet, N_("be quiet")),

	return do_store_stash(&obj, stash_msg, quiet);
	/*
	return ret;
	struct option options[] = {
			read_cache();
	struct pathspec ps;
	N_("git stash ( pop | apply ) [--index] [-q|--quiet] [<stash>]"),
{
		fprintf_ln(stderr, _("Too many revisions specified:%s"),
		goto done;
	if (!ret) {
	remove_path(stash_index_path.buf);
	cp_upd_index.git_cmd = 1;
		if (!strcmp(argv[0], "--")) {

			ret = -1;
	}
		usage_msg_opt(xstrfmt(_("unknown subcommand: %s"), argv[0]),
	int quiet = 0;
	cp.no_stdout = 1;
	index_file = get_index_file();
	struct lock_file lock_file = LOCK_INIT;
				ret = -1;
}
		ret = 1;
static const char * const git_stash_drop_usage[] = {
		goto done;
					     "<commit> argument"));
	free(dir.entries);
	if (write_index_as_tree(&info->w_tree, &istate, stash_index_path.buf, 0,
	struct pathspec ps;
			discard_cache();
	};
	struct stash_info info;
	if (get_oid("HEAD", &dummy))
	struct index_state istate = { NULL };
	if (!quiet) {
		OPT_BOOL('k', "keep-index", &keep_index,


	the_repository->index_file = stash_index_path.buf;
	   "          [--] [<pathspec>...]]"),
 * u_commit is set to the commit containing the untracked files tree
	}
		}
			ret = -1;
	cp.git_cmd = 1;
	}
				     " or --all at the same time"));
static int stash_patch(struct stash_info *info, const struct pathspec *ps,
		ret = update_index(&out);
		return !!apply_stash(argc, argv, prefix);
	argv_array_pushl(&cp.args, "apply", "--cached", NULL);
			cp_add.git_cmd = 1;
		read_cache();
	struct strbuf stash_msg_buf = STRBUF_INIT;
			fprintf_ln(stderr, _("Cannot update %s with %s"),
}
	   "          [-u|--include-untracked] [-a|--all] [<message>]"),
	NULL
	if (!argc) {
	if (!patch_mode) {
	case 0: /* Not found, but valid ref */
	 * affecting the current index, so we use GIT_INDEX_FILE with
	}
		strbuf_addf(&info->revision, "%s@{0}", ref_stash);
static int store_stash(int argc, const char **argv, const char *prefix)
		if (keep_index == 1 && !is_null_oid(&info.i_tree)) {
	}
				goto done;
}
		}
	else if (!strcmp(argv[0], "list"))
	int index = 0;
static int do_drop_stash(struct stash_info *info, int quiet)

}
			   int quiet)
struct stash_info {
			&info->i_tree, parents, &info->i_commit, NULL, NULL)) {
			struct child_process cp_diff = CHILD_PROCESS_INIT;

	cp.git_cmd = 1;
	return 0;
			cp_diff.git_cmd = 1;
		free(ps_matched);
		return !!push_stash(argc, argv, prefix, 0);
	int i;
	return diff_result_code(&rev.diffopt, 0);
		OPT__QUIET(&quiet, N_("be quiet, only report errors")),
static const char * const git_stash_store_usage[] = {
	int i;
			     git_stash_apply_usage, 0);
}
	init_revisions(&rev, NULL);
	if (pipe_command(&cp_upd_index, files.buf, files.len, NULL, 0,

	NULL
	if (unpack_trees(nr_trees, t, &opts))



		branch_name = strrchr(branch_ref, '/') + 1;
	argv_array_pushv(&args, argv);
		exit(1);
	int ret;
 * > 0 if there are changes.
	struct object_id w_tree;

			 "--diff-filter=A", NULL);
			fprintf_ln(stderr, _("Cannot record "
	if (argc > 1) {

static int git_stash_config(const char *var, const char *value, void *cb)
static int branch_stash(int argc, const char **argv, const char *prefix)
static int stash_working_tree(struct stash_info *info, const struct pathspec *ps)
		    oideq(&c_tree, &info->i_tree)) {
	}
	}
static int do_store_stash(const struct object_id *w_commit, const char *stash_msg,
			if (pipe_command(&cp_diff, NULL, 0, &out, 0, NULL, 0)) {
};
static int do_create_stash(const struct pathspec *ps, struct strbuf *stash_msg_buf,

}
				   &parents);
	setup_diff_pager(&rev.diffopt);
				add_pathspecs(&cp.args, ps);
		} else {
	else if (!strcmp(argv[0], "branch"))
		if (!show_stat && !show_patch) {
	setenv(INDEX_ENVIRONMENT, the_repository->index_file, 1);
	struct child_process cp = CHILD_PROCESS_INIT;
	}
			   N_("stash message")),
	/*
		       quiet ? UPDATE_REFS_QUIET_ON_ERR :
		die(_("'%s' is not a stash-like commit"), revision);
		ret = 1;
	int quiet = 0;
	int ret;
	}
		struct strbuf out = STRBUF_INIT;
	argv_array_push(&revision_args, argv[0]);
	if ((ret = do_apply_stash(prefix, &info, index, quiet)))
			argv_array_pushl(&cp.args, "reset", "--hard", "-q",
	int ret = 0;
		ret = -1;
			 N_("keep index")),
			goto done;
		OPT_BOOL('p', "patch", &patch_mode,
	if (!argc)
				argv_array_push(&cp.args, ":/");

	free_stash_info(&info);
		ret = 1;

	int ret;
	if (get_oid(revision, &info->w_commit)) {
	int quiet = 0;
{


	 * however it should be done together with apply_cached.

	if (write_index_as_tree(&info->w_tree, &istate, stash_index_path.buf, 0,


		OPT_END()
};
	for (i = 0; i < dir.nr; i++) {
		 */
				ret = -1;
	struct strbuf commit_tree_label = STRBUF_INIT;
	remove_path(stash_index_path.buf);
{

		if (dir_path_match(&the_index, ent, ps, max_len, seen)) {
				goto done;
		if (show_stat)
	int ret = 0;
static void assert_stash_like(struct stash_info *info, const char *revision)
static int push_stash(int argc, const char **argv, const char *prefix,
	if (ret)
{
	struct strbuf stash_msg_buf = STRBUF_INIT;
	}
}
	struct stash_info info;
					     oid_to_hex(&info->w_commit));
{
	const struct object_id *bases[1];
		return !!list_stash(argc, argv, prefix);
	};
		argv_array_pushf(&cp.env_array, GIT_DIR_ENVIRONMENT"=%s",


	}
	    get_oidf(&info->i_tree, "%s^2:", revision))
		error(_("%s is not a valid reference"), revision);
	init_revisions(&rev, NULL);
	struct merge_options o;

};
static int update_index(struct strbuf *out)
