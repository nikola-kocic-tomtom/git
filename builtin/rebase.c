	enum action action = ACTION_NONE;
	if (opts->gpg_sign_opt)
	if (opts->allow_rerere_autoupdate)
		.git_format_patch_opt = STRBUF_INIT	\
		rebase_write_basic_state(opts);

	struct commit *upstream;
	    (action != ACTION_NONE) ||
	setenv(GIT_REFLOG_ACTION_ENVIRONMENT, "rebase", 0);
	struct option builtin_rebase_options[] = {
		if (argc > 1)
	struct branch *current_branch = branch_get(NULL);
	add_var(&script_snippet, "upstream", opts->upstream ?

		else if (exec.nr > 0)
	tree = parse_tree_indirect(oid);
	} else if (status == 2) {
	add_var(&script_snippet, "rebase_cousins",
		OPT_CMDMODE(0, "add-exec-commands", &command,
		break;
	char *revisions = NULL, *shortrevisions = NULL;
}

					   builtin_rebase_options);
				      "show_current_patch" };
			 N_("keep original branch points of cousins")),

		OPT_PASSTHRU_ARGV(0, "ignore-whitespace", &options.git_am_opts,
		unpack_tree_opts.reset = 1;
	unpack_tree_opts.merge = 1;
		return error_errno(_("could not read '%s'."), todo_file);
static void NORETURN error_on_missing_default_upstream(void)
#define REBASE_OPTIONS_INIT {			  	\
		remove_branch_state(the_repository, 0);
 */
			if (commit_tree("", 0, the_hash_algo->empty_tree, NULL,
		OPT_STRING(0, "switch-to", &opts.switch_to, N_("switch-to"),
			}
	}
	 * We always write to orig-head, but interactive rebase used to write to

		else if (exec.nr)
		else
			 N_("rebase all reachable commits up to the root(s)")),
				die(_("Could not create new root commit"));
		OPT_CMDMODE(0, "skip", &command, N_("skip commit"), ACTION_SKIP),
		OPT_CMDMODE(0, "skip", &action,
	res = edit_todo_list(the_repository, &todo_list, &new_todo, NULL, NULL, flags);
		options.onto_name = xstrdup(buf.buf);
	if (res)
		goto leave_reset_head;
	if (!status) {

	return opts->type == REBASE_MERGE ||
		    (options.restrict_revision ?
			return -1;

			puts(_("HEAD is up to date, rebase forced."));
	unpack_tree_opts.src_index = the_repository->index;
	replay.drop_redundant_commits = (opts->empty == EMPTY_DROP);
		goto finished_rebase;

		/*



{


	enum action command = ACTION_NONE;
		options.flags |= REBASE_FORCE;
			    strcmp(p, "error") && strcmp(p, "error-all"))


		      const char *switch_to_branch, unsigned flags,
					       options.head_name,
	if (can_fast_forward(options.onto, options.upstream, options.restrict_revision,
		/* Run sequencer-based rebase */
			PARSE_OPT_NOARG | PARSE_OPT_HIDDEN,
}
	ACTION_NONE = 0,
static struct replay_opts get_replay_opts(const struct rebase_options *opts)
#include "lockfile.h"
	 * Check if we are already based on onto with linear history,
		}
			}
	case ACTION_NONE: {
	strbuf_addf(&msg, "%s: checkout %s",
	 * orig_head -- commit object name of tip of the branch before rebasing

	strbuf_release(&head_reflog);
	struct object *obj;
		ret = update_ref(reflog_head, "HEAD", oid, orig,
		refresh_index(the_repository->index, REFRESH_QUIET, NULL, NULL,
	ACTION_CONTINUE,
	case ACTION_ABORT: {
			if (*p && strcmp(p, "warn") && strcmp(p, "nowarn") &&
			  "See its entry in 'git help config' for details."));
		OPT_BIT('f', "force-rebase", &options.flags,


	case ACTION_REARRANGE_SQUASH:
	strbuf_addf(&msg, "%s: ", reflog_action ? reflog_action : "rebase");
	add_var(&script_snippet, "signoff", opts->signoff ? "--signoff" : "");
	if (opts->strategy_opts)
	REBASE_MERGE,
		 "Please specify which branch you want to rebase against.\n"
		} else if (old_orig)
			usage_with_options(builtin_rebase_usage,
		OPT_BOOL(0, "rebase-cousins", &opts.rebase_cousins,
			return -1;
	add_var(&script_snippet, "upstream_name", opts->upstream_name);
	format_patch.out = open(rebased_patches,
		options.switch_to = argv[0];
			 "stash", "apply", autostash.buf, NULL);
				puts(_("HEAD is up to date."));
		{OPTION_STRING, 'r', "rebase-merges", &rebase_merges,
		set_reflog_action(&options);
	BUG_ON_OPT_ARG(arg);
	const char *rebase_merges = NULL;
	/* options.gpg_sign_opt will be either "-S" or NULL */
	    read_one(state_dir_path("onto", opts), &buf))
	write_file(state_dir_path("orig-head", opts), "%s",

				  &options.git_am_opts, NULL,
	argc = parse_options(argc, argv, prefix, options,
	}
#include "cache-tree.h"

	const char *head_hash = NULL;
		strbuf_addf(&buf, "%s/rewritten", merge_dir());
	struct string_list commands = STRING_LIST_INIT_DUP;
	REBASE_PRESERVE_MERGES
		 * so here the last command is always empty */
static int parse_opt_am(const struct option *opt, const char *arg, int unset)
			   opts->gpg_sign_opt);
			N_("display a diffstat of what changed upstream"),


leave_reset_head:
		OPT_BOOL(0, "autosquash", &opts.autosquash,
{
		const char *cmd_live_rebase =
	if (strategy_options.nr) {
		goto leave_reset_head;
{
			    ACTION_CONTINUE),
		      "and run me again.  I am stopping in case you still "
		goto reset_head_refs;

		struct argv_array args = ARGV_ARRAY_INIT;
			else
	if (opts->squash_onto) {
				       options.state_dir);
		break;
			 "\n"),
	struct tree_desc desc[2] = { { NULL }, { NULL } };

			    oid_to_hex(oid), "1", NULL);
	struct strbuf buf = STRBUF_INIT;
			repo_update_index_if_able(the_repository, &lock_file);
	}
	else if (status == 0) {

		ret = sequencer_continue(the_repository, &replay_opts);

	case ACTION_SKIP: {
		free(rebased_patches);
 * Copyright (c) 2018 Pratik Karki
static GIT_PATH_FUNC(path_squash_onto, "rebase-merge/squash-onto")
						&todo_list))
		return error_errno(_("could not read '%s'."), todo_file);
		strbuf_addstr(&dir, opts->state_dir);
	if (reschedule_failed_exec >= 0)
	int ret, flags, total_argc, in_progress = 0;
{
		opts.stat_width = -1; /* use full terminal width */
	 */
				if (reset_head(&options.orig_head, "checkout",
				options.upstream_name = "@{-1}";

	return status;
	unsigned flags = 0;
				 int unset)

	argv_array_pushl(&format_patch.args, "format-patch", "-k", "--stdout",
	int allow_empty_message;
		rerere_clear(the_repository, &merge_rr);
		OPT_BOOL_F(0, "allow-empty-message", &opts.allow_empty_message,
				}
			 &reschedule_failed_exec,
		if (!strcmp(option, "--committer-date-is-author-date") ||
		REBASE_NO_QUIET = 1<<0,
		return error_errno(_("could not mark as interactive"));
		  0 },
	/*
	 * everything leading up to orig_head) on top of onto.

	stash_apply.git_cmd = 1;
		      "If that is not the case, please\n\t%s\n"
	if (opts->allow_rerere_autoupdate > 0)
	if (!is_merge(options))
	}
	int abbreviate_commands = 0, ret = 0;


	git_config(rebase_config, &options);

		replay.have_squash_onto = 1;
			xstrdup_or_null(resolve_ref_unsafe("HEAD", 0, NULL,
		OPT_BIT(0, "no-ff", &options.flags,
	if (options.signoff) {
	todo_list_release(&new_todo);
done:

			   "HEAD", NULL);
	free(rebased_patches);
			N_("GPG-sign commits"),
		   oid_to_hex(&opts->orig_head));
	if (reset_head(&options.onto->object.oid, "checkout", NULL,


	status = run_command_v_opt(argv, RUN_USING_SHELL);
	const char *todo_file = rebase_path_todo();
	const char *onto_name;
		options.strategy_opts = xstrdup(buf.buf);
	 *
		goto leave_reset_head;
		return run_command(&am);
		oidcpy(&replay.squash_onto, opts->squash_onto);
	int i;

			N_("use apply strategies to rebase"),
			    struct commit *onto, const char *orig_head)
			if (!strcmp(options.upstream_name, "-"))
		options.state_dir = apply_dir();

	strbuf_stripspace(&todo_list.buf, 1);
			   N_("rebase strategy")),
			    ACTION_EDIT_TODO),
	 * user upgraded git with an ongoing interactive rebase.
		; /* merge backend cleans up after itself */
		.git_am_opts = ARGV_ARRAY_INIT,		\
		opts->autostash = git_config_bool(var, value);
#include "revision.h"
			die(_("cannot combine '--keep-base' with '--root'"));
		  N_("the upstream commit"), PARSE_OPT_NONEG, parse_opt_commit,
	if (init_basic_state(&replay,
				       NULL, RESET_HEAD_HARD, NULL, NULL) < 0)
		argv_array_push(&am.args, opts->gpg_sign_opt);
#include "quote.h"
		return 0;
	unpack_tree_opts.fn = reset_hard ? oneway_merge : twoway_merge;
		goto done;
	/* If a hook exists, give it a chance to interrupt*/
	switch (command) {

static const char *action_names[] = { "undefined",
				 autostash.buf, NULL);
		free((void *)desc[--nr].buffer);
	if (file_exists(state_dir_path("verbose", opts)))
			break;
				     rebased_patches);
			       options.head_name, RESET_HEAD_HARD,
	add_var(&script_snippet, "onto", opts->onto ?
	else {
	env = getenv(GIT_REFLOG_ACTION_ENVIRONMENT);
	} else {
				die(_("Cannot autostash"));
	if (action != ACTION_NONE && !in_progress)
#include "sequencer.h"
	struct strbuf orig_head_reflog = STRBUF_INIT, head_reflog = STRBUF_INIT;
	if (file_exists(state_dir_path("quiet", opts)))
			  "--rebase-merges"));
	case ACTION_SKIP: {
		opts->rebase_merges ? "t" : "");
		strbuf_addstr(&buf, "...");
	options.revisions = revisions.buf;
			break;
	add_var(&script_snippet, "gpg_sign_opt", opts->gpg_sign_opt);
		    opts->head_name);
		strbuf_reset(&buf);
			"As a result, git cannot rebase them."),
static int parse_opt_empty(const struct option *opt, const char *arg, int unset)
			opts->autosquash = 0;
		if (has_unstaged_changes(the_repository, 1)) {

	enum empty_type empty;
	 * user should see them.
			  "Use --rebase-merges instead."));
	if (!ok_to_skip_pre_rebase &&
					       NULL, buf.buf) < 0) {
				  N_("passed to 'git am'"), PARSE_OPT_NOARG),
}
			    "squash!/fixup! under -i")),
static int read_basic_state(struct rebase_options *opts)
		if (read_basic_state(&options))
		}
		opts->type = REBASE_MERGE; /* implied */
	if (!(opts->flags & REBASE_NO_QUIET))
		strbuf_addstr(buf, "; ");
				  enum action command)
		else
#define RESET_ORIG_HEAD (1<<4)
	while (to && to != from) {
			"patches to replay\n"
	}
		       RESET_HEAD_DETACH | RESET_ORIG_HEAD |
	if (opts->type == REBASE_APPLY) {


	if (run_hook)

		split_exec_commands(opts->cmd, &commands);
		return -1;
		goto cleanup;
		OPT_BOOL(0, "autostash", &options.autostash,
	format_patch.git_cmd = 1;
{

		write_file(path_squash_onto(), "%s\n",
	if (get_oid(name, &oid))
	if (get_revision_ranges(opts->upstream, opts->onto, &opts->orig_head,
	if (cmd && *cmd) {
			    ACTION_SHOW_CURRENT_PATCH),
		OPT_STRING(0, "onto-name", &opts.onto_name, N_("onto-name"), N_("onto name")),

				      "edit_todo",
		return -1;
	if (options.autostash) {
		if (0 <= fd)
	if (options.strategy) {
{

	add_var(&script_snippet, "diffstat",
	}
		goto leave_reset_head;
			die(_("a base commit must be provided with --upstream or --onto"));

			options.empty = EMPTY_ASK;

	struct strbuf autostash = STRBUF_INIT;
			FREE_AND_NULL(options.head_name);
				    opts->state_dir);

	struct commit *restrict_revision;
		write_file(state_dir_path("strategy", opts), "%s",
	if (current_branch) {
		strbuf_reset(&buf);
	struct strbuf msg = STRBUF_INIT;
				&head_hash, &revisions, &shortrevisions))
		REBASE_VERBOSE = 1<<1,
			if (!options.upstream_name)
	int allow_preemptive_ff = 1;
		OPT_STRING('s', "strategy", &options.strategy,
	case REBASE_APPLY:
static GIT_PATH_FUNC(apply_dir, "rebase-apply")
		else
		const char *option = options.git_am_opts.argv[i], *p;
	}
		BUG("unexpected number of arguments left to parse");
{
	if (read_one(path, &autostash))
				die(_("could not read index"));
		OPT_STRING_LIST('X', "strategy-option", &strategy_options,
		diffcore_std(&opts);
		strbuf_reset(&buf);

			if (capture_command(&stash, &buf, GIT_MAX_HEXSZ))
		strbuf_release(&autostash);
		}
			strbuf_reset(&buf);
				       oid_to_hex(&merge_base),
		struct commit *head =

			N_("cherry-pick all commits, even if unchanged"),
			 N_("automatically re-schedule any `exec` that fails")),
cleanup:

		  N_("restrict-revision"), N_("restrict revision"),
		if (options.rebase_merges)
		OPT_CALLBACK_F(0, "empty", &options, "{drop,keep,ask}",
	}
		REBASE_DIFFSTAT = 1<<2,

			if (safe_create_leading_directories_const(autostash))

		 "\n"
		opts->gpg_sign_opt = xstrdup(buf.buf);
		OPT_BIT('v', "verbose", &opts.flags,
					 "stash", "create", "autostash", NULL);
	}
	add_var(&script_snippet, "strategy", opts->strategy);
		break;
		   opts->onto ? oid_to_hex(&opts->onto->object.oid) : "");
		strbuf_addf(&buf, "rm -fr \"%s\"", options.state_dir);
			argv_array_push(&am.args, opts->gpg_sign_opt);
}
			printf(_("Current branch %s is up to date, rebase "
			if (options.switch_to) {
			PARSE_OPT_OPTARG, NULL, (intptr_t) "" },
			goto cleanup;
				options.type = REBASE_MERGE;
}

		goto finished_rebase;
			stash.git_cmd = 1;

		opts->autosquash = git_config_bool(var, value);
		ret = check_todo_list_from_file(the_repository);
		OPT_STRING(0, "onto", &options.onto_name,
		OPT_STRING_LIST('x', "exec", &exec, N_("exec"),
	if (argc == 1)
			    N_("abort but keep HEAD where it is"), ACTION_QUIT),

		  PARSE_OPT_NONEG, parse_opt_commit, 0 },
	 * with new commits recreated by replaying their changes.
	 * If the branch to rebase is given, that is the branch we will rebase

		if (git_config_bool(var, value))
		}

		if (argc < 1) {
		const char *state_dir_base =
			 orig_head_reflog.buf, head_reflog.buf);
	if (!file_exists(path))
	if (!interactive)

		oid_to_hex(&opts->upstream->object.oid) : NULL);
		OPT_BOOL(0, "signoff", &opts.signoff, N_("sign commits")),
		if (is_directory(buf.buf)) {
	free_commit_list(merge_bases);
			free(opts->gpg_sign_opt);
		      "I wonder if you are in the middle of another rebase.  "
}
	return res && is_linear_history(onto, head);
		res = error_errno(_("could not write '%s'"), todo_file);

		opts->type == REBASE_PRESERVE_MERGES;
	}
	BUG_ON_OPT_ARG(arg);
		/* Sanity check */
			finish_rebase(opts);

			REBASE_NO_QUIET | REBASE_VERBOSE | REBASE_DIFFSTAT),
}
	case ACTION_SHOW_CURRENT_PATCH: {

	int root, root_with_onto;
			return -1;
	strbuf_addf(&head_reflog, "rebase finished: returning to %s",
	if (isatty(2) && options.flags & REBASE_NO_QUIET)

		if (!options.head_name)

		return status;
			orig = &oid_orig;
	reflog_action = getenv(GIT_REFLOG_ACTION_ENVIRONMENT);
		status = error_errno(_("could not open '%s' for reading"),
	}
	res = 1;
			exit(1);
						    options.onto_name);
		if (options.flags & REBASE_VERBOSE) {
	}
	delete_ref(NULL, "REBASE_HEAD", NULL, REF_NO_DEREF);
{
	case ACTION_NONE:
	add_var(&script_snippet, "restrict_revision", opts->restrict_revision ?
		remove_dir_recursively(&dir, 0);
		ret = error(_("failed to find tree of %s"),
	if (file_exists(state_dir_path("strategy_opts", opts))) {

		OPT_END()
	merge_bases = get_merge_bases(upstream, head);
		printf(_("If you wish to set tracking information for this "
				 NULL, 0, UPDATE_REFS_MSG_ON_ERR);
	if (!res && todo_list_write_to_file(the_repository, &new_todo, todo_file,

};
			   PARSE_OPT_HIDDEN),
	add_var(&script_snippet, "rebase_root", opts->root ? "t" : "");
		if (!to->parents)
		if (!ret)
		struct lock_file lock_file = LOCK_INIT;
	struct object_id squash_onto;
/* -i followed by -p is still explicitly interactive, but -p alone is not */

			stash.no_stdin = 1;
	argc = parse_options(argc, argv, prefix,
			"the current branch.") :
			  "You can run \"git stash pop\" or \"git stash drop\" "
			/* compatible */
	}
				die("Invalid whitespace option: '%s'", p);
		write_file(state_dir_path("quiet", opts), "%s", "");
}
	return 0;
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		goto run_rebase;
	}
		OPT_STRING(0, "strategy-opts", &opts.strategy_opts, N_("strategy-opts"),


				die(_("Could not create directory for '%s'"),
	enum rebase_type type;
	}
			argv++;
	ACTION_REARRANGE_SQUASH,
				die(_("Unexpected stash response: '%s'"),
				      "merge options"));
			   N_("the branch or commit to checkout")),
		opts->flags |= REBASE_FORCE;
				die(_("could not reset --hard"));
				error_on_missing_default_upstream();
	}




		die(_("The --edit-todo action can only be used during "
			N_("do not show diffstat of what changed upstream"),
	if (opts->gpg_sign_opt)
			options.strategy = "recursive";
	if (options.reapply_cherry_picks)

				error(_("could not remove '%s'"),
				break;
					      todo_file, NULL, NULL, -1, 0);
	 * 		  HEAD (already detached)
					 "refs/heads/", &branch_name))
			    ACTION_CONTINUE),
static const char *state_dir_path(const char *filename, struct rebase_options *opts)
{
		opts->git_format_patch_opt.buf);

				O_WRONLY | O_CREAT | O_TRUNC, 0666);
	while (nr)
			_("Applying autostash resulted in conflicts.\n"

	struct todo_list todo_list = TODO_LIST_INIT;
	struct commit *head = lookup_commit(the_repository, head_oid);
 * no merge commits. This function *expects* `from` to be an ancestor of
			strbuf_add_unique_abbrev(&buf, &oid, DEFAULT_ABBREV);

						   *head_hash);

			_("You are not currently on a branch."));
			"--rerere-autoupdate" : "--no-rerere-autoupdate" : "");
	const char *todo_file = rebase_path_todo();
		OPT_BOOL(0, "root", &options.root,
		      opts->revisions);
			options.head_name ? options.head_name : "detached HEAD",
	struct argv_array git_am_opts;
	}
		struct replay_opts replay_opts = get_replay_opts(opts);
{
		split_exec_commands(opts->cmd, &commands);
			 N_("automatically re-schedule any `exec` that fails")),
		options.rebase_merges = 1;
			N_("display a diffstat of what changed upstream"),
		if (run_command_v_opt(args.argv, RUN_GIT_CMD))
		break;
		string_list_remove_empty_items(commands, 0);
			if (fork_point < 0)
		case REBASE_MERGE:
		write_file(state_dir_path("allow_rerere_autoupdate", opts),
static GIT_PATH_FUNC(merge_dir, "rebase-merge")
		return status;
	const char *backend, *backend_func;
		printf(_("Applied autostash.\n"));
		struct string_list merge_rr = STRING_LIST_INIT_DUP;
	add_var(&script_snippet, "force_rebase",
	case ACTION_SHORTEN_OIDS:
			ret = !!sequencer_remove_state(&replay);

	}
			ret = error(_("could not remove '%s'"),
		strbuf_release(&msg);


	total_argc = argc;
		return;
	if (is_directory(opts->state_dir))
		const char *last_slash = strrchr(options.state_dir, '/');
			return 1;
	struct commit_list *merge_bases = NULL;
		die(_("The pre-rebase hook refused to rebase."));
	const char *state_dir;
		ret = edit_todo_file(flags);
			   &options.allow_empty_message,
		options.upstream = peel_committish(options.upstream_name);
	unpack_tree_opts.dst_index = the_repository->index;
	}
		replay.action = REPLAY_INTERACTIVE_REBASE;
	*revisions = xstrfmt("%s...%s", oid_to_hex(&base_rev->object.oid),
			branch = branch_get(NULL);
	case ACTION_CONTINUE: {
				      todo_file, NULL, NULL, -1, 0);
	if (strbuf_read_file(&todo_list.buf, todo_file, 0) < 0)
static struct commit *peel_committish(const char *name)
	if (strbuf_read_file(&todo_list.buf, todo_file, 0) < 0)
		OPT_END(),
	BUG_ON_OPT_NEG(unset);
"You can instead skip this commit: run \"git rebase --skip\".\n"

		BUG("action: %d", action);
	if (write_locked_index(the_repository->index, &lock, COMMIT_LOCK) < 0) {
		/* Do not need to switch branches, we are already on it. */
		if (read_one(state_dir_path("allow_rerere_autoupdate", opts),
			options.upstream_name = branch_get_upstream(branch,
			options.type = REBASE_MERGE;
	FILE *interactive;
	struct commit *onto;
			 N_("automatically stash/stash pop before and after")),

		write_file(state_dir_path("gpg_sign_opt", opts), "%s",
		die(_("It seems that there is already a %s directory, and\n"
	struct strbuf script_snippet = STRBUF_INIT, buf = STRBUF_INIT;
		opts->flags & REBASE_VERBOSE ? "t" : "");
		if (!(opts->flags & REBASE_INTERACTIVE_EXPLICIT)) {
	static size_t prefix_len;
{
		error(_("could not generate todo list"));
		string_list_clear(&merge_rr, 1);
{
	if (!strcmp(var, "rebase.stat")) {
		OPT_BOOL(0, "keep-base", &keep_base,
#define RESET_HEAD_HARD (1<<1)
	struct rebase_options *opts = opt->value;
	case REBASE_PRESERVE_MERGES:

	if (todo_list_parse_insn_buffer(the_repository, todo_list.buf.buf,
	replay.reschedule_failed_exec = opts->reschedule_failed_exec;

		OPT_CMDMODE(0, "edit-todo", &command, N_("edit the todo list"),
	return 0;
		OPT_CMDMODE(0, "show-current-patch", &action,
		return error_errno(_("could not read '%s'."), todo_file);
		goto done;
				 opts->git_format_patch_opt.buf);
	if (action == ACTION_EDIT_TODO && !is_merge(&options))
		break;
static int run_am(struct rebase_options *opts)
				   builtin_rebase_options);

	if (strbuf_read_file(&todo_list.buf, todo_file, 0) < 0)
			trace2_cmd_mode(action_names[action]);
#include "rerere.h"
		usage_with_options(builtin_rebase_usage,
	else if (!strcasecmp(value, "keep"))
	}
	if (trace2_is_enabled()) {
	    run_hook_le(NULL, "pre-rebase", options.upstream_arg,
	struct strbuf msg = STRBUF_INIT;
}
			 resolve_ref_unsafe("HEAD", 0, NULL, &flag))
			return -1;
		usage_with_options(builtin_rebase_interactive_usage, options);
			      the_hash_algo->empty_tree : &merge_base,

	} else if (argc == 0) {
				      "abort",
#include "dir.h"
		OPT_BOOL(0, "rebase-merges", &opts.rebase_merges, N_("rebase merge commits")),
	if (opts->restrict_revision)
}
		reset_head(NULL, "Fast-forwarded", options.head_name,

	N_("git rebase [-i] [options] [--exec <cmd>] [--onto <newbase>] "
	EMPTY_KEEP,
	if (upstream) {
		if (!options.onto_name) {
	strbuf_addf(&orig_head_reflog, "rebase finished: %s onto %s",

		return error_errno(_("could not write '%s'."), todo_file);
		return error(_("invalid orig-head: '%s'"), buf.buf);
		default:

				  NULL, N_("passed to 'git am'"),
		if (has_unstaged_changes(the_repository, 1) ||
	struct object_id head_oid;
	}
		if (options.type == REBASE_MERGE) {

static int finish_rebase(struct rebase_options *opts)
		    &options.orig_head, &merge_base) &&
		ret = !!finish_rebase(&options);
	ACTION_QUIT,
	struct commit *base_rev = upstream ? upstream : onto;
	};
	if (!refs_only && hold_locked_index(&lock, LOCK_REPORT_ON_ERROR) < 0) {
		strbuf_reset(&buf);

	if (!prefix_len) {
		remove_branch_state(the_repository, 0);
		break;
		.flags = REBASE_NO_QUIET, 		\
	}
			strbuf_addf(&buf, "%s/interactive", merge_dir());
}

	if (strchr(cmd, '\n'))
		else
	if (options.type == REBASE_MERGE)
	flags |= opts->reapply_cherry_picks ? TODO_LIST_REAPPLY_CHERRY_PICKS : 0;
			struct child_process stash = CHILD_PROCESS_INIT;
	argv_array_pushv(&am.args, opts->git_am_opts.argv);
	if (options.empty != EMPTY_UNSPECIFIED)
		break;
				; /* be quiet */

				 detach_head ? REF_NO_DEREF : 0,
	strbuf_addstr(&autostash, "^0");
		opts->flags &= ~REBASE_NO_QUIET;
	if (get_oid(buf.buf, &opts->orig_head))
		shortrev = find_unique_abbrev(&base_rev->object.oid,
	strbuf_setlen(&path, prefix_len);
	return ret;
	}
	case ACTION_SHOW_CURRENT_PATCH:
	memset(&unpack_tree_opts, 0, sizeof(unpack_tree_opts));
			warning(_("ignoring invalid allow_rerere_autoupdate: "
		options.dont_finish_rebase = 1;
		OPT_CMDMODE(0, "expand-ids", &command,
		goto cleanup;
		const char *shortrev;
					goto cleanup;
	if (repo_read_index(the_repository) < 0)
	}
	const char *upstream_name;
		    getenv(GIT_REFLOG_ACTION_ENVIRONMENT), options.onto_name);
		strbuf_setlen(&msg, prefix_len);

	 * Now we are rebasing commits upstream..orig_head (or with --root,
	 * If the onto is a proper descendant of the tip of the branch, then

	int res;
	BUG_ON_OPT_ARG(arg);
{
		if (get_oid_mb(options.onto_name, &merge_base) < 0) {
		goto done;
	}
		       RESET_HEAD_RUN_POST_CHECKOUT_HOOK,

			N_("shorten commit ids in the todo list"), ACTION_SHORTEN_OIDS),
			die(_("cannot combine '--preserve-merges' with "
	case ACTION_EDIT_TODO:
		argv_array_push(&options.git_am_opts, "-q");


{
	argv_array_pushf(&am.args, "--resolvemsg=%s", resolvemsg);

}
	strbuf_release(&script_snippet);
			get_fork_point(options.upstream_name, head);
		if (!options.upstream)
		argv_array_pushl(&cmd.args, "show", "REBASE_HEAD", "--", NULL);
		{ OPTION_STRING, 'S', "gpg-sign", &gpg_sign, N_("key-id"),
	strbuf_addf(&buf, "%s/applying", apply_dir());
	argv_array_push(&format_patch.args, revisions.buf);
	REBASE_UNSPECIFIED = -1,
					       RESET_HEAD_RUN_POST_CHECKOUT_HOOK,
	struct object_id *squash_onto;
	else if (opts->allow_rerere_autoupdate == RERERE_NOAUTOUPDATE)
	*head_hash = find_unique_abbrev(orig_head, GIT_MAX_HEXSZ);
		new_todo = TODO_LIST_INIT;
		if (get_oid("HEAD", &head))
			update_ref(reflog_orig_head, "ORIG_HEAD", orig,
		ret = run_command(&cmd);
	    !(opts->flags & REBASE_INTERACTIVE_EXPLICIT)) {

		    opts->head_name, oid_to_hex(&opts->onto->object.oid));
	add_var(&script_snippet, "revisions", opts->revisions);
			die(_("Does not point to a valid commit '%s'"),

	else if (!strcasecmp(value, "ask"))
			BUG("unhandled rebase type (%d)", options.type);
	else
			else
	struct tree *tree;
		opts->strategy_opts = xstrdup(buf.buf);
		case REBASE_PRESERVE_MERGES:
			REBASE_FORCE),
	N_("git rebase--interactive [<options>]"),
			N_("use merging strategies to rebase"),
		.type = REBASE_UNSPECIFIED,	  	\


	BUG_ON_OPT_NEG(unset);
		oid_to_hex(&opts->restrict_revision->object.oid) : NULL);
		argv_array_clear(&am.args);
				 oid_to_hex(&opts->restrict_revision->object.oid));
		} else
		OPT_RERERE_AUTOUPDATE(&options.allow_rerere_autoupdate),
	struct todo_list todo_list = TODO_LIST_INIT;
static void imply_merge(struct rebase_options *opts, const char *option);
		return EMPTY_DROP;
		OPT_PASSTHRU_ARGV(0, "committer-date-is-author-date",
		}
			options.empty = EMPTY_KEEP;
		goto done;
	default:
	flags |= opts->root_with_onto ? TODO_LIST_ROOT_WITH_ONTO : 0;

	}
		in_progress = 1;
static int reset_head(struct object_id *oid, const char *action,

			return -1;
	if (opts->action && !strcmp("continue", opts->action)) {
		run_hook_le(NULL, "post-checkout",

		OPT_PASSTHRU_ARGV(0, "whitespace", &options.git_am_opts,
			argv_array_pushl(&stash.args,
		BUG("move_to_original_branch without onto");
		strbuf_addf(&path, "%s/", opts->state_dir);
			else if (!strcmp(branch_name, "HEAD") &&
	struct strbuf buf = STRBUF_INIT;

			PARSE_OPT_NOARG | PARSE_OPT_NONEG,
		if (todo_list_parse_insn_buffer(the_repository, todo_list.buf.buf,
}
				      "skip",
}
		opts->squash_onto ? oid_to_hex(opts->squash_onto) : "");
	add_var(&script_snippet, "squash_onto",
		opts->signoff = 1;
		{ OPTION_STRING, 'S', "gpg-sign", &opts.gpg_sign_opt, N_("key-id"),
	struct object_id orig_head;
		}
		replay.allow_rerere_auto = opts->allow_rerere_autoupdate;
		if (get_oid("HEAD", &options.orig_head))
		if (!strcmp(buf.buf, "--rerere-autoupdate"))
		imply_merge(&options, "--exec");

			exit(1);
		 "\n"),
			 "\n"
		argv_array_push(&am.args, "--skip");
					      "numerical value"));

		return EMPTY_ASK;

	if (opts->strategy)
	ret = !!run_specific_rebase(&options, action);
		ret = complete_action(the_repository, &replay, flags,
		imply_merge(&options, "--rebase-merges");

	NULL
		die(_("--reschedule-failed-exec requires "
static int transform_todo_file(unsigned flags)
		diff_flush(&opts);
			xstrdup("-S") : NULL;
		opts->flags |= REBASE_VERBOSE;
	struct object_id oid;
			/* Lazily switch to the target branch if needed... */
	} else
		opts->gpg_sign_opt = git_config_bool(var, value) ?
			   N_("be quiet. implies --no-stat"),
		options.dont_finish_rebase = 1;
			die(_("No such ref: %s"), "HEAD");
		else

		rollback_lock_file(&lock_file);
				       oid_to_hex(&options.onto->object.oid));


		return error_errno(_("could not write '%s'."), todo_file);
	add_var(&script_snippet, "rebase_merges",
	}
	if (restrict_revision && !oideq(&restrict_revision->object.oid, merge_base))
		imply_merge(&options, "--reapply-cherry-picks");
				strbuf_addstr(&msg, "updating ORIG_HEAD");
		      "have something\n"
			exit(1);
			  "at any time.\n"));
			parse_opt_keep_empty },
#include "packfile.h"
	}
			options.type = REBASE_PRESERVE_MERGES;
static int can_fast_forward(struct commit *onto, struct commit *upstream,

		break;
#include "run-command.h"
		     oid_to_hex(&options.restrict_revision->object.oid) :

		OPT_NEGBIT('q', "quiet", &options.flags,

		opts->head_name ? opts->head_name : "detached HEAD");
			/* remove the leading "-S" */
	exit(1);
{
	ret = reset_head(NULL, "", opts->head_name, RESET_HEAD_REFS_ONLY,
	case REBASE_PRESERVE_MERGES:
}
	unsigned reset_hard = flags & RESET_HEAD_HARD;
		}
		{ OPTION_CALLBACK, 'm', "merge", &options, NULL,
			 N_("apply all changes, even those already present upstream")),
	oidcpy(merge_base, &merge_bases->item->object.oid);
		OPT_SET_INT_F('p', "preserve-merges", &options.type,
			    oid_to_hex(&options.orig_head));
			"these revisions:\n"
				   builtin_rebase_options);
			die(_("error: cannot combine '--preserve-merges' with "
	if (options.flags & REBASE_NO_QUIET)

			printf(_("Created autostash: %s\n"), buf.buf);
	if (!(options.flags & REBASE_NO_QUIET))
	return ret;
		goto cleanup;
			 N_("add a Signed-off-by: line to each commit")),

	if (opts->flags & REBASE_VERBOSE)
	if (opts->type == REBASE_MERGE) {
	free(shortrevisions);
		xstrdup(head_name.buf) : NULL;
	}

		int fd;
		strbuf_addf(buf, "unset %s; ", name);
		*shortrevisions = xstrdup(shorthead);
	int rebase_merges, rebase_cousins;
	char *squash_onto_name = NULL;
	return ret;
				state_dir_path("autostash", &options);
	if (fork_point > 0) {
		    ". git-sh-setup && . %s && %s", backend, backend_func);
			      "'--rebase-merges'"));
		if (!options.strategy)
		  N_("squash onto"), PARSE_OPT_NONEG, parse_opt_object_id, 0 },
						      options.switch_to);
			    branch_name);
	if (in_progress) {
	} else {
			strbuf_reset(&buf);
	return 0;
	if (!head)

	if (!strcmp(var, "rebase.autostash")) {
	BUG_ON_OPT_NEG(unset);
			replay.action = REPLAY_INTERACTIVE_REBASE;
			   N_("strategy options")),

		parse_commit(to);
			return res;
	char *head_name;
		status = run_am(opts);
			N_("expand commit ids in the todo list"), ACTION_EXPAND_OIDS),
	const char *switch_to;
		oidcpy(merge_base, &null_oid);
	strbuf_release(&head_name);
	/* Ensure that the hash is not mistaken for a number */

	}

	}
		imply_merge(&options, "--empty");

			options.root_with_onto = 1;
{
			if (!skip_prefix(options.head_name,
	todo_list_release(&todo_list);

				    strategy_options.items[i].string);
		      const char *reflog_orig_head, const char *reflog_head)
}
	int fork_point = -1;
	add_var(&script_snippet, "head_name",
"\"git rebase --abort\".");
	}
		   opts->head_name ? opts->head_name : "detached HEAD");
		if (opts->gpg_sign_opt)
	const char *argv[] = { NULL, NULL };
	if (res)
		"--root [<branch>]"),
	}
}
		{ OPTION_CALLBACK, 'i', "interactive", &options, NULL,


	argv[0] = script_snippet.buf;

	flags |= command == ACTION_SHORTEN_OIDS ? TODO_LIST_SHORTEN_IDS : 0;
		{ OPTION_CALLBACK, 'k', "keep-empty", &options, NULL,
			 "--no-cover-letter", "--pretty=mboxrd", "--topo-order",

	return 0;
	}
	struct argv_array make_script_args = ARGV_ARRAY_INIT;
			opts->flags |= REBASE_DIFFSTAT;
	if (!oideq(&onto->object.oid, &merge_bases->item->object.oid))
 * `to`.


	if ((options.flags & REBASE_INTERACTIVE_EXPLICIT) ||

static int check_exec_cmd(const char *cmd)
		OPT_CMDMODE(0, "quit", &action,
	if (!opts->onto)
	if (opts->dont_finish_rebase)
	}
		break;
		rerere_clear(the_repository, &merge_rr);
		break;
	struct object_id squash_onto = null_oid;
		  PARSE_OPT_NONEG, parse_opt_commit, 0 },
				options.type = REBASE_APPLY;
		for (i = 0; i < exec.nr; i++)
				int unset)
			setenv("GIT_SEQUENCE_EDITOR", ":", 1);



	case REBASE_APPLY:
				       oid_to_hex(&options.onto->object.oid));
	if (!strcmp(var, "rebase.reschedulefailedexec")) {
	}
		goto run_rebase;
	if (argc > 2)
	const char *upstream_arg;
		strbuf_reset(&buf);
/*
				    make_script_args.argc, make_script_args.argv,

		oid = &head_oid;
		strbuf_addf(&buf, "refs/heads/%s", branch_name);
		    options.root ? oid_to_hex(&options.onto->object.oid) :
			die(_("could not read index"));
		break;
			    N_("show the patch file being applied or merged"),
		return error(_("Could not read '%s'"), path);
			parse_opt_merge },
		} else {
			struct replay_opts replay = REPLAY_OPTS_INIT;
	default:
	return 0;



	res = todo_list_write_to_file(the_repository, &todo_list,
		OPT_BOOL(0, "reschedule-failed-exec", &opts.reschedule_failed_exec,
}
	if (opts->action && !strcmp("skip", opts->action)) {
		break;
		strbuf_addstr(&options.git_format_patch_opt, " --progress");
			PARSE_OPT_OPTARG, NULL, (intptr_t)""},
			REBASE_FORCE),
/* Initialize the rebase options from the state directory. */
				die(_("cannot combine apply options with "
				     rebased_patches);
	int status;
	ACTION_SKIP,
static int is_merge(struct rebase_options *opts)
			 N_("use 'merge-base --fork-point' to refine upstream")),
	}
		BUG("invalid command '%d'", command);
	strbuf_addf(&revisions, "%s..%s",
		ret = -1;
		/* all am options except -q are compatible only with --apply */
	strbuf_release(&autostash);
	struct replay_opts replay = REPLAY_OPTS_INIT;
}
		return 0;
{
			    "during an interactive rebase"), ACTION_EDIT_TODO),
		struct strbuf dir = STRBUF_INIT;
	struct rebase_options *options = opt->value;
			options.type = REBASE_APPLY;
	opts.rebase_cousins = -1;
	struct unpack_trees_options unpack_tree_opts;
			      &options.onto->object.oid, "", &opts);
	int autosquash;
	static struct strbuf path = STRBUF_INIT;
{
{
	}
	if (file_exists(state_dir_path("allow_rerere_autoupdate", opts))) {
static char const * const builtin_rebase_usage[] = {

				  "'%s'"), buf.buf);
			N_("rearrange fixup/squash lines"), ACTION_REARRANGE_SQUASH),
	}
}
static int do_interactive_rebase(struct rebase_options *opts, unsigned flags)
		allow_preemptive_ff = 0;
}
	stash_apply.no_stderr = stash_apply.no_stdout =
	res = todo_list_rearrange_squash(&todo_list);
		options.upstream_arg = "--root";

			    oid_to_hex(orig ? orig : &null_oid),
				die(_("'%s': need exactly one merge base"),
					    options.switch_to);
	if (options.empty == EMPTY_UNSPECIFIED) {
{
		diff_setup_done(&opts);
static int parse_opt_interactive(const struct option *opt, const char *arg,
	init_checkout_metadata(&unpack_tree_opts.meta, switch_to_branch, oid, NULL);
		OPT_CMDMODE(0, "continue", &command, N_("continue rebase"),
		options.upstream_name = NULL;
			char *tmp = xstrdup(opts->gpg_sign_opt + 2);
			options.squash_onto = &squash_onto;
		options.action = "continue";
	 */
		else if (!strcmp(branch_name, "HEAD") &&
		if (options.onto_name)
	}
static int add_exec_commands(struct string_list *commands)
	}
	struct option options[] = {

		todo_list_release(&todo_list);
		ret = error(_("could not read index"));
	if (read_one(state_dir_path("head-name", opts), &head_name) ||
				fork_point = 1;
{

	}
		set_reflog_action(&options);
	/* Make sure the branch to rebase onto is valid. */
			if (reset_head(NULL, "reset --hard",
};

			trace2_cmd_mode("interactive");
		OPT_PASSTHRU_ARGV(0, "ignore-date", &options.git_am_opts, NULL,
			       NULL, NULL) < 0)
		struct string_list merge_rr = STRING_LIST_INIT_DUP;
		return 0; /* nothing to move back to */
	if (!upstream)
	if (file_exists(state_dir_path("orig-head", opts))) {
}

			    &buf))
}
		argv_array_clear(&am.args);
			if (discard_index(the_repository->index) < 0 ||
		int flag;
	int res = 0;
	if (options.git_am_opts.argc || options.type == REBASE_APPLY) {
		struct object_id head;


		OPT_BOOL(0, "no-verify", &ok_to_skip_pre_rebase,

		OPT_STRING(0, "cmd", &opts.cmd, N_("cmd"), N_("the command to run")),
			builtin_rebase_interactive_usage, PARSE_OPT_KEEP_ARGV0);
	struct object_id oid;
	} else if (!options.onto_name)
		struct child_process cmd = CHILD_PROCESS_INIT;
		else
#include "diff.h"
reset_head_refs:
		return error(_("exec commands cannot contain newlines"));
	unpack_tree_opts.head_idx = 1;
static void set_reflog_action(struct rebase_options *options)
	/*
			if (is_merge(&options))
		options.cmd = xstrdup(buf.buf);
	}
	}
		die(_("%s requires the merge backend"), option);
	free(options.cmd);
	ACTION_SHOW_CURRENT_PATCH,
struct rebase_options {
		imply_merge(&options, "--merge");
static int get_revision_ranges(struct commit *upstream, struct commit *onto,

finished_rebase:
		fd = hold_locked_index(&lock_file, 0);
	if (argc == 2 && !strcmp(argv[1], "-h"))
		strbuf_release(&dir);
			die_if_checked_out(buf.buf, 1);
		if (!options.onto)
	}

			 "it...\n"));
	if (opts->git_format_patch_opt.len)

}
			die(_("Cannot read HEAD"));



			     opts->onto, head_hash)) {
int cmd_rebase(int argc, const char **argv, const char *prefix)
		/* rebase.c adds a new line to cmd after every command,
	} else {
/* -i followed by -m is still -i */
		strbuf_reset(&buf);
		return error_errno(_("could not write '%s'."), todo_file);

	if (!options.root) {

			strbuf_trim_trailing_newline(&buf);
			   opts->allow_rerere_autoupdate == RERERE_AUTOUPDATE ?
	strbuf_reset(&buf);
	if (is_merge(opts) &&
};
	replay.signoff = opts->signoff;
	char *rebased_patches;
	struct replay_opts replay = get_replay_opts(opts);
		strbuf_reset(&buf);
		return 0;

	if (!strcmp(var, "rebase.usebuiltin")) {
	if (!strcasecmp(value, "drop"))
		argv_array_pushf(&make_script_args, "^%s",
#define GIT_REFLOG_ACTION_ENVIRONMENT "GIT_REFLOG_ACTION"
	const char *action;
		options.strategy = xstrdup(options.strategy);
	struct strbuf head_name = STRBUF_INIT;
		int res = 0;

		      "case, please try\n\t%s\n"
	add_var(&script_snippet, "allow_rerere_autoupdate",
				N_("pass the argument through to the merge "
			last_slash ? last_slash + 1 : options.state_dir;
			N_("GPG-sign commits"),
	opts->flags |= REBASE_INTERACTIVE_EXPLICIT;
		/* Is it a local branch? */
		fd = hold_locked_index(&lock_file, 0);
	string_list_clear(&commands, 0);
			   REBASE_NO_QUIET | REBASE_VERBOSE | REBASE_DIFFSTAT),
		if (options.type == REBASE_PRESERVE_MERGES)
			if (strcmp(options.git_am_opts.argv[i], "-q"))
	char *cmd;
		sq_quote_buf(buf, value);
		OPT_BOOL_F(0, "allow-empty-message",
					    NULL, NULL, -1, flags & ~(TODO_LIST_SHORTEN_IDS)))
	return res;
			if (is_null_oid(&merge_base))

	}
		options.upstream_arg = options.upstream_name;
		if (read_one(state_dir_path("orig-head", opts), &buf))

	ACTION_CHECK_TODO_LIST,
		status = run_sequencer_rebase(opts, action);

		opts->type = REBASE_MERGE;
				printf(_("Current branch %s is up to date.\n"),
	free(options.head_name);
		ret = error(_("could not determine HEAD revision"));
	 * in which case we could fast-forward without replacing the commits
#include "unpack-trees.h"
	imply_merge(opts, unset ? "--no-keep-empty" : "--keep-empty");
	if (update_orig_head) {

	FREE_AND_NULL(options.gpg_sign_opt);
			strbuf_addf(&buf, " --%s",
	switch (opts->type) {
	case REBASE_PRESERVE_MERGES:
	strbuf_release(&buf);
		if (opts->gpg_sign_opt) {
	add_var(&script_snippet, "orig_head", oid_to_hex(&opts->orig_head));
		oid_to_hex(&opts->onto->object.oid) : NULL);
					&squash_onto, NULL, NULL) < 0)
				 resolve_ref_unsafe("HEAD", 0, NULL, &flag))
		if (options.root)
		options.restrict_revision =
	replay.action = REPLAY_INTERACTIVE_REBASE;
	size_t prefix_len;
	replay.gpg_sign = xstrdup_or_null(opts->gpg_sign_opt);
	case ACTION_EXPAND_OIDS:
static int edit_todo_file(unsigned flags)
		opts->flags & REBASE_DIFFSTAT ? "t" : "");
	if (!strcmp(var, "commit.gpgsign")) {
	}
	unlink(rebased_patches);
	struct strbuf revisions = STRBUF_INIT;
		diff_setup(&opts);

			struct object_id oid;
static GIT_PATH_FUNC(path_interactive, "rebase-merge/interactive")
			die(_("could not move back to %s"),
};
}
		strbuf_addstr(&buf, options.upstream_name);
#include "builtin.h"
		die(_("Could not detach HEAD"));

			       struct object_id *orig_head, const char **head_hash,
	if (is_merge(&options))
	}
		options.action = "skip";
		struct string_list merge_rr = STRING_LIST_INIT_DUP;
	 */

	EMPTY_UNSPECIFIED = -1,

	int dont_finish_rebase;
	strbuf_release(&orig_head_reflog);
			       "mark them as resolved using git add"));
		opts.output_format |=

		 */
		return error_errno(_("could not create temporary %s"), merge_dir());
	struct strbuf dir = STRBUF_INIT;
	argv_array_pushl(&stash_apply.args,
{
		status = run_command(&am);
}
static int rearrange_squash_in_todo_file(void)
{

		*shortrevisions = xstrfmt("%s..%s", shortrev, shorthead);
		goto leave_reset_head;
				branch_name = options.head_name;
	if (file_exists(state_dir_path("signoff", opts))) {
	int autostash;
	}
		} else {
				    buf.buf);
		if (!*rebase_merges)
	if (opts.rebase_cousins >= 0 && !opts.rebase_merges)
	/* Detach HEAD and reset the tree */
			N_("check the todo list"), ACTION_CHECK_TODO_LIST),
	return 0;
{
	}
		    oid_to_hex(&opts->orig_head));
static int parse_opt_keep_empty(const struct option *opt, const char *arg,
			opts->gpg_sign_opt = tmp;
			exit(1);
	};
			write_file(autostash, "%s", oid_to_hex(&oid));
			options.rebase_cousins = 1;
	if (!run_command(&stash_apply))
		goto leave_reset_head;
	const char *reflog_action;
	struct object_id merge_base;
#define RESET_HEAD_DETACH (1<<0)
				  N_("action"), N_("passed to 'git apply'"), 0),
			    ACTION_SHOW_CURRENT_PATCH),
	int status;
			 "    git branch --set-upstream-to=%s/<branch> %s\n"
		goto run_rebase;
	struct strbuf git_format_patch_opt;
{
			     opts->head_name ? opts->head_name : "detached HEAD",
				N_("option"),
	add_var(&script_snippet, "action", opts->action ? opts->action : "");
				      NULL, NULL, -1, flags);


			options.flags |= REBASE_INTERACTIVE_EXPLICIT;
/* Returns the filename prefixed by the state_dir */
	BUG_ON_OPT_NEG(unset);
	N_("git rebase --continue | --abort | --skip | --edit-todo"),
	free_commit_list(merge_bases);

	int ret;
			parse_opt_am },
	}
			die(_("could not discard worktree changes"));
	struct string_list strategy_options = STRING_LIST_INIT_NODUP;
		OPT_NEGBIT(0, "ff", &opts.flags, N_("allow fast-forward"),
		return error_errno(_("could not read '%s'."), todo_file);
		to = to->parents->item;
		return error_errno(_("could not read '%s'"), path);
			ret = !!finish_rebase(&options);
	strbuf_release(&buf);
				  N_("passed to 'git apply'"), 0),
	if (file_exists(state_dir_path("strategy", opts))) {
		apply_autostash(opts);
			 "--no-base", NULL);
		if (to->parents->next)
	git_config_get_bool("rebase.abbreviatecommands", &abbreviate_commands);
	const char *todo_file = rebase_path_todo();
		{OPTION_NEGBIT, 'n', "no-stat", &options.flags, NULL,
}
			PARSE_OPT_NOARG, NULL, REBASE_DIFFSTAT },
		string_list_clear(&merge_rr, 1);
	}
			if (ret)
	replay.keep_redundant_commits = (opts->empty == EMPTY_KEEP);
#include "rebase-interactive.h"
		OPT_CMDMODE(0, "edit-todo", &action, N_("edit the todo list "
	if (am.in < 0) {

	add_var(&script_snippet, "GIT_DIR", absolute_path(get_git_dir()));

		else if (!strcmp(options.default_backend, "apply"))
	int res = 0;
		argv_array_pushf(&am.args, "--resolvemsg=%s", resolvemsg);

int cmd_rebase__interactive(int argc, const char **argv, const char *prefix)
		opts->rebase_cousins ? "t" : "");
{
				N_("add exec lines after each commit of the "
				      "continue",

			      REBASE_PRESERVE_MERGES, PARSE_OPT_HIDDEN),


					&todo_list)) {
	if (ret)
			"git rebase (--continue | --abort | --skip)";
		argv_array_pushl(&args,
	else {
	run_command_v_opt(argv_gc_auto, RUN_GIT_CMD);
	if (is_directory(apply_dir())) {
	gpg_sign = options.gpg_sign_opt ? "" : NULL;
		ret = do_interactive_rebase(opts, flags);
		argv_array_pushf(&am.args, "--resolvemsg=%s", resolvemsg);
		return -1;
		struct string_list commands = STRING_LIST_INIT_DUP;
	return ret;
		struct diff_options opts;
	die(_("unrecognized empty type '%s'; valid values are \"drop\", \"keep\", and \"ask\"."), value);
		strbuf_release(&dir);
		unlink(rebased_patches);
			PARSE_OPT_NOARG | PARSE_OPT_HIDDEN,
			branch_name, options.onto_name);
	unpack_tree_opts.update = 1;
	if (argc == 1) {
enum rebase_type {
		.default_backend = "merge",	  	\

{
					    getenv(GIT_REFLOG_ACTION_ENVIRONMENT),
	if (file_exists(state_dir_path("gpg_sign_opt", opts))) {
		return error(_("unusable todo list: '%s'"), todo_file);
	if (!value)
		strbuf_addf(&msg, "rebase finished: %s onto %s",
	replay.allow_ff = !(opts->flags & REBASE_FORCE);
		*old_orig = NULL, oid_old_orig;
	write_file(state_dir_path("onto", opts), "%s",
		case REBASE_UNSPECIFIED:
	/*
		free(opts->gpg_sign_opt);
"To abort and get back to the state before \"git rebase\", run "
			 "branch you can do so with:\n"
{
		ret = transform_todo_file(flags);
	setup_unpack_trees_porcelain(&unpack_tree_opts, action);
			     builtin_rebase_options,
	 * We ignore errors in 'gc --auto', since the
		warning(_("the rebase.useBuiltin support has been removed!\n"
#include "refs.h"
			   N_("strategy"), N_("use the given merge strategy")),
	add_var(&script_snippet, "autosquash", opts->autosquash ? "t" : "");
	if (oideq(&merge_base, &options.orig_head)) {
		printf(_("Fast-forwarded %s to %s.\n"),
						&options.orig_head);
		goto done;
	replay.verbose = opts->flags & REBASE_VERBOSE;
		argv_array_push(&options.git_am_opts, "--signoff");
enum empty_type {

		ret = 1;
		return move_to_original_branch(opts);

	if (opts->type == REBASE_MERGE) {
			DIFF_FORMAT_SUMMARY | DIFF_FORMAT_DIFFSTAT;
		    !strcmp(option, "--whitespace=strip"))
		ret = error(_("could not write index"));
	struct rebase_options *opts = opt->value;
			&commands, opts->autosquash, &todo_list);
	}
	int ret = 0, nr = 0;

	todo_list_release(&todo_list);

		return EMPTY_KEEP;
	struct todo_list todo_list = TODO_LIST_INIT;

		options.action = "abort";

	opts->onto = lookup_commit_or_die(&oid, buf.buf);

	struct rebase_options *opts = data;
	if (gpg_sign)
		rerere_clear(the_repository, &merge_rr);

}
	case ACTION_CONTINUE: {

	int signoff;

	N_("git rebase [-i] [options] [--exec <cmd>] "
		ret = -1;
	opts->type = REBASE_MERGE;

	if (res)
		imply_merge(&options, "--root without --onto");
		opts.squash_onto = &squash_onto;
			N_("mode"),
		}
	struct rebase_options opts = REBASE_OPTIONS_INIT;
					 &flags));
	if ((!oid || !reset_hard) && get_oid("HEAD", &head_oid)) {
	free(options.gpg_sign_opt);
	const char *path = state_dir_path("autostash", opts);
		stash_apply.no_stdin = 1;
	unsigned update_orig_head = flags & RESET_ORIG_HEAD;
				printf(_("Changes to %s:\n"),

{
static void add_var(struct strbuf *buf, const char *name, const char *value)
	}
}
	    allow_preemptive_ff) {
		 "See git-rebase(1) for details.\n"
			 "--src-prefix=a/", "--dst-prefix=b/", "--no-renames",
		return NULL;
	flags |= opts->rebase_merges ? TODO_LIST_REBASE_MERGES : 0;
	int reapply_cherry_picks;
	obj = parse_object(the_repository, &oid);
	return 1;

		set_reflog_action(&options);


	argv_array_clear(&make_script_args);

}
	if (require_clean_work_tree(the_repository, "rebase",
		if (status)
			die(_("cannot combine '--keep-base' with '--onto'"));
			 N_("use the merge-base of upstream and branch as the current base")),
		return move_to_original_branch(opts);
	}
			N_("try to rebase merges instead of skipping them"),
					ret = !!error(_("could not switch to "

	if (format_patch.out < 0) {
	for (i = 0; i < options.git_am_opts.argc; i++) {
		setenv("GIT_CHERRY_PICK_HELP", resolvemsg, 1);

}
	/* Make sure no rebase is in progress */
static int move_to_original_branch(struct rebase_options *opts)
	case ACTION_ADD_EXEC: {

			opts->allow_rerere_autoupdate == RERERE_AUTOUPDATE ?
	struct child_process am = CHILD_PROCESS_INIT;
			old_orig = &oid_old_orig;
	switch (opts->type) {

		OPT_CMDMODE(0, "show-current-patch", &command, N_("show the current patch"),
		parse_strategy_opts(&replay, opts->strategy_opts);
}
enum action {

		strbuf_reset(&buf);
#include "branch.h"
		free(rebased_patches);
		}
		options.action = "show-current-patch";

	interactive = fopen(path_interactive(), "w");

			       char **revisions, char **shortrevisions)
	if (!oid)
		backend_func = "git_rebase__preserve_merges";
		strbuf_release(&revisions);
	ret = sequencer_make_script(the_repository, &todo_list.buf,
	}
	int ok_to_skip_pre_rebase = 0;
		{ OPTION_CALLBACK, 'k', "keep-empty", &options, NULL,
	if (!strcmp(var, "rebase.autosquash")) {
}
		else if (!strcmp("rebase-cousins", rebase_merges))
	}
		OPT_CMDMODE(0, "continue", &action, N_("continue"),
	merge_bases = get_merge_bases(onto, head);
			   N_("rebase onto given branch instead of upstream")),
static int parse_opt_merge(const struct option *opt, const char *arg, int unset)
	if (refs_only)
	write_file(state_dir_path("head-name", opts), "%s",
static int apply_autostash(struct rebase_options *opts)
		if (reset_head(&options.orig_head, "reset",
		return git_config_string(&opts->default_backend, var, value);
		printf(_("First, rewinding head to replay your work on top of "
		if (!strcmp(options.default_backend, "merge"))
	delete_reflog("REBASE_HEAD");
			PARSE_OPT_NOARG | PARSE_OPT_NONEG,
		return -1;
	else {
			exit(1);
	BUG_ON_OPT_ARG(arg);
#include "commit-reach.h"
			    N_("skip current patch and continue"), ACTION_SKIP),
	}
			if (get_oid(buf.buf, &oid))
	switch (options.type) {
	setenv(GIT_REFLOG_ACTION_ENVIRONMENT, buf.buf, 1);
				       branch_name);
	options.allow_empty_message = 1;
		argv_array_push(&am.args, "--rerere-autoupdate");
	/*
				 UPDATE_REFS_MSG_ON_ERR);

		opts->allow_empty_message ?  "--allow-empty-message" : "");
	} else if (is_directory(merge_dir())) {
	if (!opts->upstream && opts->squash_onto)
	struct rebase_options *opts = opt->value;
			   opts->strategy_opts);
				xstrdup(oid_to_hex(&squash_onto));
	const char *argv_gc_auto[] = { "gc", "--auto", NULL };
				options.type = REBASE_MERGE;
run_rebase:
		if (reset_head(NULL, "reset", NULL, RESET_HEAD_HARD,

			opts->allow_rerere_autoupdate = RERERE_NOAUTOUPDATE;

			; /* be quiet */

			       NULL, NULL) < 0)
		discard_cache();
				options.flags |= REBASE_INTERACTIVE_EXPLICIT;
	case ACTION_CHECK_TODO_LIST:

	default:
		opts->flags |= REBASE_NO_QUIET;
	case ACTION_EDIT_TODO:
		} else {
	if (action != ACTION_NONE && total_argc != 2) {

		break;
	for (i = 0; i < exec.nr; i++)
			const char *autostash =
	}
	}
	todo_list_release(&todo_list);
	int reschedule_failed_exec = -1;
		BUG("Not a fully qualified branch: '%s'", switch_to_branch);
	ACTION_ABORT,
}



	if (!merge_bases || merge_bases->next)
			       /* this is now equivalent to !opts->upstream */
	}
	flags |= abbreviate_commands ? TODO_LIST_ABBREVIATE_CMDS : 0;
	ACTION_SHORTEN_OIDS,
			parse_opt_keep_empty },
	return replay;
		    state_dir_base, cmd_live_rebase, buf.buf);
	if (!opts->head_name)
	char *strategy, *strategy_opts;
	strbuf_addf(&script_snippet,
	status = run_command(&format_patch);
		backend = "git-rebase--preserve-merges";
	return git_default_config(var, value, data);
	/*
	strbuf_release(&revisions);
			return 0;
		die(_("No rebase in progress?"));
	}
		options.type = REBASE_APPLY;
	} flags;

	return 0;

	}
		{ OPTION_CALLBACK, 0, "upstream", &opts.upstream, N_("upstream"),
			argc ? argv[0] : NULL, NULL))
	struct string_list exec = STRING_LIST_INIT_NODUP;
		argv_array_pushf(&format_patch.args, "^%s",

			   opts->strategy);
	apply_autostash(opts);

		warning(_("git rebase --preserve-merges is deprecated. "
		opts->allow_rerere_autoupdate ?
	int res = 0;
				   builtin_rebase_options);
			opts->allow_rerere_autoupdate = RERERE_AUTOUPDATE;

		return error(_("unusable todo list: '%s'"), todo_file);

		/* We want color (if set), but no pager */
		options.head_name =
	strbuf_addf(&buf, "rebase (%s)", options->action);
			      N_("(DEPRECATED) try to recreate merges instead of "
};
	 */
		opts->strategy = xstrdup(buf.buf);
			branch_name = "HEAD";
		usage_with_options(builtin_rebase_usage,
		if (flags & REF_ISSYMREF) {
		if (status)


			   "-%s-rerere-autoupdate",
		write_file(state_dir_path("verbose", opts), "%s", "");
	replay.allow_empty = 1;
			 N_("allow pre-rebase hook to run")),
		OPT_BOOL(0, "autosquash", &options.autosquash,

	if (options.type != REBASE_UNSPECIFIED)
	sq_quote_argv_pretty(&buf, opts->git_am_opts.argv);
static const char *resolvemsg =
			    &buf))
	shorthead = find_unique_abbrev(orig_head, DEFAULT_ABBREV);
		OPT_STRING(0, "strategy", &opts.strategy, N_("strategy"),

	if (rebase_merges) {
		options.state_dir = merge_dir();
	/*
		return 0;
	}

	add_var(&script_snippet, "keep_empty", opts->keep_empty ? "yes" : "");
		status = error_errno(_("could not open '%s' for writing"),
			   N_("allow rebasing commits with empty messages"),
	 * we just fast-forwarded.
		strbuf_addf(buf, "%s=", name);
			    options.default_backend);
static const char * const builtin_rebase_interactive_usage[] = {
	replay.strategy = opts->strategy;
		options.onto = peel_committish(options.onto_name);
		} else if (!(options.flags & REBASE_NO_QUIET))
		else if (!strcmp(buf.buf, "--no-rerere-autoupdate"))
		if (read_basic_state(&options))

			ret = create_symref("HEAD", switch_to_branch,
	const char *revisions;
	ACTION_ADD_EXEC
		free(shortrevisions);
			allow_preemptive_ff = 0;
		if (!get_oid("HEAD", &oid_orig)) {
		diff_tree_oid(is_null_oid(&merge_base) ?
	EMPTY_DROP,
		if (res)
#include "config.h"
		; /* do nothing */
	}
				strbuf_addf(&buf, "%s: checkout %s",

	strbuf_release(&msg);
#include "exec-cmd.h"
		add_var(&script_snippet, "switch_to", opts->switch_to);
		.keep_empty = 1,			\
			    oid_to_hex(&head_oid));
			options.head_name = NULL;
	else {
#include "parse-options.h"
		OPT_BOOL(0, "reapply-cherry-picks", &options.reapply_cherry_picks,
	}
 *
	if (todo_list_parse_insn_buffer(the_repository, todo_list.buf.buf,
	free(revisions);
		else
			N_("insert exec commands in todo list"), ACTION_ADD_EXEC),
			N_("cherry-pick all commits, even if unchanged"),


		todo_list_release(&todo_list);

	opts->head_name = starts_with(head_name.buf, "refs/") ?
	if (opts->action && !strcmp("show-current-patch", opts->action)) {
					&todo_list)) {
		ret = error(_("failed to find tree of %s"), oid_to_hex(oid));
	if(file_exists(buf.buf))
		options.state_dir = apply_dir();
	add_var(&script_snippet, "state_dir", opts->state_dir);
N_("Resolve all conflicts manually, mark them as resolved with\n"
			PARSE_OPT_NOARG | PARSE_OPT_NONEG,

#include "commit.h"
		if (0 <= fd)
				  PARSE_OPT_NOARG),
				 "ignoring them"),
static int is_linear_history(struct commit *from, struct commit *to)
	return ret;
			   REBASE_FORCE),
			PARSE_OPT_OPTARG, NULL, (intptr_t) "" },
	if (strbuf_read_file(buf, path, 0) < 0)
				   old_orig, 0, UPDATE_REFS_MSG_ON_ERR);
	add_var(&script_snippet, "verbose",
		BUG("options.type was just set above; should be unreachable.");
	} else
	}
	strbuf_reset(&msg);


	if (options.type == REBASE_UNSPECIFIED) {
		todo_list_release(&todo_list);
	free(squash_onto_name);
	if (!reflog_head) {
};
	struct strbuf revisions = STRBUF_INIT;

	flags |= opts->rebase_cousins > 0 ? TODO_LIST_REBASE_COUSINS : 0;
			die("cannot combine '--signoff' with "
	}
	}

		opts->reschedule_failed_exec = git_config_bool(var, value);
		OPT_BIT('v', "verbose", &options.flags,
		write_file(state_dir_path("strategy_opts", opts), "%s",
	unsigned detach_head = flags & RESET_HEAD_DETACH;
	if (!is_directory(merge_dir()) && mkdir_in_gitdir(merge_dir()))
		warning(_("--[no-]rebase-cousins has no effect without "
			       &opts->upstream->object.oid),
	rebased_patches = xstrdup(git_path("rebased-patches"));
	if (!is_null_oid(&squash_onto))
			die(_("Unknown mode: %s"), rebase_merges);
		goto cleanup;

			N_("keep commits which start empty"),
		argv_array_push(&am.args, "--no-rerere-autoupdate");

#include "wt-status.h"
	replay.allow_empty_message = opts->allow_empty_message;
	}
	const char *shorthead;


		free(rebased_patches);
	    options.autosquash) {
			if (keep_base)
	int reschedule_failed_exec;
		return 0;
		opts.stat_graph_width = -1; /* respect statGraphWidth config */
		argv_array_push(&am.args, "--show-current-patch");
	strbuf_reset(&buf);
		goto leave_reset_head;
		if (read_one(state_dir_path("strategy", opts), &buf))
		strbuf_reset(&buf);
 * Determines whether the commits in from..to are linear, i.e. contain
	add_var(&script_snippet, "allow_empty_message",
			BUG("unusable todo list");
		      "If that is the\n"
}
}
		{ OPTION_CALLBACK, 0, "squash-onto", &squash_onto, N_("squash-onto"),
		if (!opts->onto && !opts->upstream)
	int res;
		for (i = 0; i < strategy_options.nr; i++)
		}
				 "forced.\n"), branch_name);
	return status ? -1 : 0;
	if (switch_to_branch && !starts_with(switch_to_branch, "refs/"))
				options.onto_name);
		ret = add_exec_commands(&commands);
		opts->autosquash = 0;
				if (!isdigit(*(p++)))
		opts->flags & REBASE_FORCE ? "t" : "");
static enum empty_type parse_empty_value(const char *value)
static int run_specific_rebase(struct rebase_options *opts, enum action action)
				reflog_orig_head = msg.buf;
				printf(_("Changes from %s to %s:\n"),
		.empty = EMPTY_UNSPECIFIED,	  	\
	opts->keep_empty = !unset;
		return 0;
			die(_("--strategy requires --merge or --interactive"));
		ret = sequencer_remove_state(&replay);
static int init_basic_state(struct replay_opts *opts, const char *head_name,
		options.onto = lookup_commit_or_die(&merge_base,
		} else {
		 * Note: incompatibility with --signoff handled in signoff block above
			opts->flags &= ~REBASE_DIFFSTAT;
				    options.upstream_name);
	strbuf_release(&buf);
			return status;
			    struct commit *restrict_revision,
		if (check_exec_cmd(exec.items[i].string))
			delete_ref(NULL, "ORIG_HEAD", old_orig, 0);
	}
			options.empty = EMPTY_DROP;
		if (!read_ref(buf.buf, &options.orig_head)) {
		      "valuable there.\n"),
	struct child_process stash_apply = CHILD_PROCESS_INIT;
		      "interactive rebase."));
	return 0;
		options.state_dir = merge_dir();
		if (read_one(state_dir_path("gpg_sign_opt", opts),
			repo_update_index_if_able(the_repository, &lock_file);
	add_var(&script_snippet, "cmd", opts->cmd);
			N_("keep commits which start empty"),

	ACTION_EDIT_TODO,

 */
	if (repo_read_index_unmerged(the_repository) < 0) {
		       NULL, msg.buf))
	int keep_base = 0;
		ret = !!finish_rebase(&options);
	strbuf_release(&buf);
		BUG("Unhandled rebase type %d", opts->type);
		} else if (skip_prefix(option, "--whitespace=", &p)) {
			options.head_name = xstrdup(buf.buf);
	}

			struct branch *branch;
	EMPTY_ASK
	default:
			strbuf_addf(&buf, "exec %s\n", exec.items[i].string);
		usage_with_options(builtin_rebase_usage,
	int use_legacy_rebase;
		error(_("\ngit encountered an error while preparing the "

	am.git_cmd = 1;
	int ret;
	}
			else
		/* If not is it a valid ref (branch or commit)? */
		switch (options.type) {
	options->empty = value;
			    "'--preserve-merges'");
#define RESET_HEAD_RUN_POST_CHECKOUT_HOOK (1<<2)
		options.onto_name = options.upstream_name;

		else if (skip_prefix(option, "-C", &p)) {
	return (struct commit *)peel_to_type(name, 0, obj, OBJ_COMMIT);
			die(_("invalid upstream '%s'"), options.upstream_name);

	opts->type = REBASE_MERGE;
	if (opts->allow_rerere_autoupdate == RERERE_AUTOUPDATE)

			strbuf_addstr(&buf, options.state_dir);
			   RESET_HEAD_REFS_ONLY, "HEAD", msg.buf);
	}
	printf(_("%s\n"
				"" : "-no");
{
	strbuf_trim_trailing_newline(buf);
								    NULL);
		struct replay_opts replay = REPLAY_OPTS_INIT;
			parse_opt_interactive },
			options.upstream_name = argv[0];
		OPT_BOOL(0, "signoff", &options.signoff,
			REBASE_NO_QUIET | REBASE_VERBOSE | REBASE_DIFFSTAT),
	case REBASE_MERGE:
			options.onto_name = squash_onto_name =

	int ret = 0;
			imply_merge(&options, "--merge");
		strbuf_addstr(&msg, "updating HEAD");
	int keep_empty;
	if (exec.nr) {
	if (options.flags & REBASE_DIFFSTAT) {
	todo_list_release(&todo_list);
		OPT_STRING(0, "head-name", &opts.head_name, N_("head-name"), N_("head name")),
	    !git_env_bool("GIT_TEST_REBASE_USE_BUILTIN", -1))
		 "    git rebase '<branch>'\n"
	int allow_rerere_autoupdate;
			N_("let the user edit the list of commits to rebase"),

	const char *branch_name;


	}
				    options.onto_name);
		int fd;
		 *       git-rebase.txt caveats with "unless you know what you are doing"
	struct rebase_options options = REBASE_OPTIONS_INIT;
	argv_array_push(&am.args, "am");
		refresh_cache(REFRESH_QUIET);
		if (i >= 0) {
	}
static void imply_merge(struct rebase_options *opts, const char *option)

	return 0;

		    has_uncommitted_changes(the_repository, 1)) {
	return path.buf;
		break;

	struct object_id *orig = NULL, oid_orig,
				   "editable list")),


	const char *todo_file = rebase_path_todo();
	switch (action) {
			res = error(_("Cannot store %s"), autostash.buf);

		argv_array_clear(&args);
		branch_name = argv[0];
		string_list_clear(&commands, 0);
	default:
	unsigned run_hook = flags & RESET_HEAD_RUN_POST_CHECKOUT_HOOK;
	 * Note that can_fast_forward() initializes merge_base, so we have to
	if (reschedule_failed_exec > 0 && !is_merge(&options))
	argv_array_push(&am.args, "--rebasing");
			if(file_exists(buf.buf)) {
			    ACTION_ABORT),
				    options.state_dir);
	enum {
#include "argv-array.h"
	unsigned refs_only = flags & RESET_HEAD_REFS_ONLY;

	return write_basic_state(opts, head_name, onto, orig_head);
	replay.quiet = !(opts->flags & REBASE_NO_QUIET);
		free(opts->strategy);
		if (repo_read_index(the_repository) < 0)
		return status;

		if (!(options.flags & REBASE_FORCE)) {
/*
"\"git add/rm <conflicted_files>\", then run \"git rebase --continue\".\n"
		       remote, current_branch->name);
	char *gpg_sign_opt;


	}
			      NULL);
		OPT_BOOL(0, "reschedule-failed-exec",
	return 0;
	add_var(&script_snippet, "strategy_opts", opts->strategy_opts);
	}
				  N_("passed to 'git am'"), PARSE_OPT_NOARG),
				strbuf_reset(&buf);

			die(_("Could not resolve HEAD to a revision"));
		if (read_one(state_dir_path("strategy_opts", opts), &buf))

		for (i = options.git_am_opts.argc - 1; i >= 0; i--)
 * "git rebase" builtin command
				    _("Please commit or stash them."), 1, 1)) {
	sequencer_init_config(&replay);
		if (!file_exists(state_dir_path("stopped-sha", opts)))

	 * head. Fall back to reading from head to cover for the case that the
{
		OPT_CMDMODE(0, "check-todo-list", &command,
			       &opts->onto->object.oid :

	fclose(interactive);

		if (is_merge(&options))
	const char *gpg_sign = NULL;
	if (opts->switch_to)
		options.gpg_sign_opt = xstrfmt("-S%s", gpg_sign);

	REBASE_APPLY,
	add_var(&script_snippet, "git_am_opt", buf.buf);
	 * call it before checking allow_preemptive_ff.

		    !strcmp(option, "--ignore-date") ||
		ret = update_ref(reflog_head, switch_to_branch, oid,

				   "strategy")),
	strbuf_addstr(&path, filename);
	return ret;
static int rebase_write_basic_state(struct rebase_options *opts)
		strbuf_addstr(&dir, opts->state_dir);
		return error(_("unusable todo list: '%s'"), todo_file);
	NULL
	return 0;
	argv_array_push(&am.args, "--patch-format=mboxrd");
	 * branch_name -- branch/commit being rebased, or
			    N_("abort and check out the original branch"),
		OPT_CMDMODE(0, "rearrange-squash", &command,
	if (options.type == REBASE_PRESERVE_MERGES) {
		"[--onto <newbase> | --keep-base] [<upstream> [<branch>]]"),

{
			} else
		int i;
			   oid_to_hex(opts->squash_onto));
			else

	rollback_lock_file(&lock);
	return !!run_sequencer_rebase(&opts, command);
	todo_list_add_exec_commands(&todo_list, commands);
							"%s"),
		OPT_RERERE_AUTOUPDATE(&opts.allow_rerere_autoupdate),
			       PARSE_OPT_NONEG, parse_opt_empty),
					      DEFAULT_ABBREV);
	}
	if (!reset_hard && !fill_tree_descriptor(the_repository, &desc[nr++], &head_oid)) {
		goto done;
		return 0;
static int rebase_config(const char *var, const char *value, void *data)
	if (opts->signoff)

	}
			   N_("allow commits with empty messages"),
	const char *env;
{
				 "stash", "store", "-m", "autostash", "-q",
	enum empty_type value = parse_empty_value(arg);
			 N_("move commits that begin with squash!/fixup!")),
		free(opts->gpg_sign_opt);
			shortrevisions, opts->onto_name, opts->onto, head_hash,
			while (*p)
		strbuf_reset(&buf);
	if (get_oid(buf.buf, &oid))
			  "Your changes are safe in the stash.\n"
				 oid_to_hex(&opts->restrict_revision->object.oid));
	if (opts->strategy_opts)
		OPT_CMDMODE(0, "abort", &action,
	struct lock_file lock = LOCK_INIT;
	struct todo_list todo_list = TODO_LIST_INIT,
			oid_to_hex(&options.onto->object.oid));
		{ OPTION_CALLBACK, 0, "restrict-revision", &opts.restrict_revision,
	} else if (read_one(state_dir_path("head", opts), &buf))
	if (!is_merge(opts))
	opts->type = REBASE_APPLY;

			     builtin_rebase_usage, 0);
	if (opts->restrict_revision)
	if (options.use_legacy_rebase ||
static int read_one(const char *path, struct strbuf *buf)
			      "'--reschedule-failed-exec'"));
			    struct object_id *head_oid, struct object_id *merge_base)


			ret = !!remove_dir_recursively(&buf, 0);
					    reflog_head);
		rollback_lock_file(&lock_file);
	if (keep_base) {
			if (!reflog_orig_head) {


		break;
			strbuf_reset(&buf);
			strbuf_reset(&buf);
		} else if (!get_oid(branch_name, &options.orig_head))
		if (options.reschedule_failed_exec)
}
	case REBASE_MERGE:

		const char *remote = current_branch->remote_name;
		return error(_("could not get 'onto': '%s'"), buf.buf);
			if (!(options.flags & REBASE_NO_QUIET))
	add_var(&script_snippet, "onto_name", opts->onto_name);
			trace2_cmd_mode("interactive-exec");
			die(_("Unknown rebase backend: %s"),
	prime_cache_tree(the_repository, the_repository->index, tree);
		if (options.flags & REBASE_INTERACTIVE_EXPLICIT)
		prefix_len = path.len;
		struct lock_file lock_file = LOCK_INIT;
		return move_to_original_branch(opts);


	/* Does the command consist purely of whitespace? */
		write_file(state_dir_path("signoff", opts), "--signoff");
	 * head_name -- refs/heads/<that-branch> or NULL (detached HEAD)

#define RESET_HEAD_REFS_ONLY (1<<3)
	struct child_process format_patch = CHILD_PROCESS_INIT;
		case REBASE_APPLY:

		free(opts->strategy_opts);
	add_var(&script_snippet, "git_format_patch_opt",
					die(_("switch `C' expects a "
{
		if (read_basic_state(&options))
	strbuf_addf(&revisions, "%s...%s",
		return error(_("empty exec command"));
/* Read one file, then strip line endings */
	strbuf_release(&msg);
{
static void split_exec_commands(const char *cmd, struct string_list *commands)
		}
	struct strbuf buf = STRBUF_INIT;
{
	}
		free(revisions);
			return status;
		options.action = "edit-todo";
	if (!switch_to_branch)
			      "GIT_SEQUENCE_EDITOR=:; export GIT_SEQUENCE_EDITOR; ");
		die("Nothing to do");
	 */

		current_branch ? _("There is no tracking information for "
		fprintf(stderr,
	if (options.type == REBASE_PRESERVE_MERGES)
					&todo_list)) {
			; /* default mode; do nothing */
		opts->use_legacy_rebase = !git_config_bool(var, value);

	if (strstr(options.onto_name, "...")) {
	else if (opts->type == REBASE_MERGE)
		reset_head(&opts->orig_head, "checkout", opts->head_name, 0,
			 "--full-index", "--cherry-pick", "--right-only",
		    oid_to_hex(&options.orig_head));
	    (exec.nr > 0) ||
	if (keep_base) {
	todo_list_release(&todo_list);
	if (!strcmp(var, "rebase.backend")) {
		if (remove_dir_recursively(&dir, 0))
		res = todo_list_write_to_file(the_repository, &todo_list,
	if (options.root && !options.onto_name)
		OPT_CMDMODE(0, "shorten-ids", &command,
	if (todo_list_parse_insn_buffer(the_repository, todo_list.buf.buf,

		    !strcmp(option, "--whitespace=fix") ||
			die(_("fatal: no such branch/commit '%s'"),
	argv_array_pushl(&make_script_args, "", revisions, NULL);
	case ACTION_QUIT: {
		int i;


			lookup_commit_reference(the_repository,
		if (!remote)

		{ OPTION_CALLBACK, 0, "apply", &options, NULL,
	status = run_command(&am);

	close_object_store(the_repository->objects);

	am.in = open(rebased_patches, O_RDONLY);
	ACTION_EXPAND_OIDS,
	return 0;

		return; /* only override it if it is "rebase" */
		REBASE_FORCE = 1<<3,
	const char *default_backend;
	res = todo_list_write_to_file(the_repository, &todo_list, todo_file,
		argv_array_push(&am.args, "--resolved");
		OPT_BOOL(0, "fork-point", &fork_point,
		goto run_rebase;
			 N_("move commits that begin with "
			       N_("how to handle commits that become empty"),
		if (!get_oid("ORIG_HEAD", &oid_old_orig))
	struct rebase_options *opts = opt->value;
				      "quit",
		OPT_PASSTHRU_ARGV('C', NULL, &options.git_am_opts, N_("n"),
		status = run_command(&am);
	 */
		REBASE_INTERACTIVE_EXPLICIT = 1<<4,

			remote = _("<remote>");
				repo_read_index(the_repository) < 0)
		ret = rearrange_squash_in_todo_file();
		goto done;
			   PARSE_OPT_HIDDEN),
		/* Is it "rebase other branchname" or "rebase other commit"? */
	if (!res)
	if (!fill_tree_descriptor(the_repository, &desc[nr++], oid)) {
	prefix_len = msg.len;
		 * Note: incompatibility with --interactive is just a strong warning;
			argc--;
	return 0;
static int run_sequencer_rebase(struct rebase_options *opts,
	if (strbuf_read_file(&todo_list.buf, todo_file, 0) < 0)
{
	if (!merge_bases || merge_bases->next) {
{
		     oid_to_hex(&options.upstream->object.oid)),
		goto run_rebase;
		cmd.git_cmd = 1;
		reflog_head = msg.buf;
			"\n    %s\n\n"

				die(_("'%s': need exactly one merge base with branch"),


		{ OPTION_CALLBACK, 0, "onto", &opts.onto, N_("onto"), N_("onto"),
	if (!oideq(merge_base, &onto->object.oid))
		string_list_split(commands, cmd, '\n', -1);
		}
	flags |= opts->keep_empty ? TODO_LIST_KEEP_EMPTY : 0;
		      "--exec or --interactive"));

			puts(_("You must edit all merge conflicts and then\n"
	if (!cmd[strspn(cmd, " \t\r\f\v")])
	return 0;
		options.reschedule_failed_exec = reschedule_failed_exec;
		}
			   N_("revision"),
				    flags);
	if (status) {
	}

		    oid_to_hex(opts->root ?

}
		break;

		/* fallthrough */
	if (!detach_head)
	}
	if (unpack_trees(nr, desc, &unpack_tree_opts)) {
		else if (strcmp("no-rebase-cousins", rebase_merges))

	}
		die(_("could not read index"));
		argv_array_clear(&am.args);

		die(_("It looks like 'git am' is in progress. Cannot rebase."));
	}
	strbuf_release(&revisions);
	struct todo_list todo_list = TODO_LIST_INIT;
		opts.detect_rename = DIFF_DETECT_RENAME;

		strbuf_addstr(&script_snippet,



	}
	if (env && strcmp("rebase", env))
		options.upstream = NULL;

		argv_array_split(&format_patch.args,
