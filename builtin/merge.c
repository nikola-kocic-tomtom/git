	 */
	else if (!strcmp(k, "merge.renormalize"))
{


			strbuf_commented_addf(&msg, "\n");
		goto done;
	OPT_BOOL(0, "abort", &abort_current_merge,
			verify_merge_signature(remoteheads->item, verbosity,
		}
			getenv("GIT_REFLOG_ACTION"), msg);
	finish(head, remoteheads, &result_commit, "In-index merge");

			return &all_strategy[i];
			    branch->merge[i]->src, branch->remote_name);
	 * this variable to 0 when we find HEAD among the independent
		       merge_msg.len);
		restore_state(&head_commit->object.oid, &stash);
	 * the tag object pointed at by "refs/tags/$T" where $T is the

		strbuf_commented_addf(&msg, _(merge_editor_comment));
		remote_head_oid = &remoteheads->item->object.oid;
	N_("git merge --abort"),
	if (!bmo)
		isatty(0) && isatty(1) &&
					/* Automerge succeeded. */
}
static struct commit_list *collect_parents(struct commit *head_commit,



			die(_("Bad value '%s' in environment '%s'"), e, name);
 * Copyright (c) 2008 Miklos Vajna <vmiklos@frugalware.org>
	repo_rerere(the_repository, allow_rerere_auto);
		die_errno(_("could not read '%s'"), filename);
	if (!remote_head)
		 * left to be resolved, with 2 when it does not

	if (argc == 1 && !strcmp(argv[0], "FETCH_HEAD")) {
		return git_config_string(&cleanup_arg, k, v);

		load_command_list("git-merge-", &main_cmds, &other_cmds);
			add_strategies(pull_octopus, DEFAULT_OCTOPUS);
	opts.trivial_merges_only = 1;

#include "config.h"
			else if (len == 1)
	}
	argc = parse_options(argc, argv, prefix, builtin_merge_options,
}

				       COMMIT_LOCK | SKIP_IF_UNCHANGED))
			best_strategy);
};
	strbuf_release(&buf);
	strbuf_release(&reflog_message);
static const char no_scissors_editor_comment[] =
			if (parse_merge_opt(&o, xopts[x]))

	if (ctx->prefix && !is_absolute_path(arg))
		ret = finish_automerge(head_commit, head_subsumed,
			 * HEAD^^" would be missed.
	if (shortlog_len < 0)
	 * merged?  If so we do not want to record it as a parent of
	strbuf_addf(&buf, "Merge made by the '%s' strategy.", wt_strategy);
		if (all_strategy[i].attr & attr)
	if (verbosity < 0 && show_progress == -1)
		strbuf_addch(&out, '\n');
#include "builtin.h"
			goto done;
		 */
		if (!strcmp(name, all_strategy[i].name))
				    oid_to_hex(&branch_head), remote);
	return is_throwaway_tag;
		clean = merge_recursive(&o, head,
	int i = 0;
		else
	int len;
		opts.stat_graph_width = -1; /* respect statGraphWidth config */
	int i, ret = 0;

		int ret, cnt;
	 * the editor and after we invoke run_status above.
	reset_hard(head, 1);
		if (verbosity >= 0 && !merge_msg.len)
		strbuf_release(&truname);
	if (automerge_was_ok) {
				merge_was_ok = 1;
	if (unset)
	}
#include "dir.h"
			die(_("You have not concluded your cherry-pick (CHERRY_PICK_HEAD exists)."));
	static struct cmdnames main_cmds, other_cmds;
	status = fmt_merge_msg_config(k, v, cb);
	branch = branch_to_free = resolve_refdup("HEAD", 0, &head_oid, NULL);
	strbuf_addf(msg, "%s\t\tcommit '%s'\n",
		add_pending_object(&rev, &j->item->object, NULL);
	struct commit_list *remoteheads, *p;
		read_empty(remote_head_oid, 0);
	if (branch)
{
			commit_list_insert(j->item, &reversed);
			    int head_subsumed,
		goto done;
		default_to_upstream = git_config_bool(k, v);
					  overwrite_ignore)) {
	while ((commit = get_revision(&rev)) != NULL) {
{
		if (up_to_date) {

		if (!strcmp(strategy, "subtree"))

			if (!oideq(&common_one->item->object.oid, &j->item->object.oid)) {
	int rc = -1;
				    "%s\t\tbranch '%s'%s of .\n",
			update_ref(reflog_message.buf, "HEAD", new_head, head,
		N_("--abort but leave index and working tree alone")),
	 * anywhere.
		 * to forbid "git merge" into a branch yet to be born.
				      builtin_merge_options);
	struct rev_info rev;
		strbuf_release(autogen);
	if (status)

				_("No merge strategy handled the merge.\n"));
	args[i] = NULL;
static int option_renormalize;
		option_edit = default_edit_option();
	struct strbuf buf = STRBUF_INIT;
		 * There is no unmerged entry, don't advise 'git
		setenv(buf.buf, merge_remote_util(commit)->name, 1);

			*head_subsumed = 0;
		 (!remoteheads->next && !common->next &&
	struct object_id oid;
static int read_tree_trivial(struct object_id *common, struct object_id *head,
		}
};

			DIFF_FORMAT_SUMMARY | DIFF_FORMAT_DIFFSTAT;

#include "remote.h"
static struct strbuf merge_msg = STRBUF_INIT;
}
		if (desc && desc->obj) {
		if (remoteheads->next) {
		die(_("not a valid object: %s"), buffer.buf);
{
		 */
static int quit_current_merge;
		if (use_strategies[i]->attr & NO_TRIVIAL)
		/*
			ret = 1;
	}
			 */
	if (merge_was_ok)

static int setup_with_upstream(const char ***argv)
			    oid_to_hex(&desc->obj->oid),
		ctx->opt = NULL;
 * branch we have for the upstream of the current branch
	if (!is_in_cmdlist(&main_cmds, name) && !is_in_cmdlist(&other_cmds, name)) {
		}
	  N_("GPG sign commit"), PARSE_OPT_OPTARG, NULL, (intptr_t) "" },
	return git_diff_ui_config(k, v, cb);
	OPT_CALLBACK('X', "strategy-option", &xopts, N_("option=value"),
		return 0;
	opts.update = 1;
	write_file_buf(git_path_merge_mode(the_repository), buf.buf, buf.len);
	return 0;

		return error(_("Unable to write index."));
	 * merge with a throw-away tag from a contributor with
		return error(_("switch `m' requires a value"));
{

		 * but first the most common case of merging one remote.
				die(_("Unknown option for merge-recursive: -X%s"), xopts[x]);
	if (refresh_and_write_cache(REFRESH_QUIET, SKIP_IF_UNCHANGED, 0) < 0)
	struct object_id result_tree, result_commit;
	void *branch_to_free;
	args[i++] = "-u";
	}
			remotes = &commit_list_insert(commit, remotes)->next;
static int evaluate_result(void)
		option_commit = 1;
		early = 0;
#include "diffcore.h"
		abort_commit(remoteheads, NULL);
		if (!remoteheads)
	else if (!strcmp(k, "merge.verifysignatures"))
		}
		} else {
static void squash_message(struct commit *commit, struct commit_list *remoteheads)
					   int *head_subsumed,
	while (parents) {
			strbuf_addf(msg, "%s\t\ttag '%s' of .\n",
			goto cleanup;
		if (!commit) {
		if (option_commit > 0)
		strbuf_setlen(&truname, truname.len - len);
		}
	int i;
	args[i++] = empty_tree_oid_hex();
	write_file_buf(git_path_merge_msg(the_repository), merge_msg.buf,


	pptr = commit_list_append(remoteheads->item, pptr);
	if (!trees[nr_trees++])


	NULL
			      struct commit_list *remoteheads,
static int overwrite_ignore = 1;
	trees[nr_trees] = parse_tree_indirect(head);
	if (buf->len)
	struct commit *remote_head;
{
	return cnt;
		return try_merge_command(the_repository,
	/* Are we merging a tag? */
		return status;

	return i;
		struct strbuf truname = STRBUF_INIT;
					 common, remoteheads,
		N_("option for selected merge strategy"), option_parse_x),
	} else if (!strcmp(k, "commit.gpgsign")) {

	char *tag_ref;
	if (!msg.len)
	 * auto resolved the merge cleanly.
					       check_trust_level);
	    oideq(&oid, &merge_remote_util(commit)->obj->oid))
#define NO_TRIVIAL      (1<<3)
	 * At this point, we need a real merge.  No matter what strategy

	if (file_exists(git_path_merge_head(the_repository))) {
	if (fd < 0)
static int option_edit = -1;
static const char *sign_commit;
		ret = try_merge_strategy(use_strategies[i]->name,
		for_each_string_list_item(item, &list)

static int option_parse_n(const struct option *opt,

				      argc, argv, &merge_msg);
static void write_merge_heads(struct commit_list *);

	else if (!strcmp(k, "pull.octopus"))


		int v = git_parse_maybe_bool(e);
			!common->next &&
}
	return (!fstat(0, &st_stdin) &&
	struct strbuf sb = STRBUF_INIT;
	return remoteheads;
	if (get_oid(buffer.buf, stash))
	use_strategies[use_strategies_nr++] = s;
		return -1;

{

		if (v < 0)

};
	 * Thus, we will get the cleanup mode which is returned when we _are_
	return 0;
		ret = cmd_reset(nargc, nargv, prefix);
	 * the standard merge summary message to be appended

		N_("create a single commit instead of doing a merge")),

	ALLOC_GROW(use_strategies, use_strategies_nr + 1, use_strategies_alloc);
static const char *branch;
	write_tree_trivial(&result_tree);
	remove_merge_branch_state(the_repository);
		return clean ? 0 : 1;
		return 0;
	/*
		if (!file_exists(git_path_merge_head(the_repository)))
	    !strcmp(str, ".mergeoptions")) {
	append_strategy(get_strategy(name));
					found = 1;
	setup_revisions(0, NULL, &rev, NULL);
#include "cache.h"
			goto cleanup;
	if (!head_commit || !argc)
	/* Find what parents to record by checking independent ones. */
			git_committer_info(IDENT_STRICT);
	 * we use, it would operate on the index, possibly affecting the
		handle_fetch_head(remotes, autogen);
			strbuf_addf(msg, "%s\t\tbranch '%s' of .\n",
			      builtin_merge_usage, builtin_merge_options);
				seen_nonzero |= (*ptr != '0');

	} else if (ctx->argc > 1) {
	prepare_to_commit(remoteheads);
			goto done;
{

	struct tree_desc t[MAX_UNPACK_TREES];
		!fstat(1, &st_stdout) &&
			cnt = evaluate_result();
	if (squash)
		return 0;
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		die(_("read-tree failed"));
			&result_commit, NULL, sign_commit))
			/*
			append_strategy(get_strategy(item->string));
static int count_unmerged_entries(void)
		st_stdin.st_dev == st_stdout.st_dev &&
		PARSE_OPT_NOARG, option_parse_n },
	else {
	xopts[xopts_nr++] = xstrdup(arg);
		/*
	strbuf_addbuf(&msg, &merge_msg);
	int best_cnt = -1, merge_was_ok = 0, automerge_was_ok = 0;
	int i;
	write_file_buf(git_path_merge_msg(the_repository), msg.buf, msg.len);
	if (!read_ref(tag_ref, &oid) &&
	OPT_BOOL(0, "quit", &quit_current_merge,
	remoteheads = collect_parents(head_commit, &head_subsumed,
	const char *best_strategy = NULL, *wt_strategy = NULL;
		if (default_to_upstream)
	write_file_buf(git_path_squash_msg(the_repository), out.buf, out.len);
	init_diff_ui_defaults();
	int status;
					 common, head_arg, remoteheads);
		if (cleanup_mode == COMMIT_MSG_CLEANUP_SCISSORS) {
		 * a real merge.
		if (!commit) {
	else if (!strcmp(k, "pull.twohead"))
		struct strbuf msg = STRBUF_INIT;
	{ "resolve",    0 },
	/* Run a post-merge hook */
	struct tree *trees[MAX_UNPACK_TREES];

			if (!ret) {
	ret->name = xstrdup(name);
	printf(_("Wonderful.\n"));
		}

		char *ptr;
#include "parse-options.h"
		struct commit *c = j->item;
	}
static int signoff;

	} else if (!remoteheads->next && common->next)
#include "wt-status.h"
	if (write_cache_as_tree(oid, 0, NULL))
		remotes = &commit_list_insert(head_commit, remotes)->next;
		else if (!remoteheads->next)
		return git_config_string(&pull_octopus, k, v);
 *
	ctx.date_mode = rev.date_mode;
		strbuf_addf(&truname, "refs/heads/%s", remote);
	/* Check how many files differ. */
	struct stat st_stdin, st_stdout;

	int i;
	OPT_SET_INT(0, "ff", &fast_forward, N_("allow fast-forward (default)"), FF_ALLOW),
	struct strbuf msgbuf = STRBUF_INIT;
	  PARSE_OPT_OPTARG, NULL, DEFAULT_MERGE_LOG_LEN },

	if (autogen) {
	strbuf_release(&merge_msg);
		N_("read message from file"), PARSE_OPT_NONEG,
{
   "\n");
	if (verbose)


		free(branch_mergeoptions);
#include "alias.h"
		common = get_merge_bases(head_commit, remoteheads->item);
	if (fast_forward == FF_NO)
		 * a problem as it is only overriding the default, not a user
{

{
		die(_("failed to write commit object"));
	setenv("GIT_REFLOG_ACTION", buf.buf, 0);

		      N_("abort if fast-forward is not possible"),

	return 0;
	args[i++] = oid_to_hex(oid);

	struct strbuf buf = STRBUF_INIT;
	len = strbuf_read(&buffer, cp.out, 1024);
	int i, ret = 0, head_subsumed;
					 head_commit);
static void write_tree_trivial(struct object_id *oid)
	strbuf_release(&msg);
			die(_("You cannot combine --squash with --no-ff."));
}
			/* See if it is really trivial. */
	else

cleanup:

	for (i = 0; i < ARRAY_SIZE(all_strategy); i++)
	return 1;
	/*
#include "help.h"
	OPT_BOOL(0, "allow-unrelated-histories", &allow_unrelated_histories,
	argc++;
	else
			    type_name(desc->obj->type),
			if (!found)

}
		init_tree_desc(t+i, trees[i]->buffer, trees[i]->size);
			fprintf(stderr, _("Merge with strategy %s failed.\n"),
	write_file_buf(git_path_merge_head(the_repository), buf.buf, buf.len);


			}

	}
	else
	    merge_remote_util(commit)->obj->type != OBJ_TAG)
	}
			for (i = 0; i < other_cmds.cnt; i++)
						  DEFAULT_ABBREV));
	 * to ensure this.
	 */
			}
	fputs(msgbuf.buf, fp);
   "the commit.\n");
		oid_to_hex(&remote_head->object.oid), remote);

	if (!strcmp(strategy, "recursive") || !strcmp(strategy, "subtree")) {
	opts.shortlog_len = shortlog_len;
			die(_("You have not concluded your merge (MERGE_HEAD exists).\n"
static int save_state(struct object_id *stash)
static int allow_trivial = 1, have_message, verify_signatures;
		diff_flush(&opts);
static int option_parse_message(const struct option *opt,
	 * a "just to catch up" merge to fast-forward.
static void handle_fetch_head(struct commit_list **remotes, struct strbuf *merge_names)
	if (quit_current_merge) {
				early = 1;
static struct strategy all_strategy[] = {
		restore_state(&head_commit->object.oid, &stash);
		N_("continue the current in-progress merge")),
		if (!file_exists(git_path_merge_head(the_repository)))
	}

struct strategy {
			    "an empty head"));
		goto done;
	close(cp.out);

			len++; /* count ~ */
		if (verbosity >= 0)
		}
	if (fast_forward == FF_ONLY)
		init_merge_options(&o, the_repository);
			fprintf(stderr, " %s", main_cmds.names[i]->name);
						&& !all_strategy[j].name[ent->len])
{
#include "run-command.h"
		 * If the merged head is a valid one there is no reason
	for (pos = 0; pos < merge_names->len; pos = npos) {
				use_strategies[0]->name);
		if (other_cmds.cnt) {
		else
	const char *e = getenv(name);
		return -1;
			&result_commit, NULL, sign_commit))

		autogen = &merge_names;
					 strategy, xopts_nr, xopts,
	args[i++] = "read-tree";
	strbuf_release(&bname);
{
		die(_("No remote for the current branch."));
	git_config(git_merge_config, NULL);
	N_("git merge [<options>] [<commit>...]"),
#include "tag.h"
}
			     struct diff_options *opt, void *data)
		loaded = 1;
	int *count = data;
	struct strbuf bname = STRBUF_INIT;
	repo_init_revisions(the_repository, &rev, NULL);
	opts.merge = 1;
		 */
		return error(_("could not read file '%s'"), arg);

{
		return status;

						 _("not something we can merge"));
	strbuf_addstr(&buf, "merge");
		N_("merge commit message (for a non-fast-forward merge)"),
		exclude_cmds(&main_cmds, &not_strategies);
					automerge_was_ok = 1;
			int j, found = 0;
	if (dwim_ref(remote, strlen(remote), &branch_head, &found_ref) > 0) {
		 * If head can reach all the merge then we are up to date.
		opts.detect_rename = DIFF_DETECT_RENAME;
	} else if (argc == 1 && !strcmp(argv[0], "-")) {
				      builtin_merge_usage,
		if (orig_argc != 2)
#include "cache-tree.h"

static char *branch_mergeoptions;
/*
}
	} else
			die(_("There is no merge in progress (MERGE_HEAD missing)."));
	 * by default; otherwise we would not keep the signature
			commit = get_merge_parent(merge_names->buf + pos);
		ctx->argc--;
	show_diffstat = unset;
	MOVE_ARRAY(argv + 1, argv, argc + 1);

	run_command_v_opt(args, RUN_GIT_CMD);
				ret = merge_trivial(head_commit, remoteheads);
	} else {
		} else if (v && !strcmp(v, "only")) {
		skip_prefix(branch, "refs/heads/", &branch);
	parse_options(argc, argv, NULL, builtin_merge_options,
	}
			    git_path_merge_msg(the_repository), "merge", NULL))
	 */
		is_throwaway_tag = 0;

		diff_tree_oid(head, new_head, "", &opts);
	{ "recursive",  DEFAULT_TWOHEAD | NO_TRIVIAL },
}
			run_command_v_opt(argv_gc_auto, RUN_GIT_CMD);
	const char *filename;
	}

	 */
	}
	argc = split_cmdline(bmo, &argv);
}
		strbuf_addf(&out, "commit %s\n",
	int i = 0;
	}
		diff_setup_done(&opts);
			die(_("You have not concluded your cherry-pick (CHERRY_PICK_HEAD exists).\n"
		option_renormalize = git_config_bool(k, v);
#include "rerere.h"
			fast_forward = FF_ONLY;
{
			fprintf(stderr, _("Available custom strategies are:"));
		  common->item == remoteheads->item)) {

	}
}
			if (ptr)
		return;
		remoteheads = reduce_parents(head_commit, head_subsumed, remoteheads);
		/* Invoke 'git commit' */
	strbuf_release(&buffer);
 *
	fd = open(filename, O_RDONLY);
	if (0 < option_edit) {
		parse_tree(trees[i]);
	}
		 * We are not doing octopus, not fast-forward, and have


		goto done;
		remove_merge_branch_state(the_repository);
	if (!merge_names)
		struct merge_options o;
		die(_("git write-tree failed to write a tree"));
	remote = bname.buf;
		/* Again the most common case of merging one remote. */
		}
	}
	if (start_command(&cp))
	if (file_exists(git_path_cherry_pick_head(the_repository))) {
		/*
		finish(head_commit, remoteheads, &commit->object.oid, msg.buf);
		early = 1;
	if (branch_mergeoptions)
	for (i = 0; i < ARRAY_SIZE(all_strategy); i++)
	else if (!strcmp(k, "commit.cleanup"))

		N_("abort the current in-progress merge")),

	remoteheads = NULL;
static void finish_up_to_date(const char *msg)
		head_commit = lookup_commit_or_die(&head_oid, "HEAD");
	 * to the given message.
		BUG("the control must not reach here under --squash");
		die(_("No current branch."));
		}
					       &head_commit->object.oid,
		for (i = 0; i < argc; i++) {
		option_commit = 0;
		opts.stat_width = -1; /* use full terminal width */

	FILE *fp;
		_("Not committing merge; use 'git commit' to complete the merge.\n"));
		/*
	if (run_command_v_opt(args, RUN_GIT_CMD))
	if (strbuf_read_file(msg, filename, 0) < 0)
	/*
{
	}
	prepare_to_commit(remoteheads);
	 * nothing to restore.
		option_parse_message),
						 const struct option *opt,
	return 0;
		; /* We already have its result in the working tree. */

		int nargc = 1;

			     struct object_id *one)
 */
			scissors_editor_comment :
		die(_("No default upstream defined for the current branch."));
		if (ref_exists(truname.buf)) {
		 * only one common.
#include "commit-reach.h"
	 * there.
	OPT_CALLBACK('m', "message", &merge_msg, N_("message"),
		if (verbosity >= 0) {
		}
	free_commit_list(common);
#include "merge-recursive.h"
	if (abort_current_merge) {
	}
		if (advice_resolve_conflict)
	struct commit_list *parents, **pptr = &parents;
		if (autogen) {
	 * working tree, and when resolved cleanly, have the desired
		return v;
	char *found_ref;
		goto out;
};
	const char *ptr;

	/* We are going to make a new commit. */
		N_("perform a commit if the merge succeeds (default)")),
				if (!strncmp(ent->name, all_strategy[j].name, ent->len)
	if (argc < 0)
		} /* do not barf on values from future versions of git */

					  "commit-msg",
	args[i++] = oid_to_hex(oid);
		}
			oideq(&common->item->object.oid, &head_commit->object.oid)) {
		opts.output_format |=

				       &result_tree, wt_strategy);
			printf(_("Updating %s..%s\n"),
		}
		if (clean < 0)
		N_("merge strategy to use"), option_parse_strategy),

		parse_branch_merge_options(branch_mergeoptions);
					   struct strbuf *merge_msg)
	}
#include "commit.h"
		free(list);
	rev.commit_format = CMIT_FMT_MEDIUM;

		if (starts_with(found_ref, "refs/heads/")) {
	write_merge_heads(remoteheads);
	if (unset)
	 * Re-read the index as pre-merge-commit hook could have updated it,
	cp.argv = argv;
		o.renormalize = option_renormalize;
	 * current branch.
				merge_name(merge_remote_util(p->item)->name, autogen);
		 */
	if (option_edit < 0)
		append_signoff(&msg, ignore_non_trailer(msg.buf, msg.len), 0);
	OPT_BOOL('e', "edit", &option_edit,
		strbuf_commented_addf(&msg, _(cleanup_mode == COMMIT_MSG_CLEANUP_SCISSORS ?
			if (*ptr)
	git_committer_info(IDENT_STRICT);
static int default_edit_option(void)
	if (close(fd) < 0)
			struct commit_list *common_one;
	/*
	finish(head, remoteheads, &result_commit, buf.buf);
	filename = git_path_merge_msg(the_repository);
		/*
	OPT_BOOL(0, "signoff", &signoff, N_("add Signed-off-by:")),
		const char *nargv[] = {"reset", "--merge", NULL};
	} else if (!remoteheads ||
		struct merge_remote_desc *desc;
	opts.add_title = !have_message;
			argc = setup_with_upstream(&argv);
		return 0;
		/* otherwise, we need a real merge. */
			allow_trivial = 0;
	struct commit_list *parents = NULL;
		return error(_("Unable to write index."));
		repo_diff_setup(the_repository, &opts);
		remoteheads = reduce_parents(head_commit, head_subsumed, remoteheads);
		die(_("Bad branch.%s.mergeoptions string: %s"), branch,
		ret = cmd_commit(nargc, nargv, prefix);
				}
	} else
			die(_("Non-fast-forward commit does not make sense into "

static void parse_branch_merge_options(char *bmo)
		strbuf_addf(&buf, " %s", merge_remote_util(p->item)->name);

	    skip_prefix(str, branch, &str) &&
	run_diff_files(&rev, 0);
		DIFF_FORMAT_CALLBACK;
	 */
	strbuf_release(&out);
	/*
static int allow_unrelated_histories;
#include "sequencer.h"
		return -1;
	} else if (best_strategy == wt_strategy)
	}
	const char *str;
	}
			  const char *arg, int unset)
		check_trust_level = 0;
#include "resolve-undo.h"
		argv[0] = "@{-1}";
		else
		if (checkout_fast_forward(the_repository,

			/*
		/*
		}
		struct commit *commit = p->item;
	struct strbuf out = STRBUF_INIT;
	if (strbuf_read_file(buf, arg, 0) < 0)
			npos = ptr - merge_names->buf + 1;


		if (orig_argc != 2)
			oid = &c->object.oid;
		/* an explicit -m msg without --[no-]edit */
	if (continue_current_merge) {
		len++;
	struct commit_list *remoteheads = NULL;
}

	if (!trees[nr_trees++])
	 * Check if we are _not_ on a detached HEAD, i.e. if there is a
		    get_oid_hex(merge_names->buf + pos, &oid))
	if (len)
#include "color.h"
	return ret;
	struct commit_list *j;
			die(_("There is no merge to abort (MERGE_HEAD missing)."));
				up_to_date = 0;
static void abort_commit(struct commit_list *remoteheads, const char *err_msg)
			append_strategy(&all_strategy[i]);
	for (i = 0; i < nr_trees; i++) {
		if (use_strategies[i]->attr & NO_FAST_FORWARD)
	 * Check how many unmerged entries are
		 * Remember which strategy left the state in the working

		if (i) {
	struct unpack_trees_options opts;

static void write_merge_state(struct commit_list *);
		if (fast_forward == FF_NO)
		o.show_rename_progress =
	add_pending_object(&rev, &commit->object, NULL);
{
			}

	     remote < ptr && ptr[-1] == '^';
	fmt_merge_msg(merge_names, merge_msg, &opts);
		die(_("could not run stash."));
		struct commit_list *j;
			oid_to_hex(&commit->object.oid));
	if (!strcmp(k, "merge.diffstat") || !strcmp(k, "merge.stat"))
		st_stdin.st_mode == st_stdout.st_mode);
static void reset_hard(const struct object_id *oid, int verbose)
	OPT_SET_INT_F(0, "ff-only", &fast_forward,
		strbuf_addstr(&reflog_message, getenv("GIT_REFLOG_ACTION"));
	read_merge_msg(&msg);
			commit = NULL; /* bad */

		struct string_list_item *item;
	     ptr--)
	return 0;
		goto done;
	/*

	remove_merge_branch_state(the_repository);
	struct object_id result_commit;
		struct commit *commit;
	have_message = 1;
			"stopped before committing as requested\n"));
static int merging_a_throwaway_tag(struct commit *commit)
			show_progress == -1 ? isatty(2) : show_progress;
	if (is_null_oid(stash))
{
	const char *name;
	struct strbuf *buf = opt->value;
			abort_commit(remoteheads, NULL);
			ret = 1;
}
	 * tagname recorded in the tag object.  We want to allow such
	 * Pick the result from the best strategy and have the user fix
#include "utf8.h"
	exit(1);

	/*
		if (use_strategies_nr != 1)
				   0, UPDATE_REFS_DIE_ON_ERR);
		 * The backend exits with 1 when conflicts are
	     */
			fprintf(stderr,
	return ret;
				early = 1; /* "name~" is "name~1"! */
	    !merge_remote_util(commit)->obj ||
	if (!trees[nr_trees++])
	parents = remoteheads;
		oidclr(&stash);
	if (have_message)

	if (new_head && show_diffstat) {
static int continue_current_merge;
	remotes = &remoteheads;

	}
	struct strbuf *buf = opt->value;

		finish_up_to_date(_("Already up to date."));
static void append_strategy(struct strategy *s)
						  DEFAULT_ABBREV),
		ret = suggest_conflicts();
	struct strbuf msg = STRBUF_INIT;
			die(_("You cannot combine --squash with --commit."));
	if (len) {
		}
			  const char *arg, int unset)

static int show_diffstat = 1, shortlog_len = -1, squash;

	if (!remoteheads)
	opts.credit_people = (0 < option_edit);
	for (p = remoteheads; p; p = p->next)
		return is_throwaway_tag;
		}
 * Pretend as if the user told us to merge with the remote-tracking
	const char *args[6];

static const char scissors_editor_comment[] =
	 * If we have a resulting tree, that means the strategy module
		BUG("-F cannot be negated");

static const char * const builtin_merge_usage[] = {
	static int loaded;
	if (!use_strategies) {
	for (len = 0, ptr = remote + strlen(remote);
	}
		strbuf_addf(msg, "%s\t\t%s '%s'\n",
			die(_("No commit specified and merge.defaultToUpstream not set."));

		arg = prefix_filename(ctx->prefix, arg);
	/*
	const char *head_arg = "HEAD";
		N_("do not show a diffstat at the end of the merge"),
		ret = 2;

}
	struct branch *branch = branch_get(NULL);
				remoteheads->item, reversed, &result);
	struct strbuf buffer = STRBUF_INIT;

	if (branch &&

{
		   &head_commit->object.oid, NULL, 0, UPDATE_REFS_DIE_ON_ERR);
	OPT_BOOL(0, "continue", &continue_current_merge,
{
	/* Use editor if stdin and stdout are the same and is a tty */
			 * Here we *have* to calculate the individual
		if (!branch->merge[i]->dst)
			for (p = remoteheads; p; p = p->next)
	struct commit_list *parents, **remotes;
		strbuf_setlen(buf, 0);
		for (j = remoteheads; j; j = j->next) {
		 */
		return error(_("option `%s' requires a value"), opt->long_name);
	}
#include "log-tree.h"
	cp.out = -1;
#include "unpack-trees.h"
			if (best_cnt <= 0 || cnt <= best_cnt) {
		NULL, 0, option_read_message },
	cp.git_cmd = 1;
	resolve_undo_clear();
		/* Invoke 'git reset --merge' */
/*
	oidclr(&branch_head);
		strbuf_addf(buf, "%s%s", buf->len ? "\n\n" : "", arg);

	for (j = remoteheads; j; j = j->next)
N_("Please enter a commit message to explain why this merge is necessary,\n"
		 */
		return -1;
	if (use_strategies_nr == 1 ||
		prepare_merge_message(autogen, merge_msg);
				use_strategies[i]->name);
	}
}
	}
		commit = remoteheads->item;
static const char *cleanup_arg;
static int suggest_conflicts(void)
	fprintf(stderr,
	if (!name)
	if (!branch || is_null_oid(&head_oid))
	int fd, pos, npos;
	opts.head_idx = 2;

	if (head_commit)


	}
	/*
		try_merge_strategy(best_strategy, common, remoteheads,
			fprintf(stderr, ".\n");
		if (have_message)
		show_diffstat = git_config_bool(k, v);
	strbuf_release(&sb);
	const char *index_file = get_index_file();
	write_merge_state(remoteheads);
static void write_merge_state(struct commit_list *remoteheads)
		if (starts_with(found_ref, "refs/tags/")) {
{
	struct commit_list *j;
	{ OPTION_STRING, 'S', "gpg-sign", &sign_commit, N_("key-id"),

		arg = *++ctx->argv;
	if (finish_command(&cp) || len < 0)
		args[i] = branch->merge[i]->dst;
			usage_msg_opt(_("--continue expects no arguments"),
		if (ptr) {
 * Builtin "git merge"

#include "revision.h"
	if (unset)
		 N_("allow merging unrelated histories")),
	const char *args[] = { "stash", "apply", NULL, NULL };
					  struct commit_list *remoteheads)
		N_("show a diffstat at the end of the merge")),
			npos = merge_names->len;
	if (unpack_trees(nr_trees, t, &opts))
	 */

	setup_revisions(0, NULL, &rev, NULL);
	refresh_cache(REFRESH_QUIET);

						 int unset)
					  git_path_merge_msg(the_repository), NULL))
}
	static const char name[] = "GIT_MERGE_AUTOEDIT";
done:
			die(_("%s - not something we can merge"), argv[0]);
	ret->attr = NO_TRIVIAL;
	FF_ONLY
		struct commit_list *j;
			goto cleanup;
			      builtin_merge_usage, builtin_merge_options);
	 */
	for (p = remoteheads; p; p = p->next) {
	OPT_BOOL(0, "commit", &option_commit,
	if (strbuf_read(merge_names, fd, 0) < 0)
	return 0;
		die(_("'%s' does not point to a commit"), remote);
	else {
	}
	struct strbuf fetch_head_file = STRBUF_INIT;
					   int argc, const char **argv,
	free(branch_to_free);
	OPT_BOOL(0, "verify-signatures", &verify_signatures,
				const char *arg, int unset)
	return 0;
	struct strbuf buf = STRBUF_INIT;
		squash_message(head_commit, remoteheads);
		return NULL;
	ctx.fmt = rev.commit_format;
			int seen_nonzero = 0;
	ret = xcalloc(1, sizeof(struct strategy));
		}
			       find_unique_abbrev(&head_commit->object.oid,
			    remote);

	} else {
		branch_mergeoptions = xstrdup(v);
	}
		else
		die(_("failed to write commit object"));
	args[i] = NULL;
#include "string-list.h"
		strbuf_addf(&reflog_message, "%s: %s",
		wt_strategy = use_strategies[i]->name;
		refresh_cache(REFRESH_QUIET);
	if (signoff)
				if (option_commit) {
	rev.ignore_merges = 1;
	else if (arg) {
	/* See if remote matches <name>^^^.. or <name>~<number> */
	rev.diffopt.output_format |=
	if (desc && desc->obj && desc->obj->type == OBJ_TAG) {
 * Based on git-merge.sh by Junio C Hamano.
static struct option builtin_merge_options[] = {
{

			  const struct object_id *stash)
	 * We can't use cleanup_mode because if we're not using the editor,
	else if (!strcmp(k, "merge.ff")) {
	 * All the rest are the commits being merged; prepare
}

	}

					  int *head_subsumed,
	    save_state(&stash))
	if (!argc) {
		finish(head_commit, remoteheads, NULL, NULL);
}
static int verbosity;
   "especially if it merges an updated upstream into a topic branch.\n"
				    (early ? " (early part)" : ""));

	if (prepare_revision_walk(&rev))
		usage_with_options(builtin_merge_usage,

	if (string) {
		else
	 */
{
	 * Otherwise, we are playing an integrator's role, making a
			fast_forward = FF_NO;
	int cnt = 0;
}
			       find_unique_abbrev(&remoteheads->item->object.oid,
#include "packfile.h"
		show_diffstat = 0;
			    struct commit_list *remoteheads,
static void read_empty(const struct object_id *oid, int verbose)
		remotes = &commit_list_insert(commit, remotes)->next;
	}

	filename = git_path_fetch_head(the_repository);
		strbuf_reset(&buf);

		 * squash can now silently disable option_commit - this is not
		have_message = 1;
	trees[nr_trees] = parse_tree_indirect(one);
	 * sync with the head commit.  The strategies are responsible
			 * user should see them.

	args[i++] = "-m";
		if (advice_resolve_conflict)
		/* No common ancestors found. */

static int merge_trivial(struct commit *head, struct commit_list *remoteheads)
		N_("edit message before committing")),
		struct diff_options opts;
static int git_merge_config(const char *k, const char *v, void *cb)
	}
		goto done;

	*head_subsumed = 1;
				add_cmdname(&not_strategies, ent->name, ent->len);
	fclose(fp);
	const char *filename = git_path_merge_msg(the_repository);
		}
	struct commit_list **remotes = &remoteheads;
			goto cleanup;
		N_("verify that the named commit has a valid GPG signature")),
	strbuf_release(&msgbuf);
	const char *arg;
static void finish(struct commit *head_commit,
static const char **xopts;
		}
			printf(_("Nope.\n"));
	args[i++] = "-u";
			    struct object_id *result_tree,
		;

			   UPDATE_REFS_DIE_ON_ERR);
		fprintf(stderr, _("Available strategies are:"));
	    skip_prefix(k, "branch.", &str) &&
	if (commit_tree(merge_msg.buf, merge_msg.len, &result_tree, parents,
	 * using an editor.
						 const char *arg_not_used,



static int finish_automerge(struct commit *head,
		args[i++] = "-v";
			common_one = get_merge_bases(head_commit, j->item);
		strbuf_addstr(&msg, "Fast-forward");
	if (verbosity >= 0)
		if (write_locked_index(&the_index, &lock,
			continue; /* not-for-merge */
	 * tree in the index -- this means that the index must be in
			  ((struct tag *)merge_remote_util(commit)->obj)->tag);

	 * We want to forbid such a merge from fast-forwarding
		printf(_("Using the %s to prepare resolving by hand.\n"),

					      argc, argv, NULL);
	return 0;
	}


static size_t use_strategies_nr, use_strategies_alloc;


	OPT_BOOL(0, "squash", &squash,
		die_resolve_conflict("merge");
	OPT_BOOL(0, "no-verify", &no_verify, N_("bypass pre-merge-commit and commit-msg hooks")),
		usage_with_options(builtin_merge_usage, builtin_merge_options);
		return;
	int orig_argc = argc;
		return git_config_string(&pull_twohead, k, v);
	if (find_hook("pre-merge-commit"))
	tag_ref = xstrfmt("refs/tags/%s",
	(*count) += q->nr;

				help_unknown_ref(argv[i], "merge",

		hold_locked_index(&lock, LOCK_DIE_ON_ERROR);
		remove_merge_branch_state(the_repository);
			strbuf_release(&truname);
	struct strbuf reflog_message = STRBUF_INIT;
}
	OPT_SET_INT(0, "progress", &show_progress, N_("force progress reporting"), 1),
			    const char *wt_strategy)
	else if (!remoteheads->next && !common->next && option_commit) {
		printf("%s%s\n", squash ? _(" (nothing to squash)") : "", msg);
		else if (memcmp(merge_names->buf + pos + hexsz, "\t\t", 2))

	 * it up.
}
	 * get_cleanup_mode will return COMMIT_MSG_CLEANUP_SPACE instead, even
static void restore_state(const struct object_id *head,
			printf(_("Rewinding the tree to pristine...\n"));
		if (remoteheads->next)
		commit_list_insert(head, &parents);
	if (run_command_v_opt(args, RUN_GIT_CMD))
	}
	opts.src_index = &the_index;
		else
	    /*
	 * Is the current HEAD reachable from another commit being


		sign_commit = git_config_bool(k, v) ? "" : NULL;
		if (allow_trivial && fast_forward != FF_ONLY) {
	if (!branch)
	ctx.abbrev = rev.abbrev;
{
		printf(_("Rewinding the tree to pristine...\n"));
		ptr = strrchr(remote, '~');
}
	const char *filename;
		if (!allow_unrelated_histories)
				    oid_to_hex(&branch_head), remote);

}
		struct commit *result;
	write_tree_trivial(result_tree);
		for (x = 0; x < xopts_nr; x++)
	else if (!remoteheads->next)
				   head_commit);
		if (use_strategies_nr > 1)


	{ OPTION_CALLBACK, 'n', NULL, NULL, NULL,
	const char **args;
			struct commit *commit = get_merge_parent(argv[i]);
		if (npos - pos < hexsz + 2 ||
		 */
		if (fast_forward != FF_ONLY && merging_a_throwaway_tag(commit))
 */

	remote_head = get_merge_parent(remote);
N_("Lines starting with '%c' will be ignored, and an empty message aborts\n"
			merge_names->buf[pos + hexsz] = saved;
				best_cnt = cnt;
		/*
	args = xcalloc(st_add(branch->merge_nr, 1), sizeof(char *));
	commit->object.flags |= UNINTERESTING;
	if (run_commit_hook(0 < option_edit, get_index_file(), "prepare-commit-msg",
			merge_names->buf[pos + hexsz] = '\0';

out:

			printf(_("Trying merge strategy %s...\n"),
	return remoteheads;

		args[i++] = "-v";
	parents = reduce_heads(remoteheads);
		}
					       &remoteheads->item->object.oid)) {
			no_scissors_editor_comment), comment_line_char);
	BUG_ON_OPT_ARG(arg);
		strbuf_setlen(merge_msg, merge_msg->len - 1);
			    struct commit_list *common,
				break;

	read_cache_from(index_file);
	args[i] = NULL;
enum ff_type {
};
		abort_commit(remoteheads, NULL);
	 */
			struct commit_list *p;
	 *
	*argv = args;
	 * though the message is meant to be processed later by git-commit.
	int len, early;
static int option_parse_x(const struct option *opt,
		/*
static enum parse_opt_result option_read_message(struct parse_opt_ctx_t *ctx,
{
	ALLOC_GROW(xopts, xopts_nr + 1, xopts_alloc);
		common = get_octopus_merge_bases(list);
	strbuf_release(&buf);
	if (verify_signatures) {
#include "diff.h"
	fp = xfopen(filename, "a");
	args[i++] = "--reset";
		o.branch1 = head_arg;
	 */
{
{
#include "fmt-merge-msg.h"

	if (remoteheads && !common) {
	memset(&opts, 0, sizeof(opts));
/* This is called when no merge was necessary. */
		head_commit = NULL;
				  "Please, commit your changes before you merge."));

			ret++;
	opts.dst_index = &the_index;
		goto done;
	 * something like "git pull $contributor $signed_tag".
		struct cmdnames not_strategies;

		    _(split_cmdline_strerror(argc)));
	printf(_("Squash commit -- not updating HEAD\n"));
	return ret;
	OPT_CLEANUP(&cleanup_arg),
			while (*++ptr && isdigit(*ptr)) {

	status = git_gpg_config(k, v, NULL);
		return 0;
	free(tag_ref);
	else {
		 * handle the given merge at all.
	}

	     * Stash away the local changes so that we can try more than one.
			printf(_("Trying really trivial in-index merge...\n"));


	int i, nr_trees = 0;
	/*

			exit(128);

		memset(&not_strategies, 0, sizeof(struct cmdnames));

	args[i++] = "read-tree";
			wt_status_append_cut_line(&msg);
	if (merge_msg && (!have_message || shortlog_len))
static void read_merge_msg(struct strbuf *msg)
			    filename, merge_names->buf + pos);
		strbuf_addch(buf, '\n');
	else
		strbuf_addf(&buf, "%s\n", oid_to_hex(oid));
	 * and write it out as a tree.  We must do this before we invoke

		string_list_clear(&list, 0);
}

				*ptr = '\0';

	cache_tree_free(&active_cache_tree);
}

		die(_("stash failed"));
			remotes = &commit_list_insert(commit, remotes)->next;
		for (j = common; j; j = j->next)
#include "refs.h"
	if (ctx->opt) {
	if (!argc)
	{ "octopus",    DEFAULT_OCTOPUS },
		ptr = strchr(merge_names->buf + pos, '\n');
	append_conflicts_hint(&the_index, &msgbuf,
				    oid_to_hex(&remote_head->object.oid),
		int up_to_date = 1;
	{ "ours",       NO_FAST_FORWARD | NO_TRIVIAL },
		if (launch_editor(git_path_merge_msg(the_repository), NULL, NULL))
		strbuf_release(&fetch_head_file);
	struct strategy *ret;
		int nargc = 2;
	struct commit *head_commit;
	return rc;
	} else if (fast_forward != FF_NO && !remoteheads->next &&
		}
static void add_strategies(const char *string, unsigned attr)
#define DEFAULT_OCTOPUS (1<<1)
	for (i = 0; !merge_was_ok && i < use_strategies_nr; i++) {
				len = 0; /* not ...~<number> */
	argv[0] = "branch.*.mergeoptions";
		struct object_id *oid;
		 * supplied option.
	opts.verbose_update = 1;
	struct commit_list *common = NULL;
	{ "subtree",    NO_FAST_FORWARD | NO_TRIVIAL },
	struct object_id branch_head;
			die(_("You have not concluded your merge (MERGE_HEAD exists)."));
			close_object_store(the_repository->objects);
		string_list_split(&list, string, ' ', -1);

	if (read_cache_unmerged())
			die(_("Can merge only exactly one commit into empty head"));
			usage_msg_opt(_("--abort expects no arguments"),
	{ OPTION_LOWLEVEL_CALLBACK, 'F', "file", &merge_msg, N_("path"),

	if (!branch->remote_name)
		else {
		if (starts_with(found_ref, "refs/remotes/")) {
	if (!no_verify && run_commit_hook(0 < option_edit, get_index_file(),
	for (i = 0; i < use_strategies_nr; i++) {
	}
		 */
		die_errno(_("Could not read from '%s'"), filename);
	} else if (!strcmp(k, "gpg.mintrustlevel")) {
	OPT_BOOL(0, "summary", &show_diffstat, N_("(synonym to --stat)")),
{
		if (ret < 2) {
	cleanup_message(&msg, cleanup_mode, 0);
		discard_cache();

	} else {
	for (i = 0; i < active_nr; i++)
					  &commit->object.oid,
		if (0 <= boolval) {
{
static int option_parse_strategy(const struct option *opt,
		; /* already up-to-date */
	if (!head_subsumed || fast_forward == FF_NO)
	 * and following the tags from upstream?  If so, we must have

		else
static struct commit_list *reduce_parents(struct commit *head_commit,
		else {
			      struct commit *head)
	const char *args[7];
			error(_("Not handling anything other than two heads merge."));
			}
		return 0;
	if (verbose)
			char saved = merge_names->buf[pos + hexsz];
				" (no commit created; -m option ignored)");
	}
			 * merge_bases again, otherwise "git merge HEAD^
	pptr = commit_list_append(head, pptr);
	int is_throwaway_tag = 0;
			fast_forward = boolval ? FF_ALLOW : FF_NO;
			else if (seen_nonzero)
					  &head_commit->object.oid,
	free_commit_list(remoteheads);
{
		const char *nargv[] = {"commit", NULL};

		if (!remoteheads)
#define DEFAULT_TWOHEAD (1<<0)
			 * We ignore errors in 'gc --auto', since the
static void prepare_to_commit(struct commit_list *remoteheads)
			oid = &desc->obj->oid;
		struct commit_list *list = remoteheads;
		return 0;
		struct commit_list *reversed = NULL;
	if (merge_names == &fetch_head_file)
	if (!branch->merge_nr)
static struct strategy *get_strategy(const char *name)
	rev.diffopt.format_callback = count_diff_files;
	strbuf_addbuf(&merge_msg, &msg);

	if (!head_commit) {
		   const struct object_id *new_head, const char *msg)

	else {
}
		if (commit == head_commit)
			      get_cleanup_mode(cleanup_arg, 1));
	OPT__VERBOSITY(&verbosity),
		write_merge_state(remoteheads);
}
	 * the resulting merge, unless --no-ff is given.  We will flip
	if (argc == 2 && !strcmp(argv[1], "-h"))
	if (err_msg)
static int no_verify;
	if (!msg)
}
			const char *argv_gc_auto[] = { "gc", "--auto", NULL };
	unsigned attr;
		for (i = 0; i < main_cmds.cnt; i++) {
	cleanup_mode = get_cleanup_mode(cleanup_arg, 0 < option_edit);
	 * Now we know we are merging a tag object.  Are we downstream
		}
			die(_("refusing to merge unrelated histories"));
	 */

	REALLOC_ARRAY(argv, argc + 2);


			builtin_merge_options);
			printf("%s\n", msg);

static void prepare_merge_message(struct strbuf *merge_names, struct strbuf *merge_msg)
/* Get the name for the merge commit's message. */
#include "refspec.h"
		diffcore_std(&opts);
static void count_diff_files(struct diff_queue_struct *q,
		exit(1);
	if (e) {
}
	} else if (!strcmp(k, "merge.defaulttoupstream")) {
N_("An empty message aborts the commit.\n");
	struct fmt_merge_msg_opts opts;
		desc = merge_remote_util(c);
		strbuf_addch(&msg, '\n');
				    oid_to_hex(&branch_head), remote);

	OPT_BOOL(0, "overwrite-ignore", &overwrite_ignore, N_("update ignored files (default)")),
static const char *pull_twohead, *pull_octopus;
		show_progress = 0;
					       check_trust_level);
		die(_("Not possible to fast-forward, aborting."));
		abort_commit(remoteheads, NULL);
		remoteheads = collect_parents(head_commit, &head_subsumed,
	args[2] = oid_to_hex(stash);
{
	  N_("add (at most <n>) entries from shortlog to merge commit message"),
	BUG_ON_OPT_ARG(arg_not_used);
		arg = ctx->opt;
		if (verify_signatures)
static void write_merge_heads(struct commit_list *remoteheads)
		update_ref("initial pull", "HEAD", remote_head_oid, NULL, 0,

			builtin_merge_options);
static enum ff_type fast_forward = FF_ALLOW;

		 * We do the same for "git pull".
		if (ptr)
		 */
static int default_to_upstream = 1;

	const char *argv[] = {"stash", "create", NULL};
		verify_signatures = git_config_bool(k, v);
		int boolval = git_parse_maybe_bool(v);

	strbuf_reset(msg);
	if (squash)
#include "branch.h"
	int i;
			"fix conflicts and then commit the result.\n"));
	strbuf_branchname(&bname, remote, 0);
		struct commit *commit;
static size_t xopts_nr, xopts_alloc;

	if (commit_tree(merge_msg.buf, merge_msg.len, result_tree, parents,

	struct object_id result_tree, stash, head_oid;
	if (!no_verify && run_commit_hook(0 < option_edit, index_file, "pre-merge-commit", NULL))
			die(_("No remote-tracking branch for %s from %s"),
	strbuf_reset(&buf);
	desc = merge_remote_util(remote_head);
		is_throwaway_tag = 1;
static int abort_current_merge;

	write_merge_heads(remoteheads);
	OPT_END()
		pretty_print_commit(&ctx, commit, &out);
					break;
			usage_msg_opt(_("--quit expects no arguments"),
#include "gpg-interface.h"
	if (refresh_and_write_cache(REFRESH_QUIET, SKIP_IF_UNCHANGED, 0) < 0)


	repo_init_revisions(the_repository, &rev, "");
			if (!read_tree_trivial(&common->item->object.oid,
		abort_commit(remoteheads, _("Empty commit message."));
			builtin_merge_usage, 0);

		if (ce_stage(active_cache[i]))
			die(_("unable to write %s"), get_index_file());
		die(_("revision walk setup failed"));

}
{
		 * tree.

	{ OPTION_INTEGER, 0, "log", &shortlog_len, N_("n"),
{
{
			strbuf_addf(msg, "%s\t\tremote-tracking branch '%s' of .\n",
{
	 * tips being merged.
	if (0 < option_edit) {
			die(_("not something we can merge in %s: %s"),
		merge_names = &fetch_head_file;
			o.subtree_shift = "";
	if (!merge_remote_util(commit) ||
		fprintf(stderr, ".\n");
		error("%s", err_msg);
		st_stdin.st_ino == st_stdout.st_ino &&
	struct rev_info rev;
}
	if (!loaded) {
	struct strbuf buf = STRBUF_INIT;
	struct pretty_print_context ctx = {0};
			die(_("Squash commit into empty head not supported yet"));
}
static int check_trust_level = 1;
			}
		 * add/rm <file>', just 'git commit'.
			    "Please, commit your changes before you merge."));

		die(_("read-tree failed"));
}
	strbuf_release(&buf);
		fprintf(stderr, _("Automatic merge went well; "
	strbuf_addch(&merge_msg, '\n');
			verify_merge_signature(p->item, verbosity,
	}
		struct lock_file lock = LOCK_INIT;
		o.branch2 = merge_remote_util(remoteheads->item)->name;
#include "lockfile.h"
		fprintf(stderr, _("Could not find merge strategy '%s'.\n"), name);

				goto done;
	OPT_RERERE_AUTOUPDATE(&allow_rerere_auto),
			; /* already up-to-date */
	/*
	rev.diffopt.format_callback_data = &cnt;

		}
			for (j = 0; j < ARRAY_SIZE(all_strategy); j++)
		strbuf_addf(&buf, "GITHEAD_%s",
				 const char *name, int unset)
		 * to date.
	 * It is OK to ignore error here, for example when there was
}
		die_errno(_("could not open '%s' for reading"), filename);
static struct strategy **use_strategies;
				fprintf(stderr, " %s", other_cmds.names[i]->name);
	}
	}
	else if (!len)		/* no changes */
	run_hook_le(NULL, "post-merge", squash ? "1" : "0", NULL);
			finish_up_to_date(_("Already up to date. Yeeah!"));
	} else {
	if (merge_msg->len)
			printf(_("No merge message -- not updating HEAD\n"));

		die_errno(_("could not close '%s'"), filename);
		if (fast_forward == FF_NO)
}
	int argc;
	rc = 0;
{



			    oid_to_hex(&commit->object.oid));
	FF_ALLOW,
		if (orig_argc != 2)
		}

		return;
{
{
	}
		 * We are not doing octopus and not fast-forward.  Need
	struct merge_remote_desc *desc;
			struct cmdname *ent = main_cmds.names[i];
}
	strbuf_setlen(&buffer, buffer.len-1);
		struct object_id *remote_head_oid;

	opts.fn = threeway_merge;
{
	const char **argv;
		shortlog_len = (merge_log_config > 0) ? merge_log_config : 0;
static const char merge_editor_comment[] =
	if (option_commit < 0)
	FF_NO,
		 * An octopus.  If we can reach all the remote we are up
		   struct commit_list *remoteheads,
{

		usage_with_options(builtin_merge_usage,
	trees[nr_trees] = parse_tree_indirect(common);
		if (squash)
	struct child_process cp = CHILD_PROCESS_INIT;
}
	if (!best_strategy) {

			 */
			goto done;
}
				       common, remoteheads,
	strbuf_reset(&buf);
		      builtin_merge_usage, 0);
			strbuf_addstr(&msg,
static int option_commit = -1;
			strbuf_addf(msg,
			restore_state(&head_commit->object.oid, &stash);
			add_strategies(pull_twohead, DEFAULT_TWOHEAD);

	if (squash) {
			fast_forward = FF_NO;
		struct commit *commit = pop_commit(&parents);
	if (verbosity < 0)

	cnt += count_unmerged_entries();
}
}
static int allow_rerere_auto;
#define NO_FAST_FORWARD (1<<2)
		strbuf_addstr(&buf, "no-ff");


			if (!commit)
	OPT_BOOL(0, "stat", &show_diffstat,
		for (i = 0; i < main_cmds.cnt; i++)

		int clean, x;
	strbuf_addstr(&out, "Squashed commit of the following:\n");
				    truname.buf + 11,
	remove_merge_branch_state(the_repository);
				len++;
	printf(_("Automatic merge failed; "
	if (status)
static int show_progress = -1;
	for (i = 0; i < branch->merge_nr; i++) {
	const unsigned hexsz = the_hash_algo->hexsz;
	free(argv);
				best_strategy = use_strategies[i]->name;


		/*
	struct strbuf merge_names = STRBUF_INIT, *autogen = NULL;
		}

		      FF_ONLY, PARSE_OPT_NONEG),
	for (j = remoteheads; j; j = j->next) {
		goto done;

	if (squash) {
	const struct object_id *head = &head_commit->object.oid;
static int try_merge_strategy(const char *strategy, struct commit_list *common,
		for (p = remoteheads; p; p = p->next) {
		goto cleanup;
	if (unset)
int cmd_merge(int argc, const char **argv, const char *prefix)
		struct string_list list = STRING_LIST_INIT_DUP;
static enum commit_msg_cleanup_mode cleanup_mode;

	OPT_CALLBACK('s', "strategy", &use_strategies, N_("strategy"),
	update_ref("updating ORIG_HEAD", "ORIG_HEAD",
	}
	N_("git merge --continue"),
			return 2;
static void merge_name(const char *remote, struct strbuf *msg)
		struct object_id oid;
	memset(&opts, 0, sizeof(opts));
		commit_list_insert(head_commit, &list);
