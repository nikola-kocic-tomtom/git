
	if (!is_null_oid(&orig_head) && !is_null_oid(&curr_head) &&
			BUG("submodule recursion option not understood");
static char *opt_append;
		PARSE_OPT_NONEG),
		N_("deepen history of shallow repository based on time"),
		N_("GPG sign commit"),
		argv_array_push(arr, "-q");
	strbuf_release(&msg);
		fprintf(stderr, "\n");
{
	fclose(fp);

	return merge_branch;
				   "--recursive", "--checkout", NULL);
			struct commit *merge_head, *head;
		N_("automatically stash/stash pop before and after rebase")),
#include "dir.h"
	int verbosity;
		if (!ret && (recurse_submodules == RECURSE_SUBMODULES_ON ||
	{ OPTION_CALLBACK, 0, "recurse-submodules",
 * value of "branch.$curr_branch.rebase", where $curr_branch is the current
/**
	OPT_PASSTHRU(0, "progress", &opt_progress, NULL,
	struct branch *curr_branch;

		spec_src = "HEAD";
	strbuf_release(&sb);
	if (opt_update_shallow)
static char *opt_update_shallow;
		N_("show a diffstat at the end of the merge"),
		if (get_rebase_fork_point(&rebase_fork_point, repo, *refspecs))
 *    part of the configured fetch refspec.)
	git_config(git_pull_config, NULL);
			ret = update_submodules();
	setenv("GIT_REFLOG_ACTION", msg.buf, 0);
	if (set_upstream)
		if (is_null_oid(&orig_head) && !is_cache_unborn())
				"$ git diff %s\n"
			argv_array_push(&args, "--recurse-submodules=on-demand");

		opt_ff = xstrdup_or_null(config_get_ff());

static void get_merge_heads(struct oid_array *merge_heads)
		N_("fetch from all remotes"),
	strbuf_release(&sb);
			merge_branch = mkpath("refs/heads/%s", spec_src);
};
		0),
	argv_array_pushv(&args, opt_strategies.argv);
		return -1;
	OPT_PASSTHRU(0, "all", &opt_all, NULL,
 * Builtin "git pull"
	OPT_PASSTHRU(0, "ff-only", &opt_ff, NULL,
static char *opt_verify_signatures;
	OPT_PASSTHRU('S', "gpg-sign", &opt_gpg_sign, N_("key-id"),
	if (opt_ff)
#include "submodule-config.h"
		*repo = NULL;
			fork_point = NULL;
	if (opt_depth)
		argv_array_push(&args, opt_commit);
	if (run_fetch(repo, refspecs))

	else if (skip_prefix(spec_src, "refs/heads/", &spec_src))
	struct strbuf msg = STRBUF_INIT;
static int run_merge(void)
		return NULL;
		verify_merge_signature(commit, opt_verbosity,
	    (!opt_ff || strcmp(opt_ff, "--ff-only"))) {
		starts_with(spec_src, "remotes/"))
#include "rebase.h"

#include "parse-options.h"
#include "config.h"
				"After making sure that you saved anything precious from\n"
			"for your current branch, you must specify a branch on the command line."),
/**
			die(_("Cannot merge multiple branches into empty head."));
	if (opt_diffstat)
	OPT_BOOL(0, "dry-run", &opt_dry_run,
 * 2. We fetched from a non-default remote, but didn't specify a branch to
 *
			continue;  /* ref is not-for-merge */
		argv_array_push(&args, opt_update_shallow);
	 * branch.
			fprintf_ln(stderr, _("Please specify which branch you want to merge with."));
	} else if (!strcmp(var, "gpg.mintrustlevel")) {
 */
	if (opt_prune)
/**
		opt_rebase = config_get_rebase();
static const char *get_tracking_branch(const char *remote, const char *refspec)
 * "--ff-only". Otherwise, if pull.ff is set to an invalid value, die with an
		argv_array_push(&args, opt_ff);
	N_("git pull [<options>] [<repository> [<refspec>...]]"),

		PARSE_OPT_NOARG | PARSE_OPT_NONEG),
	} else if (*refspecs)
		N_("report that we have only objects reachable from this object"),
}
	if (!opt_rebase && opt_autostash != -1)
		return NULL;
		return 1;
	OPT_PASSTHRU_ARGV(0, "deepen", &opt_fetch, N_("n"),
		const struct object_id *curr_head,

		argv_array_push(&args, opt_ipv4);
		PARSE_OPT_NOARG),
{
		const struct object_id *merge_head,
	OPT_PASSTHRU(0, "update-shallow", &opt_update_shallow, NULL,
	OPT_CLEANUP(&cleanup_arg),
	argv_array_pushl(&args, "fetch", "--update-head-ok", NULL);
	OPT_PASSTHRU('t', "tags", &opt_tags, NULL,
	if (opt_dry_run)
				_("please commit or stash them."), 1, 0);
 * Runs git-merge, returning its exit status.
}
			    oid_to_hex(merge_head));
		argv_array_push(&args, max_children);
	}
 * Returns the default configured value for --rebase. It first looks for the
				   &revs);
static char *opt_upload_pack;
	  N_("incorporate changes by rebasing rather than merging"),


	if (arg)
		PARSE_OPT_NOARG),
	struct branch *curr_branch = branch_get("HEAD");
		    &opt_allow_unrelated_histories,
static const char *get_upstream_branch(const char *remote)
 */
static int git_pull_config(const char *var, const char *value, void *cb)
				       check_trust_level);
	struct commit_list *revs = NULL, *result;
	}
			strbuf_addch(&msg, ' ');
	else
			oidclr(&rebase_fork_point);
		N_("option=value"),
 *
		return 1;
		else
	if (fork_point && !is_null_oid(fork_point))
		if (!ret && (recurse_submodules == RECURSE_SUBMODULES_ON ||
static char *opt_ipv4;
		int fatal)
static int pull_into_void(const struct object_id *merge_head,
		if (!git_config_get_value(key, &value)) {
	if (opt_log)
		N_("accept refs that update .git/shallow"),
	refspec_item_init_or_die(&spec, refspec, REFSPEC_FETCH);
	  "(false|true|merges|preserve|interactive)",
#include "cache.h"
			fprintf_ln(stderr, _("There are no candidates for merging among the refs that you just fetched."));
		0),
/**
 */
static int get_only_remote(struct remote *remote, void *cb_data)
		argv_array_push(&args, repo);

		argv_array_push(&args, opt_tags);
	}
 * configured upstream branch.
		N_("abort if fast-forward is not possible"),

	struct oid_array merge_heads = OID_ARRAY_INIT;
#include "submodule.h"
/**
		PARSE_OPT_NOARG),

	argv_push_verbosity(&cp.args);
 *    merge. We can't use the configured one because it applies to the default
		commit = lookup_commit(the_repository, merge_head);
		N_("dry run")),
	if (!git_config_get_value("pull.rebase", &value))
		0),

	if (opt_verbosity >= 0 &&
/**
			ret = rebase_submodules();

	FILE *fp;
	assert(curr_branch_remote);
				"$ git reset --hard\n"
		BUG("refspecs without repo?");
static struct option pull_options[] = {
		PARSE_OPT_NOARG),
 */
		0),
	const char *spec_src;

 *
	if (opt_edit)
	if (fatal)
}
		const struct object_id *merge_head,

	else if (skip_prefix(spec_src, "heads/", &spec_src))
	int autostash;

	argv_array_pushl(&cp.args, "submodule", "update",

		0),
		*value = parse_config_rebase("--rebase", arg, 0);
		fprintf(stderr, "\n");
		if (i)

/**
{
#include "oid-array.h"

	if (get_oid("HEAD", &curr_head))
{
			"\n"
 * Pushes "-f" switches into arr to match the opt_force level.
static int run_fetch(const char *repo, const char **refspecs)
	argv_array_pushv(&args, opt_strategy_opts.argv);
 * 1. We fetched from a specific remote, and a refspec was given, but it ended
		die(_("Invalid value for %s: %s"), key, value);
		else
			fprintf_ln(stderr, _("Please specify which branch you want to rebase against."));
	exit(1);
	while (strbuf_getline_lf(&sb, fp) != EOF) {
	if (!strcmp(var, "rebase.autostash")) {
		argv_array_push(&args, opt_upload_pack);
static char *opt_signoff;
	}
		die_no_merge_candidates(repo, refspecs);
	*refspecs = argv;
		PARSE_OPT_OPTARG),
	  PARSE_OPT_OPTARG, parse_opt_rebase },



		argv_array_push(&args, opt_signoff);
		argv_array_push(&args, "--dry-run");
	if (strcmp(curr_branch_remote, rm->name))

}
	OPT__FORCE(&opt_force, N_("force overwrite of local branch"), 0),
 */
		fprintf(stderr, "\n");
		*repo = *argv++;
		argv_array_push(&args, "--allow-unrelated-histories");
	/*
		argv_array_push(&args, opt_gpg_sign);

/**
			struct commit_list *list = NULL;
		if (checkout_fast_forward(the_repository, &orig_head,

 * Sets the GIT_REFLOG_ACTION environment variable to the concatenation of argv
/**
 * branch, and if HEAD is detached or the configuration key does not exist,
	cp.git_cmd = 1;
		if (opt_rebase)

{
		PARSE_OPT_NOARG),
	return 0;
		fprintf_ln(stderr, _("See git-pull(1) for details."));
/**
static void parse_repo_refspecs(int argc, const char **argv, const char **repo,
	OPT_PASSTHRU(0, "summary", &opt_diffstat, NULL,
		0),
		die_resolve_conflict("pull");
		return NULL;
/**
	if (opt_progress)
		argv_array_push(&args, "--show-forced-updates");
	if (!strcmp(value, "only"))
			"a branch. Because this is not the default configured remote\n"
#include "exec-cmd.h"

	const char *value;
	OPT_PASSTHRU(0, "unshallow", &opt_unshallow, NULL,
	cp.git_cmd = 1;
	argc = parse_options(argc, argv, prefix, pull_options, pull_usage, 0);
	struct branch *curr_branch = branch_get("HEAD");
{
#include "sequencer.h"

static char *opt_gpg_sign;

		N_("convert to a complete repository"),
 * Used by die_no_merge_candidates() as a for_each_remote() callback to
	if (opt_gpg_sign)
			   &revs);

			die(_("Cannot fast-forward your working tree.\n"
		N_("perform a commit if the merge succeeds (default)"),
		oidclr(&orig_head);
static char *opt_progress;
		PARSE_OPT_NOARG),
}
			"  git config pull.rebase false  # merge (the default strategy)\n"
		if (!commit)
	struct strbuf sb = STRBUF_INIT;
 * remote is not the branch's configured remote or the branch does not have any
	OPT_PASSTHRU('6',  "ipv6", &opt_ipv6, NULL,
	 * Two-way merge: we treat the index as based on an empty tree,
	/* Options passed to git-rebase */
 * is not provided in argv, it is set to NULL.
		argv_array_push(&args, opt_progress);
				ret = run_merge();
		N_("option to transmit"),
	if (opt_verify_signatures) {

/**
	OPT_PASSTHRU_ARGV(0, "shallow-exclude", &opt_fetch, N_("revision"),
		N_("set upstream for git pull/fetch"),
	OPT_PASSTHRU_ARGV(0, "shallow-since", &opt_fetch, N_("time"),
		fprintf_ln(stderr, _("You are not currently on a branch."));
		 * this only checks the validity of cleanup_arg; we don't need
	*remote_name = remote->name;
	OPT_PASSTHRU_ARGV(0, "negotiation-tip", &opt_fetch, N_("revision"),
		N_("use IPv6 addresses only"),
	if (read_cache_unmerged())
static int config_autostash;

		argv_array_push(&args, opt_verify_signatures);
		return ret;
		config_autostash = git_config_bool(var, value);
	if (!get_octopus_merge_base(&oct_merge_base, curr_head, merge_head, fork_point))
		PARSE_OPT_NOARG),
		fprintf_ln(stderr, _("If you wish to set tracking information for this branch you can do so with:"));
 * error.
static char *opt_all;
	const char *curr_branch_remote;
		argv_array_push(&args, opt_ipv6);
		PARSE_OPT_OPTARG),
	if (opt_gpg_sign)
 *    remote, thus the user must specify the branches to merge.

		case RECURSE_SUBMODULES_ON:

 * REBASE_FALSE. If value is a true value, returns REBASE_TRUE. If value is
	argv_array_clear(&args);
	OPT_PASSTHRU_ARGV('s', "strategy", &opt_strategies, N_("strategy"),
				  merge_head, 0))
		N_("create a single commit instead of doing a merge"),
	}
				/* we can fast-forward this without invoking rebase */
	else if (starts_with(spec_src, "refs/") ||
	case 1:
	curr_branch_remote = remote_for_branch(curr_branch, NULL);
	} else

	NULL
 * Parses argv into [<repo> [<refspecs>...]], returning their values in `repo`
		argv_array_push(arr, "-v");

static void NORETURN die_no_merge_candidates(const char *repo, const char **refspecs)
 * Callback for --rebase, which parses arg with parse_config_rebase().
		return pull_into_void(merge_heads.oid, &curr_head);
 *    wildcard refspec which had no matches on the remote end.
/**
}

 * 3. We fetched from the branch's or repo's default remote, but:
	int status;
	return run_command(&cp);

 * REBASE_PRESERVE. If value is a invalid value, dies with a fatal error if
	return 0;
		argv_array_push(&args, opt_keep);
			die(_("Updating an unborn branch with changes added to the index."));
		return 0;

 * fork point calculated by get_rebase_fork_point(), runs git-rebase with the
	free_commit_list(result);
	cp.no_stderr = 1;
	argv_array_push(&args, "--onto");
	argv_array_clear(&args);
		argv_array_push(&args, opt_diffstat);
			break;

	cp.no_stdin = 1;
	OPT_PASSTHRU(0, "set-upstream", &set_upstream, NULL,
	curr_branch = branch_get("HEAD");
		/*
			fprintf_ln(stderr, _("Please specify which branch you want to rebase against."));

		N_("use IPv4 addresses only"),
	if (opt_rebase) {
		argv_array_push(arr, "-f");
cleanup:
		return "--ff-only";
		N_("number of submodules pulled in parallel"),
{
#include "run-command.h"
	if (refspec)
}
	argv_push_verbosity(&cp.args);
	OPT_SET_INT(0, "allow-unrelated-histories",
/**
 */
 */
	const char *filename = git_path_fetch_head(the_repository);
		const struct object_id *fork_point)
	if (!curr_branch)
		PARSE_OPT_NOARG | PARSE_OPT_HIDDEN),
	OPT_GROUP(N_("Options related to merging")),
		if (for_each_remote(get_only_remote, &remote_name) || !remote_name)
		0),

			ret = run_rebase(&curr_head, merge_heads.oid, &rebase_fork_point);
	if (opt_rebase) {
				"to recover."), oid_to_hex(&orig_head));
	get_merge_heads(&merge_heads);
 * Returns remote's upstream branch for the current branch. If remote is NULL,
		PARSE_OPT_NONEG | PARSE_OPT_NOARG),
 * Based on git-pull.sh by Junio C Hamano
		}
		fprintf_ln(stderr, _("There is no tracking information for the current branch."));
	if (repo) {

	if (!result)
	argv_array_push(&args, "FETCH_HEAD");

			fprintf_ln(stderr, _("Please specify which branch you want to merge with."));
 */
		argv_array_pushv(&args, refspecs);
			     recurse_submodules == RECURSE_SUBMODULES_ON_DEMAND))
		die(_("--[no-]autostash option is only valid with --rebase."));
/*
{
	const char **remote_name = cb_data;
 * `remote` does not name a valid remote, HEAD does not point to a branch,
	if (is_null_oid(&orig_head)) {
	ret = get_oid_hex(sb.buf, fork_point);
 */
	OPT_PASSTHRU(0, "refmap", &opt_refmap, N_("refmap"),
		N_("path to upload pack on remote end"),
	if (opt_upload_pack)
	OPT_PASSTHRU(0, "log", &opt_log, N_("n"),
}
						       &orig_head);
	result = get_octopus_merge_bases(revs);
 * Sets merge_base to the octopus merge base of curr_head, merge_head and
		argv_array_push(&args, "--interactive");
				   "--recursive", "--rebase", NULL);
	 * and try to fast-forward to HEAD. This ensures we will not lose
	struct object_id oct_merge_base;
}
	const char *remote = curr_branch ? curr_branch->remote_name : NULL;
	OPT_PASSTHRU('4',  "ipv4", &opt_ipv4, NULL,
		if (!is_null_oid(fork_point) && oideq(&oct_merge_base, fork_point))
		fprintf(stderr, "\n");
 *    a. We are not on a branch, so there will never be a configured branch to

	case 0:

		N_("deepen history of shallow clone"),
	OPT_PASSTHRU('j', "jobs", &max_children, N_("n"),
				  the_hash_algo->empty_tree,
		N_("fetch all tags and associated objects"),
		const char *remote_name = NULL;
	if (opt_ipv6)
static int opt_force;
static char *opt_keep;
 */
		   &recurse_submodules, N_("on-demand"),
	} else {

	while (force-- > 0)
	if (opt_append)
				ran_ff = 1;
 * Given the repo and refspecs, sets fork_point to the point at which the
		else

	struct strbuf sb = STRBUF_INIT;
		 * The working tree and the index file are still based on
static char *opt_tags;
	if (curr_branch) {
	OPT_GROUP(N_("Options related to fetching")),
		if (!strcmp(remote, "."))

		   PARSE_OPT_OPTARG, option_fetch_parse_recurse_submodules },
}

		PARSE_OPT_OPTARG),
		N_("server-specific"),
	commit_list_insert(lookup_commit_reference(the_repository, merge_head),
		argv_array_push(&args, opt_all);
	if (opt_allow_unrelated_histories > 0)
		argv_array_push(&args, "--no-autostash");
	if (get_oid("HEAD", &orig_head))
#include "wt-status.h"
}
		N_("merge strategy to use"),

		return 0;
	if (opt_all)
		return 1;
 * current branch forked from its remote-tracking branch. Returns 0 on success,
	if (update_ref("initial pull", "HEAD", merge_head, curr_head, 0, UPDATE_REFS_DIE_ON_ERR))
#include "refspec.h"
				N_("pull with rebase"),
#include "commit-reach.h"
		const char ***refspecs)
		PARSE_OPT_NOARG | PARSE_OPT_NONEG),


/**
		argv_array_push(&args, oid_to_hex(merge_head));
	ret = capture_command(&cp, &sb, GIT_MAX_HEXSZ);
 * refs/heads/<branch_name> to refs/remotes/<remote_name>/<branch_name>.
 *
			head = lookup_commit_reference(the_repository,
		0),
	argv_array_pushv(&args, opt_fetch.argv);
		return NULL;
	if (opt_verify_signatures &&
	OPT_PASSTHRU(0, "squash", &opt_squash, NULL,

static enum rebase_type parse_config_rebase(const char *key, const char *value,

		warning(_("Pulling without specifying how to reconcile divergent branches is\n"
}
		PARSE_OPT_NOARG),
	ret = run_command_v_opt(args.argv, RUN_GIT_CMD);
static char *opt_depth;

	int ret;
		     recurse_submodules == RECURSE_SUBMODULES_ON_DEMAND) &&
/**
	struct argv_array args = ARGV_ARRAY_INIT;

	OPT_PASSTHRU(0, "commit", &opt_commit, NULL,
	OPT_BOOL(0, "show-forced-updates", &opt_show_forced_updates,
static struct argv_array opt_fetch = ARGV_ARRAY_INIT;
static int opt_show_forced_updates = -1;
		 */

	enum rebase_type v = rebase_parse_value(value);
		argv_array_push(&args, opt_log);

			*curr_branch->merge_name);
static int check_trust_level = 1;
	else
	OPT_PASSTHRU(0, "depth", &opt_depth, N_("depth"),
			"or --ff-only on the command line to override the configured default per\n"

 *
}
		fprintf_ln(stderr, _("You asked to pull from the remote '%s', but did not specify\n"
			remote_name = _("<remote>");
	OPT_PASSTHRU(0, "verify-signatures", &opt_verify_signatures, NULL,
	if (cleanup_arg)
		 * a valid value for use_editor
static const char *config_get_ff(void)

	switch (git_parse_maybe_bool(value)) {
	else if (opt_rebase == REBASE_PRESERVE)
int cmd_pull(int argc, const char **argv, const char *prefix)
		if (starts_with(p, "\tnot-for-merge\t"))
#include "remote.h"


	} else if (!curr_branch) {

	argv_array_push(&args, "rebase");
	struct branch *curr_branch;
		N_("specify fetch refmap"),
static const char * const pull_usage[] = {
{
		*value = unset ? REBASE_FALSE : REBASE_TRUE;
	const char *merge_branch;
		return "--ff";
	else
	if (opt_signoff)
		return status;
		switch (recurse_submodules) {

{
		if (!ran_ff)
	{ OPTION_CALLBACK, 'r', "rebase", &opt_rebase,
		argv_array_push(&args, opt_edit);
/* Options passed to git-merge or git-rebase */
			}
 *    b. We are on a branch, but there is no configured branch to merge with.
	if (opt_rebase < 0)
		error(_("Invalid value for %s: %s"), key, value);
	else
{
		goto cleanup;

	if (*refspecs) {
	 * index/worktree changes that the user already made on the unborn
		return -1;
			"  git config pull.rebase true   # rebase\n"

	return REBASE_INVALID;
		 * orig_head commit, but we are merging into curr_head.
	if (file_exists(git_path_merge_head(the_repository)))
		PARSE_OPT_NOARG),
	OPT_PASSTHRU('a', "append", &opt_append, NULL,
		argv_array_push(&args, "--autostash");
	} else
		PARSE_OPT_NOARG),

		default:
	enum rebase_type *value = opt->value;
	OPT_PASSTHRU(0, "stat", &opt_diffstat, NULL,
		int ret = run_merge();

	}
 * Appends merge candidates from FETCH_HEAD that are not marked not-for-merge
			"commit %s."), oid_to_hex(&orig_head));
		starts_with(spec_src, "tags/") ||

		N_("keep downloaded pack"),
	return *value == REBASE_INVALID ? -1 : 0;
 */
	if (cleanup_arg)
	for (verbosity = opt_verbosity; verbosity > 0; verbosity--)
/**
		argv_array_push(&args, oid_to_hex(fork_point));
	OPT_PASSTHRU_ARGV('X', "strategy-option", &opt_strategy_opts,
	/* Options passed to git-merge */
		N_("(synonym to --stat)"),
		argv_array_push(&args, opt_append);
	}
static int opt_autostash = -1;
	if (v != REBASE_INVALID)
		argv_array_push(&args, opt_gpg_sign);
		PARSE_OPT_NOARG),
 *
		argv_array_push(&args, "--preserve-merges");

	struct child_process cp = CHILD_PROCESS_INIT;


	argv_push_verbosity(&args);
}
{
		N_("verify that the named commit has a valid GPG signature"),
 * Parses the value of --rebase. If value is a false value, returns
	return branch_get_upstream(curr_branch, NULL);
 * 4. We fetched from the branch's or repo's default remote, but the configured
 * -1 on failure.
		 */
		if ((recurse_submodules == RECURSE_SUBMODULES_ON ||
			"discouraged. You can squelch this message by running one of the following\n"
		recurse_submodules = git_config_bool(var, value) ?

static char *opt_squash;
	/* Shared options */
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		fprintf_ln(stderr, "    git pull %s %s", _("<remote>"), _("<branch>"));

		 *
	}
			enum rebase_type ret = parse_config_rebase(key, value, 1);


		fprintf_ln(stderr, "    git branch --set-upstream-to=%s/%s %s\n",
		argv_array_push(&args, opt_squash);
		fprintf_ln(stderr, "    git pull %s %s", _("<remote>"), _("<branch>"));
	refspec_item_clear(&spec);
		N_("allow fast-forward"),
	return 0;
			free(key);
		argv_array_push(&args, opt_prune);
{
			fprintf_ln(stderr, _("There is no candidate for rebasing against among the refs that you just fetched."));
			"from the remote, but no such ref was fetched."),
			merge_head = lookup_commit_reference(the_repository,
static char *opt_diffstat;
		}
	} else if (!curr_branch->merge_nr) {
	struct child_process cp = CHILD_PROCESS_INIT;
		    N_("allow merging unrelated histories"), 1),
 * Given the current HEAD oid, the merge head returned from git-fetch and the
		PARSE_OPT_NOARG),
}
static struct argv_array opt_strategies = ARGV_ARRAY_INIT;
		argv_array_push(&args, opt_refmap);
		const char *refspec)

	if (!*spec_src || !strcmp(spec_src, "HEAD"))

	for (verbosity = opt_verbosity; verbosity < 0; verbosity++)
	/* Shared options */
		fprintf_ln(stderr, _("Generally this means that you provided a wildcard refspec which had no\n"


		check_trust_level = 0;
	const char *value;
/**
	OPT_PASSTHRU_ARGV('o', "server-option", &opt_fetch,
{
		fprintf_ln(stderr, _("See git-pull(1) for details."));
static int parse_opt_rebase(const struct option *opt, const char *arg, int unset)
	OPT_BOOL(0, "autostash", &opt_autostash,
 * exist, returns REBASE_FALSE.
		free(key);
		const struct object_id *curr_head)
	free_commit_list(revs);
		PARSE_OPT_OPTARG),

 * Derives the remote-tracking branch from the remote and refspec.
	if (opt_tags)
	autostash = config_autostash;
}
	OPT_PASSTHRU('p', "prune", &opt_prune, NULL,
 * Fetch one or more remote refs and merge it/them into the current HEAD.
	argv_array_pushv(&args, opt_strategies.argv);
			argv_array_push(&args, "--recurse-submodules=no");
 * into merge_heads.
	argv_array_clear(&args);

	int force = opt_force;
	if (argc > 0) {
	OPT__VERBOSITY(&opt_verbosity),
		PARSE_OPT_NOARG),

	fp = xfopen(filename, "r");
	if (opt_rebase == REBASE_MERGES)
static char *opt_ipv6;
#include "builtin.h"
	if (opt_autostash == 0)
	if (opt_keep)
#include "refs.h"
/* Shared options */
 */
	OPT_PASSTHRU('k', "keep", &opt_keep, NULL,
		return v;
 *    up not fetching anything. This is usually because the user provided a
 * Runs git-fetch, returning its exit status. `repo` and `refspecs` are the
	if (git_config_get_value("pull.ff", &value))
	die(_("Invalid value for pull.ff: %s"), value);
		case RECURSE_SUBMODULES_OFF:
		warning(_("fetch updated the current branch head.\n"
	else if (opt_show_forced_updates == 0)
		PARSE_OPT_NOARG),
					  &curr_head, 0))

	for (i = 0; i < argc; i++) {
{

	if (status)
		   N_("control for recursive fetching of submodules"),

		argv_array_push(&args, set_upstream);
}
			die(_("unable to access commit %s"),
#include "tempfile.h"
			require_clean_work_tree(the_repository,

 * FIXME: The current implementation assumes the default mapping of
			   &revs);
		return "--no-ff";
		N_("force progress reporting"),
	struct remote *rm;
 *    branch to merge didn't get fetched. (Either it doesn't exist, or wasn't
	    !strcmp(opt_verify_signatures, "--verify-signatures"))
	if (opt_unshallow)
	cp.git_cmd = 1;

		merge_branch = NULL;
		get_cleanup_mode(cleanup_arg, 0);
	argv_push_verbosity(&args);
static char *cleanup_arg;
	reduce_heads_replace(&result);
					"matches on the remote end."));
		N_("deepen history of shallow clone"),
	int ret;

{
	/* Shared options */
{
	int ret;
		case RECURSE_SUBMODULES_ON_DEMAND:
 */
	commit_list_insert(lookup_commit_reference(the_repository, curr_head),
	/* Shared options */
	OPT_PASSTHRU(0, "upload-pack", &opt_upload_pack, N_("path"),
	if (opt_progress)
	} else if (repo && curr_branch && (!remote || strcmp(repo, remote))) {

	argv_array_pushv(&args, opt_strategy_opts.argv);
	curr_branch = branch_get("HEAD");
	cp.no_stdin = 1;
		N_("do not show a diffstat at the end of the merge"),
			!oideq(&orig_head, &curr_head)) {

 * fatal is true, otherwise returns REBASE_INVALID.
		remote_branch = get_upstream_branch(repo);
 * retrieve the name of the remote if the repository only has one remote.
		 N_("check for forced-updates on all updated branches")),
		const struct object_id *fork_point)
	if (!rm)

	const char *repo, **refspecs;
			argv_array_push(&args, "--recurse-submodules=on");

/**
		return -1;
}
		}
 * fork_point. Returns 0 if a merge base is found, 1 otherwise.
			remote_branch, curr_branch->name, NULL);
	if (!remote_branch)
}
	cp.no_stdin = 1;
		argv_array_push(&args, opt_unshallow);
	oidcpy(merge_base, &result->item->object.oid);
static char *opt_commit;
	else if (opt_autostash == 1)
			repo);

							     &merge_heads.oid[0]);
	if (opt_diffstat)
#include "lockfile.h"

		goto cleanup;
static void set_reflog_message(int argc, const char **argv)

 */

	if (checkout_fast_forward(the_repository,
 */
	status = git_gpg_config(var, value, cb);
			commit_list_insert(head, &list);
		N_("deepen history of shallow clone, excluding rev"),
{
 *
		if (opt_rebase)
	/* Options passed to git-fetch */
	if (ret)
		N_("add Signed-off-by:"),
		else
				remote_name, _("<branch>"), curr_branch->name);
		warning(_("ignoring --verify-signatures for rebase"));
		argv_array_push(&args, opt_progress);
{
		const char *p;
/**
	OPT_PASSTHRU('n', NULL, &opt_diffstat, NULL,
	const char *remote_branch;
	if (!is_null_oid(fork_point))
	rm = remote_get(remote);
			return ret;
		set_reflog_message(argc, argv);
static char *opt_edit;
 */

{
 * appropriate arguments and returns its exit status.

	}

	if (recurse_submodules != RECURSE_SUBMODULES_DEFAULT)
		oidclr(&curr_head);
		argv_array_push(&args, opt_diffstat);
static char *max_children;
 */
 * Dies with the appropriate reason for why there are no merge candidates:
static char *opt_refmap;
		strbuf_addstr(&msg, argv[i]);
};
	argv_push_force(&args);

 * Read config variables.
		;
		if (!autostash) {
		return 0;
			RECURSE_SUBMODULES_ON : RECURSE_SUBMODULES_OFF;
 */
	argv_array_push(&args, oid_to_hex(merge_head));
		remote_branch = get_tracking_branch(repo, refspec);
				opt_ff = "--ff-only";
		oid_array_append(merge_heads, &oid);
	if (!curr_branch)

	 */
}
			"preference for all repositories. You can also pass --rebase, --no-rebase,\n"
		 * Update the working tree to match curr_head.
	return ret ? -1 : 0;

		fprintf(stderr, "\n");
	ret = run_command_v_opt(args.argv, RUN_GIT_CMD);

	if (*spec_src) {

static int get_octopus_merge_base(struct object_id *merge_base,
		PARSE_OPT_NOARG),
static void argv_push_force(struct argv_array *arr)
			break;
			"fast-forwarding your working tree from\n"
 * looks for the value of "pull.rebase". If both configuration keys do not
		struct commit *commit;
	if (!getenv("GIT_REFLOG_ACTION"))
		N_("add (at most <n>) entries from shortlog to merge commit message"),
		char *key = xstrfmt("branch.%s.rebase", curr_branch->name);
		/*
	struct argv_array args = ARGV_ARRAY_INIT;
			autostash = opt_autostash;
	}
	return git_default_config(var, value, cb);
	if (opt_refmap)
	if (opt_dry_run)
			"\n"
			merge_branch = mkpath("refs/remotes/%s/%s", remote, spec_src);

	struct refspec_item spec;

		argv_array_pushf(&args, "--cleanup=%s", cleanup_arg);
		if (opt_autostash != -1)

		return 1;
	}
		N_("append to .git/FETCH_HEAD instead of overwriting"),
static int rebase_submodules(void)
	return run_command(&cp);
	struct object_id oid;
	OPT_END()

	else if (opt_rebase == REBASE_INTERACTIVE)
	argv_array_pushl(&cp.args, "merge-base", "--fork-point",
		commit_list_insert(lookup_commit_reference(the_repository, fork_point),
static char *opt_log;
				"output, run\n"

		fprintf_ln(stderr, _("Your configuration specifies to merge with the ref '%s'\n"
		if (!autostash)


 *
			"  git config pull.ff only       # fast-forward only\n"
	parse_repo_refspecs(argc, argv, &repo, &refspecs);
	return ret;
			if (is_descendant_of(merge_head, list)) {
static struct argv_array opt_strategy_opts = ARGV_ARRAY_INIT;

 * "merges", returns REBASE_MERGES. If value is "preserve", returns
	struct object_id rebase_fork_point;
	if (max_children)
 * as a string and `refspecs` as a null-terminated array of strings. If `repo`
	if (opt_verify_signatures)
	struct child_process cp = CHILD_PROCESS_INIT;

static int recurse_submodules = RECURSE_SUBMODULES_DEFAULT;
 * repository and refspecs to fetch, or NULL if they are not provided.
		argv_array_push(&args, opt_depth);
	int ret;
{
	if (opt_show_forced_updates > 0)
 */

{
	spec_src = spec.src;
		N_("edit message before committing"),
			die(_("cannot rebase with locally recorded submodule modifications"));

	argv_array_pushl(&cp.args, "submodule", "update",
static enum rebase_type config_get_rebase(void)

static int run_rebase(const struct object_id *curr_head,

static int get_rebase_fork_point(struct object_id *fork_point, const char *repo,
		die_conclude_merge();
	argv_array_pushl(&args, "merge", NULL);
		;
			"commands sometime before your next pull:\n"
		return parse_config_rebase("pull.rebase", value, 1);
	ret = run_command_v_opt(args.argv, RUN_GIT_CMD);
#include "revision.h"

		int ret = 0;
static enum rebase_type opt_rebase = -1;
static int opt_verbosity;
	/* Options passed to git-fetch */

	if (!opt_ff)
		die(_("Cannot rebase onto multiple branches."));
	int i;
	if (opt_rebase && merge_heads.nr > 1)
static char *opt_unshallow;
	if (ret)
	if (*remote_name)
static void argv_push_verbosity(struct argv_array *arr)
}

		if (opt_rebase)
		0),
		return ret;
 *       merge with.

 */
static char *opt_ff;
	if (opt_ipv4)
		argc--;

		argv_array_push(&args, "--no-show-forced-updates");
static int update_submodules(void)
{
static int opt_allow_unrelated_histories;
 * If pull.ff is unset, returns NULL. If pull.ff is "true", returns "--ff". If
		    submodule_touches_in_range(the_repository, &rebase_fork_point, &curr_head))
	return ret;
	argv_push_verbosity(&args);
}
	if (opt_squash)
	struct object_id orig_head, curr_head;
 * the current branch's configured default remote is used. Returns NULL if
	if (!merge_heads.nr)
		 * The fetch involved updating the current branch.

	OPT_PASSTHRU(0, "ff", &opt_ff, NULL,
static int opt_dry_run;
	return REBASE_FALSE;
/* Options passed to git-fetch */
	/* Options passed to git-merge or git-rebase */
		if (parse_oid_hex(sb.buf, &oid, &p))
			"You can replace \"git config\" with \"git config --global\" to set a default\n"
			break;
	OPT_PASSTHRU(0, "signoff", &opt_signoff, NULL,
		argv_array_push(&args, "--rebase-merges");
	OPT_PASSTHRU(0, "edit", &opt_edit, NULL,
		PARSE_OPT_NOARG),
}
			continue;  /* invalid line: does not start with object ID */
 * pull.ff is "false", returns "--no-ff". If pull.ff is "only", returns
		if (merge_heads.nr > 1)
	} else if (!strcmp(var, "submodule.recurse")) {
 * Pushes "-q" or "-v" switches into arr to match the opt_verbosity level.
 * "Pulls into void" by branching off merge_head.
	if (opt_commit)
 *
		N_("prune remote-tracking branches no longer on remote"),
	return ret;

static char *set_upstream;
		int ran_ff = 0;
		N_("option for selected merge strategy"),
 */
		spec_src = "";
	} else
	struct argv_array args = ARGV_ARRAY_INIT;
			"invocation.\n"));
			     recurse_submodules == RECURSE_SUBMODULES_ON_DEMAND))
static char *opt_prune;
