	if (cmd == 'q') {
 * Copyright (c) 2005 Junio C Hamano
	}
	return opts->action == REPLAY_REVERT ? revert_usage : cherry_pick_usage;
			break;
		OPT_BOOL('n', "no-commit", &opts->no_commit, N_("don't automatically commit")),
		verify_opt_compatible(me, this_operation,
	int res;
	opts->strategy = xstrdup_or_null(opts->strategy);
		OPT_CMDMODE(0, "quit", &cmd, N_("end revert or cherry-pick sequence"), 'q'),
		opts->revs->no_walk = REVISION_WALK_NO_WALK_UNSORTED;
			  const char *arg, int unset)
	}
		replay->mainline = 0;
	if (unset) {
		if (va_arg(ap, int))
	return sequencer_pick_revisions(the_repository, opts);
		OPT_CMDMODE(0, "continue", &cmd, N_("resume revert or cherry-pick sequence"), 'c'),
 *


		OPT_CMDMODE(0, "abort", &cmd, N_("cancel revert or cherry-pick sequence"), 'a'),

				NULL);

		OPT_NOOP_NOARG('r', NULL),

			this_operation = "--abort";
		OPT_CALLBACK('X', "strategy-option", &opts, N_("option"),
	if (*end || replay->mainline <= 0)
	if (cleanup_arg) {
		else if (cmd == 'c')
static void verify_opt_compatible(const char *me, const char *base_opt, ...)
		return error(_("option `%s' expects a number greater than zero"),
				"--strategy", opts->strategy ? 1 : 0,
	}

	const char *me = action_name(opts);
	return 0;
		OPT_CLEANUP(&cleanup_arg),
			this_operation = "--continue";
int cmd_revert(int argc, const char **argv, const char *prefix)
			assert(cmd == 'a');
				"--no-commit", opts->no_commit,
	/* implies allow_empty */
}
#include "branch.h"
	struct option *options = base_options;
			this_operation = "--skip";
		OPT_END()


			OPT_BOOL(0, "allow-empty-message", &opts->allow_empty_message, N_("allow commits with empty messages")),
		OPT_BOOL('e', "edit", &opts->edit, N_("edit the commit message")),
		repo_init_revisions(the_repository, opts->revs, NULL);
#include "cache.h"
	NULL
	struct replay_opts **opts_ptr = opt->value;

	va_list ap;
			remove_branch_state(the_repository, 0);
				"--mainline", opts->mainline,
	if (cmd == 'a')
			OPT_BOOL(0, "allow-empty", &opts->allow_empty, N_("preserve initially empty commits")),
	opts.action = REPLAY_REVERT;
				"--no-commit", opts->no_commit,

}
	}
	return res;
		else {
			N_("option for merge strategy"), option_parse_x),
/*

	replay->mainline = strtol(arg, &end, 10);
	if (argc > 1)
	opts->xopts[opts->xopts_nr++] = xstrdup(arg);

		  N_("GPG sign commit"), PARSE_OPT_OPTARG, NULL, (intptr_t) "" },
				NULL);
 *
		s_r_opt.assume_dashdash = 1;
				"--edit", opts->edit,
{
	NULL
		die(_("%s: %s cannot be used with %s"), me, this_opt, base_opt);
	N_("git cherry-pick <subcommand>"),
		options = parse_options_concat(options, cp_extra);

			PARSE_OPT_KEEP_UNKNOWN);
			usage_with_options(usage_str, options);
	if (cmd == 's')
		argc = setup_revisions(argc, argv, opts->revs, &s_r_opt);
 * Copyright (c) 2007 Johannes E. Schindelin
	struct replay_opts opts = REPLAY_OPTS_INIT;
{
			OPT_END(),

	if (res < 0)
	res = run_sequencer(argc, argv, &opts);
	if (opts->action == REPLAY_PICK) {
			OPT_BOOL('x', NULL, &opts->record_origin, N_("append commit name")),

				"--ff", opts->allow_ff,
		return 0;
};
		die(_("revert failed"));
	/* These option values will be free()d */
	const char * const * usage_str = revert_or_cherry_pick_usage(opts);


		die(_("cherry-pick failed"));

		return 0;
		struct option cp_extra[] = {
static const char * const cherry_pick_usage[] = {
int cmd_cherry_pick(int argc, const char **argv, const char *prefix)
			PARSE_OPT_KEEP_ARGV0 |
			this_operation = "--quit";
		else if (cmd == 's')
	while ((this_opt = va_arg(ap, const char *))) {
			     N_("select mainline parent"), option_parse_m),
};

	struct option base_options[] = {
		OPT_CMDMODE(0, "skip", &cmd, N_("skip current commit and continue"), 's'),
	if (cmd) {
	if (this_opt)
static int option_parse_x(const struct option *opt,
	const char *this_opt;

#include "revision.h"
	if (opts->keep_redundant_commits)
		memset(&s_r_opt, 0, sizeof(s_r_opt));
	sequencer_init_config(&opts);
LAST_ARG_MUST_BE_NULL
	N_("git cherry-pick [<options>] <commit-ish>..."),
		if (!strcmp(argv[1], "-"))
	int res;
	if (unset)
		OPT_RERERE_AUTOUPDATE(&opts->allow_rerere_auto),
		};
}
 *
	if (opts->allow_ff)
#include "config.h"
	argc = parse_options(argc, argv, NULL, options, usage_str,
{
{

#include "builtin.h"
	opts.action = REPLAY_PICK;
}
				"--signoff", opts->signoff,
		return sequencer_rollback(the_repository, opts);
	res = run_sequencer(argc, argv, &opts);
		}
	};
			argv[1] = "@{-1}";
			     opt->long_name);
				"--no-rerere-autoupdate", opts->allow_rerere_auto == RERERE_NOAUTOUPDATE,
	char *end;
			  const char *arg, int unset)

		verify_opt_compatible(me, "--ff",
			OPT_BOOL(0, "keep-redundant-commits", &opts->keep_redundant_commits, N_("keep redundant, empty commits")),
	struct replay_opts *opts = *opts_ptr;
		return ret;
		if (!ret)
 */
	opts->gpg_sign = xstrdup_or_null(opts->gpg_sign);
 * Based on git-revert.sh, which is
#include "parse-options.h"
		OPT_STRING(0, "strategy", &opts->strategy, N_("strategy"), N_("merge strategy")),
	const char *cleanup_arg = NULL;
		opts->revs = NULL;
	struct replay_opts *replay = opt->value;
	}
	N_("git revert <subcommand>"),

static const char *action_name(const struct replay_opts *opts)
 * This implements the builtins revert and cherry-pick.
}
{
				"--rerere-autoupdate", opts->allow_rerere_auto == RERERE_AUTOUPDATE,
}
	if (isatty(0))
	va_end(ap);
}
		opts->revs = xmalloc(sizeof(*opts->revs));
#include "rerere.h"
		opts.edit = 1;

static const char * const *revert_or_cherry_pick_usage(struct replay_opts *opts)
		return sequencer_continue(the_repository, opts);
	N_("git revert [<options>] <commit-ish>..."),
	va_start(ap, base_opt);

{

		{ OPTION_STRING, 'S', "gpg-sign", &opts->gpg_sign, N_("key-id"),
	ALLOC_GROW(opts->xopts, opts->xopts_nr + 1, opts->xopts_alloc);
#include "dir.h"
		struct setup_revision_opt s_r_opt;
	return 0;

	int cmd = 0;
	if (cmd) {
		OPT_CALLBACK('m', "mainline", opts, N_("parent-number"),
		if (argc < 2)
		opts->default_msg_cleanup = get_cleanup_mode(cleanup_arg, 1);
#include "sequencer.h"
	return res;

	if (res < 0)
{
				"-x", opts->record_origin,
				"--strategy-option", opts->xopts ? 1 : 0,
		int ret = sequencer_remove_state(opts);
				"-x", opts->record_origin,

		if (cmd == 'q')
{
	}

	if (cmd == 'c')
 * Copyright (c) 2005 Linus Torvalds
		char *this_operation;

#include "diff.h"
		opts->allow_empty = 1;
				"--signoff", opts->signoff,
	/* Check for incompatible command line arguments */
		usage_with_options(usage_str, options);
	sequencer_init_config(&opts);
	}
}
		return sequencer_skip(the_repository, opts);
static const char * const revert_usage[] = {
	return opts->action == REPLAY_REVERT ? "revert" : "cherry-pick";
static int run_sequencer(int argc, const char **argv, struct replay_opts *opts)
			OPT_BOOL(0, "ff", &opts->allow_ff, N_("allow fast-forward")),
	struct replay_opts opts = REPLAY_OPTS_INIT;
		OPT_BOOL('s', "signoff", &opts->signoff, N_("add Signed-off-by:")),
	} else {
		opts->explicit_cleanup = 1;
static int option_parse_m(const struct option *opt,
