
			die("unable to read from stdin; aborting");
		 * input at this point.
			return error(_("Invalid value for --show-current-patch: %s"), arg);
			state->msg);
		do_commit(state);
		if (!fgets(reply, sizeof(reply), stdin))
		return 0;
		str = "b";

	 */
			else
	struct ident_split id;
	int ret;
				am_state_release(&state);
 * state->cur will be set to the index of the first mail, and state->last will
	remote_tree = parse_tree_indirect(remote);
		am_rerere_clear();
		read_state_file(&sb, state, "rerere-autoupdate", 1);
	rev_info.diff = 1;
/**
		if (skip_prefix(sb.buf, "# User ", &str))
				rc = error(_("invalid Date line"));



		 */
		die("unknown option passed through to git apply");
	rev_info.diffopt.flags.binary = 1;
{

	}
 */
		goto done;
		OPT_BOOL(0, "ignore-date", &state.ignore_date,
	if (!has_orig_head)
	enum resume_type mode;
		[SHOW_PATCH_DIFF] = "diff",
	case SCISSORS_UNSET:
	o.branch1 = "HEAD";
 * Reads the contents of `file` in the `state` directory into `sb`. Returns the
			 * however git's timezone is in hours + minutes east of
 * a mbox file or a Maildir. Returns 0 on success, -1 on failure.
		 * in your translation. The program will only accept English
	opts.head_idx = 1;
		return -1;
	}
		goto done;
 * name, email and date respectively. The patch body will be written to the
	int ret;
			const char **paths, int keep_cr)
	write_state_text(state, "author-script", sb.buf);
	c = init_copy_notes_for_rewrite("rebase");

				fclose(in);
	memset(state, 0, sizeof(*state));
	}

	else if (!strcmp(arg, "mboxrd"))
	argv_array_pushf(&cp.args, "--build-fake-ancestor=%s", index_file);
				state.dir);

		break;
		goto done;
		printf_ln(_("No changes - did you forget to use 'git add'?\n"
	case SCISSORS_FALSE:
		ret = PATCH_FORMAT_MBOX;
	argc = parse_options(argc, argv, prefix, options, usage, 0);
		OPT_PASSTHRU_ARGV(0, "directory", &state.git_apply_opts, N_("root"),
		puts(_("Commit Body is:"));
		vfprintf(fp, fmt, ap);
	int options = 0;


}
	delete_ref(NULL, "REBASE_HEAD", NULL, REF_NO_DEREF);

 * Dies with a user-friendly message on how to proceed after resolving the
		mail = mkpath("%s/%0*d", state->dir, state->prec, i + 1);
			       "--show-current-patch=%s"),
	write_state_count(state, "last", state->last);
		return 0;
	if (sq_dequote_to_argv_array(sb.buf, &state->git_apply_opts) < 0)

	strbuf_release(&author_name);

	strbuf_release(&sb);
	case SHOW_PATCH_DIFF:
{
 */
	 * Please update $__git_patchformat in git-completion.bash

}

		patch_format = detect_patch_format(paths);
}
		if (state->interactive && do_interactive(state))
{

	run_diff_index(&rev_info, 1);
 * contents in bytes.
	int quiet;
/**
			IDENT_STRICT);

	}
		return -1;
	FILE *fp;
		 */
			RESUME_RESOLVED),
		else if (skip_prefix(sb.buf, "Email: ", &x))

	free(state->author_name);
		putc('\n', fp);
static inline const char *am_path(const struct am_state *state, const char *path)
	FILE *fp;
		die(_("failed to read the index"));

	if (get_oid("HEAD", &head))
			N_("abort the patching operation but keep HEAD where it is."),
			fprintf(out, "From:%s\n", str);
		str = "t";
 * Returns 1 if the patch should be skipped, 0 otherwise.

			if (!strcmp(arg, valid_modes[new_value]))
	/*
	return 0;
 */
		struct rev_info rev_info;
			N_("run interactively")),
		return -1;
{
		str = "f";
	read_state_file(&sb, state, "scissors", 1);
		  PARSE_OPT_OPTARG, NULL, (intptr_t) "" },

	struct tree *tree;
	struct strbuf sb = STRBUF_INIT;
 * trust and commit what the user has in the index and working tree.
		write_state_bool(state, "rerere-autoupdate",
static void am_append_signoff(struct am_state *state)
	fclose(fp);

	if (!get_oid("HEAD", &curr_head)) {
 * better to bail out than to do something that the user does not expect.
	/*


struct am_state {
		mi.metainfo_charset = get_commit_output_encoding();

		struct argv_array paths = ARGV_ARRAY_INIT;
}
/**



	case KEEP_TRUE:
	if (clean_index(&head, &head))
		break;
		BUG("invalid value for state->scissors");

		assert(!is_null_oid(&state->orig_commit));

	oidcpy(&state->orig_commit, &commit_oid);
		die(_("unable to write index file"));
	/*
	struct lock_file lock_file = LOCK_INIT;
{
			0),
		break;
 * parse_options() callback that validates and sets opt->value to the
		if (resume.mode)

	}
	strbuf_release(&sb);

		 * the --rebasing case, it is up to the caller to take care of
static int run_applypatch_msg_hook(struct am_state *state)
 * commits listed in the file to their rewritten commits.
	if (state->rebasing)
 *	GIT_AUTHOR_NAME='$author_name'

		}
	struct object_id orig_tree, their_tree, our_tree;
		OPT_CMDMODE(0, "skip", &resume.mode,
	case RESUME_ABORT:
		break;
				rc = error(_("invalid timestamp"));
	return 0;

	if (!state->msg)
 */
	if (unpack_trees(1, t, &opts)) {

 * Performs a checkout fast-forward from `head` to `remote`. If `reset` is

		}
	const char *series_dir;
	/* when --rebasing, records the original commit the patch came from */
		}
	case SCISSORS_FALSE:
			if (!launch_editor(am_path(state, "final-commit"), &msg, NULL)) {
		if (!state->rebasing)
	else
		N_("git am [<options>] (--continue | --skip | --abort)"),
	if (lstat(state->dir, &st) < 0 || !S_ISDIR(st.st_mode))

enum patch_format {
	if (write_cache_as_tree(&index, 0, NULL))

			 * UTC. Convert it.

	return ret;
}
	for (;;) {
/**
 *
 * set, trailing whitespace will be removed.
	}
	if (!git_config_get_bool("commit.gpgsign", &gpgsign))
	argv_array_clear(&apply_paths);


			 * Applying the patch to an earlier tree and merging
 * state directory's "patch" file.
#include "builtin.h"
		if (trim)
				rc = error(_("invalid Date line"));

		OPT_BOOL('c', "scissors", &state.scissors,
			die(_("Resolve operation not in progress, we are not resuming."));
	argv_array_push(&cp.args, hook);
	KEEP_FALSE = 0,
{
			strbuf_release(&msg);
}
	if (state->utf8)
{
		argv_array_push(&cp.args, "--mboxrd");
 *	GIT_AUTHOR_EMAIL='$author_email'
	if (split_ident_line(&id, ident_line, ident_len) < 0)
		return sb->len;
			"You should 'git add' each file with resolved conflicts to mark them as such.\n"
		return -1;
	ident_line = find_commit_header(buffer, "author", &ident_len);
	if (has_orig_head)
	if (!state->author_name || !state->author_email || !state->author_date)
/**
{

	if (regcomp(&regex, header_regex, REG_NOSUB | REG_EXTENDED))
	if (len < 0)
			N_("add a Signed-off-by line to the commit message"),
			fprintf(out, "Date: %s\n", show_date(timestamp, tz2, DATE_MODE(RFC2822)));
		die(_("missing author line in commit %s"),
 * Clean the index without touching entries that are not modified between
	struct strbuf sb = STRBUF_INIT;
	state->signoff = !strcmp(sb.buf, "t");

		return split_mail_conv(stgit_patch_to_mail, state, paths, keep_cr);


	const char *filename = am_path(state, "author-script");
	if (state->resolvemsg) {
#include "string-list.h"
		die(_("invalid ident line: %.*s"), (int)ident_len, ident_line);

			xmemdupz(id.mail_begin, id.mail_end - id.mail_begin);
	in_progress = am_in_progress(&state);
 */
{

	if (!is_null_oid(&state->orig_commit)) {
			     arg, valid_modes[resume->sub_mode]);
		if (apply_status) {
	cp.git_cmd = 1;
		goto done;
	struct strbuf sb = STRBUF_INIT;
	read_state_file(&sb, state, "threeway", 1);

#include "unpack-trees.h"
	if (state->rebasing) {
 *
	state->last = i;
	regfree(&regex);
	case KEEP_NON_PATCH:
 */



 * Aborts the current am session if it is safe to do so.

 * Returns true if `str` consists of only whitespace, false otherwise.
	}
	 * changes.
 * be set to the index of the last mail.
		} else if (*reply == 'n' || *reply == 'N') {
 */
	struct string_list merge_rr = STRING_LIST_INIT_DUP;
			break; /* End of header */
 */
			if (state->rebasing)

 */
	int utf8;
static int parse_opt_patchformat(const struct option *opt, const char *arg, int unset)
{


				state->msg = strbuf_detach(&msg, &state->msg_len);
		return;
	RESUME_SKIP,
	if (strbuf_read_file(sb, am_path(state, file), 0) >= 0) {
	struct option options[] = {
 *	GIT_AUTHOR_DATE='$author_date'
{
	FILE *fp;
		paths = stdin_only;
}

static void get_commit_info(struct am_state *state, struct commit *commit)
 * Attempt a threeway merge, using index_path as the temporary index.
	struct notes_rewrite_cfg *c;
	am_state_init(&state);
		[SHOW_PATCH_RAW] = "raw"
				tz2 = -tz2;
		return split_mail_mbox(state, paths, keep_cr, 0);
	regex_t regex;

 *
				   the_repository->hash_algo->empty_tree);
	default:
	int ret = 1;
	 */
		 * 2. stdin is not a tty: the user is trying to feed us a patch

	va_list ap;
	memset(&opts, 0, sizeof(opts));
}
		if (new_value >= ARRAY_SIZE(valid_modes))
	reflog_msg = getenv("GIT_REFLOG_ACTION");
	 */
	if (read_state_file(&sb, state, "next", 1) < 0)
		if (!sb.len)
 * `index_file` is not NULL, the patch will be applied to that index.

			N_("pass --keep-cr flag to git-mailsplit for mbox format"),
	struct strbuf l2 = STRBUF_INIT;
	RESUME_FALSE = 0,
 * in `paths` must be a file/directory that is formatted according to

	setup_pager();
		printf_ln(_("You still have unmerged paths in your index.\n"
	 */
{
	int len;
			fclose(in);
	const char *header_regex = "^[!-9;-~]+:";

 * Set keep_cr to 0 to convert all lines ending with \r\n to end with \n, 1
{
 * state->msg will be set to the patch message. state->author_name,
	if (!state->quiet) {
			ret = error(_("Failed to copy notes from '%s' to '%s'"),

		write_state_bool(state, "dirtyindex", 1);
	int force_apply = 0;

	buffer = logmsg_reencode(commit, NULL, get_commit_output_encoding());
}
		return split_mail_mbox(state, paths, keep_cr, 1);

	opts.fn = oneway_merge;
	write_state_bool(state, "sign", state->signoff);
	if (in_progress)
 * Removes the am_state directory, forcefully terminating the current am
 */
	KEEP_NON_PATCH  /* pass -b flag to git-mailinfo */
		rollback_lock_file(&lock_file);
 * Splits a list of files/directories into individual email patches. Each path
			am_path(state, "final-commit"));
{
#include "cache.h"

			subject_printed = 1;

 */
 *
#include "notes-utils.h"
		fprintf(fp, "%s ", oid_to_hex(&state->orig_commit));
	/*
	while (!strbuf_getline_lf(&sb, in)) {

			struct strbuf msg = STRBUF_INIT;
		free(new_oid_str);
		out = fopen(mail, "w");
	return sb.buf;
		NULL
	else if (!strcmp(arg, "hg"))
 * Returns the length of the first line of msg.
{

		write_state_text(state, "rebasing", "");
		return error(_("Invalid value for --patch-format: %s"), arg);
	struct unpack_trees_options opts;
	static struct strbuf sb = STRBUF_INIT;
			return 0;
		   NULL, REF_NO_DEREF, UPDATE_REFS_DIE_ON_ERR);
	 * wildly different changes in parts the patch did not touch, so
{

		exit(128);

		 */
		return 0;
		die_errno(_("failed to create directory '%s'"), state->dir);

enum scissors_type {

				say(state, stdout, _("No changes -- Patch already applied."));
	strbuf_release(&sb);
 * information.
	RESUME_SHOW_PATCH
	argv_array_push(&cp.args, "--");
		return error(_("Could not parse object '%s'."), oid_to_hex(&index));
	index_tree = parse_tree_indirect(&index);
			const char *file, int trim)
/**
	rev_info.abbrev = 0;
	const char * const usage[] = {
	argv_array_push(&cp.args, "apply");
	read_state_file(&sb, state, "keep", 1);
 */
		{ OPTION_STRING, 'S', "gpg-sign", &state.sign_commit, N_("key-id"),

	return ret;
		die(_("unable to parse commit %s"), oid_to_hex(&commit->object.oid));
	finish_copy_notes_for_rewrite(the_repository, c, msg);


{
	RESUME_ABORT,
	/*
			goto next;
	}
	if (id.name_begin)
		apply_state.cached = 1;
{
	read_cache_from(index_path);
/**

 * Returns true if it is safe to reset HEAD to the ORIG_HEAD, false otherwise.
			RESUME_QUIT),
};
		BUG("invalid mode for --show-current-patch");
		die(_("unable to write new index file"));

	FILE *fp = xfopen(mail, "r");
 */
		BUG("state file 'next' does not exist");
 * Resets rerere's merge resolution metadata.
	state->cur = 1;


	SIGNOFF_FALSE = 0,

/**

	struct strbuf sb = STRBUF_INIT;
}
static int is_mail(FILE *fp)
	const char *reflog_msg, *author;
			die(_("could not parse %s"), am_path(state, "abort-safety"));
	const char *invalid_line = _("Malformed input line: '%s'.");
	RESUME_QUIT,
	if (strbuf_getline_lf(&sb, fp) ||
	 */
	/*

			goto finish;
 */
	argv_array_push(&cp.args, am_path(state, "patch"));
			N_("lie about committer date")),
	static const char *stdin_only[] = {"-", NULL};
/**
/**
}
 */
			goto done;
	case SCISSORS_TRUE:
	strbuf_stripspace(&msg, 0);

	RESUME_APPLY,
	return 0;
	default:
		exit(1);
	}
 */
	 * NOTE: Since the "next" and "last" files determine if an am_state


 * `head` and `remote`.
	SIGNOFF_EXPLICIT /* --signoff was set on the command-line */
		/*
			N_("pass it through git-apply"),

	argv_array_push(&cp.args, "mailsplit");
		old_oid = &parent;
			}



}
	SHOW_PATCH_RAW = 0,
 * problem. This message can be overridden with state->resolvemsg.
	argv_array_pushf(&cp.args, "-o%s", state->dir);

#include "lockfile.h"
		OPT_SET_INT(0, "keep-non-patch", &state.keep,
				goto next; /* mail should be skipped */

	return 0;

		if (parse_oid_hex(sb.buf, &from_obj, &p)) {
	 */
/**
		am_abort(&state);
done:
/**
	write_state_text(state, "keep", str);

			goto finish;
static int str_isspace(const char *str)
#include "repository.h"
	KEEP_TRUE,      /* pass -k flag to git-mailinfo */

	}
			break;
	if (init_apply_state(&apply_state, the_repository, NULL))


	switch (state->keep) {
		am_run(&state, 0);
	delete_ref(NULL, "REBASE_HEAD", NULL, REF_NO_DEREF);
 */
	get_commit_info(state, commit);
		setenv("GIT_COMMITTER_DATE",
typedef int (*mail_conv_fn)(FILE *out, FILE *in, int keep_cr);
{
		}
	while (strbuf_fread(&sb, 8192, in) > 0) {
enum keep_type {

}
	}
	assert(!state->author_email);
		rollback_lock_file(&lock_file);
	char *their_tree_name;
 */
 * If `resume` is true, we are "resuming". The "msg" and authorship fields, as
			}
	struct object_id commit_oid;
				strbuf_addch(&msg, '\n');
		die(_("unable to write new index file"));
	/*


 */
		struct commit *commit = lookup_commit_or_die(&head, "HEAD");
		OPT_STRING(0, "resolvemsg", &state.resolvemsg, NULL,
	read_cache_unmerged();
 * message suitable for parsing with git-mailinfo.
	am_state_release(&state);
 * state->author_name, state->author_email and state->author_date accordingly.
}
		die_errno(_("fseek failed"));
				free(state->msg);
		if (*sb.buf == '\t' || *sb.buf == ' ')
	fclose(mi.output);
}
 * Saves state->msg in the state directory's "final-commit" file.

	}
			goto next;

	if (resume->mode == RESUME_SHOW_PATCH && new_value != resume->sub_mode)
 */
};
	diff_setup_done(&rev_info.diffopt);
	opts.head_idx = 1;
	 */
{
			 */

 * Will always return 0 as the patch should never be skipped.
		o.verbosity = 0;
		*opt_value = PATCH_FORMAT_STGIT_SERIES;
	has_curr_head = curr_branch && !is_null_oid(&curr_head);
static int am_in_progress(const struct am_state *state)
	SCISSORS_TRUE        /* pass --scissors to git-mailinfo */
}
	case SHOW_PATCH_RAW:
 * Determines if the file looks like a piece of RFC2822 mail by grabbing all
		discard_cache();
 * Initializes am_state with the default values.
static void am_abort(struct am_state *state)
	fp = fopen(*paths, "r");

	read_state_file(&sb, state, "sign", 1);
#include "diffcore.h"
	state->msg_len = strlen(state->msg);

	free(state->author_date);
	if (get_mail_commit_oid(&commit_oid, mail) < 0)
	int res, opts_left;
 * It is not safe to reset HEAD when:
			}
			strbuf_addstr(&author_email, x);
{

	PATCH_FORMAT_MBOXRD

	if (file_exists(am_path(state, "dirtyindex")))
 * number of bytes read on success, -1 if the file does not exist. If `trim` is

/**
			strbuf_addstr(&sb, am_path(state, "patch-merge-index"));
	const struct object_id *bases[1] = { &orig_tree };
	assert(!state->author_date);

	write_state_count(state, "next", state->cur);

	int ret;
/**
		argv_array_clear(&paths);
			  "space at the end of lines might be lost."));
	assert(!state->author_name);
			goto next;


		const char *mail;
	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);
		goto finish;
/**
	if (state->interactive) {

		break;
	 * Otherwise, check the first few lines of the first patch, starting
static int fall_back_threeway(const struct am_state *state, const char *index_path)
			 state->allow_rerere_autoupdate == RERERE_AUTOUPDATE);
	int rc = 0;
		strbuf_reset(&sb);
{

	} else

 */
 */
	sq_quote_argv(&sb, state->git_apply_opts.argv);
	int new_value = SHOW_PATCH_RAW;
	int ret = 0;
			xmemdupz(id.name_begin, id.name_end - id.name_begin);
		state->author_name =
 * Returns 0 on success, -1 on failure.
	default:
	strbuf_release(&last);
			fprintf(out, "\n%s\n", sb.buf);

	state->msg = strbuf_detach(&sb, &state->msg_len);
	 * from the first non-blank line, to try to detect its format.
	if (repo_index_has_changes(the_repository, NULL, &sb)) {
	struct object_id head;

}
	/* various operating modes and command line options */
			resume.mode = RESUME_APPLY;
static int fast_forward_to(struct tree *head, struct tree *remote, int reset)
	}
		BUG("invalid value for state->keep");
 * script, and thus if the file differs from what this function expects, it is
	state->msg = xstrdup(msg + 2);
{

static void am_rerere_clear(void)
	}
 *
static void say(const struct am_state *state, FILE *fp, const char *fmt, ...)
 *
			am_append_signoff(&state);
		diff_setup_done(&rev_info.diffopt);
			N_("allow fall back on 3way merging if needed")),
	if (state->threeway && !index_file)
		usage_with_options(usage, options);
 * Once split out, the individual email patches will be stored in the state
				goto exit;
	strbuf_addbuf(&msg, &mi.log_message);
	am_load(state);
	} else {
	state->last = strtol(last.buf, NULL, 10);
	default:
}
	struct strbuf sb = STRBUF_INIT;
static int run_apply(const struct am_state *state, const char *index_file)
		write_state_text(state, "abort-safety", oid_to_hex(&curr_head));
	state->author_name = strbuf_detach(&author_name, NULL);
	while (!strbuf_getline_lf(&sb, fp)) {

	return ret ? -1 : 0;
			RESUME_RESOLVED),

					int keep_cr)
	struct object_id index;
 */
		fclose(fp);
	case RESUME_RESOLVED:
	int prec;
	argv_array_push(&cp.args, "rebase");
 *
#include "rerere.h"
 * non-indented lines and checking if they look like they begin with valid
		break;
		am_load(&state);
	if (!paths[0] || paths[1])
 */
	return 0;

/**
		break;
		OPT_CMDMODE('r', "resolved", &resume.mode,
		OPT_BOOL('i', "interactive", &state.interactive,
	assert(state->msg);

/**
next:

	else

	if (status)
	int allow_rerere_autoupdate;
					NULL);
	state->msg_len = 0;
	int last;
	status = git_gpg_config(k, v, NULL);
		if (regexec(&regex, sb.buf, 0, NULL, 0)) {
{
		return ret;
		return error("could not write tree");
	setup_mailinfo(&mi);

	else
		resume = 0;
				"it will be removed. Please do not use it anymore."));

 * message suitable for parsing with git-mailinfo.
				goto exit;

	strbuf_release(&sb);
		if (*reply == 'y' || *reply == 'Y') {
	write_state_bool(state, "messageid", state->message_id);
		OPT_BOOL('u', "utf8", &state.utf8,

/**
#include "merge-recursive.h"
		apply_state.apply_verbosity = verbosity_silent;
	if (read_am_author_script(state) < 0)
		if (*p != ' ') {

			long tz, tz2;
		if (apply_status && state->threeway) {
		git_config_get_bool("am.keepcr", &keep_cr);
enum show_patch_type {
 */
	}
 * failure.
		if (state.interactive && !paths.argc)
	} else {
	struct child_process cp = CHILD_PROCESS_INIT;
	unlink(am_path(state, "final-commit"));
	} else
	if (id.mail_begin)
 * Reads the state directory's "rewritten" file, and copies notes from the old
		ret = run_command_v_opt(av, RUN_GIT_CMD);
}
		write_state_text(state, "abort-safety", oid_to_hex(&head));
			N_("strip everything before a scissors line")),
	}
	SCISSORS_FALSE = 0,  /* pass --no-scissors to git-mailinfo */
	/*
	int rebasing;
	SCISSORS_UNSET = -1,
			N_("pass it through git-apply"),
	case RESUME_APPLY:
#include "exec-cmd.h"
		ret = PATCH_FORMAT_MBOX;
static int read_commit_msg(struct am_state *state)
	int gpgsign;
		oidcpy(&orig_head, the_hash_algo->empty_tree);
 */

	while (!strbuf_getline_lf(&sb, in)) {


			 */
 */
static int copy_notes_for_rebase(const struct am_state *state)
{
 */
	switch (patch_format) {
	strbuf_addf(&sb, "%s: %.*s", reflog_msg, linelen(state->msg),
		BUG("check_apply_state() failed");
	if (!index_tree)
	ret = run_hook_le(NULL, "applypatch-msg", am_path(state, "final-commit"), NULL);
	struct strbuf last = STRBUF_INIT;
			N_("use current timestamp for author date")),
	}


	while (!strbuf_getline(&sb, fp)) {
				   UPDATE_REFS_DIE_ON_ERR);
	assert(state->msg);

		assert(!is_null_oid(&state->orig_commit));
/**
		am_resolve(&state);
				skip = parse_mail_rebase(state, mail);
 */
static int split_mail_mbox(struct am_state *state, const char **paths,
 * directory's "patch" file.
	opts.fn = twoway_merge;

			return error(_("could not parse patch '%s'"), *paths);
		if (!strcmp(*paths, "-"))
		  N_("GPG-sign commits"),
 * 1. git-am previously failed because the index was dirty.
	const char *msg = "Notes added by 'git rebase'";
		else if (!subject_printed) {
 * all the hard work, and we do not have to do any patch application. Just
	discard_cache();
	am_run(state, 0);
	return git_default_config(k, v, NULL);
	clear_apply_state(&apply_state);
		printf_ln(_("To restore the original branch and stop patching, run \"%s --abort\"."), cmdline);

	struct strbuf l3 = STRBUF_INIT;
static int merge_tree(struct tree *tree)
	write_state_text(state, "original-commit", oid_to_hex(&commit_oid));
 *
		"Not rewinding to ORIG_HEAD"));
		fprintf(fp, "%s\n", oid_to_hex(&head));
	strbuf_getline(&l3, fp);


}
	if (run_hook_le(NULL, "pre-applypatch", NULL))
 * Applies all queued mail.
			N_("synonyms for --continue"),
	state->author_date = xstrdup(show_ident_date(&id, DATE_MODE(NORMAL)));
	state->utf8 = !strcmp(sb.buf, "t");
	const char *buffer, *ident_line, *msg;
enum resume_type {
	fp = xfopen(am_path(state, "rewritten"), "r");
 * be filled up.
};
	state->prec = 4;
	while (!strbuf_getline_lf(&sb, fp)) {
			errno = 0;
		die(_("could not parse %s"), am_path(state, "original-commit"));
		oidclr(&head);
 * The author script is of the format:

			run_command(&cp);
	if (!fp)
		am_destroy(state);
	case KEEP_TRUE:
	FILE *fp;
	while (strbuf_fread(&sb, 8192, in) > 0) {
		}


			const char **paths, int keep_cr)
 * Sets commit_id to the commit hash where the mail was generated from.
{
		 * List paths that needed 3-way fallback, so that the user can
		mi.use_scissors = 0;
		}
		rev_info.diffopt.filter |= diff_filter_bit('M');
	const char *valid_modes[] = {
			if (errno) {
		goto exit;
	else

 */
/**
	}
	if (starts_with(l1.buf, "# This series applies on GIT commit")) {
 * written to `out`. Return 0 on success, or -1 on failure.
			apply_status = fall_back_threeway(state, sb.buf);
 */

		 * TRANSLATORS: Make sure to include [y], [n], [e], [v] and [a]
			in = stdin;
		return error(_("Could not parse object '%s'."), oid_to_hex(remote));
		ret = 1;
	opts.reset = reset;
 */
	state->rebasing = !!file_exists(am_path(state, "rebasing"));
	state->utf8 = 1;
	rerere_clear(the_repository, &merge_rr);
static int safe_to_abort(const struct am_state *state)
{
next:
			parse_opt_patchformat),
 * of patches.
	int committer_date_is_author_date;
	read_commit_msg(state);
	struct merge_options o;
		patch_path = am_path(state, "patch");
		warning(_("Patch sent with format=flowed; "
		mi.use_scissors = 1;
	/* commit metadata and message */
				break;
	strbuf_addstr(&sb, "GIT_AUTHOR_DATE=");
	struct resume_mode resume = { .mode = RESUME_FALSE };

 * Resume the current am session by skipping the current patch.
	if (lstat(am_path(state, "last"), &st) || !S_ISREG(st.st_mode))
		  N_("show the patch being applied"),

 * the state directory.

/**



 * Returns 1 if there is an am session in progress, 0 otherwise.
			continue;
		WANT_AUTHOR_IDENT,
	write_file(am_path(state, name), "%d", value);
	if (run_apply(state, index_path))

			0),

{
	strbuf_release(&sb);
#include "mailinfo.h"
			state->ignore_date ? NULL : state->author_date,
		break;
	if (!remote_tree)
		patch_path = am_path(state, msgnum(state));
 * directory, with each patch's filename being its index, padded to state->prec
}
	curr_branch = resolve_refdup("HEAD", 0, &curr_head, NULL);
			return 0;
	struct strbuf sb = STRBUF_INIT;

	series_dir_buf = xstrdup(*paths);
	append_signoff(&sb, 0, 0);


	assert(!state->author_date);

 */
static void am_resolve(struct am_state *state)
	}
			N_("(internal use for git-rebase)")),
			return 1;
	if (parse_tree(head) || parse_tree(remote))

static int get_mail_commit_oid(struct object_id *commit_id, const char *mail)
int cmd_am(int argc, const char **argv, const char *prefix)
{
			}
	}
static int clean_index(const struct object_id *head, const struct object_id *remote)
	add_pending_object(&rev_info, &tree->object, "");
		break;

 *

			if (state->signoff)

		if (do_interactive(state))


		die(_("failed to clean index"));
 * to the commit's respective info.
	if (file_exists(am_path(state, "rerere-autoupdate"))) {
			write_commit_msg(state);
			RERERE_NOAUTOUPDATE : RERERE_AUTOUPDATE;
		int ret;
	int ret;
static void write_commit_msg(const struct am_state *state)
	}
	default:
	struct resume_mode *resume = container_of(opt_value, struct resume_mode, mode);
	say(state, stdout, _("Falling back to patching base and 3-way merge..."));
{
/*
}
			1, PARSE_OPT_NONEG),
{

static int parse_mail_rebase(struct am_state *state, const char *mail)
		N_("git am [<options>] [(<mbox> | <Maildir>)...]"),

#include "cache-tree.h"
	default:
				argv_array_push(&paths, mkpath("%s/%s", prefix, argv[i]));
		OPT_BOOL('3', "3way", &state.threeway,
 * Resume the current am session after patch application failure. The user did

	struct child_process cp = CHILD_PROCESS_INIT;
/**
	argv_array_pushv(&apply_opts, state->git_apply_opts.argv);
				goto exit;
			validate_resume_state(state);


 * Commits the current index with state->msg as the commit message and
		read_cache_from(index_file);

}

	assert(!state->msg);
	const char *x;
				"Use \"git am --abort\" to remove it."),
	}
		ret = fn(out, in, keep_cr);
 */
	int patch_format = PATCH_FORMAT_UNKNOWN;
	struct strbuf sb = STRBUF_INIT;

	free(series_dir_buf);

			ret = error(invalid_line, sb.buf);
 * Given an StGit series file, converts the StGit patches in the series into
	fclose(fp);
/**
	struct tree *head_tree, *remote_tree, *index_tree;
	resume->sub_mode = new_value;
/**
	return 0;
	if (!*paths)
 * Setup a new am session for applying patches
enum signoff_type {
/**
}
	/* current and last patch numbers, 1-indexed */
		return split_mail_stgit_series(state, paths, keep_cr);
			N_("pass -m flag to git-mailinfo")),
	if (unmerged_cache()) {
}
	struct commit *result;
	int ret = 0;
	strbuf_addf(&sb, "%0*d", state->prec, state->cur);
#include "config.h"
static const char *msgnum(const struct am_state *state)
	struct strbuf sb = STRBUF_INIT;
	rev_info.disable_stdin = 1;
	}
	write_state_count(state, "next", state->cur);
		else if (starts_with(sb.buf, "From") || starts_with(sb.buf, "Date"))
exit:
	rev_info.diffopt.flags.full_index = 1;

			 * the result may have produced the same tree as ours.
	if (!head_tree)
	update_ref(sb.buf, "HEAD", &commit, old_oid, 0,
	 * may be wildly different from ours, but their_tree has the same set of
	while (!strbuf_getline_lf(&sb, fp)) {
			return error_errno(_("could not open '%s' for reading"),
		delete_ref(NULL, curr_branch, NULL, REF_NO_DEREF);
	struct rev_info rev_info;

	case PATCH_FORMAT_MBOX:

	fclose(fp);
	for (; *str; str++)
	}

		goto done;
			state->ignore_date ? "" : state->author_date, 1);
	enum patch_format ret = PATCH_FORMAT_UNKNOWN;
		return error(_("Could not parse object '%s'."), oid_to_hex(head));
	assert(!state->msg);
	am_next(state);
 * directly. This is used in --rebasing mode to bypass git-mailinfo's munging
 * A split_patches_conv() callback that converts a mercurial patch to a RFC2822
		state->threeway = 1;
			strbuf_release(&sb);
/**
	}
		OPT_PASSTHRU_ARGV(0, "reject", &state.git_apply_opts, NULL,
	init_merge_options(&o, the_repository);
		if (run_applypatch_msg_hook(state))
	am_load(state);
 * Increments the patch pointer, and cleans am_state for the application of the
	if (!get_oid("HEAD", &head))
	if (run_command(&cp))
/**
	struct strbuf author_date = STRBUF_INIT;
	cp.trace2_hook_name = "post-rewrite";

 * Appends signoff to the "msg" field of the am_state.
	/* number of digits in patch filename */
	if (split_mail(state, patch_format, paths, keep_cr) < 0) {

static void am_run(struct am_state *state, int resume)
		write_state_text(state, "abort-safety", "");
		fclose(fp);
	else if (!strcmp(arg, "mbox"))
	am_rerere_clear();

	switch (state->keep) {
			}
/**
		die(_("failed to write commit object"));
		BUG("state file 'last' does not exist");
}
	git_committer_info(IDENT_STRICT);
	const char *sign_commit;
	else if (!strcmp(arg, "stgit"))
		mi.keep_non_patch_brackets_in_subject = 1;
		}

}
	}

 */


	write_commit_patch(state, commit);
			PARSE_OPT_NOARG),
		state->scissors = SCISSORS_TRUE;
	struct strbuf sb = STRBUF_INIT;
}
		struct object_id from_obj, to_obj;
	}
	strbuf_attach(&sb, state->msg, state->msg_len, state->msg_len);
	strbuf_release(&msg);

 * patch and committing it.

		}
			strbuf_trim(sb);
	SIGNOFF_TRUE = 1,
	if (refresh_and_write_cache(REFRESH_QUIET, 0, 0) < 0)
	}
		/*
		*opt_value = PATCH_FORMAT_UNKNOWN;
 * Applies current patch with git-apply. Returns 0 on success, -1 otherwise. If
static int show_patch(struct am_state *state, enum show_patch_type sub_mode)
	if (ret)

	argv_array_pushf(&cp.args, "-d%d", state->prec);
	}
	struct object_id head;
		  parse_opt_show_current_patch, RESUME_SHOW_PATCH },
		argv_array_push(&patches, mkpath("%s/%s", series_dir, sb.buf));
		return error("could not build fake ancestor");

	struct strbuf author_email = STRBUF_INIT;
		else
	rev_info.diffopt.output_format = DIFF_FORMAT_PATCH;

			"already introduced the same changes; you might want to skip this patch."));
	if (keep_cr)
		printf("%s", state->msg);
	char *curr_branch;
	}
	}


static int linelen(const char *msg)

}
	    !skip_prefix(sb.buf, "From ", &x) ||
	FREE_AND_NULL(state->author_name);
	const char *str;

	git_config(git_am_config, NULL);
	int binary = -1;


				   &parents);
	am_rerere_clear();
}
{
	strbuf_addch(&sb, '\n');
			am_path(state, "author-script"));
				am_path(state, "final-commit"));
	write_state_text(state, "apply-opt", sb.buf);
static int split_mail(struct am_state *state, enum patch_format patch_format,

	repo_init_revisions(the_repository, &rev_info, NULL);
 * A split_mail_conv() callback that converts an StGit patch to an RFC2822

	return 0;

	return 1;
 * Validates the am_state for resuming -- the "msg" and authorship fields must
 * Writes the diff of the index against HEAD as a patch to the state


	strbuf_reset(&sb);
	rev_info.diffopt.file = fp;
/**
	 * entry, this is likely an StGit patch.
			die(_("'%s' was deleted by the applypatch-msg hook"),
#include "prompt.h"

 */
 * 2. HEAD has moved since git-am previously failed.
		update_ref("am --abort", "HEAD", &orig_head,
		const char *cmdline = state->interactive ? "git am -i" : "git am";
		if (argc || (resume.mode == RESUME_FALSE && !isatty(0)))
		break;
	PATCH_FORMAT_UNKNOWN = 0,
			const char **paths, int keep_cr)
	};
			die_user_resolve(state);
	return ret;
		BUG("invalid patch_format");
	switch (resume.mode) {
}

	if (commit_tree(state->msg, state->msg_len, &tree, parents, &commit,
		OPT_HIDDEN_BOOL('b', "binary", &binary,
	if (state->rebasing) {
}

		int i;
	strbuf_reset(&sb);
#include "parse-options.h"
	if (repo_read_index_preload(the_repository, NULL, 0) < 0)
		am_destroy(&state);
	 * This is not so wrong. Depending on which base we picked, orig_tree
		mi.keep_subject = 1;
		am_setup(&state, patch_format, paths.argv, keep_cr);
 */
 * Returns 0 on success, -1 if the file could not be parsed.

 * Builtin "git am"

	 * If we are allowed to fall back on 3-way merge, don't give false
	else if (!strcmp(arg, "stgit-series"))

		fprintf_ln(stderr, _("Patch format detection failed."));
		*opt_value = PATCH_FORMAT_STGIT;
 * Based on git-am.sh by Junio C Hamano.
{
			fprintf(out, "\n%s\n", sb.buf);
		fwrite(sb.buf, 1, sb.len, out);
	opts.merge = 1;
 * well as the state directory's "patch" file is used as-is for applying the
			ret = 0;
		return error_errno(_("could not open '%s' for reading"), *paths);
	case KEEP_NON_PATCH:
	if (!repo_index_has_changes(the_repository, NULL, NULL)) {
		const char *av[4] = { "show", NULL, "--", NULL };
{

		fprintf(fp, "%s\n", oid_to_hex(&commit));
		if (*sb.buf == '#')
	strbuf_release(&sb);
 * For convenience to call write_file()
}
{
		} else if (starts_with(sb.buf, "# ")) {

		if (!state->rebasing)
			am_load(state);

 */
		write_index_patch(state);
 * Builds an index that contains just the blobs needed for a 3way merge.
/**
		state->scissors = SCISSORS_FALSE;
/**
/**
	state->author_email = strbuf_detach(&author_email, NULL);
		char reply[64];
	opts.update = 1;
	assert(!state->author_name);
		 * in progress:
static void am_state_release(struct am_state *state)

 * Writes `commit` as a patch to the state directory's "patch" file.
		}
}


		run_post_rewrite_hook(state);
 * Reads the commit message from the state directory's "final-commit" file,
	return mkpath("%s/%s", state->dir, path);
		      oid_to_hex(&commit->object.oid));
	rev_info.diffopt.close_file = 1;
	repo_rerere(the_repository, 0);
 */
 * Releases memory allocated by an am_state.
	git_config_get_bool("am.messageid", &state->message_id);
			N_("pass -b flag to git-mailinfo"), KEEP_NON_PATCH),

		break;
	FILE *fp;
	opts.dst_index = &the_index;

		OPT_RERERE_AUTOUPDATE(&state.allow_rerere_autoupdate),
		mi.metainfo_charset = NULL;
	/*

	int *opt_value = opt->value;
	return 0;

			strbuf_addstr(&msg, x);
};
	struct strbuf msg = STRBUF_INIT;
 * Returns 0 if the user chooses to apply the patch, 1 if the user chooses to
		OPT_SET_INT('s', "signoff", &state.signoff,
	struct strbuf sb = STRBUF_INIT;
		 * review them with extra care to spot mismerges.
	struct argv_array apply_opts = ARGV_ARRAY_INIT;
		BUG("invalid value for state->scissors");
			break;

{
	say(state, stdout, _("Using index info to reconstruct a base tree..."));
	return ret;
	return 0;

	free(state->dir);
 * detection fails.
		(starts_with(l3.buf, "From:") ||
		/*
	}
	else

		strbuf_release(&sb);
/**
		OPT_SET_INT_F(0, "keep-cr", &keep_cr,
	case SCISSORS_UNSET:
	write_in_full(1, sb.buf, sb.len);
	ret = capture_command(&cp, &last, 8);
 * RFC2822 messages suitable for parsing with git-mailinfo, and queues them in
		 * Catch user error to feed us patches when there is a session

	if (!ret) {
		return -1;
			if (tz > 0)
}

	if (state->message_id)
		FREE_AND_NULL(state->msg);
	msg = strstr(buffer, "\n\n");
	refresh_cache(REFRESH_QUIET);
}
	}

 * Calls `fn` for each file in `paths` to convert the foreign patch to the
	strbuf_addch(&sb, '\n');

			N_("continue applying patches after resolving a conflict"),
		if (skip_prefix(sb.buf, "Subject: ", &x)) {
		}
}


		am_destroy(state);
/**
 */

			N_("pass it through git-apply"),
		mi.add_message_id = 1;
	/* Skip pine's internal folder data */
	va_end(ap);
		if (copy_note_for_rewrite(c, &from_obj, &to_obj))
	if (lstat(am_path(state, "next"), &st) || !S_ISREG(st.st_mode))
	 * errors during the initial attempt.
	int has_curr_head, has_orig_head;
	rev_info.diff = 1;
		free(their_tree_name);
{
	 */
		 *    from standard input. This is somewhat unreliable -- stdin
			timestamp = parse_timestamp(str, &end, 10);
			continue;

	}
	head_tree = parse_tree_indirect(head);
		if (str_isspace(sb.buf))
	struct strbuf sb = STRBUF_INIT;
	strbuf_release(&sb);

static void NORETURN die_user_resolve(const struct am_state *state)
		break;
 * where $author_name, $author_email and $author_date are quoted. We are strict
	default:
		ret = PATCH_FORMAT_HG;
		state->allow_rerere_autoupdate = 0;
		die(_("git write-tree failed to write a tree"));
{
	case PATCH_FORMAT_STGIT_SERIES:
	if (res)

	struct object_id curr_head, orig_head;
		   UPDATE_REFS_DIE_ON_ERR);

	oidclr(&state->orig_commit);
	}
		reset_ident_date();

#include "commit.h"
		return error(_("Repository lacks necessary blobs to fall back on 3-way merge."));
		printf_ln(_("When you have resolved this problem, run \"%s --continue\"."), cmdline);
 * Returns 0 on success, -1 if the file does not exist.

		}
	strbuf_release(&l1);


	if (!msg)
};
				am_append_signoff(state);
		} else if (skip_prefix(sb.buf, "Author: ", &x))
	if (!c)
 */
		int ret;
	if (mboxrd)
	clean_index(&curr_head, &orig_head);


			N_("pass it through git-apply"),
};
#define USE_THE_INDEX_COMPATIBILITY_MACROS
	free(state->msg);
	if (!has_curr_head)
	argv_array_pushv(&cp.args, state->git_apply_opts.argv);
 * over the merged tree's. Returns 0 on success, -1 on failure.
 *

	rev_info.no_commit_id = 1;
 *
 */
	free(curr_branch);
		} else if (*reply == 'a' || *reply == 'A') {
		break;
/**
 */
	strbuf_release(&l2);
}
		 *
	if (!*paths || !strcmp(*paths, "-") || is_directory(*paths))
			}


	int keep; /* enum keep_type */
	clear_mailinfo(&mi);

		OPT_CMDMODE(0, "quit", &resume.mode,
	return 0;

	fp = xfopen(am_path(state, "patch"), "w");
			N_("pass it through git-apply"),
/**
		am_destroy(state);
	if (!strcmp(sb.buf, "t"))
			N_("do not pass --keep-cr flag to git-mailsplit independent of am.keepcr"),

		OPT_PASSTHRU_ARGV(0, "whitespace", &state.git_apply_opts, N_("action"),
		printf_ln("%s", state->resolvemsg);
	struct strbuf sb = STRBUF_INIT;
		OPT__QUIET(&state.quiet, N_("be quiet")),
	opts.dst_index = &the_index;
#include "quote.h"
		const char *mail = am_path(state, msgnum(state));

		OPT_PASSTHRU_ARGV(0, "include", &state.git_apply_opts, N_("path"),
}
		*opt_value = PATCH_FORMAT_HG;
		FILE *fp = xfopen(am_path(state, "rewritten"), "a");
	else

{

	struct strbuf sb = STRBUF_INIT;
	RESUME_RESOLVED,


	if (l1.len && !l2.len &&
	state->msg = strbuf_detach(&sb, &state->msg_len);

	SHOW_PATCH_DIFF = 1,
#include "refs.h"
	read_state_file(&sb, state, "quiet", 1);
#include "branch.h"
 *
		}
#include "sequencer.h"
	if (!is_empty_or_missing_file(am_path(state, "rewritten"))) {
					&apply_state, &force_apply, &options,
		OPT_PASSTHRU_ARGV('C', NULL, &state.git_apply_opts, N_("n"),
		if (read_commit_msg(state) < 0)

		return -1;

		return 0;
	if (!hook)
 */
	struct strbuf sb = STRBUF_INIT;

	if (!get_oid("HEAD", &head)) {
	va_start(ap, fmt);
	case RESUME_SHOW_PATCH:

		am_skip(&state);
	opts.src_index = &the_index;

 * with our parsing, as the file was meant to be eval'd in the old git-am.sh
		else if (skip_prefix(sb.buf, "# Date ", &str)) {
	write_file(am_path(state, name), "%s", string);
 *

		tree = get_commit_tree(commit);
	ret = run_command(&cp);
	else if (get_oid_hex(sb.buf, &state->orig_commit) < 0)
static int detect_patch_format(const char **paths)
		/* It's a header if it matches header_regex */
	}
		state->allow_rerere_autoupdate = strcmp(sb.buf, "t") ?
	PATCH_FORMAT_STGIT,
	add_pending_object(&rev_info, &commit->object, "");
	const char *argv_gc_auto[] = {"gc", "--auto", NULL};
		repo_init_revisions(the_repository, &rev_info, NULL);
 */
	unuse_commit_buffer(commit, buffer);
#include "packfile.h"
	}
		copy_notes_for_rebase(state);
	if (state->rebasing)
 */
			tz = strtol(str, &end, 10);
	rev_info.diffopt.use_color = 0;
		argv_array_push(&cp.args, "--keep-cr");
}
			N_("pass it through git-apply"),
	am_destroy(state);

	write_state_text(state, name, value ? "t" : "f");
			/*
		OPT_SET_INT_F(0, "no-keep-cr", &keep_cr,
	init_tree_desc(&t[0], head->buffer, head->size);
	write_file_buf(filename, state->msg, state->msg_len);
 * Returns 0 on success, -1 on failure.
		return -1;

}
		fprintf_ln(stderr, _("The -b/--binary option has been a no-op for long time, and\n"
	if (write_cache_as_tree(&tree, 0, NULL))

		return 1;
				advise(_("Use 'git am --show-current-patch=diff' to see the failed patch"));
 * next patch.

		if (resume) {
		 */
	read_state_file(&sb, state, "messageid", 1);
		if (file_exists(state.dir) && !state.rebasing) {
	say(state, stdout, _("Applying: %.*s"), linelen(state->msg), state->msg);
	if (!strcmp(sb.buf, "t"))
		} else {
static void write_state_bool(const struct am_state *state,
	int scissors; /* enum scissors_type */
	if (mi.format_flowed)
		 * 1. mbox path(s) are provided on the command-line.
	struct apply_state apply_state;
		add_pending_oid(&rev_info, "HEAD", &our_tree, 0);
		if (resume.mode == RESUME_FALSE)
	strbuf_release(&sb);
		  PARSE_OPT_CMDMODE | PARSE_OPT_OPTARG | PARSE_OPT_NONEG | PARSE_OPT_LITERAL_ARGHELP,
		commit_list_insert(lookup_commit(the_repository, &parent),

		OPT_END()

		oidclr(&state->orig_commit);
	sq_quote_buf(&sb, state->author_email);
	strbuf_getline(&l2, fp);

{
		str = "f";
	if (!strcmp(l1.buf, "# HG changeset patch")) {
		OPT_SET_INT('k', "keep", &state.keep,
		if (!file_exists(mail))
	o.branch2 = their_tree_name;
	write_state_bool(state, "quiet", state->quiet);
	update_ref("am", "REBASE_HEAD", &commit_oid,

	else if (!strcmp(sb.buf, "f"))
	 * session is in progress, they should be written last.

			fprintf(out, "%s\n", sb.buf);


			if (errno) {
	read_state_file(&sb, state, "apply-opt", 1);
static void am_state_init(struct am_state *state)
 * digits.
	strbuf_release(&sb);
			break;

		fwrite(sb.buf, 1, sb.len, out);
 *
#include "tempfile.h"

 * Returns the filename of the current patch email.

/**
			N_("pass it through git-apply"),
	log_tree_commit(&rev_info, commit);
		} else {
			printf_ln(_("Patch failed at %s %.*s"), msgnum(state),
			update_ref("am", "ORIG_HEAD", &curr_head, NULL, 0,
		old_oid = NULL;
			const char *pager = git_pager(1);
			strbuf_addstr(&author_name, x);
	const char *hook = find_hook("post-rewrite");
		OPT_CMDMODE(0, "abort", &resume.mode,
		return split_mail_conv(hg_patch_to_mail, state, paths, keep_cr);

}
	unlink(am_path(state, "dirtyindex"));
 * applied.
			    !repo_index_has_changes(the_repository, NULL, NULL)) {
 *
		  "(diff|raw)",
 */
		for (i = 0; i < argc; i++) {
	}

			in = fopen(*paths, "r");
	if (oideq(&head, &abort_safety))
	return 0;
/**
	char *series_dir_buf;
	strbuf_addstr(&sb, "GIT_AUTHOR_EMAIL=");
{
}
		state->author_email =
	if (unpack_trees(2, t, &opts)) {
	fp = xfopen(am_path(state, "patch"), "w");
			write_author_script(state);
{
}
	}
	state->last = strtol(sb.buf, NULL, 10);
	if (read_state_file(&sb, state, "final-commit", 0) < 0) {
		const char *str;
	repo_init_revisions(the_repository, &rev_info, NULL);
	if (check_apply_state(&apply_state, force_apply))

static int do_interactive(struct am_state *state)

 * Returns 0 on success, -1 on failure.
	struct stat st;
 * `patch_format`.
/**
			/*
		oidcpy(&head, the_hash_algo->empty_tree);
	if (is_empty_or_missing_file(am_path(state, "patch"))) {
 * Returns path relative to the am_state directory.

	if (!state->quiet) {
	int message_id;
					   mail);


static int split_mail_stgit_series(struct am_state *state, const char **paths,
			ret = error(invalid_line, sb.buf);

	if (read_state_file(&sb, state, "last", 1) < 0)
			errno = 0;
	FREE_AND_NULL(state->msg);

{


	FILE *fp;
	argv_array_clear(&apply_opts);

	struct object_id curr_head;
 */
	PATCH_FORMAT_MBOX,
	strbuf_reset(&sb);
	free(their_tree_name);
			goto finish;

		return -1;
	return ret;
		 * Handle stray state directory in the independent-run case. In

		OPT_CMDMODE(0, "continue", &resume.mode,
		die_user_resolve(state);
/**
	state->cur = 1;

		fprintf(fp, "%s ", oid_to_hex(&state->orig_commit));
	case PATCH_FORMAT_HG:
 * Merges a tree into the index. The index's stat info will take precedence

	return ret;

				rc = error(_("invalid timezone offset"));
	strbuf_release(&sb);
/**
			N_("restore the original branch and abort the patching operation."),
		const char *x;
	if (get_oid("HEAD", &our_tree) < 0)
	cp.git_cmd = 1;
	exit(128);
			continue;
	state->msg = strbuf_detach(&msg, &state->msg_len);
			0),
	return ret;
		 *    intend to feed us a patch but wanted to continue
 * Reads and parses the state directory's "author-script" file, and sets

	/* state directory path */


	argv_array_push(&apply_paths, am_path(state, "patch"));
	while (!strbuf_getline(&l1, fp)) {
	if (!strcmp(author_name.buf, "Mail System Internal Data")) {

 * session.
		if (!isspace(*str))
	strbuf_reset(sb);

			N_("pass -k flag to git-mailinfo"), KEEP_TRUE),
			N_("historical option -- no-op")),
	state->scissors = SCISSORS_UNSET;

 * state directory's "author-script" file.

	if (opts_left != 0)
}
	strbuf_release(&sb);
			delete_ref(NULL, "ORIG_HEAD", NULL, 0);

		printf_ln(_("If you prefer to skip this patch, run \"%s --skip\" instead."), cmdline);
 * true, any unmerged entries will be discarded. Returns 0 on success, -1 on
	return -1;
	strbuf_addstr(&sb, "GIT_AUTHOR_NAME=");
	run_hook_le(NULL, "post-applypatch", NULL);
	for (i = 0; *paths; paths++, i++) {
	}
		*opt_value = PATCH_FORMAT_MBOXRD;
		reflog_msg = "am";
exit:
	opts.src_index = &the_index;
	argv_array_push(&apply_opts, "apply");
/**
		repo_rerere(the_repository, state->allow_rerere_autoupdate);

	mi.output = xfopen(am_path(state, "info"), "w");
	if (!safe_to_abort(state)) {

		break;
		OPT_CALLBACK(0, "patch-format", &patch_format, N_("format"),
	case RESUME_QUIT:
	mi.input = xfopen(mail, "r");

		return res;
	o.detect_directory_renames = MERGE_DIRECTORY_RENAMES_NONE;
		if (sb.len != the_hash_algo->hexsz * 2 + 1) {
		OPT_PASSTHRU_ARGV(0, "ignore-space-change", &state.git_apply_opts, NULL,
{
			     const char *name, int value)
	struct tree_desc t[1];
	size_t msg_len;

	else if (curr_branch)

 * Interactively prompt the user on whether the current patch should be


 * Like parse_mail(), but parses the mail by looking up its commit ID
		if (get_oid_hex(sb.buf, &abort_safety))
{
	struct tree_desc t[2];
		die(_("cannot resume: %s does not exist."),
	if (build_fake_ancestor(state, index_path))
#include "log-tree.h"
			else
 */
		run_command_v_opt(argv_gc_auto, RUN_GIT_CMD);
	read_cache();

	fclose(mi.input);

 * to disable this behavior, -1 to use the default configured setting.
/**
		return -1;

static void write_state_count(const struct am_state *state,
	if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK))
		oidcpy(&our_tree, the_hash_algo->empty_tree);
	opts.merge = 1;

	 * In rebasing mode, it's up to the caller to take care of
	 * recursive ends up canceling them, saying that we reverted all those
 */
	struct strbuf l1 = STRBUF_INIT;
	} else {
		assert(state->rebasing);
		{ OPTION_CALLBACK, 0, "show-current-patch", &resume.mode,
		 starts_with(l3.buf, "Author:") ||

{
	} else {
			goto finish;
 * Attempts to detect the patch_format of the patches contained in `paths`,
					   *paths);
		keep_cr = 0;
	}
	state->threeway = !strcmp(sb.buf, "t");
			char *end;
	struct object_id abort_safety, head;
	write_state_bool(state, "utf8", state->utf8);
		if (resume)
	if (state->allow_rerere_autoupdate)

static int split_mail_conv(mail_conv_fn fn, struct am_state *state,
		return error(_("Only one StGIT patch series can be applied at once"));
finish:

	if (index_file) {
/**
}



	return 0;
			0),
	if (write_locked_index(&the_index, &lock_file, COMMIT_LOCK))
finish:
	write_state_bool(state, "threeway", state->threeway);
		die(_("could not parse %s"), am_path(state, "apply-opt"));
			   UPDATE_REFS_DIE_ON_ERR);
			0),
	assert(!state->author_email);
	if (read_state_file(&sb, state, "original-commit", 1) < 0)
	}
		 starts_with(l3.buf, "Date:"))) {
 *
	remove_branch_state(the_repository, 0);
		die_errno(_("failed to read '%s'"), patch_path);
	struct strbuf sb = STRBUF_INIT;
		OPT_PASSTHRU_ARGV(0, "exclude", &state.git_apply_opts, N_("path"),
{
 * Callback signature for split_mail_conv(). The foreign patch should be

static int git_am_config(const char *k, const char *v, void *cb)
	am_run(state, 0);
{
	return 0;
		die("could not parse patch");
	}
/**
		if (!out) {
/**

	if (write_index_as_tree(&orig_tree, &the_index, index_path, 0, NULL))
/**
	return 1;

			tz2 = labs(tz) / 3600 * 100 + labs(tz) % 3600 / 60;


		OPT_PASSTHRU_ARGV(0, "ignore-whitespace", &state.git_apply_opts, NULL,
		say(state, stderr, _("applying to an empty history"));

static void am_load(struct am_state *state)

 * Returns 0 on success, -1 on failure.
	struct strbuf sb = STRBUF_INIT;
		return PATCH_FORMAT_MBOX;
		OPT_PASSTHRU_ARGV('p', NULL, &state.git_apply_opts, N_("num"),
 * state->orig_commit will be set to the original commit ID.

	if (mailinfo(&mi, am_path(state, "msg"), am_path(state, "patch")))
		BUG("invalid resume value");
static void validate_resume_state(const struct am_state *state)
 * Sets state->msg, state->author_name, state->author_email, state->author_date

 */

static void am_next(struct am_state *state)
		die("invalid pattern: %s", header_regex);
 * state->author_email and state->author_date will be set to the patch author's
	strbuf_release(&author_date);
	};
		am_run(&state, 1);
}
	init_tree_desc(&t[1], remote->buffer, remote->size);
	if (starts_with(l1.buf, "From ") || starts_with(l1.buf, "From: ")) {


/**
	PATCH_FORMAT_HG,

 * skip it.
	FREE_AND_NULL(state->author_email);
		break;
	char *dir;
			"If there is nothing left to stage, chances are that something else\n"
			      const char *name, int value)
			&state.committer_date_is_author_date,
	if (!patch_format)
	rev_info.disable_stdin = 1;
		OPT_HIDDEN_BOOL(0, "rebasing", &state.rebasing,
	if (index_file) {
static void am_setup(struct am_state *state, enum patch_format patch_format,
	resume->mode = RESUME_SHOW_PATCH;
	hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);

/**
	close(cp.in);
		return 0;
	const char *patch_path;
		return error(_("Did you hand edit your patch?\n"
		oidcpy(&curr_head, the_hash_algo->empty_tree);



	rev_info.no_commit_id = 1;
{
			timestamp_t timestamp;

 *
	int in_progress;
static int run_post_rewrite_hook(const struct am_state *state)
 * PATCH_FORMAT_* enum value corresponding to `arg`.

		str = "";
	int *opt_value = opt->value;
static int read_am_author_script(struct am_state *state)
		for (new_value = 0; new_value < ARRAY_SIZE(valid_modes); new_value++) {
{
#include "apply.h"

	if (state->committer_date_is_author_date)
		else if (skip_prefix(sb.buf, "Author:", &str))
		 * stray directories.

			die(_("previous rebase directory %s still exists but mbox given."),
}
	state->author_date = strbuf_detach(&author_date, NULL);
	switch (state->scissors) {
			N_("recode into utf8 (default)")),
	while (state->cur <= state->last) {
	validate_resume_state(state);
	assert(state->rebasing);
/**
	if (!reflog_msg)
static void write_state_text(const struct am_state *state,
	memset(&opts, 0, sizeof(opts));
	enum show_patch_type sub_mode;
	argv_array_clear(&state->git_apply_opts);

		const char *p;
	if (in_progress) {
{

 * read from `in`, and the converted patch (in RFC2822 mail format) should be
	if (merge_tree(remote_tree))
#include "diff.h"
	state->quiet = !strcmp(sb.buf, "t");
	struct object_id tree, parent, commit;

			N_("override error message when patch failure occurs")),

	    get_oid_hex(x, commit_id) < 0)
		if (get_oid_hex(p + 1, &to_obj)) {
		 *    unattended.
		die(_("Failed to split patches."));
			if (skip)
		if (in != stdin)
	if (keep_cr < 0) {
		write_state_text(state, "applying", "");
	strbuf_release(&sb);
		return status;
	if (write_index_as_tree(&their_tree, &the_index, index_path, 0, NULL))
	case KEEP_FALSE:
	int ret = 0;

		state->scissors = SCISSORS_UNSET;
	if (argc == 2 && !strcmp(argv[1], "-h"))
		} else if (*reply == 'e' || *reply == 'E') {

	warning(_("You seem to have moved HEAD since the last 'am' failure.\n"
	state->cur = strtol(sb.buf, NULL, 10);
	const char *filename = am_path(state, "final-commit");
		if (state.signoff == SIGNOFF_EXPLICIT)

		state->keep = KEEP_FALSE;
	len = strbuf_read_file(&sb, patch_path, 0);


	read_state_file(&sb, state, "utf8", 1);
	argv_array_clear(&state->git_apply_opts);
/**
	if (binary >= 0)
	}
			die(_("interactive mode requires patches on the command line"));

		die_user_resolve(state);
/**
done:
			return error_errno(_("could not open '%s' for writing"),
static int hg_patch_to_mail(FILE *out, FILE *in, int keep_cr)
	int subject_printed = 0;
{


	strbuf_release(&sb);
	if (fseek(fp, 0L, SEEK_SET))
	strbuf_addch(&sb, '\n');
				goto next;
	switch (sub_mode) {
	if (parse_tree(tree))
	switch (state->scissors) {

	opts_left = apply_parse_options(apply_opts.argc, apply_opts.argv,
	FREE_AND_NULL(state->author_date);
	} else
 * Runs post-rewrite hook. Returns it exit code.
		str = "t";

	string_list_clear(&merge_rr, 1);
	argv_array_push(&cp.args, "-b");
		state->sign_commit = gpgsign ? "" : NULL;
	return 0;
 * header field names.

 * state->author_name, state->author_email and state->author_date as the author
			SIGNOFF_EXPLICIT),
static int stgit_patch_to_mail(FILE *out, FILE *in, int keep_cr)
}
				  &state->author_email, &state->author_date, 1);
		const char *str;
				pager = "cat";
			state->interactive = 0;
	struct argv_array git_apply_opts;
		OPT_BOOL('m', "message-id", &state.message_id,
		break;
	struct strbuf sb = STRBUF_INIT;
 *
	char *author_date;
			PARSE_OPT_NOARG),
			N_("pass it through git-apply"),
		printf_ln(_("Patch is empty."));
			N_("format the patch(es) are in"),
	int interactive;
		BUG("invalid value for state->keep");
	do_commit(state);

	assert(!state->author_email);
 * This function only supports a single StGit series file in `paths`.
				return 0;

 *

			RESUME_SKIP),

	else
	case KEEP_FALSE:
			struct child_process cp = CHILD_PROCESS_INIT;
{
		printf(_("Apply? [y]es/[n]o/[e]dit/[v]iew patch/[a]ccept all: "));
static int build_fake_ancestor(const struct am_state *state, const char *index_file)
 * returning the PATCH_FORMAT_* enum value. Returns PATCH_FORMAT_UNKNOWN if
		return error(_("--show-current-patch=%s is incompatible with "

	rev_info.diffopt.file = fp;
	case PATCH_FORMAT_STGIT:
			   has_curr_head ? &curr_head : NULL, 0,
		break;
	struct commit *commit;
		} else if (*reply == 'v' || *reply == 'V') {
	cp.in = xopen(am_path(state, "rewritten"), O_RDONLY);
	/* Extract message and author information */
{


	 * housekeeping.


			N_("skip the current patch"),
		oidclr(&abort_safety);
	const char *resolvemsg;
 * Returns 0 on success, -1 on failure.
			struct strbuf sb = STRBUF_INIT;
	int ignore_date;
 */
	 * when you add new options

	fp = xfopen(am_path(state, "info"), "r");
			fprintf(out, "From: %s\n", str);
	size_t ident_len;
	int threeway;
	return read_author_script(filename, &state->author_name,
		return -1;
			strbuf_addstr(&author_date, x);
		puts("--------------------------");
static void am_destroy(const struct am_state *state)
	am_next(state);

	}
				linelen(state->msg), state->msg);
		rev_info.diffopt.output_format = DIFF_FORMAT_NAME_STATUS;
	strbuf_addstr(&msg, "\n\n");
			N_("pass it through git-apply"),
			ret = error(invalid_line, sb.buf);
		die(_("cannot resume: %s does not exist."),
		break;
		die_user_resolve(state);


	if (get_oid("HEAD", &head))
 * at the end.

		}
	int status;
	struct unpack_trees_options opts;
			0, PARSE_OPT_NONEG),
	case RESUME_SKIP:
		else if (skip_prefix(sb.buf, "Date: ", &x))
{

		FILE *in, *out;
 * If state->quiet is false, calls fprintf(fp, fmt, ...), and appends a newline
		 *    could be /dev/null for example and the caller did not
	case PATCH_FORMAT_MBOXRD:
		fclose(out);
	if (fast_forward_to(index_tree, remote_tree, 0))
				"It does not apply to blobs recorded in its index."));
	}

		apply_status = run_apply(state, NULL);
		if (l1.len)
			die(_("Stray %s directory found.\n"
	struct child_process cp = CHILD_PROCESS_INIT;
	 * We default to mbox format if input is from stdin and for directories
			int skip;
		say(state, stdout, _("Applying: %.*s"), linelen(state->msg), state->msg);
}
static void write_index_patch(const struct am_state *state)

static void do_commit(const struct am_state *state)
	assert(!state->author_name);


#include "dir.h"
			if (!apply_status &&
		ret = PATCH_FORMAT_STGIT_SERIES;
		write_state_text(state, "abort-safety", "");
		die(_("Dirty index: cannot apply patches (dirty: %s)"), sb.buf);
	rev_info.show_root_diff = 1;
	int cur;
	if (unset)


	if (errno == ENOENT)
	author = fmt_ident(state->author_name, state->author_email,

	};
				int keep_cr, int mboxrd)
	if (!patch_format) {


	}
	if (mkdir(state->dir, 0777) < 0 && errno != EEXIST)
	git_config_get_bool("am.threeway", &state->threeway);

	rev_info.diffopt.close_file = 1;

		}
		die(_("could not parse author script"));
	struct object_id orig_commit;
	fclose(fp);
	argv_array_init(&state->git_apply_opts);
static int read_state_file(struct strbuf *sb, const struct am_state *state,
	discard_cache();
	strbuf_release(&sb);
		if (ret)
	}

		ret = -1;
	cp.stdout_to_stderr = 1;
/**
	write_state_text(state, "scissors", str);
			prepare_pager_args(&cp, pager);
static void write_author_script(const struct am_state *state)
	state->dir = git_pathdup("rebase-apply");
		close_object_store(the_repository->objects);
	ret = split_mail_conv(stgit_patch_to_mail, state, patches.argv, keep_cr);
{
#include "run-command.h"
		break;
			 * mercurial's timezone is in seconds west of UTC,
};
		am_next(state);
				argv_array_push(&paths, argv[i]);
		state->author_email = xstrdup("");
	struct lock_file lock_file = LOCK_INIT;
}
		apply_state.index_file = index_file;
		BUG("init_apply_state() failed");

			0),
	struct argv_array patches = ARGV_ARRAY_INIT;
	assert(!state->author_date);
	if (merge_recursive_generic(&o, &our_tree, &their_tree, 1, bases, &result)) {

	struct argv_array apply_paths = ARGV_ARRAY_INIT;

{
 * RFC2822 mail format suitable for parsing with git-mailinfo.
		} else {
}
		ret = PATCH_FORMAT_STGIT;
	if (!ident_line)
	struct rev_info rev_info;

	commit = lookup_commit_or_die(&commit_oid, mail);
	struct am_state state;

	return strchrnul(msg, '\n') - msg;
			if (in != stdin)

		run_diff_index(&rev_info, 1);
{
			return 0;
	strbuf_release(&sb);
			if (!pager)
 */
	else if (!strcmp(sb.buf, "b"))
	char *author_email;
	}
	 * If the second line is empty and the third is a From, Author or Date
		}

 * Parses `mail` using git-mailinfo, extracting its patch and authorship info.

			argv_array_push(&cp.args, am_path(state, "patch"));
	sq_quote_buf(&sb, state->author_name);
		state->keep = KEEP_TRUE;
	}
	}
		if (!in)
		int apply_status;

#include "revision.h"
	init_tree_desc(&t[0], tree->buffer, tree->size);
 */
			if (advice_amworkdir)

				skip = parse_mail(state, mail);
		FILE *fp = xfopen(am_path(state, "rewritten"), "a");
	case RESUME_FALSE:

				goto exit;

	 * when you add new options
	argv_array_clear(&patches);
		*opt_value = PATCH_FORMAT_MBOX;
	has_orig_head = !get_oid("ORIG_HEAD", &orig_head);
	struct commit_list *parents = NULL;

	struct object_id head;
	state->cur++;
			     const char *name, const char *string)
	if (read_state_file(&sb, state, "abort-safety", 1) > 0) {
		char *new_oid_str;
	char *author_name;
	if (!get_oid_commit("HEAD", &parent)) {
 * Splits out individual email patches from `paths`, where each path is either
}
		return 0;
	strbuf_addstr(&sb, state->dir);

static int parse_mail(struct am_state *state, const char *mail)
			fprintf(out, "Subject: %s\n", sb.buf);

			author, state->sign_commit))

		break;

	unlink(am_path(state, "author-script"));
struct resume_mode {
	char *msg;
	}
			"You might run `git rm` on a file to accept \"deleted by them\" for it."));
}
	unlink(am_path(state, "original-commit"));
	remove_dir_recursively(&sb, 0);
	strbuf_release(&l3);
	rev_info.diffopt.output_format = DIFF_FORMAT_PATCH;
			if (is_absolute_path(argv[i]) || !prefix)
		die(_("could not parse %s"), mail);
static int parse_opt_show_current_patch(const struct option *opt, const char *arg, int unset)

	case SCISSORS_TRUE:

		puts("--------------------------");
	argv_array_pushv(&cp.args, paths);
	series_dir = dirname(series_dir_buf);


			if (resume.mode == RESUME_ABORT || resume.mode == RESUME_QUIT) {
	} else {


			if (msg.len)
	their_tree_name = xstrfmt("%.*s", linelen(state->msg), state->msg);
	 * Please update $__git_showcurrentpatch in git-completion.bash

		OPT_BOOL(0, "committer-date-is-author-date",
	struct strbuf author_name = STRBUF_INIT;
 * Runs applypatch-msg hook. Returns its exit code.
	else


		rev_info.diffopt.filter |= diff_filter_bit('A');

/**
	free(state->author_email);
	fclose(fp);
	if (l1.len && is_mail(fp)) {

	fp = xfopen(*paths, "r");
	}
				state.dir);
	return ret;
	state->message_id = !strcmp(sb.buf, "t");
 */
				am_destroy(&state);
	if (fast_forward_to(head_tree, head_tree, 1))
static void write_commit_patch(const struct am_state *state, struct commit *commit)
}
	return rc;
	if (arg) {
			if (*end) {

		state->author_name = xstrdup("");
	if (!state->rebasing) {
			ret = error(invalid_line, sb.buf);

		state->keep = KEEP_NON_PATCH;
 * setting state->msg to its contents and state->msg_len to the length of its
		/*
		ret = show_patch(&state, resume.sub_mode);
		/* Reload index as apply_all_patches() will have modified it. */
{

	strbuf_release(&author_email);
}
 *

	PATCH_FORMAT_STGIT_SERIES,
	diff_setup_done(&rev_info.diffopt);
		av[1] = new_oid_str = xstrdup(oid_to_hex(&state->orig_commit));

	res = apply_all_patches(&apply_state, apply_paths.argc, apply_paths.argv, options);
	const struct object_id *old_oid;
			}
	int ret = 0;
		/* Ignore indented folded lines */

	}
	if (state->quiet)
		break;

};

	die_errno(_("could not read '%s'"), am_path(state, file));
			exit(1);
}
static void am_skip(struct am_state *state)

		return error(_("Failed to merge in the changes."));
					oid_to_hex(&from_obj), oid_to_hex(&to_obj));
	 */
	assert(!state->msg);
	/* Ensure a valid committer ident can be constructed */

			if (!skip_prefix(end, " ", &str)) {
		strbuf_reset(&sb);
			RESUME_ABORT),
	int keep_cr = -1;
	int i;
}
	int signoff; /* enum signoff_type */
 * Returns 1 if the file looks like a piece of mail, 0 otherwise.
		return -1;
 * Loads state from disk.
	sq_quote_buf(&sb, state->author_date);
}
		apply_state.check_index = 1;

			PARSE_OPT_NOARG),
	struct mailinfo mi;

			continue; /* skip comment lines */
 * Saves state->author_name, state->author_email and state->author_date in the
		tree = lookup_tree(the_repository,
	return ret;
	rev_info.diffopt.use_color = 0;
