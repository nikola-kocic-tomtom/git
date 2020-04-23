}
		s->ahead_behind_flags = AHEAD_BEHIND_FULL;
		set_ident_var(&email, xmemdupz(ident.mail_begin, ident.mail_end - ident.mail_begin));
{
	if (!no_verify &&
			s->rename_limit = git_config_int(k, v);
	}
	free(*buf);
	run_command_v_opt(argv_gc_auto, RUN_GIT_CMD);

"\n");
		current_head = lookup_commit_or_die(&oid, "HEAD");
}
	return 1;
		struct string_list_item *p = &(list->items[i]);
		hold_locked_index(&index_lock, LOCK_DIE_ON_ERROR);
		read_cache_from(get_lock_file_path(&index_lock));
	struct object_id oid;

	}
				flags.ignore_submodules = 1;
			 * ignore mode by passing a command line option we do

			status_printf(s, GIT_COLOR_NORMAL,
	finalize_deferred_config(s);
		{ OPTION_STRING, 'u', "untracked-files", &untracked_files_arg, N_("mode"), N_("show untracked files, optional modes: all, normal, no. (Default: all)"), PARSE_OPT_OPTARG, NULL, (intptr_t)"all" },
	[WT_STATUS_UPDATED]	  = "updated",
		if (ident_cmp(&ai, &ci))

		 * that the name and mail pointers will at least be valid,

			     builtin_status_options,
	}
	 * (B) on failure, rollback the real index;
		if (status_format == STATUS_FORMAT_NONE ||

};

		 * fmt_ident. They may fail the sane_ident test, but we know
	commit_style = COMMIT_PARTIAL;
	repo_init_revisions(the_repository, &revs, NULL);
	unlink(git_path_merge_msg(the_repository));
 * the commit message and/or authorship.
		strbuf_addch(&buf, hack);
static int opt_parse_rename_score(const struct option *opt, const char *arg, int unset)
	if (update_head_with_reflog(current_head, &oid, reflog_msg, &sb,


		OPT_STRING('C', "reuse-message", &use_message, N_("commit"), N_("reuse message from specified commit")),
		exit(1);
			    N_("show status in long format (default)"),
		OPT_BOOL('o', "only", &only, N_("commit only specified files")),
static struct lock_file index_lock; /* real index */
	fclose(s->fp);

		else
			fputs(_(empty_amend_advice), stderr);
	commit = lookup_commit_reference_by_name(name);
	}

}
	return 0;
	if (status_format != STATUS_FORMAT_PORCELAIN &&
	av[++ac] = "--all";
	if (s.show_ignored_mode == SHOW_MATCHING_IGNORED &&
		char *buffer;
		refresh_cache_or_die(refresh_flags);
	 * (1) get lock on the real index file;
		else {

		hook_arg1 = "message";

	 */
		return git_config_pathname(&template_file, k, v);
			merge_contains_scissors = 1;
static struct strbuf message = STRBUF_INIT;
		s->show_ignored_mode = SHOW_MATCHING_IGNORED;
		format_commit_message(commit, "fixup! %s\n\n",
		}
	if (candidate)
	 * Most hints are counter-productive when the commit has
	if (!memchr(sb->buf, comment_line_char, sb->len))

 * is specified explicitly.
	static const char *rename_score_arg = (const char *)-1;
	if (!strcasecmp(slot, "added"))
		OPT_FILENAME('F', "file", &logfile, N_("read message from file")),
		} else
	struct wt_status *s = cb;
	int refresh_flags = REFRESH_QUIET;
		hook_arg1 = "template";
};

static int prepare_to_commit(const char *index_file, const char *prefix,
define_list_config_array_extra(color_status_slots, {"added"});
	 * (2) update the_index as necessary;
	if (refresh_cache(refresh_flags | REFRESH_IN_PORCELAIN))
				  git_path("next-index-%"PRIuMAX,

}
	s->fp = fopen_for_writing(git_path_commit_editmsg());

	 *
	/* Determine parents */
		if (update_main_cache_tree(WRITE_TREE_SILENT) == 0) {
		old_index_env = xstrdup_or_null(getenv(INDEX_ENVIRONMENT));
/*
			struct diff_flags flags = DIFF_FLAGS_INIT;
				  " yourself if you want to.\n"


	case COMMIT_NORMAL:

	}
		hook_arg1 = "merge";
		OPT_COLUMN(0, "column", &s.colopts, N_("list untracked files in columns")),
		if (strbuf_read(&sb, 0, 0) < 0)
	case COMMIT_AS_IS:
		refresh_flags |= REFRESH_UNMERGED;
	struct tree_desc t;
	}
{

"If you wish to commit it anyway, use:\n"
			c = lookup_commit_reference_by_name(squash_message);
			status_printf_ln(s, GIT_COLOR_NORMAL,
static struct lock_file false_lock; /* used only for partial commits */
 * Builtin "git commit"
		struct ident_split ident;

	if (auto_comment_line_char)
			return -1;
		if (whence == FROM_MERGE)
		struct pretty_print_context ctx = {0};
		  N_("ignore changes to submodules, optional when: all, dirty, untracked. (Default: all)"),
{
	const char *argv_gc_auto[] = {"gc", "--auto", NULL};
	determine_author_info(author_ident);
	 * (A) if all goes well, commit the real index;
 * Copyright (c) 2007 Kristian Høgsberg <krh@redhat.com>
		s->hints = advice_status_hints;
		OPT_PATHSPEC_FROM_FILE(&pathspec_from_file),
	}
		return 0;

		struct argv_array env = ARGV_ARRAY_INIT;
	if (0 <= fd)
				(int)(ci.mail_end - ci.mail_begin), ci.mail_begin);
	if (s->fp == NULL)
	int f = 0;
	hold_locked_index(&index_lock, LOCK_DIE_ON_ERROR);
static const char *find_author_by_nickname(const char *name)
		return git_config_string(&cleanup_arg, k, v);
		use_editor = edit_flag;
	if (signoff)
		hook_arg1 = "message";
	if (also + only + all + interactive > 1)
				    prefix, pathspec_from_file, pathspec_file_nul);
		return 0;
	}
		if (strbuf_read_file(&sb, template_file, 0) < 0)
	}
#include "builtin.h"
	 *
	s.is_initial = get_oid(s.reference, &oid) ? 1 : 0;
		die(_("repository has been updated, but unable to write\n"
	if (use_editor && include_status) {
			flags |= SUMMARY_INITIAL_COMMIT;
	COMMIT_PARTIAL
	BUG_ON_OPT_NEG(unset);
		size_t merge_msg_start;
	int merge_contains_scissors = 0;
	repo_rerere(the_repository, 0);
	 */
	if (use_message)
		if (cleanup_mode == COMMIT_MSG_CLEANUP_SCISSORS &&
static void finalize_deferred_config(struct wt_status *s)
				die(_("Corrupt MERGE_HEAD file (%s)"), m.buf);
				  " Lines starting\n"
			     struct wt_status *s,
#define USE_THE_INDEX_COMPATIBILITY_MACROS
	if (!pathspec.nr && (also || (only && !amend && !allow_empty)))
	 * As-is commit.

					: is_from_rebase(whence)
	if (unset) {
static const char *color_status_slots[] = {
	s.colopts = 0;
	struct commit *commit;
}
	}
		if (!v)
static int no_post_rewrite, allow_empty_message, pathspec_file_nul;
	else
		if (split_ident_line(&ident, force_author, strlen(force_author)) < 0)
			setenv(INDEX_ENVIRONMENT, old_index_env, 1);
	struct commit_list *parents = NULL;
		if (!commit)

		else if (!strcmp(v, "no"))
			    N_("machine-readable output"), STATUS_FORMAT_PORCELAIN),
		OPT_CLEANUP(&cleanup_arg),
}
				(int)(ai.name_end - ai.name_begin), ai.name_begin,

				(int)(ai.mail_end - ai.mail_begin), ai.mail_begin);
N_("You asked to amend the most recent commit, but doing so would make\n"

	 * The remaining cases don't modify the template message, but
	}
	else if (!strcmp(arg, "v1") || !strcmp(arg, "1"))
	/*
	if (!strcmp(k, "status.renames")) {
	if (read_cache_preload(&pathspec) < 0)
			 N_("terminate entries with NUL")),
	s->hints = advice_status_hints; /* must come after git_config() */
		die("%s", err.buf);
	return committable ? 0 : 1;
	struct string_list partial = STRING_LIST_INIT_DUP;

		if (launch_editor(git_path_commit_editmsg(), NULL, env.argv)) {
#include "diff.h"
{
		if (author_date_is_interesting())
	else
				wt_status_add_cut_line(s->fp);
			struct strbuf date_buf = STRBUF_INIT;
		progress_flag = REFRESH_PROGRESS;
		       PATHSPEC_PREFER_FULL,
		die(_("failed to unpack HEAD tree object"));
		saved_color_setting = s->use_color;
		if (!stat(git_path_squash_msg(the_repository), &statbuf)) {
		have_option_m = 0;
		extra = read_commit_extra_headers(current_head, exclude_gpgsig);
		int slot = parse_status_slot(slot_name);
			parent = get_merge_parent(m.buf);
		fd = hold_locked_index(&index_lock, 0);
	revs.mailmap = &mailmap;
		s->show_untracked_files = SHOW_NORMAL_UNTRACKED_FILES;
		OPT_STRING(0, "squash", &squash_message, N_("commit"), N_("use autosquash formatted message to squash specified commit")),
	 *
	s->hints = 0;
		discard_cache();
 * The default commit message cleanup mode will remove the lines
#include "wt-status.h"
		s->show_untracked_files = SHOW_NO_UNTRACKED_FILES;
		if (!renew_authorship) {
			warning(_("Failed to update main cache tree"));
{

		if (git_config_bool(k, v))
		 * If squash_commit was used for the commit subject,


}
				: _("\n"
		if (amend)
{
{
					"If this is not correct, please remove the file\n"

		int is_bool;
		 * "merge --squash" was originally performed
		if (pathspec.nr)
			reduce_heads_replace(&parents);
				wt_status_add_cut_line(s->fp);
	 * Please update $__git_untracked_file_modes in
				fputs(_(empty_cherry_pick_advice_single), stderr);
	}
	if (!strcmp(k, "status.short")) {
		*value = STATUS_FORMAT_PORCELAIN_V2;
				_("Please enter the commit message for your changes."
		return 0;
	struct commit_extra_header *extra = NULL;
		*candidate = ' ';

		OPT_SET_INT(0, "long", &status_format,
		if (is_bool && s->submodule_summary)
	return !!(current_head->parents && current_head->parents->next);
	switch (commit_style) {
	strbuf_release(&sb);
		s->display_comment_prefix = git_config_bool(k, v);

	comment_line_char = candidates[0];
	opts.index_only = 1;
	}
		 * the editor and after we invoke run_status above.
static const char *author_message, *author_message_buffer;
		the_repository->index_file = old_repo_index_file;
	*value = arg;
	}
	if (status)
				ident_shown++ ? "" : "\n",
		usage_with_options(builtin_commit_usage, builtin_commit_options);
	if (dry_run)
{
	if (fixup_message)
	if (!quiet) {
				_("%s"
	 */
		if (!committer_ident_sufficiently_given())
		commit_post_rewrite(the_repository, current_head, &oid);
"    git cherry-pick --continue\n"
	UNLEAK(err);

		/*
		die((_("Option -m cannot be combined with -c/-C/-F.")));
		die(_("Invalid ignored mode '%s'"), ignored_arg);
		OPT_SET_INT(0, "porcelain", &status_format,
		{ OPTION_CALLBACK, 0, "porcelain", &status_format,

		use_message = "HEAD";
				 const struct commit *current_head, int is_status)
{
	} else if (pathspec_file_nul) {
#include "parse-options.h"
	} else if (use_message) {
#include "mailmap.h"
			die_errno(_("could not read MERGE_MSG"));
	if (!strcmp(k, "status.branch")) {
	    run_commit_hook(use_editor, index_file, "commit-msg", git_path_commit_editmsg(), NULL)) {
}
	}
	else if (!strcmp(ignored_arg, "traditional"))
static int list_paths(struct string_list *list, const char *with_tree,

static int opt_parse_m(const struct option *opt, const char *arg, int unset)
			if (!strcmp(sb.buf, "no-ff"))
	struct strbuf buf = STRBUF_INIT;
		return 0;
		die(_("Invalid untracked files mode '%s'"), untracked_files_arg);
		 */
	if (!strcmp(k, "status.submodulesummary")) {
		if (!a)
		s->relative_paths = git_config_bool(k, v);
	 * create commit from it.  Then
		OPT_HIDDEN_BOOL(0, "allow-empty-message", &allow_empty_message,
	}
		OPT_BOOL(0, "dry-run", &dry_run, N_("show what would be committed")),
		use_message_buffer = read_commit_message(use_message);
		OPT_STRING(0, "date", &force_date, N_("date"), N_("override date for commit")),
static char *fixup_message, *squash_message;
	if (whence != FROM_COMMIT) {

	if (edit_message)
	if (clean_message_contents)
		if (write_locked_index(&the_index, &index_lock, 0))
	    status_format != STATUS_FORMAT_PORCELAIN_V2)
			if (write_locked_index(&the_index, &index_lock, 0))
			fprintf(stderr,
	if (!strcmp(k, "status.relativepaths")) {
	assert_split_ident(&author, author_ident);
}
	return ret;
	} else {
{
	handle_untracked_files_arg(&s);

				      const char * const usage[],
		buffer = strstr(use_message_buffer, "\n\n");
	case COMMIT_NORMAL:
				"Committer: %.*s <%.*s>"),
		strbuf_addf(out, "%lu", t);

		err = commit_lock_file(&index_lock);
	if (!s->is_initial)

	struct strbuf committer_ident = STRBUF_INIT;
"    git commit --allow-empty\n"
			pptr = commit_list_append(parent, pptr);
	if (!strcmp(k, "status.renamelimit")) {
	strbuf_reset(&sb);
	struct rev_info revs;
	wt_status_collect(&s);
		s.detect_rename = !no_renames;
	if (parse_date(in, out) < 0) {
	if (amend && !use_message && !fixup_message)
	committable = run_status(stdout, index_file, prefix, 0, s);
			die(_("unable to write new_index file"));
	}
	struct pathspec pathspec;

		OPT_BOOL(0, "amend", &amend, N_("amend previous commit")),
			else
			author_message = use_message;
	if (commit) {
				_("%s"

#include "sequencer.h"
		if (!active_nr && read_cache() < 0)
	struct object_id oid;

	if (s->show_branch < 0)
	return 0;
	if (!untracked_files_arg)
	    !(amend && is_a_merge(current_head))) {

	opts.dst_index = &the_index;
		  N_("show ignored files, optional modes: traditional, matching, no. (Default: traditional)"),
}
	}
		die(_("--pathspec-file-nul requires --pathspec-from-file"));
	else if (!arg)
					? "commit (rebase)"

	tree = parse_tree_indirect(&current_head->object.oid);
	 * (1) get the real index;
static enum wt_status_format status_format = STATUS_FORMAT_UNSPECIFIED;
	if (logfile || have_option_m || use_message || fixup_message)
					 sb.len - merge_msg_start) <
		struct strbuf date_buf = STRBUF_INIT;

		rollback_index_files();

		rollback_lock_file(&false_lock);
		  PARSE_OPT_OPTARG, NULL, (intptr_t)"traditional" },
	if (fwrite(sb.buf, 1, sb.len, s->fp) < sb.len)
		/* end commit contents options */
	read_cache_from(ret);
		return strbuf_detach(&buf, NULL);
	if (!ignored_arg)
}
			reflog_msg = "commit (initial)";
		OPT__QUIET(&quiet, N_("suppress summary after successful commit")),


		if (s->rename_limit == -1)
static enum commit_msg_cleanup_mode cleanup_mode;
		update_main_cache_tree(WRITE_TREE_SILENT);
		parse_pathspec_file(&pathspec, 0,
	/*

	static struct wt_status s;
}
	if (!strcmp(k, "commit.cleanup"))
	if (message_is_empty(&sb, cleanup_mode) && !allow_empty_message) {
	 * (1) return the name of the real index file.
	/*
	if (unpack_trees(1, &t, &opts))
		/*

			die(_("You are in the middle of a cherry-pick -- cannot amend."));
				? _("\n"
		OPT_BOOL('n', "no-verify", &no_verify, N_("bypass pre-commit and commit-msg hooks")),
		struct commit_list **pptr = &parents;
			if (!parent)
			 whence == FROM_REBASE_PICK) {
			if (ignore_submodule_arg &&


				die_errno(_("could not read MERGE_MODE"));
		  PARSE_OPT_OPTARG, NULL, (intptr_t)"all" },
	if (!strcmp(k, "commit.verbose")) {
		/* p->util is skip-worktree */
		adjust_comment_line_char(&sb);
#include "color.h"
static int dry_run_commit(int argc, const char **argv, const char *prefix,


		if (split_ident_line(&ident, a, len) < 0)
		return git_column_config(k, v, "status", &s->colopts);

	const char *av[20];
}
		 */
		hook_arg1 = "commit";
 * Take a union of paths in the index and the named tree (typically, "HEAD"),
		whence = FROM_MERGE;
	if (s->ahead_behind_flags == AHEAD_BEHIND_UNSPECIFIED)
			die(_("--pathspec-from-file is incompatible with pathspec arguments"));
	    skip_prefix(k, "color.status.", &slot_name)) {

	}
	int show_branch;
		commit_style = COMMIT_NORMAL;
 */


			reflog_msg = is_from_cherry_pick(whence)
		*value = STATUS_FORMAT_PORCELAIN;
			 N_("compute full ahead/behind values")),
			status_printf_ln(s, GIT_COLOR_NORMAL,


/*
		       PATHSPEC_PREFER_FULL,
	if (unset)
			status_format = STATUS_FORMAT_PORCELAIN;

			continue;
/*
	const char *slot_name;
		status_deferred_config.ahead_behind = git_config_bool(k, v);
			if (add_to_cache(p->string, &st, 0))
 */
		commit = lookup_commit_reference_by_name(fixup_message);
		the_repository->index_file =

	STATUS_FORMAT_UNSPECIFIED,
		parents = copy_commit_list(current_head->parents);
			if (whence == FROM_COMMIT && !merge_contains_scissors)
		*value = STATUS_FORMAT_PORCELAIN;
					"It looks like you may be committing a merge.\n"
	parse_pathspec(&pathspec, 0,
				    PATHSPEC_PREFER_FULL,
	N_("git status [<options>] [--] <pathspec>..."),
		die(_("could not read commit message: %s"), strerror(saved_errno));
	if (squash_message) {
		discard_cache();
	 * The caller should run hooks on the real index,
		unsigned long t = approxidate_careful(in, &errors);
	/*
				*candidate = ' ';
		goto out;
	 */

		discard_cache();
	} else if (amend) {
			die(_("cannot do a partial commit during a cherry-pick."));
			s->submodule_summary = -1;
		if (!reflog_msg)

			die(_("commit '%s' has malformed author line"), author_message);
	if (!strcmp(k, "diff.renamelimit")) {

		      const struct pathspec *pattern)
	else {
	s->ignore_submodule_arg = ignore_submodule_arg;
		if (cleanup_mode == COMMIT_MSG_CLEANUP_ALL)
			 * be really confusing.

	const char *p;
		 */
	clear_pathspec(&pathspec);
			hook_arg1 = "merge";
	if (squash_message) {
		 */

			hook_arg1 = "squash";
			    N_("show status in long format (default)"),
			die_errno(_("could not read SQUASH_MSG"));
	if (use_deferred_config && s->show_branch < 0)
	}
		struct object_id oid;
		if (!ce_path_match(&the_index, ce, pattern, m))
	return 0;
static void status_init_config(struct wt_status *s, config_fn_t fn)
	} else {
{
				      struct wt_status *s)
 * if editor is used, and only the whitespaces if the message
	}
	if (patch_interactive)
			for (i = 0; i < active_nr; i++)
		ctx.date_mode.type = DATE_NORMAL;
	discard_cache();

		die(_("Only one of -c/-C/-F/--fixup can be used."));
	else
	handle_ignored_arg(&s);
	determine_whence(s);
	}
N_("Otherwise, please use 'git cherry-pick --skip'\n");

			die(_("commit '%s' lacks author header"), author_message);
		/*
	init_diff_ui_defaults();
"\n");
	}
			struct commit *c;
"\n"

	if (!strcmp(k, "status.showuntrackedfiles")) {

	 * Reject an attempt to record a non-merge empty commit without
	const char *ret;
				  logfile);
			if (reopen_lock_file(&index_lock) < 0)
	if (!s.is_initial)
	 * (4) get lock on the false index file;
		have_option_m = 1;
	}
			strbuf_addbuf(&sb, &message);
	if (s->null_termination) {

	struct strbuf author_ident = STRBUF_INIT;
		}
		goto out;
		else if (is_from_rebase(whence))
	return LOOKUP_CONFIG(color_status_slots, slot);
		goto out;
		struct stat st;
			s->show_untracked_files = SHOW_NORMAL_UNTRACKED_FILES;

	}
				die(_("unable to update temporary index"));
	char *candidate;
			struct commit *parent;
		if (!reflog_msg)
	if (amend && !current_head)
					"	%s\n"
		die_errno(_("could not write commit template"));
	update_main_cache_tree(WRITE_TREE_SILENT);
int cmd_commit(int argc, const char **argv, const char *prefix)
			 * configured. Otherwise we won't commit any
		OPT_BOOL(0, "no-renames", &no_renames, N_("do not detect renames")),
		s->whence = whence;

		{ OPTION_CALLBACK, 'M', "find-renames", &rename_score_arg,
 */
			flags.override_submodule_config = 1;
		       prefix, argv);
	else if (!strcmp(ignored_arg, "matching"))
		format_commit_message(commit, "%aN <%aE>", &buf, &ctx);
	struct tree *tree;

#include "quote.h"

	case COMMIT_AS_IS:
			    STATUS_FORMAT_SHORT),
		if ((p[0] == '\n' || p[0] == '\r') && p[1]) {
		fprintf(stderr, _("Aborting commit due to empty commit message.\n"));
		break;
		die_errno(_("could not open '%s'"), git_path_commit_editmsg());
{
				allow_fast_forward = 0;
	sequencer_post_commit_cleanup(the_repository, 0);
	if (with_tree) {
			unsetenv(INDEX_ENVIRONMENT);



		sign_commit = git_config_bool(k, v) ? "" : NULL;
		else if (is_from_cherry_pick(whence) ||
		return 0;
		struct ident_split ident;
	status_init_config(&s, git_commit_config);
	read_cache_from(index_file);
		hook_arg1 = "message";
				  "with '%c' will be kept; you may remove them"
} status_deferred_config = {
		size_t len;
		ret = get_index_file();
	finalize_colopts(&s.colopts, -1);
		if (ident.date_begin) {
static const char empty_amend_advice[] =
			 N_("show stash information")),
static int is_a_merge(const struct commit *current_head)
	opts.src_index = &the_index;
					      &ctx);
	 * (0) find the set of affected paths;
		s->show_ignored_mode = SHOW_TRADITIONAL_IGNORED;
					   (uintmax_t) getpid()),
	if (all && argc > 0)
		struct commit *commit;
	if (force_author && !strchr(force_author, '>'))
	if (force_author) {
			format_commit_message(c, "squash! %s\n\n", &sb,
static const char empty_rebase_pick_advice[] =
	if (!commit)

}
			die_errno(_("could not read '%s'"), template_file);
"    git cherry-pick --skip\n"
				whence == FROM_MERGE ?
"\n"
		author_message = "CHERRY_PICK_HEAD";
	if (!no_verify && find_hook("pre-commit")) {
			if (whence == FROM_CHERRY_PICK_SINGLE)
			die(_("could not parse HEAD commit"));
	 * In either case, rollback the false index.
	    !renew_authorship) {
	}

		OPT_BOOL('i', "include", &also, N_("add specified files to index for commit")),
{
	if (prepare_revision_walk(&revs))

	cleanup_mode = get_cleanup_mode(cleanup_arg, use_editor);
	int fd;
		die(_("failed to write commit object"));
	 * and create commit from the_index.
		if (author_date_is_interesting())
static char *untracked_files_arg, *force_date, *ignore_submodule_arg, *ignored_arg;
		status_format = STATUS_FORMAT_NONE;
		if (amend)
	status = git_gpg_config(k, v, NULL);
 * beginning with # (shell comments) and leading and trailing
		append_signoff(&sb, ignore_non_trailer(sb.buf, sb.len), 0);
	 * (3) write the_index out to the real index (still locked);
		char *max_prefix = common_prefix(pattern);
static void rollback_index_files(void)
	}
	wt_status_prepare(the_repository, s);
} commit_style;
		fclose(fp);
		oidcpy(&s->oid_commit, &oid);
		OPT_GROUP(N_("Commit message options")),
}

			strbuf_addstr(&sb, "squash! ");
	if (amend && whence != FROM_COMMIT) {
#include "lockfile.h"
			remove_file_from_cache(p->string);
			committable = index_differs_from(the_repository,
static const char empty_cherry_pick_advice_multi[] =
			    N_("show status concisely"), STATUS_FORMAT_SHORT),
		rollback_index_files();
	if (have_option_m && (edit_message || use_message || logfile))
		  N_("GPG sign commit"), PARSE_OPT_OPTARG, NULL, (intptr_t) "" },

		add_files_to_cache(also ? prefix : NULL, &pathspec, 0);
{

		OPT_SET_INT(0, "long", &status_format,
	struct wt_status *s = cb;
			exit(1);
		      "in the current commit message"));
	if (!use_message && !is_from_cherry_pick(whence) &&
							 parent, &flags, 1);

	/* Finally, get the commit message */
		struct strbuf m = STRBUF_INIT;

		break;
#include "help.h"
		return 0;
	av[++ac] = buf.buf;

static const char * const builtin_commit_usage[] = {

		else if (is_from_cherry_pick(whence))

		break;
		 * which is enough for our tests and printing here.

		refresh_cache_or_die(refresh_flags);
	else if (!strcmp(arg, "v2") || !strcmp(arg, "2"))
	if (commit_tree_extended(sb.buf, sb.len, &active_cache_tree->oid,

	if (amend) {
}
	}
 * whitespaces (empty lines or containing only whitespaces)

	return ret;
	memset(&opts, 0, sizeof(opts));
		set_ident_var(&email, xmemdupz(ident.mail_begin, ident.mail_end - ident.mail_begin));
			die_errno(_("could not read log file '%s'"),
	}
	} else if (fixup_message) {
	char *name, *email, *date;

	 * (5) reset the_index from HEAD;
}
	unlink(git_path_squash_msg(the_repository));
		OPT_STRING(0, "fixup", &fixup_message, N_("commit"), N_("use autosquash formatted message to fixup specified commit")),
	}
		s->detect_rename = git_config_rename(k, v);
	ret = report_path_error(m, pattern);

		  N_("mode"),
		s->submodule_summary = git_config_bool_or_int(k, v, &is_bool);
				!merge_contains_scissors)
			strbuf_add(&date_buf, ident.date_begin, ident.date_end - ident.date_begin);
		assert_split_ident(&ci, &committer_ident);
{
	cleanup_message(&sb, cleanup_mode, verbose);
	for (i = 0; i < active_nr; i++) {

	free(email);

		commit_list_insert(current_head, &parents);
		if (s.detect_rename < DIFF_DETECT_RENAME)

		  N_("n"), N_("detect renames, optionally set similarity index"),
		OPT_BOOL(0, "no-post-rewrite", &no_post_rewrite, N_("bypass post-rewrite hook")),
	for (p = sb->buf; *p; p++) {
		if (strbuf_read_file(&sb, logfile, 0) < 0)
 * Enumerate what needs to be propagated when --porcelain
		hook_arg2 = "";
	if (s->relative_paths)

			die(_("interactive add failed"));
		print_commit_summary(the_repository, prefix,
{

			reflog_msg = "commit (merge)";
		} else {
	wt_status_print(&s);
	unsigned int progress_flag = 0;

		return 1;
		struct ident_split ci, ai;
		return color_parse(v, s->color_palette[slot]);
	s.verbose = verbose;
#include "log-tree.h"
	if (logfile)
				     &oid, flags);


	} else if (!stat(git_path_squash_msg(the_repository), &statbuf)) {
			struct pretty_print_context ctx = {0};
	[WT_STATUS_REMOTE_BRANCH] = "remoteBranch",
}
	int clean_message_contents = (cleanup_mode != COMMIT_MSG_CLEANUP_NONE);

}
#include "dir.h"
	 */
	else
		OPT_STRING('c', "reedit-message", &edit_message, N_("commit"), N_("reuse and edit message from specified commit")),
		die(_("unable to select a comment character that is not used\n"
		OPT_BOOL(0, "interactive", &interactive, N_("interactively add files")),
				"Author:    %.*s <%.*s>"),
		/*
		current_head = NULL;
			die(_("You are in the middle of a merge -- cannot amend."));
	[WT_STATUS_CHANGED]	  = "changed",
		else if (is_from_cherry_pick(whence))
	parse_pathspec(&s.pathspec, 0,


			       current_head, &s, &author_ident)) {
#include "refs.h"
	repo_read_index(the_repository);


	else if (is_from_cherry_pick(whence) || whence == FROM_REBASE_PICK) {
			 N_("show branch information")),
		  N_("mode"),
		dry_run = 1;
		OPT_BOOL('p', "patch", &patch_interactive, N_("interactively add changes")),
		OPT_BOOL('z', "null", &s.null_termination,
		pptr = commit_list_append(current_head, pptr);
	s->verbose = verbose;
					"If this is not correct, please remove the file\n"
	verbose = -1; /* unspecified */
			if (cleanup_mode == COMMIT_MSG_CLEANUP_SCISSORS &&
	opts.merge = 1;
	refresh_index(&the_index,

			update_main_cache_tree(WRITE_TREE_SILENT);
{
	free(name);
static const char *read_commit_message(const char *name)
	/*
		exit(128); /* We've already reported the error, finish dying */
		OPT_BOOL(0, "branch", &s.show_branch, N_("show branch information")),
		fprintf(stderr, _("Aborting commit; you did not edit the message.\n"));
	rollback_index_files();
static int edit_flag = -1; /* unspecified */
	old_display_comment_prefix = s->display_comment_prefix;
		commit_style = COMMIT_NORMAL;
		s->reference = "HEAD^1";
					git_path_cherry_pick_head(the_repository));

			strbuf_add(&date_buf, ident.tz_begin, ident.tz_end - ident.tz_begin);
{
	/* Ignore status.displayCommentPrefix: we do need comments in COMMIT_EDITMSG. */
#include "commit-reach.h"
	if (get_oid("HEAD", &oid))
					  builtin_commit_usage,
	[WT_STATUS_UNMERGED]	  = "unmerged",
			die(_("--pathspec-from-file with -a does not make sense"));
		OPT_END(),

		if (isatty(0))
	 */
		die_resolve_conflict("commit");
	    s.show_untracked_files == SHOW_NO_UNTRACKED_FILES)
		strbuf_addbuf(&sb, &message);
	if (!tree)
		f++;
	strbuf_release(&buf);
	}
			(char *)get_lock_file_path(&index_lock);

		s->rename_limit = git_config_int(k, v);
				  LOCK_DIE_ON_ERROR);
	if (!prepare_to_commit(index_file, prefix,
			return error(_("Invalid untracked files mode '%s'"), v);
}

		s->show_untracked_files = SHOW_ALL_UNTRACKED_FILES;
		       prefix, argv);
	if (run_commit_hook(use_editor, index_file, "prepare-commit-msg",
				fputs(_(empty_rebase_pick_advice), stderr);
		rollback_lock_file(&false_lock);
					"and try again.\n")
	}
		/*
		return 0;
	run_commit_hook(use_editor, get_index_file(), "post-commit", NULL);
		set_ident_var(&date, strbuf_detach(&date_buf, NULL));
	strbuf_release(&committer_ident);
	out_enc = get_commit_output_encoding();
		if (get_oid(parent, &oid)) {

		      "new_index file. Check that disk is not full and quota is\n"
			if (strbuf_read_file(&sb, git_path_squash_msg(the_repository), 0) < 0)
				ident_shown++ ? "" : "\n",
}
	 *
		argv_array_pushf(&env, "GIT_INDEX_FILE=%s", index_file);

			s.detect_rename = DIFF_DETECT_RENAME;
				die(_("updating files failed"));

	struct strbuf *buf = opt->value;
		s.prefix = prefix;
	return 0;
	[WT_STATUS_LOCAL_BRANCH]  = "localBranch",
	 * (6) update the_index the same way as (2);
static enum commit_whence whence;
	 * If the user did not give a "--[no]-ahead-behind" command
	export_one("GIT_AUTHOR_DATE", author.date_begin, author.tz_end, '@');
		strbuf_setlen(buf, 0);
	};
					"	%s\n"
		set_ident_var(&name, xmemdupz(ident.name_begin, ident.name_end - ident.name_begin));
	}
			status_printf_ln(s, GIT_COLOR_NORMAL,
					"It looks like you may be committing a cherry-pick.\n"
		die(_("unable to write new_index file"));
static int run_status(FILE *fp, const char *index_file, const char *prefix, int nowarn,
			s->detect_rename = git_config_rename(k, v);

		template_file = NULL;
};
		old_repo_index_file = the_repository->index_file;
	else if (!strcmp(untracked_files_arg, "no"))
	if (use_deferred_config && status_format == STATUS_FORMAT_UNSPECIFIED)
				  "An empty message aborts the commit.\n"), comment_line_char);
			     struct commit *current_head,
		{ OPTION_STRING, 0, "ignored", &ignored_arg,

		 * message options add their content.
	}
	} else if (logfile) {
	return git_diff_ui_config(k, v, NULL);
static void create_base_index(const struct commit *current_head)
	 */
			s->show_untracked_files = SHOW_ALL_UNTRACKED_FILES;
		if (active_cache_changed
#include "revision.h"
	}
		hook_arg1 = "message";
	struct ident_split author;
		die(_("index file corrupt"));
	}
	if (!only && !pathspec.nr) {
		}



static char *sign_commit, *pathspec_from_file;
		die(_("cannot read the index"));
		; /* default already initialized */
		ctx.output_encoding = get_commit_output_encoding();
		strbuf_addstr(buf, arg);
			if (strbuf_read_file(&sb, git_path_merge_mode(the_repository), 0) < 0)
 * and return the paths that match the given pattern in list.

				      const struct option *options,

				ident_shown++ ? "" : "\n",
	} else if (template_file) {

	p = sb->buf;
	return logmsg_reencode(commit, NULL, out_enc);
		return dry_run_commit(argc, argv, prefix, current_head, &s);
		else if (!strcmp(v, "normal"))


		OPT_BOOL(0, "ahead-behind", &s.ahead_behind_flags,
{
	}

static const char empty_cherry_pick_advice_single[] =
	 * git-completion.bash when you add new options
	free_commit_extra_headers(extra);
	if (!strcmp(k, "commit.template"))
	*buf = val;
		if (have_option_m)
	for (p = candidates; *p == ' '; p++)
	 */
			item->util = item; /* better a valid pointer than a fake one */
	if (!strcmp(k, "commit.status")) {
static const char *prepare_index(int argc, const char **argv, const char *prefix,
		argv_array_clear(&env);
	hold_lock_file_for_update(&false_lock,
	string_list_clear(&partial, 0);
	int use_deferred_config = (status_format != STATUS_FORMAT_PORCELAIN &&
		usage_with_options(builtin_status_usage, builtin_status_options);
	}
		      &s.pathspec, NULL, NULL);
	}
		if (strbuf_read_file(&sb, git_path_merge_msg(the_repository), 0) < 0)
		 * These should never fail because they come from our own
static void assert_split_ident(struct ident_split *id, const struct strbuf *buf)
	if (!strcmp(k, "status.showstash")) {
{
			    !strcmp(ignore_submodule_arg, "all"))
	 * (short, long etc.) then we inherit from the status.aheadbehind
				die(_("unable to write index file"));
}

		else if (!strcmp(v, "all"))
			 */
		 * Insert the proper subject line before other commit
		return 0;
#include "unpack-trees.h"
	argc = parse_options(argc, argv, prefix,
	if (all || (also && pathspec.nr)) {
	 *
		struct commit_extra_header **tail = &extra;


#include "commit.h"
	parse_tree(tree);
	if (!*p)
#include "config.h"
				   !s->null_termination);
	s.commit_template = 1;
		item = string_list_insert(list, ce->name);
	wt_status_collect_free_buffers(&s);
	 * Non partial, non as-is commit.
	if (write_locked_index(&the_index, &index_lock, 0))
		run_status(stdout, index_file, prefix, 0, s);
		if (whence != FROM_COMMIT) {
		rollback_lock_file(&index_lock);
 */

static int use_editor = 1, include_status = 1;
static void export_one(const char *var, const char *s, const char *e, int hack)


		;


				 parents, &oid, author_ident.buf, sign_commit,
	 * The caller should run hooks on the locked real index, and
	die(_("--author '%s' is not 'Name <email>' and matches no existing author"), name);
			 * Unless the user did explicitly request a submodule
				_("%s"
		if (!reflog_msg)
		if (whence == FROM_MERGE)
		OPT_SET_INT('s', "short", &status_format,
			ctx.output_encoding = get_commit_output_encoding();
{
	int i;

		return 0;
	 * already started.
	 */

	if (starts_with(k, "column."))
	/* Sanity check options */
		status_deferred_config.show_branch = git_config_bool(k, v);

		hook_arg1 = "commit";
		OPT_CALLBACK('m', "message", &message, N_("message"), N_("commit message"), opt_parse_m),
			int i, ita_nr = 0;
}
			die(_("invalid date format: %s"), force_date);
	 * (2) update the_index with the given paths;
	if (have_option_m && !fixup_message) {
		; /* default already initialized */
		if (buf->len)
		strbuf_complete_line(buf);
	if (!strcmp(k, "diff.renames")) {

	return 0;
		    wt_status_locate_end(sb.buf + merge_msg_start,
				N_("ok to record an empty change")),
		a = find_commit_header(author_message_buffer, "author", &len);
	const char *hook_arg2 = NULL;
		use_editor = 0;
	 * are for unmerged entries.
	if (git_env_bool(GIT_TEST_COMMIT_GRAPH, 0) &&
	email = xstrdup_or_null(getenv("GIT_AUTHOR_EMAIL"));

	struct strbuf err = STRBUF_INIT;
		die(_("Only one of --include/--only/--all/--interactive/--patch can be used."));
	for (i = 0; i < list->nr; i++) {
#include "string-list.h"
			die_errno(_("could not read log from standard input"));
		s->show_branch = status_deferred_config.show_branch;
	if (fixup_message && squash_message)
static void refresh_cache_or_die(int refresh_flags)
	if (template_untouched(&sb, template_file, cleanup_mode) && !allow_empty_message) {
	if (hack)
		clean_message_contents = 0;
			die(_("--long and -z are incompatible"));
		break; /* nothing to do */
			die(_("Cannot read index"));
		rollback_index_files();
			parent = "HEAD^1";
{
		if (!v)

	static struct wt_status s;
		OPT_GROUP(N_("Commit contents options")),
{

	}
#include "run-command.h"
	enum ahead_behind_flags ahead_behind;
		config_commit_verbose = git_config_bool_or_int(k, v, &is_bool);
	if (skip_prefix(k, "status.color.", &slot_name) ||
	}
 *
				IDENT_STRICT));
		s->show_stash = git_config_bool(k, v);
#include "gpg-interface.h"
		rollback_lock_file(&index_lock);
			die(_("You are in the middle of a rebase -- cannot amend."));
	}
			 * comparing index and parent, no matter what is
		append_merge_tag_headers(parents, &tail);
		return WT_STATUS_UPDATED;

			    STATUS_FORMAT_LONG),
	}
{
		OPT_SET_INT(0, "short", &status_format, N_("show status concisely"),
				      &sb, &ctx);
				 extra)) {
	char *m;
#include "submodule.h"
		hook_arg2 = use_message;
		if (allow_fast_forward)
		if (!lstat(p->string, &st)) {
		OPT_HIDDEN_BOOL(0, "allow-empty", &allow_empty,

		verbose = (config_commit_verbose < 0) ? 0 : config_commit_verbose;
	return 0;
		    status_format == STATUS_FORMAT_UNSPECIFIED)
		OPT_BOOL(0, "status", &include_status, N_("include status in commit message template")),
			  const struct commit *current_head, struct wt_status *s)
		s->show_ignored_mode = SHOW_NO_IGNORED;
		else
		      "not exceeded, and then \"git restore --staged :/\" to recover."));
		if (interactive_add(argc, argv, prefix, patch_interactive) != 0)
	if (file_exists(git_path_merge_head(the_repository)))

	if (argc == 2 && !strcmp(argv[1], "-h"))
			return config_error_nonbool(k);
		err = commit_lock_file(&index_lock);
		} else
		exit(1);
	if (use_message) {
	s->display_comment_prefix = 1;
	if ((intptr_t)rename_score_arg != -1) {
		author_message_buffer = read_commit_message(author_message);
		if (!stat(git_path_merge_mode(the_repository), &statbuf)) {

	if (!strcmp(k, "commit.gpgsign")) {
		if (ce->ce_flags & CE_UPDATE)
	struct stat statbuf;
	else if (!strcmp(untracked_files_arg, "all"))
	if (s.relative_paths)
				  " Lines starting\nwith '%c' will be ignored, and an empty"
	 *
		hook_arg1 = "message";
static int author_date_is_interesting(void)
{
			if (candidate)
		OPT_BOOL(0, "show-stash", &s.show_stash,
	int err = 0;
		return 0;
	/*
	if (amend && !no_post_rewrite) {
	av[++ac] = NULL;
{
	}
#include "cache-tree.h"
		    || !cache_tree_fully_valid(active_cache_tree))
		strbuf_release(&m);
		else
	 * just set the argument(s) to the prepare-commit-msg hook.
		if (interactive)
		unsigned int flags = 0;
				    &err)) {
	if (use_deferred_config &&
			s.rename_score = parse_rename_score(&rename_score_arg);
		hold_locked_index(&index_lock, LOCK_DIE_ON_ERROR);
			 * submodules which were manually staged, which would
		rollback_index_files();
				N_("ok to record a change with an empty message")),

	index_file = prepare_index(argc, argv, prefix, current_head, 1);
		OPT_PATHSPEC_FILE_NUL(&pathspec_file_nul),
	handle_untracked_files_arg(s);
	status_format = STATUS_FORMAT_NONE; /* Ignore status.short */
	if (force_date) {
	if (f > 1)
out:
static int parse_force_date(const char *in, struct strbuf *out)
		die(_("No paths with --include/--only does not make sense."));
		OPT_BOOL('e', "edit", &edit_flag, N_("force edit of commit")),
static void handle_untracked_files_arg(struct wt_status *s)
			/*
static enum {
			 N_("compute full ahead/behind values")),

				show_ident_date(&ai, DATE_MODE(NORMAL)));


		struct pretty_print_context ctx = {0};
	unlink(git_path_merge_head(the_repository));
	}
	export_one("GIT_AUTHOR_NAME", author.name_begin, author.name_end, 0);
			status_printf_ln(s, GIT_COLOR_NORMAL,
		clear_mailmap(&mailmap);
	return author_message || force_date;

	const char **value = opt->value;
		 * Re-read the index as pre-commit hook could have updated it,
	if (update_main_cache_tree(0)) {
					: "commit";
		{ OPTION_STRING, 'S', "gpg-sign", &sign_commit, N_("key-id"),
		}
static void determine_author_info(struct strbuf *author_ident)
	argc = parse_and_validate_options(argc, argv, builtin_commit_options,
		if (all)
		 * then we're possibly hijacking other commit log options.

	read_mailmap(revs.mailmap, NULL);
	 * (A) if all goes well, commit the real index;
		      struct wt_status *s)
{
	if (read_cache() < 0)
	int committable;
		 * Reset the hook args to tell the real story.

	/* This checks if committer ident is explicitly given */
		return;
}
	reflog_msg = getenv("GIT_REFLOG_ACTION");
		OPT_BOOL('s', "signoff", &signoff, N_("add Signed-off-by:")),
			strbuf_addstr(&sb, skip_blank_lines(buffer + 2));
		commit_style = COMMIT_AS_IS;
		if (write_locked_index(&the_index, &index_lock, 0))
	}
#include "utf8.h"
		use_message = edit_message;
	int i, ret;
	};
	candidate = strchr(candidates, *p);
		OPT__VERBOSE(&verbose, N_("be verbose")),
}
	git_config(fn, s);
}
	}
		fprintf(s->fp, "\n");
	if (!strcmp(k, "status.aheadbehind")) {
	refresh_cache(REFRESH_QUIET);
	 * config setting.  In all other cases (and porcelain V[12] formats
	struct stat statbuf;
		*value = STATUS_FORMAT_NONE;
	[WT_STATUS_UNTRACKED]	  = "untracked",
			return 0;
		fd = -1;
	} else {

	int committable;
		s->use_color = 0;
}
					? "commit (cherry-pick)"
	else if (!strcmp(untracked_files_arg, "normal"))
		BUG("unable to parse our own ident: %s", buf->buf);
		return 0;
		if (parse_force_date(force_date, &date_buf))
	if (no_renames != -1)
				fputs(_(empty_cherry_pick_advice_multi), stderr);
		die(_("unable to write temporary index file"));
				       COMMIT_LOCK | SKIP_IF_UNCHANGED))

		return;
			die(_("unable to create temporary index"));

			     struct strbuf *author_ident)

	if (!strcmp(k, "status.displaycommentprefix")) {
	opts.fn = oneway_merge;
	return git_status_config(k, v, s);

		s->ahead_behind_flags = status_deferred_config.ahead_behind;
	setup_revisions(ac, av, &revs, NULL);
				      const char *prefix,
		{ OPTION_STRING, 0, "ignore-submodules", &ignore_submodule_arg, N_("when"),
		repo_update_index_if_able(the_repository, &index_lock);
	av[++ac] = "-i";
	 * The caller should run hooks on the locked false index, and

	case COMMIT_PARTIAL:
		int allow_fast_forward = 1;
	s->is_initial = get_oid(s->reference, &oid) ? 1 : 0;
		return 0;
/*
static const char * const builtin_status_usage[] = {
		die(_("You have nothing to amend."));
		FILE *fp;
static const char empty_cherry_pick_advice[] =
		int is_bool;
	free(date);
		f++;
		}
			die(_("cannot do a partial commit during a merge."));
	-1, /* unspecified */
		else if (cleanup_mode == COMMIT_MSG_CLEANUP_SCISSORS) {
static char *edit_message, *use_message;
	 * line argument *AND* we will print in a human-readable format
	unlink(git_path_merge_mode(the_repository));
	/*
		rollback_index_files();

}
	 * in particular), we inherit _FULL for backwards compatibility.
		while (strbuf_getline_lf(&m, fp) != EOF) {
	const char *index_file, *reflog_msg;
static int config_commit_verbose = -1; /* unspecified */
		if (ce_skip_worktree(ce))
	if (list_paths(&partial, !current_head ? NULL : "HEAD", &pathspec))
		die(_("Using both --reset-author and --author does not make sense"));

#include "diffcore.h"
	} else if (logfile && !strcmp(logfile, "-")) {
	[WT_STATUS_NOBRANCH]	  = "noBranch",
		break;
	struct commit *commit;
		string_list_clear(&s->change, 1);
			fprintf(stderr, _("(reading log message from standard input)\n"));
		      REFRESH_QUIET|REFRESH_UNMERGED|progress_flag,
	UNLEAK(sb);
		    argv[0]);
	}
	AHEAD_BEHIND_UNSPECIFIED,
		rollback_index_files();
	else if (!strcmp(ignored_arg, "no"))
		 * prepend SQUASH_MSG here if it exists and a
{

					ita_nr++;
		FREE_AND_NULL(old_index_env);
		const struct cache_entry *ce = active_cache[i];
		struct string_list_item *item;
		fp = xfopen(git_path_merge_head(the_repository), "r");
		ret = get_lock_file_path(&index_lock);
		status_format = status_deferred_config.status_format;
	const char *out_enc;
	if (verbose == -1)
	opts.head_idx = 1;
			 N_("terminate entries with NUL")),
		arg = arg + 1;
		strbuf_release(&buf);
		  N_("show untracked files, optional modes: all, normal, no. (Default: all)"),
	if (is_status)
	index_file = prepare_index(argc, argv, prefix, current_head, 0);
	s.ignore_submodule_arg = ignore_submodule_arg;
	if (force_author && renew_authorship)
			strbuf_addch(buf, '\n');
		if (!reflog_msg)

static int quiet, verbose, no_verify, allow_empty, dry_run, renew_authorship;
	}
	s.status_format = status_format;

	int ac = 0;
			die(_("malformed --author parameter"));
	/* Set up everything for writing the commit object.  This includes
	/*
		if (!current_head)
	} else if (whence == FROM_MERGE) {
	s->fp = fp;
 * The _message variables are commit names from which to take
		break; /* nothing to do */
			reflog_msg = "commit (amend)";

N_("and then use:\n"
}
	m = xcalloc(1, pattern->nr);
}
		OPT__VERBOSE(&verbose, N_("show diff in commit message template")),
		include_status = git_config_bool(k, v);
	if (interactive) {
	init_tree_desc(&t, tree->buffer, tree->size);
	strbuf_addstr(author_ident, fmt_ident(name, email, WANT_AUTHOR_IDENT, date,
static const char *logfile, *force_author;
	struct unpack_trees_options opts;
#include "column.h"
				(int)(ci.name_end - ci.name_begin), ci.name_begin,
{

	switch (commit_style) {
	wt_status_collect(s);

		f++;
	}

		int saved_errno = errno;
	free(m);
		s->use_color = saved_color_setting;
	if (edit_message)
			_("Please supply the message using either -m or -F option.\n"));
	if (status_format == STATUS_FORMAT_UNSPECIFIED)
			 * not ignore any changed submodule SHA-1s when
					  prefix, current_head, &s);
		}
		die(_("--reset-author can be used only with -C, -c or --amend."));
static void set_ident_var(char **buf, char *val)
	[WT_STATUS_ONBRANCH]	  = "branch",

		s->use_color = git_config_colorbool(k, v);
		error(_("Error building trees"));
		s->amend = 1;
					git_path_merge_head(the_repository) :
	if (!strcmp(k, "status.color") || !strcmp(k, "color.status")) {
		return 0;
		setenv(INDEX_ENVIRONMENT, the_repository->index_file, 1);
	status_init_config(&s, git_status_config);
		die(_("could not lookup commit %s"), name);
	static struct option builtin_status_options[] = {
					"and try again.\n"),
#include "rerere.h"
	 * A partial commit.
		whence = FROM_COMMIT;
	/*
	    !is_from_rebase(whence) && renew_authorship)
		  PARSE_OPT_OPTARG, NULL, (intptr_t)"all" },
			die(_("cannot do a partial commit during a rebase."));
	finalize_deferred_config(&s);
static const char *cleanup_arg;
			    whence == FROM_MERGE
		force_author = find_author_by_nickname(force_author);

		return 0;
	if (!current_head) {
		else if (status_format == STATUS_FORMAT_LONG)
		assert_split_ident(&ai, author_ident);

	if (!current_head) {
		if (old_index_env && *old_index_env)
	setenv(var, buf.buf, 1);
	 * (3) write the_index out to the real index (still locked);
	if (pathspec_from_file) {
			     builtin_status_usage, 0);
		  N_("version"), N_("machine-readable output"),
 * is not in effect here.
		  PARSE_OPT_OPTARG | PARSE_OPT_NONEG, opt_parse_rename_score },
		merge_msg_start = sb.len;


		die(_("revision walk setup failed"));
	strbuf_add(&buf, s, e - s);
		OPT_BOOL(0, "reset-author", &renew_authorship, N_("the commit is authored by me now (used with -C/-c/--amend)")),
			status_printf(s, GIT_COLOR_NORMAL,
	 * (7) write the_index out to the false index file;
		if (use_message && !strcmp(use_message, squash_message))
	if (amend) {
		return 0;
	}
static int opt_parse_porcelain(const struct option *opt, const char *arg, int unset)
	if (f || have_option_m)
			if (!c)
{
	return err;
		OPT_BOOL('z', "null", &s.null_termination,

		f++;
static void add_remove_files(struct string_list *list)
#include "cache.h"
	 * (B) on failure, rollback the real index.
		s->display_comment_prefix = old_display_comment_prefix;
			else if (whence == FROM_CHERRY_PICK_MULTI)
		}
	    write_commit_graph_reachable(the_repository->objects->odb, 0, NULL))
		return 0;
	if (split_ident_line(id, buf->buf, buf->len) || !id->date_begin)
			    git_path_commit_editmsg(), hook_arg1, hook_arg2, NULL))
	s->nowarn = nowarn;

		OPT_END()
		{ OPTION_STRING, 'u', "untracked-files", &untracked_files_arg,


		interactive = 1;

	} else if (!stat(git_path_merge_msg(the_repository), &statbuf)) {
			continue;
	discard_cache();
	}
				if (ce_intent_to_add(active_cache[i]))

N_("The previous cherry-pick is now empty, possibly due to conflict resolution.\n"
			s->show_untracked_files = SHOW_NO_UNTRACKED_FILES;
		return 0;
	add_remove_files(&partial);
		char *old_index_env = NULL, *old_repo_index_file;
static void adjust_comment_line_char(const struct strbuf *sb)
	 * refresh_flags contains REFRESH_QUIET, so the only errors
		if (rename_score_arg)
	N_("git commit [<options>] [--] <pathspec>..."),
	 * empty due to conflict resolution, which the user should okay.
"If you wish to skip this commit, use:\n"
	struct object_id oid;
			flags |= SUMMARY_SHOW_AUTHOR_DATE;
"\n"


		}

	struct strbuf sb = STRBUF_INIT;
{

		s->prefix = prefix;
			candidate = strchr(candidates, p[1]);
		if (slot < 0)
			    STATUS_FORMAT_LONG),
	add_remove_files(&partial);

	COMMIT_AS_IS = 1,

		/* end commit message options */
#include "commit-graph.h"
	NULL
	refresh_cache(REFRESH_QUIET);
	argc = parse_options(argc, argv, prefix, options, usage, 0);
			die(_("unable to write new_index file"));
	return argc;
	wt_status_collect_free_buffers(s);

		return status;

	if (s)
}
	struct string_list mailmap = STRING_LIST_INIT_NODUP;
		ret = get_lock_file_path(&index_lock);
 * Based on git-commit.sh by Junio C Hamano and Linus Torvalds
			committable = active_nr - ita_nr > 0;
		if (strbuf_read_file(&sb, git_path_squash_msg(the_repository), 0) < 0)
{
		return 0;
		int ident_shown = 0;
		return 0;
	s->status_format = status_format;
			set_ident_var(&date, strbuf_detach(&date_buf, NULL));
	} else {

	if (commit_index_files())
}
		int errors = 0;
static void determine_whence(struct wt_status *s)
#include "strbuf.h"
	if (!committable && whence != FROM_MERGE && !allow_empty &&
	}
	if (0 <= edit_flag)
			die(_("could not lookup commit %s"), fixup_message);
	 * We still need to refresh the index here.
		die("unsupported porcelain version '%s'", arg);
static int git_status_config(const char *k, const char *v, void *cb)
	if (!pattern->nr)
N_("Otherwise, please use 'git rebase --skip'\n");
		OPT_BOOL('b', "branch", &s.show_branch,
"to resume cherry-picking the remaining commits.\n"

static const char *use_message_buffer;
"\n"
	if (status_format != STATUS_FORMAT_NONE)
		exit(1);
	case COMMIT_PARTIAL:
		const char *a;
static int commit_index_files(void)

	static int no_renames = -1;
			continue;


		oidcpy(&s.oid_commit, &oid);
	else if (!sequencer_determine_whence(the_repository, &whence))
		die(_("Options --squash and --fixup cannot be used together"));

			author_message_buffer = use_message_buffer;
	strbuf_addstr(&committer_ident, git_committer_info(IDENT_STRICT));
			strbuf_addch(&date_buf, ' ');
		} else
	enum wt_status_format status_format;
		OPT_FILENAME('t', "template", &template_file, N_("use specified template file")),
		const char *exclude_gpgsig[3] = { "gpgsig", "gpgsig-sha256", NULL };
static int git_commit_config(const char *k, const char *v, void *cb)


		status_printf_ln(s, GIT_COLOR_NORMAL, "%s", ""); /* Add new line for clarity */
		committable = run_status(s->fp, index_file, prefix, 1, s);
		set_ident_var(&name, xmemdupz(ident.name_begin, ident.name_end - ident.name_begin));
			die(_("--pathspec-from-file is incompatible with --interactive/--patch"));
	 * explicit --allow-empty. In the cherry-pick case, it may be
	export_one("GIT_AUTHOR_EMAIL", author.mail_begin, author.mail_end, 0);

		if (buffer)
		return 1;
		  PARSE_OPT_OPTARG, opt_parse_porcelain },
		 */

			strbuf_addch(&date_buf, '@');
	return s->committable;

static void handle_ignored_arg(struct wt_status *s)
		if (s->detect_rename == -1)
	strbuf_addch(out, '@');
	/* This checks and barfs if author is badly specified */
	}
			status_deferred_config.status_format = STATUS_FORMAT_NONE;
		return 0;
static struct status_deferred_config {

		overlay_tree_on_index(&the_index, with_tree, max_prefix);
	enum wt_status_format *value = (enum wt_status_format *)opt->value;
	    s->ahead_behind_flags == AHEAD_BEHIND_UNSPECIFIED)
				      struct commit *current_head,
	ret = get_lock_file_path(&false_lock);
	if (!no_verify && run_commit_hook(use_editor, index_file, "pre-commit", NULL))
	if (use_editor) {
	else if (whence == FROM_MERGE)
	struct strbuf buf = STRBUF_INIT;
		}
		OPT_BOOL('a', "all", &all, N_("commit all changed files")),
	[WT_STATUS_HEADER]	  = "header",
				_("Please enter the commit message for your changes."
	char candidates[] = "#;@!$%^&|:";
	strbuf_addf(&buf, "--author=%s", name);
	}
	name = xstrdup_or_null(getenv("GIT_AUTHOR_NAME"));
		hook_arg2 = "CHERRY_PICK_HEAD";
				sb.len - merge_msg_start)

/*
int cmd_status(int argc, const char **argv, const char *prefix)
};
	}
	if ((is_from_cherry_pick(whence) || whence == FROM_REBASE_PICK) &&
static int parse_status_slot(const char *slot)
{

	static struct option builtin_commit_options[] = {
	if (use_optional_locks())
	const char *hook_arg1 = NULL;
				die(_("could not lookup commit %s"), squash_message);
	int status;
	wt_status_print(s);
	comment_line_char = *p;
	}
static int parse_and_validate_options(int argc, const char *argv[],
	int old_display_comment_prefix;
			status_deferred_config.status_format = STATUS_FORMAT_SHORT;


	commit = get_revision(&revs);

		hold_locked_index(&index_lock, LOCK_DIE_ON_ERROR);
		const char *parent = "HEAD";
				"Date:      %s"),
	if (write_locked_index(&the_index, &false_lock, 0))
	const char *index_file;
		hook_arg1 = "squash";
		 * and write it out as a tree.  We must do this before we invoke
	NULL
	 * (4) return the name of the locked index file.
	struct commit *current_head = NULL;
	strbuf_release(&author_ident);
}
	struct strbuf sb = STRBUF_INIT;
			fputs(_(empty_cherry_pick_advice), stderr);
		die(_("paths '%s ...' with -a does not make sense"),
"it empty. You can repeat your command with --allow-empty, or you can\n"
		if (write_locked_index(&the_index, &index_lock,

	if (arg != NULL && *arg == '=')
static int all, also, interactive, patch_interactive, only, amend, signoff;
				die_errno(_("could not read SQUASH_MSG"));
		else if (whence == FROM_REBASE_PICK)
		refresh_cache_or_die(refresh_flags);
	}
 */
	}
	}

	create_base_index(current_head);
	COMMIT_NORMAL,
	if (argc == 2 && !strcmp(argv[1], "-h"))
	if (strbuf_read_file(&sb, git_path_commit_editmsg(), 0) < 0) {
		if (p->util)
		OPT_BOOL(0, "ahead-behind", &s.ahead_behind_flags,
		} else /* COMMIT_MSG_CLEANUP_SPACE, that is. */
	   running hooks, writing the trees, and interacting with the user.  */
static const char *template_file;
{
}
		}
				   status_format != STATUS_FORMAT_PORCELAIN_V2 &&
		die(_("Unsupported combination of ignored and untracked-files arguments"));
		return 0;
	}
				  " message aborts the commit.\n"), comment_line_char);
	if (author_message) {
			return config_error_nonbool(k);

"remove the commit entirely with \"git reset HEAD^\".\n");
		return 0;
		s->show_branch = 0;
		strbuf_stripspace(&sb, 0);
		OPT_STRING(0, "author", &force_author, N_("author"), N_("override author for commit")),


static int have_option_m;
	}


		if (errors)
		if (parse_commit(current_head))
	s->index_file = index_file;
	 * (8) return the name of the false index file (still locked);
	date = xstrdup_or_null(getenv("GIT_AUTHOR_DATE"));
		free(max_prefix);
		int saved_color_setting;
