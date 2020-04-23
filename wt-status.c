 * Returns 1 if there are unstaged changes, 0 otherwise.
			return -1;
				branch_name = "";
		break;
{
			d = xcalloc(1, sizeof(*d));
		 * This entry is unchanged in the worktree (relative to the index).
	branch = branch_get(branch_name);
	int both_deleted = 0;
	branch = branch_get(branch_name);
			_("  (use \"git cherry-pick --abort\" to cancel the cherry-pick operation)"));
		goto conclude;
#include "dir.h"

	case 1: key = "DD"; break; /* both deleted */
	const char *branch_name;
	memset(&opt, 0, sizeof(opt));
	}
static void wt_status_collect_changed_cb(struct diff_queue_struct *q,
			strbuf_add_unique_abbrev(split[1], &oid,
#include "run-command.h"
/*
	struct strbuf buf = STRBUF_INIT;
	const char *c = color(WT_STATUS_HEADER, s);
	     ((commit = lookup_commit_reference_gently(r, &oid, 1)) != NULL &&
				i++)
static const char cut_line[] =
	int upstream_is_gone = 0;
static int maxwidth(const char *(*label)(int), int minval, int maxval)
{
	}
}
	case 2:
static void show_rebase_in_progress(struct wt_status *s,
		err = 1;
		trace2_region_enter("status", "initial", s->repo);
		d = it->util;
		switch (d->stagemask) {
	} else if (s->ahead_behind_flags == AHEAD_BEHIND_QUICK) {
	for (i = 0; i < dir.nr; i++) {
	add_head_to_pending(&rev_info);
	}

	struct strbuf cmd_stdout = STRBUF_INIT;
	for (i = 0; i < q->nr; i++) {
{
	for_each_reflog_ent("refs/stash", stash_count_refs, &stash_count);
					 s->state.onto);
			"--------------------------------------------------");
	}
	strbuf_release(&sb);
	rev.diffopt.flags.dirty_submodules = 1;
				 : _("No commits yet"));
		return NULL;
		} else {
		label_width += strlen(" ");
	strbuf_release(&pattern);
					 void *data)
			fprintf(stdout, "%s%c", d->rename_source, 0);
{
		color_fprintf_ln(s->fp, color(WT_STATUS_HEADER, s),
				else
}
	}
		sub[1] = d->new_submodule_commits ? 'C' : '.';
#define AB_DELAY_WARNING_IN_MS (2 * 1000)

	wt_longstatus_print_trailer(s);
	}
				strbuf_addch(&onebuf, '"');

	char *summary_content;
	return split_in_progress;
		const char *one;

	GIT_COLOR_GREEN,  /* WT_STATUS_LOCAL_BRANCH */
{
			strbuf_setlen(&extra, extra.len - 2);
		 * Copy index column fields to the head column, so that our
			else
			eol_char);
			if (d->rename_status)
		if (!d->stagemask)
static int stash_count_refs(struct object_id *ooid, struct object_id *noid,
			oidcpy(&d->oid_index, &p->two->oid);
	wt_longstatus_print_updated(s);
						     p->two->path);
		struct object_id oid;
		BUG("unhandled change_type %d in wt_longstatus_print_change_data",
		string_list_clear(&yet_to_do, 0);
	trace2_data_intmax("status", s->repo, "count/untracked",
		if (s->fp != stdout)
		if (!changes)
			oidcpy(&d->oid_head, &p->one->oid);
					   DEFAULT_ABBREV));
	s->show_untracked_files = SHOW_NORMAL_UNTRACKED_FILES;

	if (!skip_prefix(message, "checkout: moving from ", &message))
	if (!both_deleted) {
		sep_char = '\0';
	rev.diffopt.ita_invisible_in_index = 1;
		status_printf_ln(s, color,
 *
			path_from = quote_path(d->rename_source, s->prefix, &buf_from);
{
		return _("both added:");
}
#include "cache.h"
		path_from = d->rename_source;
		uint64_t t_delta_in_ms = (getnanotime() - t_begin) / 1000000;
	if (0 <= pos)
		color_fprintf(s->fp, color(WT_STATUS_UPDATED, s), "%c", d->index_status);
		color_print_strbuf(s->fp, color, &sb);
		    d->index_status == DIFF_STATUS_UNMERGED)
	strbuf_release(&sb);
			d->new_submodule_commits = !oideq(&p->one->oid,
		wt_longstatus_print_stash_summary(s);
	orig_head = read_line_from_git_path("ORIG_HEAD");
		if (!del_mod_conflict)
					   DEFAULT_ABBREV));
	else if (state->rebase_in_progress || state->rebase_interactive_in_progress)
		state->detached_from =
	repo_init_revisions(s->repo, &rev, NULL);

				path, sep_char, path_from, eol_char);
		if (trail)
		BUG("unhandled unmerged status %x", d->stagemask);
	diff_setup_done(&rev_info.diffopt);
		return 0;
		c = s->color_palette[WT_STATUS_HEADER];

 *
					 _("  (use \"git merge --abort\" to abort the merge)"));
	oidcpy(&state->detached_oid, &cb.noid);
		return _("modified:");
		path = it->string;
	rev.diffopt.flags.allow_textconv = 1;
	sti = stat_tracking_info(branch, &num_ours, &num_theirs, &base,
		}
		d = it->util;
		it = string_list_insert(&s->change, p->two->path);
	struct wt_status *s,

	 *
		d = it->util;
			if (d->dirty_submodule & DIRTY_SUBMODULE_MODIFIED)

		struct string_list_item *it;
	rev_info.diffopt.flags.quick = 1;
	if (ignore_submodules) {
				_("  (use \"git commit --amend\" to amend the current commit)"));
	int worktree_changes = wt_status_check_worktree_changes(s, &dirty_submodules);

		rev_info.diffopt.flags.ignore_submodules = 1;
	case DIFF_STATUS_DELETED:
			not_deleted = 1;
	free(s->state.onto);
			state->revert_in_progress = 1;

			wt_longstatus_print_other(s, &s->ignored, _("Ignored files"), "add -f");
	t_begin = getnanotime();
	    !get_oid("REVERT_HEAD", &oid)) {
			status_printf_ln(s, color,
	return changes;

			d->index_status = p->status;
	}

	} else
		 * fields were never set.
		wt_porcelain_v2_print_other(it, s, '!');
		printf("%s\n", one);
			break;
	if (!s->branch)
		break;
	}

		case DIFF_STATUS_TYPE_CHANGED:
	if (!stat(git_path_revert_head(r), &st) &&
		 * strbuf_split_max left a space. Trim it and re-add
	case DIFF_STATUS_UNMERGED:
	if (path_from)
		break;
}
		}

	}

	     /* perhaps sha1 is a tag, try to dereference to a commit */
static void wt_shortstatus_unmerged(struct string_list_item *it,
	va_start(ap, fmt);

	int del_mod_conflict = 0;
	strbuf_release(&buf_index);
			status_printf_ln(s, color,
	return result;
	      oideq(&cb.noid, &commit->object.oid)))) {
{

			string_list_insert(&s->untracked, ent->name);
static void wt_porcelain_v2_fix_up_changed(struct string_list_item *it)
					 _("  (use \"git restore --source=%s --staged <file>...\" to unstage)"),
				status_printf_ln(s, color,

		return _("new file:");
 *    # branch.oid <commit><eol>
	struct wt_status_change_data *d = it->util;
		    color(WT_STATUS_HEADER, s),
	if (d->dirty_submodule & DIRTY_SUBMODULE_MODIFIED)

			stages[2].mode, /* stage 3 */
	strbuf_addf(&buf, "%s%s\t%s",
			state->branch = get_branch(wt, "rebase-apply/head-name");
			putchar('"');
			one = onebuf.buf;
				    t_delta_in_ms / 1000.0);
				path, eol_char);
	default:

	wt_longstatus_print_unmerged(s);
	}
		return _("added by them:");
}
			_("  (use \"git cherry-pick --skip\" to skip this patch)"));
		dir.flags |= DIR_SHOW_IGNORED_TOO;
		} else
				if (nr_ahead || nr_behind)
		wt_longstatus_print(s);
		case DIFF_STATUS_RENAMED:
		}
		 * staged to be committed), which would be really confusing.
		color_fprintf(s->fp, header_color, LABEL(N_("different")));
				 s->state.onto);
		case DIFF_STATUS_UNMERGED:
	 * for same stage.
	 * will have checked isatty on stdout). But we then do want
	case 7:
		path = quote_path(it->string, s->prefix, &buf);
		 *
		else
				 _("You are currently bisecting."));
		setup_work_tree();

{
	if (s->whence != FROM_COMMIT)
			BUG("unhandled diff-index status '%c'", p->status);


	int len;
			BUG("unhandled diff-files status '%c'", p->status);
		status_printf_ln(s, c, _("  (use \"git add/rm <file>...\" as appropriate to mark resolution)"));
	}
	len = label_width - utf8_strwidth(how);
				    const char *color)
				printf(_("nothing added to commit but untracked files present\n"));
	const char *c = "";
				BUG("multiple renames on the same target? how?");
		goto conclude;
			strbuf_addch(&sb, comment_line_char);
	for (i = 0; i < s->change.nr; i++) {

			d->index_status = DIFF_STATUS_UNMERGED;
	s->relative_paths = 1;
	struct object_id oid;
 * [<v2_changed_items>]*
			status_printf_ln(s, color,
		 * Therefore, the collect_updated_cb was never called for this
	const char *path;

				branch_name = "";
		sum |= (1 << (stage - 1));
			oidcpy(&d->oid_index, &p->one->oid);
		 */
			 */
			; /* nothing */
	if (s->verbose > 1 &&
		trace2_region_enter("status", "index", s->repo);
		 * Copy the index column fields to the worktree column so that
	if (cmd_stdout.len) {
	s->rename_limit = -1;
{
	struct lock_file lock_file = LOCK_INIT;
	repo_init_revisions(r, &rev_info, NULL);

			status_printf_ln(s, color,
		/*
	if (!target)
	} else {
		argv_array_push(&sm_summary.args, s->amend ? "HEAD^" : "HEAD");
			state->onto = get_branch(wt, "rebase-apply/onto");
}
		status_printf_ln(s, color(WT_STATUS_HEADER, s), "%s", "");
	struct object_id noid;
			_("You are currently reverting commit %s."),
		strbuf_setlen(&sb, sb.len - 1);
{
	} else if (!strcmp(sb.buf, "detached HEAD")) /* rebase */
	strbuf_add(&cb->buf, target, end - target);
	int i;
	}
	status_printf_ln(s, GIT_COLOR_NORMAL, "%s", "");
	int dirty_submodules;
	} else {
				BUG("multiple renames on the same target? how?");
		strbuf_add_commented_lines(&summary, summary_content, len);
}

			strbuf_reset(line);
	if (!s->committable) {
static void status_printf_more(struct wt_status *s, const char *color,
	if (s->state.merge_in_progress && !has_unmerged(s))
		handle_ignore_submodules_arg(&rev.diffopt, s->ignore_submodule_arg);
		status_printf_ln(s, color(WT_STATUS_HEADER, s),
	case 5:
	} else {
		it = &(s->change.items[i]);

 * Print porcelain V2 status.
	rev.diffopt.rename_limit = s->rename_limit >= 0 ? s->rename_limit : rev.diffopt.rename_limit;
			status_printf_ln(s, color,
	while (pos < istate->cache_nr) {
					   "It took %.2f seconds to compute the branch ahead/behind values.\n"
	if (shown_header)
		state->branch = get_branch(wt, "rebase-merge/head-name");
	strbuf_reset(&cb->buf);
	pos = index_name_pos(istate, it->string, strlen(it->string));
}
				   what, len, padding, one, two);
	static int label_width;
			status_printf_ln(s, color,
	const char *line, *eol;
	char submodule_token[5];
		status_printf_ln(s, color,
		if (!s->is_initial)
	GIT_COLOR_NIL,    /* WT_STATUS_ONBRANCH */
	else
			d->mode_index = p->one->mode;
		_("You are in the middle of an am session."));
				 ? _("Initial commit")
	for (i = 0; i < s->change.nr; i++) {
			state->rebase_interactive_in_progress = 1;

			wt_longstatus_print_cached_header(s);
 *   [# branch.ab +<ahead> -<behind><eol>]]
	strbuf_release(&buf);
	} else {
			   const char *email, timestamp_t timestamp, int tz,
{
		print_rebase_state(s, color);
	free(short_base);
	}
			oidcpy(&state->cherry_pick_head_oid, &null_oid);
		if (d->stagemask)

		struct tree *tree = lookup_tree(r, the_hash_algo->empty_tree);
#include "quote.h"
	} else if (state->am_in_progress)
					 _("No commands remaining."));
		}
{
	 * diff before committing.
		rev.diffopt.flags.ignore_untracked_in_submodules = 1;
{
	if (!s->show_untracked_files)
		return _("deleted by us:");
 * [<v2_untracked_items>]*
		sub[3] = '.';
	}
	for (i = 0; i < q->nr; i++) {
	va_end(ap);
			status_printf_ln(s, color,
			d->rename_source = xstrdup(p->one->path);
		return;
static void wt_status_collect_changes_initial(struct wt_status *s)
		}
	const char *target = NULL, *end;
		 * because the scan code tries really hard to not have to compute it.
		handle_ignore_submodules_arg(&rev.diffopt, "dirty");
			free((char *)base);
	if (!upstream_is_gone && !sti)
	if (is_null_oid(&s->state.revert_head_oid))
 *

	argv_array_push(&sm_summary.args, uncommitted ? "--files" : "--cached");
			continue;
	if (advice_status_u_option)

		rev.diffopt.a_prefix = "i/";
static void wt_status_collect_changes_index(struct wt_status *s)
		trace2_region_leave("status", "initial", s->repo);
 * [<v2_ignored_items>]*

	}
			/*
}
			continue;
#define LABEL(string) (s->no_gettext ? (string) : _(string))
	how = wt_status_unmerged_status_string(d->stagemask);
		d = it->util;
		return 0;
 *
	case STATUS_FORMAT_UNSPECIFIED:
			for (i = (have_done.nr > nr_lines_to_show)
			d->dirty_submodule = p->two->dirty_submodule;
	wt_status_check_bisect(NULL, state);
		status_printf(s, color(WT_STATUS_HEADER, s), "%s", "");
	case WT_STATUS_CHANGED:
{
	const struct cache_entry *ce;
 * Convert various submodule status values into a

			status_printf_ln(s, GIT_COLOR_NORMAL, "%s", "");

		/* Lookup stats on the upstream tracking branch, if set. */

		d = it->util;
		return _("copied:");
	target = strstr(message, " to ");
		label_width = maxwidth(wt_status_diff_status_string, 'A', 'Z');
	fprintf(s->fp, "# branch.oid %s%c",
		wt_longstatus_print_trailer(s);
	}
	struct strbuf sb = STRBUF_INIT;
			 * values in these fields.
		 * A single NUL character separates them.
			s->committable = 1;
	case 3: how = "UD"; break; /* deleted by them */
	int err = 0, fd;


static char default_wt_status_colors[][COLOR_MAXLEN] = {
}
						nr_ahead, nr_behind, eol);
			 * code will output the stage values directly and not use the
		state->detached_from = xstrdup(from);
		fprintf(s->fp, "%s", trail);
	if (d->dirty_submodule & DIRTY_SUBMODULE_UNTRACKED)
	if (s->state.branch)
	}
		;
}
				Q_("Next command to do (%d remaining command):",
	refresh_index(r->index, REFRESH_QUIET, NULL, NULL, NULL);
			status_printf_ln(s, c,
	case 7: how = "UU"; break; /* both modified */
		ab_info = stat_tracking_info(branch, &nr_ahead, &nr_behind,
		}

		case DIFF_STATUS_DELETED:
static void wt_porcelain_v2_print_changed_entry(


		case DIFF_STATUS_ADDED:
			result = len;
	s->detect_rename = -1;
	comment_line_string[i] = '\0';
		case 3:
		struct string_list_item *it = &(s->change.items[i]);
	struct wt_status_change_data *d = it->util;

	strbuf_init(&cb.buf, 0);
	return c;
	} else if (!del_mod_conflict && !not_deleted) {
	if (s->verbose)
			status_printf_ln(s, c, _("  (use \"git add <file>...\" to mark resolution)"));
		/* If DIFF_STATUS_* uses outside the range [A..Z], we're in trouble */

					 _("  (use \"git restore --staged <file>...\" to unstage)"));
	}
	}
	}
static void wt_longstatus_print_tracking(struct wt_status *s)
	GIT_COLOR_RED,    /* WT_STATUS_UNTRACKED */
{
/*
	}

	/* prepend header, only if there's an actual output */
{
		case DIFF_STATUS_TYPE_CHANGED:
	    /* sha1 is a commit? match without further lookup */
					fprintf(s->fp, "# branch.ab +? -?%c",

{
	color_fprintf(s->fp, color(WT_STATUS_UNMERGED, s), "%s", how);
	if (skip_prefix(sb.buf, "refs/heads/", &branch_name))
	case DIFF_STATUS_TYPE_CHANGED:
			d->rename_source = xstrdup(p->one->path);
		} else {

{
			strbuf_reset(split[1]);
}
		label_width = maxwidth(wt_status_unmerged_status_string, 1, 7);
			d->mode_head = p->one->mode;
		wt_shortstatus_other(it, s, "!!");

	status_vprintf(s, 1, color, fmt, ap, NULL);
#include "commit.h"
				state->am_empty_patch = 1;
	return 0;
	const char *state_color = color(WT_STATUS_HEADER, s);
		branch = branch_get(branch_name);
	struct index_state *istate = s->repo->index;
		rev.diffopt.b_prefix = "w/";
	branch_name = s->branch;
	key[0] = d->index_status ? d->index_status : '.';
 *                   "(detached)" literal when detached head or
	    starts_with(line->buf, "label ") ||
		return _("deleted by them:");
	static int label_width;
	case 5: key = "DU"; break; /* deleted by us */
	if (starts_with(line->buf, "exec ") ||
		status_printf_more(s, c, "%s%.*s%s",
			dir.flags |= DIR_SHOW_IGNORED_TOO_MODE_MATCHING;
		 * output looks complete.
}
			find_unique_abbrev(&s->state.revert_head_oid,
 * are different, '?' will be substituted for the actual count.
{
		d = it->util;
	rev.diffopt.format_callback = wt_status_collect_updated_cb;
	head = read_line_from_git_path("HEAD");
			status_printf_ln(s, color,
	const char *path = NULL;
	/*
	char *one_name;

	struct strbuf buf = STRBUF_INIT;

void status_printf_ln(struct wt_status *s, const char *color,
			     oideq(&oid, &state->detached_oid);
	(*c)++;
	memset(&copts, 0, sizeof(copts));
		BUG("finalize_deferred_config() should have been called");
		/*
	case DIFF_STATUS_ADDED:
		if (read_rebase_todolist("rebase-merge/git-rebase-todo",
	switch (d->stagemask) {
		return 0;
		s->untracked_in_ms = (getnanotime() - t_begin) / 1000000;
static void show_rebase_information(struct wt_status *s,
#include "remote.h"
	static struct string_list output = STRING_LIST_INIT_DUP;
	struct wt_status_change_data *d,
			strbuf_addch(&extra, ')');
	show_rebase_information(s, color);
}
	int result = 0, i;
	if (err) {
			    const char *message, void *cb_data)
			} else if (s->state.detached_from) {
		}
		struct dir_entry *ent = dir.entries[i];
	return NULL;
	int i;
 * Turn
	struct wt_status_change_data *d;
		 *
		copts.nl = GIT_COLOR_RESET "\n";
	}
						 DEFAULT_ABBREV);
static void wt_shortstatus_other(struct string_list_item *it,
	for (i = 0; i < dir.ignored_nr; i++) {
			return 1;
		}
	struct strbuf **split;
		it = &(s->change.items[i]);

	trace2_data_intmax("status", s->repo, "count/ignored", s->ignored.nr);
		status_printf_ln(s, GIT_COLOR_NORMAL, _("Untracked files not listed%s"),

					 s->state.branch,
		free(ent);
		return;
		if (s->show_ignored_mode)
{

	if (!sb.len) {
		strbuf_release(&buf);
	status_vprintf(s, 0, color, fmt, ap, NULL);
	else
	}
		color_fprintf(s->fp, header_color, LABEL(N_("No commits yet on ")));
		if (ce_intent_to_add(ce))

			status_printf_ln(s, color,
		it = &(s->change.items[i]);
				status_printf_ln(s, color, "   %s", have_done.items[i].string);
	wt_longstatus_print_trailer(s);
	s->prefix = NULL;
		if (s->hints)
	else
			for (i = 0; i < nr_lines_to_show && i < yet_to_do.nr; i++)
			status_printf_ln(s, color,
	}
}
			d->mode_head = p->one->mode;
	const char *c = color(WT_STATUS_HEADER, s);
		 * shown any submodules she manually added (and which are

		}
 *      <behind> ::= integer behind value or '?'.
	}
					on_what = _("interactive rebase in progress; onto ");
		assert(d->mode_head == 0);

		oidcpy(&d->oid_head, &d->oid_index);
 */
#include "utf8.h"
}
		if (errno == ENOENT)


			unmerged_prefix, key, submodule_token,
	}
	struct strbuf extra = STRBUF_INIT;


	if (!skip_prefix(s->branch, "refs/heads/", &branch_name))
	else
	for_each_string_list_item(it, &s->change) {
		it = &(s->change.items[i]);
			wt_shortstatus_unmerged(it, s);
		sub[2] = (d->dirty_submodule & DIRTY_SUBMODULE_MODIFIED) ? 'M' : '.';
}
	}
 *                 <eol> ::= NUL when -z,

		it = &(s->ignored.items[i]);
 */
			state->rebase_in_progress = 1;
		 */

		struct wt_status_change_data *d;

		/*
				strbuf_addch(&linebuf, ' ');
	}
	status_printf_more(s, c, "%s%.*s%s\n", how, len, padding, one);
	if (extra.len) {
		c = s->color_palette[slot];
			      LABEL(N_("HEAD (no branch)")));
		if (!d->stagemask)
	color_fprintf(s->fp, header_color, " [");
	char *two_name;
		if (has_unmerged(s))
	}

	for (i = 0; i < s->untracked.nr; i++) {
static void show_merge_in_progress(struct wt_status *s,
		 * changed submodule SHA-1s when comparing index and HEAD, no
 *    # branch.head <head><eol>
	int i;
		return NULL;
		if (yet_to_do.nr == 0)
		break;
		 * We must have data for the index column (from the
{

	struct strbuf sb = STRBUF_INIT;
	status_printf_ln(s, c, _("Changes to be committed:"));
		if (!d->worktree_status)
		status_printf_ln(s, c, _("  (use \"git rm <file>...\" to mark resolution)"));
			path_index,
			fprintf(s->fp, "%s", trail);
	key[2] = 0;
static void wt_longstatus_print_stash_summary(struct wt_status *s)
	}
				_("  (all conflicts fixed: run \"git cherry-pick --continue\")"));
		base = NULL;
	strbuf_add_commented_lines(buf, explanation, strlen(explanation));
	for (i = 0; i < s->change.nr; i++) {

 *
	static char *padding;
		case 5:
		else
	fprintf(s->fp, "%c %s%c", prefix, path, eol_char);
		return _("added by us:");
		    d->worktree_status == DIFF_STATUS_UNMERGED)

		}
			_("All conflicts fixed but you are still merging."));
	if (s->show_untracked_files) {

	opt.def = s->is_initial ? empty_tree_oid_hex() : s->reference;
			continue;
		const char *path;
	return diff_result_code(&rev_info.diffopt, result);
		else
	mask = 0;
	} else if (!num_ours) {
	if (!fclose(fp)) {
 *

					 _("You are currently splitting a commit while rebasing branch '%s' on '%s'."),

static const char *wt_status_diff_status_string(int status)
	struct string_list_item *it;
 * appropriate message.
{

	struct object_id oid;
	rev.diffopt.format_callback = wt_status_collect_changed_cb;
			strbuf_addstr(&summary, _("Submodules changed but not updated:"));
	const char *base;
		printf(" %s\n", one);
			_("You are currently cherry-picking commit %s."),
	capture_command(&sm_summary, &cmd_stdout, 1024);
		wt_porcelain_v2_print_other(it, s, '?');
static void wt_longstatus_print_other_header(struct wt_status *s,
	for (i = 0; i < s->ignored.nr; i++) {

}
			oid_to_hex(&stages[0].oid), /* stage 1 */
{

			both_deleted = 1;
				   what, len, padding, one);
		d = it->util;
	if (shown_header)
		fprintf(s->fp, "# branch.head %s%c", "(unknown)", eol);
	*dirty_submodules = 0;
	for_each_string_list_item(it, &s->untracked)
	strbuf_release(&buf_from);
	char eol_char;

			string_list_append(&output, path);
		if (has_unmerged(s))
	int i;
	}
		} else if (!s->show_untracked_files) {
			_("  (use \"git am --abort\" to restore the original branch)"));
	wt_longstatus_print_other_header(s, what, how);
 */

			 * code will output the stage values directly and not use the
	} else {
		case 0:
			status_printf_ln(s, color,
				oid_to_hex(&d->oid_head), oid_to_hex(&d->oid_index),
		die_errno("Could not open file %s for reading",
{
					on_what = _("rebase in progress; onto ");
		path = quote_path(it->string, s->prefix, &buf);
#include "worktree.h"

	if (sum != d->stagemask)
			oidcpy(&d->oid_head, &p->one->oid);
	struct rev_info rev;
			error(_("additionally, your index contains uncommitted changes."));
	if (d->worktree_status)

	va_list ap;
	s->reference = "HEAD";
			break;
			(s->is_initial ? "(initial)" : oid_to_hex(&s->oid_commit)),
				      const char *what,
			oidcpy(&d->oid_index, &p->two->oid);
	if (!strcmp(s->branch, "HEAD")) {
	s->use_color = -1;

	if (!s->hints)
			       const char *color)
				 _("You are currently bisecting, started from branch '%s'."),
			!get_oid("CHERRY_PICK_HEAD", &oid)) {
		goto got_nothing;
	int *c = cb_data;
			status_printf_ln(s, c,
	state->detached_at = !get_oid("HEAD", &oid) &&
		if (have_done.nr == 0)

#include "argv-array.h"
	copy_pathspec(&rev.prune_data, &s->pathspec);
	if (s->whence != FROM_COMMIT)
void wt_status_append_cut_line(struct strbuf *buf)
			status_printf_ln(s, color,
			status_printf_ln(s, color,
		return;
		status = d->worktree_status;
		strbuf_release(&onebuf);
	/*

	trace2_region_enter("status", "print", s->repo);
	wt_shortstatus_print(s);
		struct wt_status_change_data *d;
		if (!get_oid(split[1]->buf, &oid)) {
/*
		fprintf(s->fp, "1 %s %s %06o %06o %06o %s %s %s%c",
	s->relative_paths = 0;

	else if (state->revert_in_progress)
{
			oid_to_hex(&stages[1].oid), /* stage 2 */
		fprintf(stdout, " %s%c", it->string, 0);
	struct commit *commit;
			d->rename_score = p->score * 100 / MAX_SCORE;

	int pos, mask;
		wt_status_check_rebase(NULL, state);
	fputs(summary.buf, s->fp);
		color_fprintf(s->fp, branch_color_remote, "%d", num_theirs);
					 _("  (use \"git restore --source=%s --staged <file>...\" to unstage)"),
	int i;
				? have_done.nr - nr_lines_to_show : 0;
		if (d->dirty_submodule)
{
		if (!skip_prefix(from, "refs/tags/", &from))
		/*
			strbuf_addch(split[1], ' ');
		return;
		int mode;
			d->mode_index = p->one->mode;
		printf(" %s\n", one);
		goto conclude;
	status_printf_ln(s, c, _("  (use \"git restore <file>...\" to discard changes in working directory)"));

static void wt_longstatus_print_submodule_summary(struct wt_status *s, int uncommitted)
	if (!column_active(s->colopts))
	struct string_list_item *it,
			d->rename_score = p->score * 100 / MAX_SCORE;
	if (!sequencer_get_last_command(r, &action)) {
		show_rebase_in_progress(s, state_color);
			wt_porcelain_v2_print_changed_entry(it, s);
	wt_longstatus_print_changed(s);
	else if (!strcmp(rebase_amend, rebase_orig_head))
	}
		if (s->hints) {
	strbuf_release(&buf);
	free(head);

	what = wt_status_diff_status_string(status);

	split = strbuf_split_max(line, ' ', 3);
			shown_header = 1;
					fprintf(s->fp, "# branch.ab +%d -%d%c",
	const char *c = color(WT_STATUS_HEADER, s);
	else if (!s->is_initial) {
	rev.diffopt.detect_rename = s->detect_rename >= 0 ? s->detect_rename : rev.diffopt.detect_rename;
				else
	color_fprintf(s->fp, header_color, "]");
		if (!d->worktree_status ||
	    starts_with(line->buf, "l "))
	rev.diffopt.output_format |= DIFF_FORMAT_CALLBACK;
	struct string_list_item *it;

	if (s->null_termination) {

				      const char *how)
	 * to insert the scissor line here to reliably remove the
	if (!d->index_status) {
	} else if (wt_status_check_rebase(NULL, state)) {
					      struct string_list_item *it)
{
	}
		abbrev_sha1_in_line(&line);
{
	status_printf_ln(s, color(WT_STATUS_HEADER, s), "%s", "");
	while (sb.len && sb.buf[sb.len - 1] == '\n')
{
	const char *c = color(WT_STATUS_HEADER, s);
				 struct wt_status *s, const char *sign)

		if (hint)

	one_name = two_name = it->string;
	int result;
	rev.diffopt.rename_score = s->rename_score >= 0 ? s->rename_score : rev.diffopt.rename_score;
		err = 1;
		 * (during the index-vs-worktree scan) and so the worktree column
	va_list ap;
		    change_type);
			continue;
		struct wt_status_change_data *d;
					 "(use \"git add\" and/or \"git commit -a\")\n"));
		} else if (s->untracked.nr) {
	for_each_string_list_item(it, &s->ignored)
{

	if (!has_deleted)
	fill_directory(&dir, istate, &s->pathspec);
				 (int)(ep - cp), cp);
	FILE *fp = fopen_or_warn(git_path("%s", filename), "r");
		eol_char = '\n';
				key, submodule_token,
	result = run_diff_files(&rev_info, 0);
{
 *                           LF when NOT -z.
static char short_submodule_status(struct wt_status_change_data *d)
void wt_status_collect(struct wt_status *s)
{
		status_printf_ln(s, c, _("  (use \"git rm --cached <file>...\" to unstage)"));
	s->fp = stdout;
		rev.diffopt.a_prefix = "c/";
	if (S_ISGITLINK(d->mode_head) ||
	color_fprintf(s->fp, branch_color_local, "%s", branch_name);

	fputc(s->null_termination ? '\0' : '\n', s->fp);
			d->mode_worktree,
	va_start(ap, fmt);
 *        <head> ::= <branch_name> the current branch name or
}
			 * values in these fields.
		putchar(' ');
}
	if (!padding) {
			it->util = d;
	status_printf_ln(s, c, _("Changes not staged for commit:"));
		} else {
		show_am_in_progress(s, state_color);
}

		one = quote_path(it->string, s->prefix, &onebuf);
	if (!f) {
	const char *c = color(change_type, s);
		putchar(' ');
	if (s->hints) {
}
			       const char *fmt, ...)
			continue;
					     &base, 0, s->ahead_behind_flags);
			strbuf_addch(&onebuf, '"');
	opt.def = s->is_initial ? empty_tree_oid_hex() : s->reference;


	return 0;
	default:
		struct object_id oid;
	color_fprintf(s->fp, color(WT_STATUS_HEADER, s), "## ");
	else if ((p = strstr(s, pattern.buf)))
				i < have_done.nr;
{
	else
	case 4: key = "UA"; break; /* added by them */
		if (!d) {

		else
	}


		;
	sub[4] = 0;
}

	int num_ours, num_theirs, sti;
	if (dwim_ref(cb.buf.buf, cb.buf.len, &oid, &ref) == 1 &&
	struct branch *branch;
		}
			oidcpy(&state->revert_head_oid, &null_oid);

	struct stat st;
/*
			fprintf(s->fp, "# branch.upstream %s%c", base, eol);
		color_fprintf_ln(s->fp, color(WT_STATUS_HEADER, s), "%c",
}
				if (s->state.rebase_interactive_in_progress)
		 * fields were never set.
					on_what = HEAD_DETACHED_FROM;
	char key[3];
		if (eol)
		return _("both modified:");
	wt_longstatus_print_trailer(s);
	}
		fputs("\n", s->fp);
static void wt_porcelain_print(struct wt_status *s)

		if (!base)
		color_fprintf(s->fp, color(WT_STATUS_UNTRACKED, s), "%s", sign);
	case STATUS_FORMAT_NONE:
	 * Only pick up the rename it's relevant. If the rename is for
	     strcmp(s->ignore_submodule_arg, "all"))) {
{
}
		wt_status_collect_changes_index(s);
		strbuf_reset(&linebuf);

	 * want color, since we are going to the commit message
			status_printf_ln(s, c,
		d->mode_head = d->mode_index;
	putchar(' ');
			eol);
			else if (s->state.detached_from)
	const char *c = color(WT_STATUS_HEADER, s);
static void wt_shortstatus_status(struct string_list_item *it,
		wt_longstatus_print_submodule_summary(s, 1);  /* unstaged */

static void wt_longstatus_print_unmerged_data(struct wt_status *s,
		else
	struct wt_status *s = data;
		wt_longstatus_print_change_data(s, WT_STATUS_CHANGED, it);
				printf(_("nothing to commit\n"));
		sub[3] = (d->dirty_submodule & DIRTY_SUBMODULE_UNTRACKED) ? 'U' : '.';
			s->committable = 1;
	va_end(ap);
		return _("unmerged:");
			if (s->hints)
	}

							  &p->two->oid);

					 struct diff_options *options,
		else if (is_null_oid(&s->state.cherry_pick_head_oid))
		return;
			break;
		rev.diffopt.b_prefix = "i/";
	return diff_result_code(&rev_info.diffopt, result);
			strbuf_addch(&linebuf, comment_line_char);
{

	rev.diffopt.output_format |= DIFF_FORMAT_PATCH;
			skip_prefix(branch_name, "refs/heads/", &branch_name);
					 s->reference);
			/* mode_worktree is zero for a delete. */
		if (s->hints)
		    s->display_comment_prefix ? "#" : "",
	} else {

	free(s->state.detached_from);
		else if (s->nowarn)
	} else
	} else {
	strbuf_addbuf(&summary, &cmd_stdout);
		return;
		color_fprintf(s->fp, header_color, ", %s", LABEL(N_("behind ")));
	}
			    int gently)

static void status_vprintf(struct wt_status *s, int at_bol, const char *color,
		return '?';
		return;
			 int get_detached_from)
				yet_to_do.nr);
	}
				 s->state.branch,
	struct wt_status_change_data *d = it->util;
	GIT_COLOR_RED,    /* WT_STATUS_REMOTE_BRANCH */
 * before or after the command.
					 s->untracked_in_ms / 1000.0);
		status_printf_ln(s, c, _("  (use \"git add/rm <file>...\" to update what will be committed)"));
	if ((!s->amend && !s->nowarn && !s->workdir_dirty) ||
	if (advice_status_ahead_behind_warning &&
	struct wt_status *s)
		if (!line.len)
					     int has_dirty_submodules)
			if (ab_info > 0) {
	strbuf_release(&line);
		struct string_list_item *it;
static void wt_porcelain_v2_print_unmerged_entry(
		}
	uint64_t t_begin = getnanotime();
		return _("both deleted:");
}
		 * it after abbreviation.

		return;
	struct strbuf buf = STRBUF_INIT;
			if (*line != '\n' && *line != '\t')
		wt_longstatus_print_submodule_summary(s, 0);  /* staged */
{
		else
		status_printf_ln(s, color,
				strbuf_addstr(&extra, _("untracked content, "));
	} else {
			if (s->state.rebase_in_progress ||
			s->committable = 1;
	rev.diffopt.rename_score = s->rename_score >= 0 ? s->rename_score : rev.diffopt.rename_score;
	status_printf(s, color(WT_STATUS_HEADER, s), "\t");
		trace2_region_leave("status", "index", s->repo);
	const char *explanation = _("Do not modify or remove the line above.\nEverything below it will be ignored.");
	strbuf_release(&onebuf);
		color_fprintf(s->fp, color(WT_STATUS_CHANGED, s), "%c", d->worktree_status);
		struct wt_status_change_data *d = it->util;
static char *read_line_from_git_path(const char *filename)
				 s->commit_template
			DIR_SHOW_OTHER_DIRECTORIES | DIR_HIDE_EMPTY_DIRECTORIES;
		it = string_list_insert(&s->change, ce->name);
		} else {



	struct stat st;

		read_rebase_todolist("rebase-merge/done", &have_done);
		status_printf_ln(s, c, _("  (commit or discard the untracked or modified content in submodules)"));
 */
					 _("You are currently editing a commit during a rebase."));


 * Extract branch information from rebase/bisect
	char *head, *orig_head, *rebase_amend, *rebase_orig_head;
	skip_prefix(branch_name, "refs/heads/", &branch_name);
		break;
		free(ent);
			string_list_insert(&s->ignored, ent->name);
	if (is_index_unborn(r->index))
	return d->worktree_status;
				/* different */
}
		state->merge_in_progress = 1;
}
	case DIFF_STATUS_RENAMED:
		sub[0] = 'N';

		d->mode_worktree = d->mode_index;
	} else if (!stat(worktree_git_path(wt, "rebase-merge"), &st)) {
				_("  (run \"git revert --continue\" to continue)"));
			strbuf_addstr(&linebuf, line);
}
		const char *s = label(i);
 *      <commit> ::= the current commit hash or the the literal

{
		    dir_path_match(istate, ent, &s->pathspec, 0, NULL))
			status_printf_ln(s, color,
			changes = -1;
#define quote_path quote_path_relative
	wt_longstatus_print_trailer(s);
		break;
	if (d->rename_status == status)
	FILE *f = fopen(git_path("%s", fname), "r");
		case DIFF_STATUS_RENAMED:
		}
	if (!strcmp(cb->buf.buf, "HEAD")) {
		if (eol)
		if (!stat(worktree_git_path(wt, "rebase-apply/applying"), &st)) {

	GIT_COLOR_GREEN,  /* WT_STATUS_UPDATED */
	rev.diffopt.format_callback_data = s;
			s->committable = 1;
static void wt_porcelain_v2_print_tracking(struct wt_status *s)
			if (*one != '"' && strchr(one, ' ') != NULL) {
 * Print porcelain V2 status info for untracked and ignored entries.
}

 *  0 : no change
	clear_directory(&dir);
			state->rebase_in_progress = 1;
	string_list_clear(&output, 0);
}
{

		color_fprintf(s->fp, branch_color_local, "%d", num_ours);
			branch_status_color = color(WT_STATUS_NOBRANCH, s);
			d->rename_status = p->status;
		len = p - s + 1;
			}
 *  1 : some change but no delete
		S_ISGITLINK(d->mode_worktree)) {
	rev.diffopt.ita_invisible_in_index = 1;
	}
		strbuf_reset(&sb);
static void wt_status_collect_updated_cb(struct diff_queue_struct *q,
	wt_status_collect_changes_worktree(s);
	} /* else use prefix as per user config */
		if (strcmp(ce->name, path) || !ce_stage(ce))
	if (s->ignore_submodule_arg) {
	for (line = sb.buf; *line; line = eol + 1) {
	}

		else

			status_printf_ln(s, GIT_COLOR_NORMAL, _("No changes"));


	oidcpy(&cb->noid, noid);
		 * index-vs-worktree scan (otherwise, this entry should not be

			? _(" (use -u option to show untracked files)") : "");
		 * mode by passing a command line option we do not ignore any


		return _("deleted:");
					   "You can use '--no-ahead-behind' to avoid this.\n"),
	for (i = 0; i < istate->cache_nr; i++) {
int has_unstaged_changes(struct repository *r, int ignore_submodules)
		sub[1] = '.';
		S_ISGITLINK(d->mode_index) ||
	len = label_width - utf8_strwidth(what);
		strbuf_release(&sb);
		run_diff_files(&rev, 0);
#include "wt-status.h"
		 *
	int shown_header = 0;
/*
	}
			_("  (use \"git bisect reset\" to get back to the original branch)"));
{
	if (!l->nr)
	}

		return 0;
				status_printf_ln(s, color,
			/* Leave {mode,oid}_head zero for an add. */
			find_unique_abbrev(&s->state.cherry_pick_head_oid,
					     const char *how)
	const char *branch_status_color = color(WT_STATUS_HEADER, s);
	case 1: how = "DD"; break; /* both deleted */
					 _("You are currently editing a commit while rebasing branch '%s' on '%s'."),
	 * If we're not going to stdout, then we definitely don't
		path = quote_path(it->string, s->prefix, &buf);
			fputs("\n", s->fp);
	else {
				 stash_count);
		status_printf_ln(s, color,
			d->stagemask |= (1 << (ce_stage(ce) - 1));

#include "object.h"
};


			_("  (use \"git am --skip\" to skip this patch)"));
		if (s->hints) {

	if (!stat(worktree_git_path(wt, "BISECT_LOG"), &st)) {
		}
	free(dir.entries);
	strbuf_getline_lf(&buf, fp);
	char eol = s->null_termination ? '\0' : '\n';
			break;
}
{
	s->change.strdup_strings = 1;
					"Next commands to do (%d remaining commands):",
		print_rebase_state(s, color);

		return;
			/* Leave {mode,oid}_head zero for adds. */
			continue;
		rev_info.diffopt.flags.ignore_submodules = 1;
		if (!d) {
		color_fprintf(s->fp, header_color, LABEL(N_("ahead ")));
}
		/* print_updated() printed a header, so do we */
	if (want_color(s->use_color))
	GIT_COLOR_RED,    /* WT_STATUS_UNMERGED */
				_("  (use \"git rebase --continue\" once you are satisfied with your changes)"));

				printf(_("nothing added to commit but untracked files "
/*
	}
	}
		struct dir_entry *ent = dir.ignored[i];
	if (s->is_initial)
		else if (is_null_oid(&s->state.revert_head_oid))
			_("  (use \"git revert --abort\" to cancel the revert operation)"));
				    const char *color)
	} else {
	int changes = 0;
	sm_summary.git_cmd = 1;
	} else if (split_commit_in_progress(s)) {

		status_printf_ln(s, color,
	strbuf_release(&buf);
	one = quote_path(it->string, s->prefix, &onebuf);


	} else {

}
	strbuf_release(&twobuf);
	struct dir_struct dir;
		padding = xmallocz(label_width);
 *    <upstream> ::= the upstream branch name, when set.

	trace2_region_leave("status", "worktrees", s->repo);
	else			/* bisect */
		struct string_list_item *it;
	assert(len >= 0);
			d->mode_index = p->two->mode;


			status_printf_ln(s, color,
	assert(pos < 0);
static void wt_longstatus_print_trailer(struct wt_status *s)
		return _("unknown:");
	wt_porcelain_v2_submodule_state(d, submodule_token);
			oidcpy(&d->oid_index, &ce->oid);
#include "diffcore.h"
					   "new files yourself (see 'git help status')."),
		struct wt_status_change_data *d;
		struct wt_status_change_data *d;
	    wt_status_check_worktree_changes(s, &dirty_submodules)) {
}
		const char *on_what = _("On branch ");

		if (s->show_ignored_mode == SHOW_MATCHING_IGNORED)
	wt_longstatus_print_state(s);
	status_printf(s, color(WT_STATUS_HEADER, s), "\t");
		if (action == REPLAY_PICK) {
	}
	wt_longstatus_print_trailer(s);
static void wt_longstatus_print_state(struct wt_status *s)
		one = quote_path(it->string, s->prefix, &onebuf);
			 s->index_file);
		wt_status_get_detached_from(r, state);
	int i;
			status_printf_ln(s, color,
 */

	if (s->is_initial) {
		return 1;
}
			s->committable = 1;
static void wt_longstatus_print_change_data(struct wt_status *s,
static void abbrev_sha1_in_line(struct strbuf *line)
	trace2_region_enter("status", "untracked", s->repo);

	rev.diffopt.file = s->fp;
		 */
	pos = index_name_pos(istate, path, strlen(path));
		wt_longstatus_print_other(s, &s->untracked, _("Untracked files"), "add");
		struct wt_status_change_data *d = it->util;
				putchar('"');
				    "Your stash currently has %d entries", stash_count),
		free(summary_content);
 *
		 */
		 */
				d->rename_status, d->rename_score,
	wt_status_append_cut_line(&buf);
			}
				_("  (use \"git commit\" to conclude merge)"));
				d->worktree_status = short_submodule_status(d);
void wt_status_add_cut_line(FILE *fp)
	if(s->show_stash)
	int not_deleted = 0;
	int shown_header = 0;
	struct rev_info rev;
		wt_shortstatus_print_tracking(s);
	} else {
			oid_to_hex(&stages[2].oid), /* stage 3 */
	struct strbuf summary = STRBUF_INIT;
	if (s->state.am_empty_patch)
		color_fprintf(s->fp, branch_color_remote, "%d", num_theirs);
	if (sti < 0) {
	case 6: how = "AA"; break; /* both added */
	}

				const char *color)
#include "lockfile.h"
		int len = s ? utf8_strwidth(s) : 0;
		it = string_list_insert(&s->change, p->two->path);
			continue;
	if (s->branch) {
}
				   "%s\n", path);
	if (!head || !orig_head || !rebase_amend || !rebase_orig_head)

		wt_status_add_cut_line(s->fp);
	case STATUS_FORMAT_PORCELAIN_V2:
			status_printf_ln(s, color,
	struct rev_info rev;

	if (!uncommitted)
			it->util = d;
{
		it = &(l->items[i]);
 *
		const struct cache_entry *ce = istate->cache[i];
				on_what = _("Not currently on any branch.");
	struct wt_status_change_data *d = it->util;
		}
	repo_init_revisions(s->repo, &rev, NULL);
	struct {
			*dirty_submodules = 1;
				printf(_("no changes added to commit "
	const struct cache_entry *ce;
		}
	struct index_state *istate = s->repo->index;
		status_printf_ln(s, color,

		if (strcmp(ce->name, it->string) || !stage)
		if (s->hints)
	strbuf_release(&cb.buf);
		status_printf_ln(s, color,

/*
		status_printf_ln(s, color,

	if (s->null_termination) {
			if (!stat(worktree_git_path(wt, "rebase-apply/patch"), &st) && !st.st_size)
	}
					 , _("  (use \"git restore --staged <file>...\" to unstage)"));
	strbuf_release(&summary);
static void wt_longstatus_print_unmerged_header(struct wt_status *s)
		at_bol = 1;
	} else {
			status_printf_ln(s, color,
static int read_rebase_todolist(const char *fname, struct string_list *lines)
	if (s->show_untracked_files != SHOW_ALL_UNTRACKED_FILES)

		default:
			_("Revert currently in progress."));
	if (s->show_ignored_mode) {
	free(ref);
		status_printf_ln(s, color,
		    dir_path_match(istate, ent, &s->pathspec, 0, NULL))
		case DIFF_STATUS_COPIED:
			d->worktree_status = p->status;
static const char *wt_status_unmerged_status_string(int stagemask)
					 s->reference);
			d = xcalloc(1, sizeof(*d));
	} else if (s->state.rebase_in_progress ||
		    d->worktree_status == DIFF_STATUS_UNMERGED)
static void wt_longstatus_print_dirty_header(struct wt_status *s,
		eol_char = '\n';
				_("  (run \"git cherry-pick --continue\" to continue)"));
		status_printf_ln(s, c,
	struct branch *branch;
			status_printf_ln(s, c
		}
		status_printf_ln(s, color(WT_STATUS_HEADER, s), "%s", "");
		sub[2] = '.';
}
		one = quote_path(it->string, s->prefix, &onebuf);
		 * A single TAB separates them (because paths can contain spaces
	struct setup_revision_opt opt;
		strbuf_trim(split[1]);
 */
	       sizeof(default_wt_status_colors));
		state->cherry_pick_in_progress = 1;
		status_printf_ln(s, c, _("  (use \"git rm --cached <file>...\" to unstage)"));
					   "may speed it up, but you have to be careful not to forget to add\n"
			status_printf_ln(s, color,
	if (has_uncommitted_changes(r, ignore_submodules)) {
	strbuf_vaddf(&sb, fmt, ap);
}
	const char *how = "??";

					have_done.nr),
{
	else if (strcmp(orig_head, rebase_orig_head))

		default:
		if (!gently)
	copts.padding = 1;

			printf("%s -> ", one);
			   struct wt_status_state *state)
int require_clean_work_tree(struct repository *r,

	struct string_list_item *it,
	const char *header_color = color(WT_STATUS_HEADER, s);
	s->repo = r;
{
			wt_longstatus_print_trailer(s);
			else
		if (!strcmp(s->branch, "HEAD")) {
	if (0 <= fd)
		status_printf_ln(s, color,
		}
			status_printf_ln(s, color,
	if (!fp) {
			}
		else {


		return 'M';

	run_diff_index(&rev, 1);
		wt_longstatus_print_change_data(s, WT_STATUS_UPDATED, it);
		if (line.len && line.buf[0] == comment_line_char)
			    const char *action,
		struct string_list_item *it;
	for (i = 0; i < s->change.nr; i++) {
		 * in the list of changes)).
 *
	if (stash_count > 0)
	const char *branch_name;
			    int ignore_submodules)
	}
		split_in_progress = 1;

		else if (s->workdir_dirty) {
		if (index_name_is_other(istate, ent->name, ent->len) &&
	else
		struct string_list have_done = STRING_LIST_INIT_DUP;
	struct column_options copts;
		path = it->string;
	struct strbuf pattern = STRBUF_INIT;
	if (has_dirty_submodules)
					 &yet_to_do))
				if (s->state.detached_at)
	}

		   !stat(git_path_merge_msg(s->repo), &st)) {
}
	char *key;
	sum = 0;

		struct string_list_item *it;
		strbuf_release(&onebuf);
	for (i = 0; i < s->change.nr; i++) {
		struct wt_status_change_data *d;
		status_printf_ln(s, color, _("You have unmerged paths."));
			break;
		 * Path(s) are C-quoted if necessary. Current path is ALWAYS first.
static void wt_status_collect_untracked(struct wt_status *s)
 * Print porcelain v2 info for tracked entries with changes.
static void wt_shortstatus_print_tracking(struct wt_status *s)
			d->rename_status = p->status;
	one = quote_path(one_name, s->prefix, &onebuf);
	for (i = 0; i < s->change.nr; i++) {

 * When an upstream is set and present, the 'branch.ab' line will
	int ab_info, nr_ahead, nr_behind;
		wt_shortstatus_print(s);
		BUG("observed stagemask 0x%x != expected stagemask 0x%x", sum, d->stagemask);
			if (s->status_format == STATUS_FORMAT_SHORT)
		/*
	s->ignored.strdup_strings = 1;
			break;
	int i;
		d = s->change.items[i].util;
		assert(d->mode_worktree == 0);
	if (!s->hints)
	setup_revisions(0, NULL, &rev, &opt);
			break;
	int status;
{
			del_mod_conflict = 1;
	strbuf_release(&buf);
		if (d->rename_source)
	case DIFF_STATUS_MODIFIED:
		comment_line_string[i++] = ' ';
	if (s->display_comment_prefix) {
				_("  (fix conflicts and run \"git cherry-pick --continue\")"));
void wt_status_print(struct wt_status *s)
	s->workdir_dirty = 1;

	if (!stat(worktree_git_path(wt, "rebase-apply"), &st)) {
			  git_path("%s", fname));
		if (!shown_header) {
	rollback_lock_file(&lock_file);
}
			error("%s", hint);
		 * In -z mode, we DO NOT C-quote pathnames.  Current path is ALWAYS first.
			break;
 * If the work tree has unstaged or uncommitted changes, dies with the

	if (!sb.len)
		status_printf_ln(s, c, _("  (use \"git add <file>...\" to update what will be committed)"));
{

}

		oidcpy(&stages[stage - 1].oid, &ce->oid);
	wt_porcelain_v2_fix_up_changed(it);
			skip_prefix(from, "refs/remotes/", &from);
	}
static void wt_longstatus_print_unmerged(struct wt_status *s)
					 _("  (fix conflicts and run \"git commit\")"));
	if (d->new_submodule_commits)
	}
 * Returns 1 if there are uncommitted changes, 0 otherwise.
		case DIFF_STATUS_ADDED:
 * upstream.  When AHEAD_BEHIND_QUICK is requested and the branches
	default:

		if (d->stagemask)
		split_in_progress = !!strcmp(head, rebase_amend);
 * Fix-up changed entries before we print them.
		status_printf_ln(s, color,
{
		if (base) {
			oidcpy(&d->oid_index, &p->one->oid);
		}
	rev.diffopt.rename_limit = s->rename_limit >= 0 ? s->rename_limit : rev.diffopt.rename_limit;
		}
			d->index_status = DIFF_STATUS_ADDED;
	switch (s->status_format) {
	 * ignore it.
			wt_longstatus_print_unmerged_header(s);

	case STATUS_FORMAT_SHORT:
		const char *fmt, va_list ap, const char *trail)
		;
	rev.diffopt.flags.override_submodule_config = 1;
	if (!worktree_changes)
		 * which are not escaped and C-quoting does escape TAB characters).
			state->am_in_progress = 1;
	color_fprintf(s->fp, branch_color_remote, "%s", short_base);
		return 'm';
	for (i = minval; i <= maxval; i++) {
				/* same */

	}
	status_printf_more(s, GIT_COLOR_NORMAL, "\n");
{
	}
	int i;
	va_list ap;
		if (!strcmp(branch_name, "HEAD")) {
	struct strbuf buf = STRBUF_INIT;
		if (column_active(s->colopts)) {
	if (!what)
					 const char *color)
 *                   with no commits.
	if (!format_tracking_info(branch, &sb, s->ahead_behind_flags))
#include "refs.h"
	if (s->verbose > 1 && s->committable) {
		struct string_list_item *it;


{
		mask |= (1 << (ce_stage(ce) - 1));
		color_fprintf(s->fp, header_color, LABEL(N_("ahead ")));
				_("  (all conflicts fixed: run \"git revert --continue\")"));
				_("  (use \"git rebase --abort\" to check out the original branch)"));

		return NULL;
	GIT_COLOR_RED,    /* WT_STATUS_NOBRANCH */

			      _(action));
			error(_("cannot %s: Your index contains uncommitted changes."),
}
			status_printf_ln(s, color,
		if (t_delta_in_ms > AB_DELAY_WARNING_IN_MS) {
	memset(&dir, 0, sizeof(dir));
		if (d->rename_source) {

			 */
 *   [# branch.upstream <upstream><eol>
	}
		 * Therefore, the collect_changed_cb was never called for this entry
		size_t len;
			state->cherry_pick_in_progress = 1;
			if (d->dirty_submodule & DIRTY_SUBMODULE_UNTRACKED)
		case DIFF_STATUS_UNMERGED:
	case 1:
	strbuf_release(&cmd_stdout);

		 * We must have data for the index column (from the head-vs-index
	}
					 void *data)
}
				strbuf_addstr(&extra, _("modified content, "));
	}

	switch (stagemask) {
	    starts_with(line->buf, "x ") ||
 *
	sm_summary.no_stdin = 1;
	struct stat st;
static void print_rebase_state(struct wt_status *s,
	strbuf_release(&linebuf);
	status_printf_ln(s, c, _("Unmerged paths:"));
	if (d->index_status)
			xstrdup(find_unique_abbrev(&cb.noid, DEFAULT_ABBREV));
	 * replace with the actual stage data.
		strbuf_trim(&line);
static const char *color(int slot, struct wt_status *s)
	for (i = 0; i < s->change.nr; i++) {
	return 1;
	char *short_base;
	repo_init_revisions(r, &rev_info, NULL);
	va_start(ap, fmt);
	/*
	}
	struct object_id oid;
	}
		const char *from = ref;
	if (s->hints) {
		else
{
	int i;
		return;
					struct wt_status_state *state)
		goto got_nothing;
"------------------------ >8 ------------------------\n";
}
	}
	struct strbuf buf_index = STRBUF_INIT;
	if (!rev_info.pending.nr) {
		return;
	}
	}
					    struct string_list_item *it)
		status_printf_more(s, color(WT_STATUS_HEADER, s), "%s", extra.buf);
	argv_array_push(&sm_summary.args, "--summary-limit");
			   struct wt_status_state *state)
	s->no_gettext = 1;
{
		status_printf_more(s, color(WT_STATUS_UNTRACKED, s),
			 * Don't bother setting {mode,oid}_{head,index} since the print

}
				Q_("Last command done (%d command done):",
			break;
		status_printf_more(s, branch_status_color, "%s", on_what);
			} else {
		break;
}
 *
static void show_am_in_progress(struct wt_status *s,
{
		if (!s->state.am_empty_patch)
	rev_info.diffopt.flags.quick = 1;
		len = 0;
		}
	case STATUS_FORMAT_PORCELAIN:

	    !s->branch || strcmp(s->branch, "HEAD"))
			break;
	if (get_detached_from)
		struct wt_status_change_data *d;
			status_printf_ln(s, color,
	struct strbuf onebuf = STRBUF_INIT, twobuf = STRBUF_INIT;
			break;
	if (s->display_comment_prefix) {
	struct rev_info rev_info;
			strbuf_addstr(&extra, " (");
	rev.diffopt.rename_score = s->rename_score >= 0 ? s->rename_score : rev.diffopt.rename_score;
	if (one_name != two_name)
	wt_longstatus_print_trailer(s);
}
void wt_status_get_state(struct repository *r,
	memset(stages, 0, sizeof(stages));
static void show_bisect_in_progress(struct wt_status *s,
	fputs(buf.buf, fp);
	case 4: how = "UA"; break; /* added by them */
			status_printf_ln(s, GIT_COLOR_NORMAL,
}
	if (!padding) {
				_("  (fix conflicts and then run \"git rebase --continue\")"));
 * "pick d6a2f0303e897ec257dd0e0a39a5ccb709bc2047 some message"
{
	char sep_char, eol_char;
				_("  (use \"git rebase --skip\" to skip this patch)"));
			if (s->hints)
			_("Cherry-pick currently in progress."));
				else
	s->rename_score = -1;
static void show_cherry_pick_in_progress(struct wt_status *s,
	struct index_state *istate = s->repo->index;
				_("  (all conflicts fixed: run \"git rebase --continue\")"));
	diff_setup_done(&rev_info.diffopt);
		struct string_list_item *it;
	}

		return 0;
		 *

			fprintf(s->fp, "\n");

			d->mode_index = p->two->mode;
	if (s->submodule_summary &&
	assert(s->branch && !s->is_initial);
	s->ahead_behind_flags = AHEAD_BEHIND_UNSPECIFIED;
		}
		ce = istate->cache[pos++];
					     int *dirty_submodules)
		wt_shortstatus_other(it, s, "??");
	const char *what;
 * are printed when the '--branch' parameter is given.
}
			exit(128);
		wt_porcelain_v2_print(s);
}
	char eol_char = s->null_termination ? '\0' : '\n';
{
			base = shorten_unambiguous_ref(base, 0);
					 s->state.onto);
{
	return err;
	rev.diffopt.output_format |= DIFF_FORMAT_CALLBACK;
#include "strbuf.h"
 * Print branch information for porcelain v2 output.  These lines
	else if (starts_with(sb.buf, "refs/"))
		} else
		status_printf_ln(s, GIT_COLOR_NORMAL,
	free(dir.ignored);
	switch (status) {
		case DIFF_STATUS_MODIFIED:
}
			continue;

				branch_name = s->state.detached_from;
	} else if (!num_theirs) {
		string_list_append(lines, line.buf);
	memset(s, 0, sizeof(*s));
		show_cherry_pick_in_progress(s, state_color);
}
		if (d->stagemask)
			if (s->hints)
#include "column.h"
	}
				strbuf_addbuf(line, split[i]);
	trace2_data_intmax("status", s->repo, "count/changed", s->change.nr);

	int i;

		 * scan).
{
{
}
	struct child_process sm_summary = CHILD_PROCESS_INIT;
	struct strbuf linebuf = STRBUF_INIT;
				d->mode_head, d->mode_index, d->mode_worktree,
 */
 *                   "(unknown)" when something is wrong.

			if (s->state.rebase_in_progress ||
		 */
		BUG("unhandled unmerged status %x", stagemask);
 conclude:
			if (s->hints)
{
		path_index = it->string;
		}
{
		handle_ignore_submodules_arg(&rev.diffopt, s->ignore_submodule_arg);
		else {
{
			_("The current patch is empty."));
	trace2_region_leave("status", "untracked", s->repo);
	}
		if (uncommitted)
		label_width += strlen(" ");
	return 0;


	case STATUS_FORMAT_LONG:


		if (!d->worktree_status ||
static char *get_branch(const struct worktree *wt, const char *path)
 * The end-of-line is defined by the -z flag.
				_("  (fix conflicts and run \"git revert --continue\")"));
			for (i = 0; split[i]; i++)
		dir.untracked = istate->untracked;
		comment_line_string[i++] = comment_line_char;
		if (!d->index_status ||
{
		return 0;
	if (for_each_reflog_ent_reverse("HEAD", grab_1st_switch, &cb) <= 0) {
	strbuf_release(&onebuf);

		switch (p->status) {
		error(_("cannot %s: You have unstaged changes."), _(action));
	s->show_branch = -1;  /* unspecified */
static void wt_porcelain_v2_print_other(
	int i, dirty_submodules;
	short_base = shorten_unambiguous_ref(base, 0);
		case DIFF_STATUS_DELETED:
	if (starts_with(s, pattern.buf + 1))
			if (d->new_submodule_commits)

		if (!shown_header) {
			    int ignore_submodules,
	struct wt_status *s)
		status_printf_ln(s, color,
}
			    const char *hint,
	static char *padding;
	} else
{
		 * entry (during the head-vs-index scan) and so the head column
	if (s->display_comment_prefix)
			fprintf(s->fp, "# branch.head %s%c", branch_name, eol);
	if (s->ignore_submodule_arg) {
		status_printf_ln(s, color,
	if (!d->worktree_status) {
	const char *p;

static int split_commit_in_progress(struct wt_status *s)
				 Q_("Your stash currently has %d entry",
	struct strbuf buf_from = STRBUF_INIT;
{
				 _("You are currently rebasing."));
	strbuf_release(&buf);
		eol = strchr(line, '\n');
}
 * fixed-length string of characters in the buffer provided.
	if (s->hints) {
			if (d->rename_status)
			strbuf_addf(&sb, _("\n"
		fprintf(stdout, "%s%c", it->string, 0);
	if (!stat(git_path_merge_head(r), &st)) {
{
{
	s->show_stash = 0;
	int i;
		if (d->new_submodule_commits || d->dirty_submodule) {

		show_bisect_in_progress(s, state_color);
		}
			d->mode_worktree = p->two->mode;
			/* Leave {mode,oid}_index zero for a delete. */
			if (have_done.nr > nr_lines_to_show && s->hints)
		add_pending_object(&rev_info, &tree->object, "");
	 * for the head and index columns during the scans and
				   const char *color)
			_("  (use \"git revert --skip\" to skip this patch)"));
					 _("It took %.2f seconds to enumerate untracked files. 'status -uno'\n"


	const char *path_index = NULL;
size_t wt_status_locate_end(const char *s, size_t len)
 *
	else if (!s->is_initial) {
{
				strbuf_addch(&sb, ' ');

	else
		strbuf_addstr(&summary, "\n\n");
	switch (change_type) {

		color_fprintf(s->fp, header_color, LABEL(N_("behind ")));
	const char *path_from = NULL;
					 "and use \"git add\" to track)\n"));
	} else
		struct strbuf onebuf = STRBUF_INIT;
	}
 * [<v2_branch>]
			status_printf_ln(s, c, _("  (use \"git add/rm <file>...\" as appropriate to mark resolution)"));
#include "diff.h"
			   s->untracked.nr);
	struct strbuf buf = STRBUF_INIT;
		return;
			d->mode_index = ce->ce_mode;
		if (state->rebase_interactive_in_progress) {
	rev.diffopt.close_file = 0;


 */
	for (cp = sb.buf; (ep = strchr(cp, '\n')) != NULL; cp = ep + 1)
	 * Note that this is a last-one-wins for each the individual
	}
	for (i = 0; i < s->change.nr; i++) {
static void wt_shortstatus_print(struct wt_status *s)
	if (s->null_termination) {
		color_fprintf(s->fp, color(WT_STATUS_NOBRANCH, s), "%s",
		d = it->util;
		else
}
		status_printf_ln(s, c, _("Changes to be committed:"));
	struct strbuf line = STRBUF_INIT;
int wt_status_check_rebase(const struct worktree *wt,
	if (s->show_branch)
			else
		/*

	char prefix)
}
	int stash_count = 0;
	struct setup_revision_opt opt;
	if (s->hints)

				branch_name = s->state.detached_from;
}

{
	if (state->merge_in_progress) {
static int wt_status_check_worktree_changes(struct wt_status *s,

	case 2: how = "AU"; break; /* added by us */
conclude:
				_("  (Once your working directory is clean, run \"git rebase --continue\")"));
		fprintf(stdout, "%s %s%c", sign, it->string, 0);
	wt_porcelain_v2_submodule_state(d, submodule_token);
	va_end(ap);
#include "sequencer.h"
		repo_update_index_if_able(r, &lock_file);
			if (s->hints)
	wt_status_get_state(s->repo, &s->state, s->branch && !strcmp(s->branch, "HEAD"));

			} else if (!ab_info) {
/*
	 */
 * into



	int result;
	if (!s->branch)
		struct strbuf onebuf = STRBUF_INIT;
	strbuf_list_free(split);
	struct stat st;
		}
					_("  (see more in file %s)"), git_path("rebase-merge/done"));
		strbuf_release(&cb.buf);
		status_printf_more(s, c, "%s%.*s%s -> %s",
		rev_info.diffopt.flags.override_submodule_config = 1;
					     int has_deleted,
 */
		    color(WT_STATUS_UNTRACKED, s));
void status_printf(struct wt_status *s, const char *color,
		/* TRANSLATORS: the action is e.g. "pull with rebase" */
			const char *fmt, ...)
{
	 * file (and even the "auto" setting won't work, since it
		strbuf_release(&buf);
}
	rebase_orig_head = read_line_from_git_path("rebase-merge/orig-head");
	memcpy(s->color_palette, default_wt_status_colors,
	for (i = 0; i < l->nr; i++) {
#include "revision.h"
static void wt_status_get_detached_from(struct repository *r,
		if (s->state.branch)


			s->hints
	two = quote_path(two_name, s->prefix, &twobuf);
			status_printf_ln(s, color,
		wt_longstatus_print_trailer(s);
					 struct diff_options *options,
		show_revert_in_progress(s, state_color);
	int len;
	status_printf_ln(s, c, "%s:", what);

		 */
				status_printf_ln(s, color, "   %s", yet_to_do.items[i].string);
	rev.diffopt.rename_limit = s->rename_limit >= 0 ? s->rename_limit : rev.diffopt.rename_limit;
	s->untracked.strdup_strings = 1;
		goto got_nothing;
	while (pos < istate->cache_nr) {
	}
	GIT_COLOR_NORMAL, /* WT_STATUS_HEADER */
			const char *fmt, ...)
	pos = -pos-1;
			show_rebase_information(s, state_color);
		case DIFF_STATUS_MODIFIED:
	struct wt_status_state *state = &s->state;
		eol_char = '\0';
		switch (p->status) {
	if (s->null_termination) {
	    (oideq(&cb.noid, &oid) ||
				printf(_("nothing to commit (use -u to show untracked files)\n"));
}
		rev.diffopt.use_color = 0;
	if (s->state.rebase_interactive_in_progress) {
	if (slot == WT_STATUS_ONBRANCH && color_is_nil(c))
	return 1;
	color_fprintf(s->fp, header_color, "...");
		if (len > result)
		if (S_ISGITLINK(p->two->mode)) {
{
	s->display_comment_prefix = 0;

		 * which will complain if the index is non-empty.
		struct diff_filepair *p;
		}

		case 1:
		p = q->queue[i];
	struct wt_status_change_data *d = it->util;

		if (advice_status_u_option && 2000 < s->untracked_in_ms) {
				printf(_("nothing to commit\n"));

	rebase_amend = read_line_from_git_path("rebase-merge/amend");
			one = quote_path(d->rename_source, s->prefix, &onebuf);
		status_printf_ln(s, color,
			else
	}
	if (!s->hints)
	fclose(f);
		;		/* all set */
	if (want_color(s->use_color))
		if (index_name_is_other(istate, ent->name, ent->len) &&
		status_printf_ln(s, color,
	const char *branch_color_local = color(WT_STATUS_LOCAL_BRANCH, s);
		const char *branch_name = s->branch;
		return strbuf_detach(&buf, NULL);
		memset(padding, ' ', label_width);
 */
	trace2_region_leave("status", "print", s->repo);
	const char *branch_color = color(WT_STATUS_ONBRANCH, s);
	} else {

	s->index_file = get_index_file();
	strbuf_release(&sb);
static void wt_longstatus_print(struct wt_status *s)
		return _("renamed:");
			d->mode_worktree = p->two->mode;

 * "pick d6a2f03 some message"
 */
}
	if (state->bisect_in_progress)
		if (!stat(worktree_git_path(wt, "rebase-merge/interactive"), &st))
		if (s->state.branch)
int wt_status_check_bisect(const struct worktree *wt,
		int i;
		summary_content = strbuf_detach(&summary, &len);
		; /* fall through, no split in progress */
	const char *base;
				fprintf(s->fp, "# branch.ab +0 -0%c", eol);
	if (has_unstaged_changes(r, ignore_submodules)) {

				    const char *color)
		 * The source path is only present when necessary.

		status_printf(s, color(WT_STATUS_HEADER, s), "\t");
				d->mode_head, d->mode_index, d->mode_worktree,
	char submodule_token[5];
		status_printf_ln(s, color,
static void wt_longstatus_print_verbose(struct wt_status *s)
static void wt_porcelain_v2_submodule_state(
					"Last commands done (%d commands done):",
	argv_array_push(&sm_summary.args, "--for-status");
		struct wt_status_change_data *d;
	while (!strbuf_getline_lf(&line, f)) {
		d = s->change.items[i].util;
	    s->ahead_behind_flags == AHEAD_BEHIND_FULL) {

			else
		sub[0] = 'S';

		BUG("unhandled diff status %c", status);
			   const char *message, void *cb_data)
 * The function assumes that the line does not contain useless spaces
	struct wt_status *s = data;
	end = strchrnul(target, '\n');
	memset(&opt, 0, sizeof(opt));
			break;
	fd = repo_hold_locked_index(r, &lock_file, 0);


}
	free(orig_head);
	int split_in_progress = 0;
			it->util = d;
				strbuf_addstr(&extra, _("new commits, "));
	strbuf_addf(&pattern, "\n%c %s", comment_line_char, cut_line);
		state->bisect_in_progress = 1;

	rev.diffopt.format_callback_data = s;
	wt_status_collect_untracked(s);
		} else if (s->is_initial) {
		const char *one;

					 "present (use \"git add\" to track)\n"));
		if (d->worktree_status == DIFF_STATUS_DELETED)
	if (split[0] && split[1]) {

	case 4:
		else
			changes = 1;
		else
	i = 0;
	if (s->is_initial) {
		status_printf_ln(s, c, _("Changes not staged for commit:"));
		one_name = d->rename_source;
{
			break;
	result = run_diff_index(&rev_info, 1);
	const char *branch_name;
					 _("You are currently splitting a commit during a rebase."));
	 */
	argv_array_push(&sm_summary.args, "submodule");

		if (err)
					    int change_type,
{
static int grab_1st_switch(struct object_id *ooid, struct object_id *noid,


		ce = istate->cache[pos++];

		case DIFF_STATUS_COPIED:
					 s->state.branch,
	if (!s->hints)
	repo_init_revisions(s->repo, &rev, NULL);
		/*
				oid_to_hex(&d->oid_head), oid_to_hex(&d->oid_index),
	case WT_STATUS_UPDATED:
	}

	case 6: key = "AA"; break; /* both added */
		if (d->rename_source)
	else if (state->cherry_pick_in_progress)

	char sub[5])
		struct strbuf onebuf = STRBUF_INIT;
	} else {
		int nr_lines_to_show = 2;
				    const char *color)
	struct strbuf sb = STRBUF_INIT;
	uint64_t t_begin = 0;
				have_done.nr);
			break;
}
		fprintf(s->fp, "2 %s %s %06o %06o %06o %s %s %c%d %s%c%s%c",
	else
		state->onto = get_branch(wt, "rebase-merge/onto");
			status_printf_ln(s, color,
					_("  (use \"git rebase --edit-todo\" to view and edit)"));
	struct branch *branch;
	strbuf_commented_addf(buf, "%s", cut_line);
			    const char *email, timestamp_t timestamp, int tz,
		status = d->index_status;
	case 3: key = "UD"; break; /* deleted by them */
		it = &(s->untracked.items[i]);
	if (s->null_termination) {
	}
		 * This entry is unchanged in the index (relative to the head).
 * [<v2_unmerged_items>]*
				branch_name = s->state.onto;
				 s->state.branch);
	if (trail)

	}
	argv_array_push(&sm_summary.args, "summary");
				 _("You are currently rebasing branch '%s' on '%s'."),
	setup_standard_excludes(&dir);
	fprintf(s->fp, "%c %s %s %06o %06o %06o %06o %s %s %s %s%c",
	 * stage [123] columns in the event of multiple cache entries
static void wt_porcelain_v2_print(struct wt_status *s)
	free(s->state.branch);
	int i;
			status_printf_ln(s, color,
	case 6:
	enum replay_action action;
		strbuf_reset(&cb->buf);
	rev.diffopt.ita_invisible_in_index = 1;


}
		oidcpy(&state->revert_head_oid, &oid);
	char comment_line_string[3];
		color_print_strbuf(s->fp, color, &linebuf);
 */
		memset(padding, ' ', label_width);
	free(rebase_orig_head);
	struct grab_1st_switch_cbdata cb;
			status_printf_ln(s, color, _("No commands done."));
			   struct wt_status *s)
	}
		 * matter what is configured. Otherwise the user won't be
#include "submodule.h"
	struct string_list_item *it,
/*
		return;

				 comment_line_char);
		strbuf_remove(&sb, 0, branch_name - sb.buf);
		 * We have no head (or it's corrupt); use the empty tree,
	setup_revisions(0, NULL, &rev, NULL);
	}
	if (s->state.branch)
		if (s->amend)
		return;
	run_diff_index(&rev, 1);
		; /* NEEDSWORK: use "git reset --unresolve"??? */
				_("git-rebase-todo is missing."));
		color_fprintf(s->fp, branch_color_local, "%d", num_ours);
	s->branch = resolve_refdup("HEAD", 0, NULL, NULL);
	if (ignore_submodules)

			fprintf(s->fp, "# branch.head %s%c", "(detached)", eol);
		else

static void show_revert_in_progress(struct wt_status *s,
		}
			printf(_("nothing to commit, working tree clean\n"));
	copy_pathspec(&rev.prune_data, &s->pathspec);
						eol);
	run_diff_files(&rev, 0);
		if (*one != '"' && strchr(one, ' ') != NULL) {
/**
{
	case DIFF_STATUS_UNKNOWN:
	} stages[3];
			goto conclude;
		 * Unless the user did explicitly request a submodule ignore
			d->stagemask = unmerged_mask(s->repo->index,
				printf(_("no changes added to commit\n"));
}
	 * Disregard d.aux.porcelain_v2 data that we accumulated
static void wt_status_collect_changes_worktree(struct wt_status *s)
	struct wt_status_change_data *d = it->util;

		wt_status_collect_changes_initial(s);
}
			wt_shortstatus_status(it, s);
		color_fprintf(s->fp, header_color, LABEL(N_("gone")));
	if (!s->show_untracked_files)
		if (!strcmp(s->reference, "HEAD"))
}
static void wt_longstatus_print_other(struct wt_status *s,
	}
			shown_header = 1;

		oidcpy(&state->cherry_pick_head_oid, &oid);
	wt_longstatus_print_dirty_header(s, worktree_changes < 0, dirty_submodules);
			 * Don't bother setting {mode,oid}_{head,index} since the print
	}
				key, submodule_token,
static int has_unmerged(struct wt_status *s)
{
				 0, s->ahead_behind_flags);
		strbuf_release(&onebuf);
			/* fallthru */
		rev.diffopt.flags.override_submodule_config = 1;
		const char *one;
			break;
		sep_char = '\t';
		}
	key[1] = d->worktree_status ? d->worktree_status : '.';
	setup_revisions(0, NULL, &rev, &opt);
{
	int i;

/**
{
	if (s->show_branch)

		strbuf_release(&extra);
			skip_prefix(s->branch, "refs/heads/", &branch_name);
/*

	} else if (!stat(git_path_cherry_pick_head(r), &st) &&
			strbuf_addstr(&summary, _("Submodule changes to be committed:"));
	if (!q->nr)

		struct diff_filepair *p;
	trace2_region_enter("status", "worktrees", s->repo);
			    s->state.rebase_interactive_in_progress)
			wt_longstatus_print_tracking(s);
 *       <ahead> ::= integer ahead value or '?'.
		if (s->hints && !s->amend) {
			 struct wt_status_state *state,
		dir.flags |=
		if (!strcmp(s->reference, "HEAD"))
	const char *branch_color_remote = color(WT_STATUS_REMOTE_BRANCH, s);
}
		upstream_is_gone = 1;
	status_vprintf(s, 1, color, fmt, ap, "\n");
			wt_porcelain_v2_print_unmerged_entry(it, s);
	free(rebase_amend);
}
	wt_longstatus_print_trailer(s);
			if (!trail)

	argv_array_pushf(&sm_summary.args, "%d", s->submodule_summary);

	target += strlen(" to ");
}
				_("  (fix conflicts and then run \"git am --continue\")"));
		status_printf_more(s, branch_color, "%s\n", branch_name);
static void wt_longstatus_print_changed(struct wt_status *s)
				      struct string_list *l,
struct grab_1st_switch_cbdata {
			 struct wt_status *s)
/**

	 */
			    s->state.rebase_interactive_in_progress) {
		struct string_list yet_to_do = STRING_LIST_INIT_DUP;
		state->revert_in_progress = 1;
	else
	struct grab_1st_switch_cbdata *cb = cb_data;
	case 3:
		show_merge_in_progress(s, state_color);
		string_list_clear(&have_done, 0);
				printf(_("nothing to commit (create/copy files "
	} else if (s->committable)
	if (has_unmerged(s)) {

	return 0;
		else
	}
	GIT_COLOR_RED,    /* WT_STATUS_CHANGED */
			strbuf_release(&onebuf);
			d = xcalloc(1, sizeof(*d));
}
	struct wt_status_change_data *d = it->util;
 * be printed with the ahead/behind counts for the branch and the
			/*
 */

	if (s->null_termination)
void wt_status_collect_free_buffers(struct wt_status *s)
				one = onebuf.buf;
	return strbuf_detach(&sb, NULL);

}
			stages[1].mode, /* stage 2 */
	struct strbuf buf;
				branch_name = s->state.onto;
got_nothing:
			strbuf_add(&linebuf, line, eol - line);
	if (has_unmerged(s)) {
}
	if (s->fp != stdout) {
	int pos, stage, sum;
		wt_porcelain_print(s);
			continue;
	case DIFF_STATUS_COPIED:
	if (is_null_oid(&s->state.cherry_pick_head_oid))
}
		if (!d->index_status)
	rev.diffopt.detect_rename = s->detect_rename >= 0 ? s->detect_rename : rev.diffopt.detect_rename;
		path_index = quote_path(it->string, s->prefix, &buf_index);
		strbuf_add_unique_abbrev(&cb->buf, noid, DEFAULT_ABBREV);
{
	switch (d->stagemask) {
		stage = ce_stage(ce);
	pos = -pos-1;
			branch_name = NULL;
	status_printf_ln(s, color,
	print_columns(&output, s->colopts, &copts);
	else
	rev.diffopt.detect_rename = s->detect_rename >= 0 ? s->detect_rename : rev.diffopt.detect_rename;
		if (at_bol && s->display_comment_prefix) {

int has_uncommitted_changes(struct repository *r,
static void wt_longstatus_print_cached_header(struct wt_status *s)

				 "%s%.*s", comment_line_string,
};
		 *
	const char *c = color(WT_STATUS_UNMERGED, s);
}
		strbuf_add_unique_abbrev(&sb, &oid, DEFAULT_ABBREV);
{
	status_printf_ln(s, c, _("  (use \"git %s <file>...\" to include in what will be committed)"), how);
			stages[0].mode, /* stage 1 */
	}
		 * Note that we only have a mode field in the worktree column

		stages[stage - 1].mode = ce->ce_mode;
	case 5: how = "DU"; break; /* deleted by us */
}

	else if (!get_oid_hex(sb.buf, &oid)) {
	if (upstream_is_gone) {
		}

	const char *one, *how;
static int unmerged_mask(struct index_state *istate, const char *path)
	}
			break;
	struct strbuf onebuf = STRBUF_INIT;
	const char *cp, *ep, *branch_name;


		 * our output looks complete.
					     const char *what,


	const char *one, *two;
	return mask;
	}
		if (!ce_path_match(istate, ce, &s->pathspec, NULL))
		default:
			/* fallthru */
		if (ce_stage(ce)) {
		s->committable = 1;
		/* HEAD is relative. Resolve it to the right reflog entry. */
	struct rev_info rev_info;
		p = q->queue[i];
 *                   "(initial)" to indicate an initialized repo
		eol_char = '\0';
 * Print porcelain v2 status info for unmerged entries.
		return _("typechange:");
		padding = xmallocz(label_width);
		wt_longstatus_print_verbose(s);
	s->use_color = 0;
		it = &(s->change.items[i]);
		state->branch = get_branch(wt, "BISECT_START");
	 * the changed section and we're printing the updated section,
	copts.indent = buf.buf;
	char *ref = NULL;
void wt_status_prepare(struct repository *r, struct wt_status *s)
static void wt_longstatus_print_updated(struct wt_status *s)
{
	return len;
	if (strbuf_read_file(&sb, worktree_git_path(wt, "%s", path), 0) <= 0)

		wt_porcelain_v2_print_tracking(s);
					yet_to_do.nr),
 * -1 : has delete
	argv_array_pushf(&sm_summary.env_array, "GIT_INDEX_FILE=%s",
		if (s->display_comment_prefix) {
					on_what = HEAD_DETACHED_AT;
		status_printf_ln(s, color,
	}
	case 2: key = "AU"; break; /* added by us */
	else
		if (!d) {
	default:
	    (!s->ignore_submodule_arg ||
	case 7: key = "UU"; break; /* both modified */
		wt_longstatus_print_unmerged_data(s, it);


	char unmerged_prefix = 'u';
