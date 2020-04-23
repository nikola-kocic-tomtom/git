	     repo_refresh_and_write_index(r, REFRESH_QUIET, 0, 1,
	if (marker == '-' || marker == '+')

	strbuf_release(&s.plain);
	hunk->start = s->plain.len;
	},
		strbuf_addstr(&s->colored,
	int skip_mode_change =
			if (file_diff->hunk_nr++)
	size_t save_len = s->plain.len, i;
		splittable_into--;

		colored_cp.argv = args.argv;
		argv_array_clear(&args);
static struct patch_mode patch_mode_checkout_index = {
		   "d - do not apply this hunk or any of the later hunks in "
		 *
				i = display_hunks(s, file_diff, i);
	while (start_index < end_index) {

		 * to the file, so there are no trailing context lines).
		p = eol == pend ? pend : eol + 1;
	hunk->end = s->plain.len;


		const char *diff_filter = s->s.interactive_diff_filter;
			if (pipe_command(&cp, s->buf.buf, s->buf.len,
			char *pend;
				   hunk->end - overlap_end);
		argv_array_clear(&args);
			s->file_diff_nr++;
#include "run-command.h"

		} else if (hunk == &file_diff->head &&
	marker = '\0';
	.apply_args = { "-R", NULL },
	.edit_hunk_hint = N_("If the patch applies cleanly, the edited hunk "

		   "d - do not unstage this hunk or any of the later hunks in "
		} else if (s->answer.buf[0] == 'g') {
			      s->buf.buf);
		clear_add_i_state(&s.s);
	hunk->colored_start = s->colored.len;
						   stdin) == EOF)
{
	if (hunk_index + splittable_into < file_diff->hunk_nr)
{
			      plain[current] == '+' ?
			ALLOC_GROW(s->file_diff, s->file_diff_nr,
	va_start(ap, cp);
			ssize_t delta, int colored, struct strbuf *out)

		   "a - discard this hunk and all later hunks in the file\n"
		strbuf_addstr(&s->colored, GIT_COLOR_RESET);
				hunk_index = undecided_next;
	/*
	if (!plain->len) {
		if (!colored) {
				/*
				   file_diff->hunk_alloc);
						 "%.*s", (int)(eol - p), p);
		   "n - do not discard this hunk from worktree\n"
			if (hunk_index)

		advise(_("Your filter must maintain a one-to-one correspondence\n"
	header->extra_end = hunk->start;
	}
					return error(_("expected context line "
{
		 * - the hunk does not overlap with the already-merged hunk(s)
			if (file_diff->hunk[i].use == UNDECIDED_HUNK) {
			 */
			size_t  overlapping_line_count = header->new_offset
			setup_child_process(s, &filter_cp,
			      s->mode->is_reverse ? '+' : '-',
					    plain + hunk->start);
};
		N_("Discard deletion from index and worktree [y,n,q,a,d%s,?]? "),
		   "d - do not apply this hunk or any of the later hunks in "
		case 'y': return 1;
		argv_array_clear(&args);
				"aborted and the hunk is left unchanged.\n"));
			if (colored_eol)
	.help_patch_text =
}
	argv_array_pushv(&args, s->mode->diff_cmd);
	.help_patch_text =
		   "a - unstage this hunk and all later hunks in the file\n"
		   "n - do not stash this hunk\n"
					"Edit again (saying \"no\" discards!) "

			BUG("buffer overrun while splitting hunks");



			      "(%"PRIuMAX"/%"PRIuMAX") ",
	argv_array_pushv(&cp.args, s->mode->apply_check_args);
		return 0;
			if (header->old_count || header->new_count)
	} else
		/*
		if ((marker == '-' || marker == '+') && ch == ' ') {
			if (file_diff->hunk_nr < 2) {
			 "between its input and output lines."));
   "? - print help\n");
				return 0;
	const char *edit_hunk_hint, *help_patch_text;
	.is_reverse = 1,
			first = 0;
				if (i != hunk_index)
				break;

		strbuf_release(&s.plain);

			continue;
	if (pipe_command(&cp, s->buf.buf, s->buf.len, NULL, 0, NULL, 0))
		pipe_command(&apply_worktree, diff->buf, diff->len,
		   "q - quit; do not discard this hunk or any of the remaining "
	.diff_cmd = { "diff-index", NULL },
	file_diff->hunk_nr += splittable_into - 1;
		 */
		if (prompt_yesno(s, _("Apply them to the worktree "
		return 0;
		}
		       size_t *hunk_index, int use_all, struct hunk *merged)
		 * - the hunk is not selected for use, or
			if (merged->end != s->plain.len) {
	.apply_args = { "-R", NULL },
			else if (ch == '-')
	size_t file_diff_alloc = 0, i, color_arg_index;
	int colored = !!s->colored.len, quit = 0;
static size_t display_hunks(struct add_p_state *s,
	},
	struct hunk_header *header = &hunk->header;
struct hunk {
			if (splittable_into < 2)
	}
			return -1;

		N_("y - discard this hunk from worktree\n"
		strbuf_setlen(&s->plain, plain_len);
	if (!eol)

			    new_offset, header->new_count);
			goto next_hunk_line;
		    header->old_offset, header->old_count,
}
				color_fprintf_ln(stdout, s->s.help_color,
				   plain + overlap_end,

			file_diff->hunk->start = p - plain->buf;
		} else if (s->answer.buf[0] == 'J') {


	.apply_check_args = { NULL },
			"ones\n"
	/*
			     "will immediately be marked for applying."),
			"the file\n"),
				    != REG_NOMATCH)

	vfprintf(stderr, fmt, args);
			header->old_count = context_line_count;
		strbuf_setlen(&s->colored, colored_len);
			else
			if (p - plain->buf != file_diff->hunk->end)
	.edit_hunk_hint = N_("If the patch applies cleanly, the edited hunk "
			* sizeof(*hunk));
		unsigned long new_offset = header->new_offset;
			}
			strbuf_addstr(&s->buf, ",s");
				eol = strchrnul(p, '\n');
		if (mode_change) {
		marker = ch;
	setup_child_process(s, &check_index,
	if (!use_all && hunk->use != USE_HUNK)
			file_diff->hunk->end = hunk->end;
			if (hunk_index + 1 < file_diff->hunk_nr)
				    "apply", "--cached", reverse, NULL);
		unsigned deleted:1, mode_change:1,binary:1;
		N_("Apply deletion to index and worktree [y,n,q,a,d%s,?]? "),
	    parse_hunk_header(s, hunk) < 0)
};
				strbuf_trim_trailing_newline(&s->answer);
	if (colored) {

{
			     "will immediately be marked for stashing."),
				if (*p != '?' && !strchr(s->buf.buf, *p))

	if (i < file_diff->hunk_nr) {
				colored_current =
		if (!revision)
			     struct file_diff *file_diff)
	strbuf_reset(&s->buf);
		 */
			if (ch == ' ')
			BUG("diff contains delete *and* a mode change?!?\n%.*s",
			strbuf_addf(out, "%s\n", GIT_COLOR_RESET);
		strbuf_addchars(out, ' ',
				hunk = &merged;
			strbuf_addstr(&s->buf, ",K");

			else if (parse_hunk_header(s, hunk) < 0)
			repo_refresh_and_write_index(s->s.r, REFRESH_QUIET, 0,

			s.mode = &patch_mode_worktree_nothead;
		 */
				plain = s->plain.buf;
	    parse_range(&p, &header->new_offset, &header->new_count) < 0 ||
				- header->colored_extra_start;
	if (diff_algorithm)

		if (diff_filter) {
		if (hunk_index + 1 > file_diff->mode_change &&

}

}
			i = hunk_index - DISPLAY_HUNKS_LINES / 2;
static int parse_hunk_header(struct add_p_state *s, struct hunk *hunk)
			if (marker == '-' || marker == '+')
#include "diff.h"
		 *
	} else if (mode == ADD_P_CHECKOUT) {
		N_("y - discard this hunk from worktree\n"

			break;
		else {
		case 'n': return 0;
		if (!repo_read_index(s->s.r))
		strbuf_add(&s->colored, plain + current, eol - current);
	    parse_diff(&s, ps) < 0) {
		   "a - stage this hunk and all later hunks in the file\n"
static struct patch_mode patch_mode_add = {
		{ r }, STRBUF_INIT, STRBUF_INIT, STRBUF_INIT, STRBUF_INIT
		argv_array_push(&args,
			file_diff->hunk_nr++;
		return error(_("could not parse colored hunk header '%.*s'"),
	const char *diff_cmd[4], *apply_args[4], *apply_check_args[4];
};
	.edit_hunk_hint = N_("If the patch applies cleanly, the edited hunk "
		struct object_id oid;
		/* As a last resort, show the diff to the user */
	.diff_cmd = { "diff-index", "--cached", NULL },
				break;
			/*
	if (s->s.use_single_key) {
		const char *deleted = NULL, *mode_change = NULL;
	return 1;

		   "q - quit; do not apply this hunk or any of the remaining "
		if (read_single_character(s) == EOF)
				if (strbuf_getline(&s->answer,
}

}
	size_t extra_start, extra_end, colored_extra_start, colored_extra_end;
#include "argv-array.h"

		}
			if (file_diff->hunk[i].use == UNDECIDED_HUNK) {
	    parse_range(&p, &header->old_offset, &header->old_count) < 0 ||
		struct child_process colored_cp = CHILD_PROCESS_INIT;
	char *eol = memchr(p, '\n', s->plain.len - hunk->start);

	clear_add_i_state(&s.s);

	} else if (mode == ADD_P_WORKTREE) {
		   "a - stash this hunk and all later hunks in the file\n"
			s.mode = &patch_mode_reset_head;
	strbuf_reset(&s->buf);
static ssize_t recount_edited_hunk(struct add_p_state *s, struct hunk *hunk,
{
static int edit_hunk_loop(struct add_p_state *s,
		hunk->colored_end = colored_end;
			regex_t regex;

				continue;

			    (int)start_index);
	colored_end = hunk->colored_end;
}
	ssize_t delta;
						     (int)(hunk->end
			hunk = file_diff->hunk + file_diff->hunk_nr - 1;
	 * If the hunk header is intact, parse it, otherwise simply use the
				err(s, _("No previous hunk"));
struct hunk_header {
			header->old_count++;
			"ones\n"
			   skip_prefix(p, "new mode ", &mode_change) &&
		BUG("miscounted old_offset: %lu != %lu",
		}
		/*
				continue;
		return error(_("could not parse diff"));

		   "n - do not discard this hunk from index and worktree\n"
	*hunk_index = i;
	struct add_p_state s = {
			}
	if (discard_index(r->index) < 0 || repo_read_index(r) < 0 ||
		*p = pend;
		return 0;
		strbuf_reset(&s->buf);
				"edit again.  If all lines of the hunk are "
			if (i < file_diff->mode_change)


	/* `header` corresponds to the merged hunk */
			hunk->colored_end = colored_current;
			}
			s.mode = &patch_mode_checkout_nothead;
			strbuf_addch(out, '\n');
				fflush(stdout);
}
					  "anyway? ")) > 0) {
			"the file\n"),
		char *eol = memchr(p, '\n', pend - p);
		    < next->new_offset + merged->delta)
		/* The user aborted editing by deleting everything */
		/*
	/* non-colored shorter than colored? */
		 * Stop merging hunks when:
				 * commands shown in the prompt that are not
	cp.argv = args.argv;
		strbuf_addf(out, "@@ -%lu,%lu +%lu,%lu @@",
	.prompt_mode = {
	fputs(s->buf.buf, stdout);
	.apply_check_args = { "--cached", NULL },
				if (s->answer.len == 0)
	recolor_hunk(s, hunk);
	header->extra_start = p - s->plain.buf;
	header->old_count = header->new_count = 0;
};
			"the file\n"),
		return error(_("could not parse colored hunk header '%.*s'"),
		 * hunks (such as the diff header).
		hunk->end = current;
		else
			/*
			response = strtoul(s->answer.buf, &pend, 10);
		   "n - do not stage this hunk\n"

				file_diff->deleted = 1;
		    header->new_offset, remaining.new_offset);
	line = s->colored.buf + hunk->colored_start;
			 * lines to the `plain` strbuf.
	hunk->colored_end = s->colored.len;
			}
				- next->new_offset;
			if (deleted)
			  skip_prefix(p, "deleted file", &deleted))) {

		return 0;
			if (*pend || pend == s->answer.buf)

next_hunk_line:
			 * Start counting into how many hunks this one can be

	 */
				overlap_start = overlap_end;
			strbuf_trim(&s->answer);
		size_t next = find_next_line(&s->buf, i);
	char *p, *pend, *colored_p = NULL, *colored_pend = NULL, marker = '\0';
{
		N_("y - stage this hunk\n"
	}

	struct add_i_state s;
	.apply_check_args = { "--cached", NULL },
	struct child_process apply_index = CHILD_PROCESS_INIT;
		N_("Discard mode change from worktree [y,n,q,a,d%s,?]? "),
			- header->old_offset;

			 * address that, we temporarily append the union of the
		N_("Discard this hunk from index and worktree [y,n,q,a,d%s,?]? "),

			strbuf_trim(&s->answer);
		N_("y - discard this hunk from index and worktree\n"
		N_("y - unstage this hunk\n"
				header->new_count++;
			filter_cp.git_cmd = 0;
			    head->colored_end - first->colored_end);
		fflush(stdout);
	hunk->splittable_into = 1;
			header->new_count++;
};
			delta += hunk->header.old_count
	.diff_cmd = { "diff-index", "-R", NULL },
   "e - manually edit the current hunk\n"
	if (!skip_prefix(p, "@@ -", &p) ||
		hunk++;
	char *pend;
				empty_tree_oid_hex() : s->revision);
						       "#%d in\n%.*s"),

		header->old_count = header->new_count = context_line_count;

			merged->end = hunk->end;
				    "'old mode'?\n\n%.*s",

	 * If there was a mode change, the first hunk is a pseudo hunk that
				recount_edited_hunk(s, hunk,
			break;
		render_hunk(s, head, 0, colored, out);
			size_t overlap_end = hunk->start;

static void summarize_hunk(struct add_p_state *s, struct hunk *hunk,
	.apply_check_args = { "-R", NULL },
		header->old_count = next->old_offset + next->old_count
		eol = s->colored.buf + s->colored.len;
		ch = s->plain.buf[current];
			s.mode = &patch_mode_checkout_head;
			    first->colored_start - head->colored_start);
			strbuf_addstr(&s->buf, ",J");

}
	const char *arg;
	for (; i + 1 < file_diff->hunk_nr; i++) {
	if (!eol)
	}
}
					  "Sorry, only %d hunks available.",

	if (!file_diff->hunk_nr)
					continue;
			header->new_offset + header->new_count;
		remaining.old_count -= header->old_count;

		else if (starts_with(p, "@@ ") ||
		err(s, _("The selected hunks do not apply to the index!"));
			strbuf_addstr(&s->buf, ",j");
		*hunk = backup;
			if (file_diff->hunk_nr < 2) {
			if (pipe_command(&filter_cp,
{

		discard_index(s->s.r->index);
	.is_reverse = 1,
			}
		   "q - quit; do not discard this hunk or any of the remaining "
			file_diff->hunk + hunk_index + 1,
	size_t splittable_into;


				 * Should not happen; previous hunk did not end
	strbuf_commented_addf(&s->buf,
	return 0;
			(file_diff->hunk_nr - hunk_index - splittable_into)
				   size_t orig_old_count, size_t orig_new_count)

	}


					hunk->use = SKIP_HUNK;
		N_("y - apply this hunk to index and worktree\n"

	return 1;
	}
	size_t hunk_index = 0;
			context_line_count = 0;
			 (hunk == &file_diff->head &&
	*merged = *hunk;
		N_("Discard deletion from index and worktree [y,n,q,a,d%s,?]? "),
		/* add one split hunk */

						 (int)splittable_into);
static struct patch_mode patch_mode_checkout_nothead = {
	eol = memchr(sb->buf + offset, '\n', sb->len - offset);
		const char *p;

			 * Extend the "mode change" pseudo-hunk to include also
			 * Do *not* change `hunk`: the mode change pseudo-hunk
			 * One of the hunks was edited: the modified hunk was

	},
		N_("Discard mode change from index and worktree [y,n,q,a,d%s,?]? "),
};
		if (first) {
		N_("Discard mode change from index and worktree [y,n,q,a,d%s,?]? "),

			"the file\n")
		if (res < 1)
		for (i = hunk_index + 1; i < file_diff->hunk_nr; i++)
		fputs(s->buf.buf, stdout);
				"given an opportunity to\n"

		else
			for (; hunk_index < file_diff->hunk_nr; hunk_index++) {
		setup_child_process(s, &apply_worktree,
	/* Now find the extra text in the colored diff */
			     "will immediately be marked for discarding."),
		eol = s->plain.buf + s->plain.len;
		   "n - do not discard this hunk from worktree\n"
		color_fprintf(stdout, s->s.prompt_color,
		}
	size_t plain_len = s->plain.len, colored_len = s->colored.len;


		}
		colored_p = colored->buf;
			if (colored)
				hunk = file_diff->hunk + hunk_index;
static int merge_hunks(struct add_p_state *s, struct file_diff *file_diff,
			   hunk->end - hunk->start);
			strbuf_add(&s->plain, s->buf.buf + i, next - i);
				regerror(ret, &regex, errbuf, sizeof(errbuf));
			i = hunk_index;
static struct patch_mode patch_mode_reset_head = {
	.prompt_mode = {
			    plain->buf + file_diff->head.start);

			eol = pend;
#define DISPLAY_HUNKS_LINES 20
			     struct file_diff *file_diff, int use_all,
	.index_only = 1,
		if (!s->answer.len)
		strbuf_addf(&s->buf, "%c%2d: ", hunk->use == USE_HUNK ? '+'
				    (int)(eol - plain->buf), plain->buf);
	init_add_i_state(&s.s, r);
	}
		fputs(s->buf.buf, stdout);
			   starts_with(p, "Binary files "))
			header->new_count++;
			merged->splittable_into += hunk->splittable_into;

		BUG("looking for next line beyond buffer (%d >= %d)\n%s",

		N_("Discard this hunk from worktree [y,n,q,a,d%s,?]? "),
	remaining = hunk->header;
			hunk->splittable_into++;
		    (int)offset, (int)sb->len, sb->buf);
	render_hunk(s, hunk, 0, 0, &s->buf);
		   "d - do not apply this hunk or any of the later hunks in "
	struct hunk_header remaining, *header;
		} else if (s->answer.buf[0] == 'K') {
#include "compat/terminal.h"
	struct strbuf *plain = &s->plain, *colored = NULL;

	 * skip the hunk header).
				    s->answer.buf, errbuf);
				    (int)header->old_count,
		} else if (s->answer.buf[0] == 'e') {
	strbuf_release(&s.colored);
			header->old_offset + header->old_count;
	struct child_process apply_worktree = CHILD_PROCESS_INIT;
	}
	},

		else
			    "apply", "--check", NULL);
		if (hunk_index + 1 < file_diff->hunk_nr)
	s.revision = revision;
				quit = 1;
				err(s, _("Sorry, cannot edit this hunk"));
		else if (!strcmp(revision, "HEAD"))
	/* patch mode */
		context_line_count = 0;
			strbuf_addstr(out, s->s.fraginfo_color);
		hunk[1].header.old_offset =
			delta = 0;
		summarize_hunk(s, hunk, &s->buf);
				      _(s->mode->help_patch_text));
			while (s->answer.len == 0) {
					     (int)len, plain + overlap_start);
				- hunk->header.new_count;
	if (colored_p != colored_pend) {
		    header->new_offset, header->new_count);
		for (i = hunk_index - 1; i >= 0; i--)
			if (ch == 'q') {
		N_("Apply deletion to index and worktree [y,n,q,a,d%s,?]? "),

};
		if (ch == 'y') {
			      s->s.file_old_color :
		    hunk->use != UNDECIDED_HUNK)
	merged->colored_start = merged->colored_end = 0;
		if (hunk->splittable_into > 1)
			strbuf_add(&s->plain,
				err(s, _("Sorry, cannot split this hunk"));
			 */
static void setup_child_process(struct add_p_state *s,

		} else if (s->answer.buf[0] == '/') {
		res = capture_command(&colored_cp, colored, 0);
			prompt_mode_type = PROMPT_DELETION;
		switch (s->plain.buf[i]) {
			header->new_count = context_line_count;
			if (colored)
					break;
			color_fprintf(stdout, s->s.help_color, "%s",
		xsnprintf((char *)args.argv[color_arg_index], 8, "--color");
			return error(_("could not parse colored diff"));
			return -1;
	size_t start, end, colored_start, colored_end, splittable_into;
	strbuf_commented_addf(&s->buf, "%s", _(s->mode->edit_hunk_hint));
			}

	if (colored)
				goto soft_increment;
static struct patch_mode patch_mode_worktree_head = {
				   file_diff->hunk_alloc);
	reassemble_patch(s, file_diff, 1, &s->buf);
			 * split

   "/ - search for a hunk matching the given regex\n"
		return -1;
				goto mismatched_output;
		   "d - do not discard this hunk or any of the later hunks in "
			      s->s.context_color);



			hunk->colored_end = colored_p - colored->buf;
		} else if (s->answer.buf[0] == 'j') {
		struct hunk *hunk = file_diff->hunk + start_index++;
		} else if (hunk == &file_diff->head &&


	return orig_old_count - orig_new_count
	}
				BUG("mode change in the middle?\n\n%.*s",
	for (;;) {
			hunk = &file_diff->head;
	return 0;
			else
		N_("Unstage deletion [y,n,q,a,d%s,?]? "),
	struct hunk *hunk = file_diff->hunk + i;
			for (;;) {
			     (int)(eol - line), line);
			     (int)(eol - line), line);
	}

	va_list ap;
			if (undecided_previous >= 0)
			"the file\n"),
			if (len > merged->end - merged->start ||
			"ones\n"
   "k - leave this hunk undecided, see previous undecided hunk\n"
	.help_patch_text =
	hunk->end = end;

	while (splittable_into > 1) {
{
		strbuf_add(out, s->colored.buf + hunk->colored_start,
				err(s, _("Malformed search regexp %s: %s"),
		   "q - quit; do not apply this hunk or any of the remaining "
		 * TRANSLATORS: do not translate [y/n]
		return 0;
				if (regexec(&regex, s->buf.buf, 0, NULL, 0)
				hunk->splittable_into++;
		memmove(file_diff->hunk + hunk_index + splittable_into,
			"ones\n"
	.diff_cmd = { "diff-index", "-R", "--cached", NULL },
	 * include the newline.
	header->colored_extra_start = p + 3 - s->colored.buf;
					    diff->len, NULL, 0, NULL, 0);
					"[y/n]? "));
	.is_reverse = 1,
				return -1;
	 * trailing `NULL`.
	eol = memchr(line, '\n', s->colored.len - hunk->colored_start);
		 */
}
			hunk[1].start = current;
				if (i == file_diff->hunk_nr)
			strbuf_add(out, p, len);
static int patch_update_file(struct add_p_state *s,
/* Coalesce hunks again that were split */
	setup_child_process(s, &cp,

static size_t find_next_line(struct strbuf *sb, size_t offset)
			prompt_mode_type = PROMPT_HUNK;
			marker = *p;
		/*
	/*
			filter_cp.use_shell = 1;
		 * first line (and not a +/- one)?
	}
		int res = read_key_without_echo(&s->answer);

			    struct file_diff *file_diff, size_t start_index)
		 */
				hunk = file_diff->hunk + hunk_index;
			    : hunk->use == SKIP_HUNK ? '-' : ' ',
						    backup.header.old_count,
	if (strbuf_edit_interactively(&s->buf, "addp-hunk-edit.diff", NULL) < 0)
		} else if (p == plain->buf)
		if (hunk_index)
enum prompt_mode_type {
					     (int)(merged->end - merged->start),

static int apply_for_checkout(struct add_p_state *s, struct strbuf *diff,
		case ' ': case '\r': case '\n':
		N_("Stage this hunk [y,n,q,a,d%s,?]? ")
					 NULL, 0, NULL, 0);
					     hunk - file_diff->hunk))
{
		   "d - do not discard this hunk or any of the later hunks in "
		if (!use_all && hunk->use != USE_HUNK)
		strbuf_add(out, s->plain.buf + hunk->start,
			else
			if (!file_diff->mode_change)
#define SUMMARY_HEADER_WIDTH 20
			s.mode = &patch_mode_checkout_index;

				BUG("counts are off: %d/%d",
	if (offset >= sb->len)
		N_("Discard deletion from worktree [y,n,q,a,d%s,?]? "),
			size_t overlap_next, len, j;
	splittable_into = hunk->splittable_into;
				    (int)(eol - plain->buf), plain->buf);
			+ next->new_count - header->new_offset;
		    (int)hunk_index, (int)file_diff->hunk_nr);
	.help_patch_text =
			memset(hunk, 0, sizeof(*hunk));

#include "prompt.h"
	if (out->len - len > SUMMARY_LINE_WIDTH)
		 * Is this the first context line after a chain of +/- lines?

			if (file_diff->hunk_nr != 1)
				render_hunk(s, file_diff->hunk + i, 0, 0,
	size_t i;
				hunk->colored_start = colored_p - colored->buf;
			strbuf_addstr(&s->buf, ",e");
					colored_p - colored->buf;
		if (undecided_previous < 0 && undecided_next < 0 &&
			for (; *p; p = eol + (*eol == '\n')) {

			hunk->use = SKIP_HUNK;
		res = prompt_yesno(s, _("Your edited hunk does not apply. "

		 * Then just increment the appropriate counter and continue
	if (colored)
		   "a - discard this hunk and all later hunks in the file\n"

				ch = marker ? marker : ' ';
			for (; hunk_index < file_diff->hunk_nr; hunk_index++) {
				header->old_count++;
		   "n - do not unstage this hunk\n"
	if (s->plain.buf[hunk->start] == '@' &&

	}
	.index_only = 1,
				"(context).\n"
			"the file\n"),
		}

	for (current = hunk->start; current < hunk->end; ) {

	PROMPT_MODE_CHANGE = 0, PROMPT_DELETION, PROMPT_HUNK,
			/*
				    (int)(eol - plain->buf), plain->buf);

		   "q - quit; do not unstage this hunk or any of the remaining "
			 */
		return res;
	end = hunk->end;
				file_diff->hunk->colored_start =
			else if (0 < response && response <= file_diff->hunk_nr)
			hunk->start = p - plain->buf;
			hunk_index = i;
			len = header->colored_extra_end
			      (uintmax_t)file_diff->hunk_nr);
	}
	fputs(s->s.reset_color, stderr);


			; /* keep the rest of the file in a single "hunk" */
			   is_octal(mode_change, eol - mode_change)) {
			if (merge_hunks(s, file_diff, &i, use_all, &merged))
	.diff_cmd = { "diff-index", "-R", NULL },
{
	else if (mode == ADD_P_RESET) {
			}
		 * The program will only accept that input at this point.
		    header->old_offset, remaining.old_offset);
	.prompt_mode = {


			     "will immediately be marked for discarding."),
		   "a - apply this hunk and all later hunks in the file\n"
					    (int)overlapping_line_count,
			    (int)(eol - (plain->buf + file_diff->head.start)),
	va_end(ap);
	struct hunk *hunk = file_diff->hunk + hunk_index;
		N_("Stash mode change [y,n,q,a,d%s,?]? "),
	 * corresponds to the mode line in the header. If the user did not want
		N_("Apply mode change to index [y,n,q,a,d%s,?]? "),
				hunk->use = USE_HUNK;
			else if (p != pend)
				BUG("'new mode' without 'old mode'?\n\n%.*s",
				   plain + overlap_start, len))

	strbuf_addf(out, " -%lu,%lu +%lu,%lu ",
			 * cannot simply take the union of the ranges. To
	unsigned long old_offset, old_count, new_offset, new_count;
	char ch;
					BUG("failed to find %d context lines "
		size_t hunk_nr, hunk_alloc;
	context_line_count = 0;
		 * Consider translating (saying "no" discards!) as

			s.mode = &patch_mode_reset_nothead;
		if (colored) {
	}



			if (s->answer.len == 0) {
	.prompt_mode = {
   "s - split the current hunk into smaller hunks\n"
			"ones\n"

	for (i = 0; i < s->buf.len; ) {
			/* abandonded */
}
	struct strbuf plain, colored;
				colored_p = colored_eol + 1;
{
				merged->start = start;
		N_("Apply mode change to index and worktree [y,n,q,a,d%s,?]? "),
	/* parsed diff */
	/* Any hunk to be used? */
						       colored_current);
		fprintf(stderr, _("No changes.\n"));
		}
{
static void recolor_hunk(struct add_p_state *s, struct hunk *hunk)
	else if (binary_count == s.file_diff_nr)
	return 1;
			p = s->plain.buf + header->extra_start;
	.apply_args = { NULL },
			if (file_diff->mode_change)
			else
	.prompt_mode = {
		N_("Stage deletion [y,n,q,a,d%s,?]? "),

				err(s, _("No other hunks to goto"));
	for (;;) {
	strbuf_complete_line(plain);

	backup = *hunk;
	struct file_diff *file_diff = NULL;
		file_diff->mode_change && file_diff->hunk->use != USE_HUNK;
	header->old_count = header->new_count = 0;
				error(_("'git apply' failed"));
		if (!revision || !strcmp(revision, "HEAD"))


				/* render the hunk into a scratch buffer */

		const char *p = s->plain.buf;
	.prompt_mode = {
			if (colored)
						 _("Split into %d hunks."),
			    "%.*s\n", (int)(eol - p), p);
	.edit_hunk_hint = N_("If the patch applies cleanly, the edited hunk "

			}
		setup_child_process(s, &colored_cp, NULL);
	 */
};
		 * Was the previous line a +/- one? Alternatively, is this the
		N_("Discard this hunk from index and worktree [y,n,q,a,d%s,?]? "),
		 * Generate the hunk header dynamically, except for special
	pend = p + plain->len;
static int parse_range(const char **p,
					    (int)(hunk->end - hunk->start),
				err(s, _("No other hunks to search"));
	},
static struct patch_mode patch_mode_reset_nothead = {
	if (!skip_mode_change) {
			first = 0;
};
			continue;
	      const char *revision, const struct pathspec *ps)
		if (merged->start < hunk->start && merged->end > hunk->start) {
		BUG("invalid hunk index: %d (must be >= 0 and < %d)",
			int ret;
				err(s, Q_("Sorry, only %d hunk available.",
	struct hunk *hunk;

		setup_child_process(s, &apply_index,
		if (marker && *p != '\\')
	 * The magic constant 4 is chosen such that all patch modes

				BUG("unhandled diff marker: '%c'", ch);

	const char *plain = s->plain.buf;
			return pipe_command(&apply_worktree, diff->buf,
		if (len)
{
				return error(_("hunks do not overlap:\n%.*s\n"
	for (i = hunk->start; i < hunk->end; i = find_next_line(plain, i))
			 * Show only those lines of the remainder that are
	 */

	 * hunk header prior to editing (which will adjust `hunk->start` to
		N_("Apply this hunk to index and worktree [y,n,q,a,d%s,?]? "),
				if (hunk->use == UNDECIDED_HUNK)
				"removed, then the edit is\n"
	struct hunk_header *header = &merged->header, *next;
		   "q - quit; do not discard this hunk or any of the remaining "
	size_t current, eol, next;

	.diff_cmd = { "diff-files", NULL },

			      (uintmax_t)hunk_index + 1,
		N_("Apply this hunk to index and worktree [y,n,q,a,d%s,?]? "),

			 * actually applicable with the current hunk.
		if (!revision)
	int applies_index, applies_worktree;
	strbuf_complete_line(out);

	.apply_for_checkout = 1,
				+ header->new_count - merged->delta
		s.mode = &patch_mode_add;
	struct child_process cp = CHILD_PROCESS_INIT;
	    !skip_prefix(p, " +", &p) ||
	    !skip_prefix(p, " @@", &p))
		struct hunk *hunk;
		reassemble_patch(s, file_diff, 0, &s->buf);
		argv_array_pushf(&args, "--diff-algorithm=%s", diff_algorithm);

		 * (saying "n" for "no" discards!) if the translation
		N_("y - apply this hunk to worktree\n"
	.edit_hunk_hint = N_("If the patch applies cleanly, the edited hunk "
	if (header->new_offset != remaining.new_offset)
	header->old_count = remaining.old_count;
		    header->new_offset + header->new_count
			     "will immediately be marked for applying."),
}
			file_diff = s->file_diff + s->file_diff_nr - 1;
static int parse_diff(struct add_p_state *s, const struct pathspec *ps)

}
		   "d - do not stage this hunk or any of the later hunks in "
	header->new_count = remaining.new_count;
		else if (colored)
			ret = regcomp(&regex, s->answer.buf,

	if (i == *hunk_index)
		fprintf(stderr, _("Only binary files changed.\n"));
};
				 * `s->buf` still contains the part of the
		else {
static struct patch_mode patch_mode_stash = {
		/* Everything decided? */
		   "a - apply this hunk and all later hunks in the file\n"
	ssize_t i, undecided_previous, undecided_next;
		if (!eol)
		   "q - quit; do not stash this hunk or any of the remaining "
		   "n - do not apply this hunk to worktree\n"
{
		} else if (ch == 'a') {
			break;
			"ones\n"
		return 0;
}
			"the file\n"),
	const char *reverse = is_reverse ? "-R" : NULL;
			    old_offset, header->old_count,
		return error(_("could not parse hunk header"));
#include "pathspec.h"
		return error(_("could not parse hunk header '%.*s'"),
	.apply_args = { "-R", "--cached", NULL },
		/* Drop edits (they were appended to s->plain) */
			/*

static int is_octal(const char *p, size_t len)
		if (s->buf.buf[i] != comment_line_char)
		}
	res = capture_command(&cp, plain, 0);
		if (file_diff->hunk_nr > 1)
		int res = edit_hunk_manually(s, hunk);
			return -1;
		   "n - do not apply this hunk to index and worktree\n"
		 *
		 * Then record the start of the next split hunk.
			else
			 * Let's ensure that at least the last context line of
	struct strbuf *plain = &s->plain;
		struct hunk merged = { 0 };
	}

		struct hunk head;
		fflush(stdout);
		error(_("mismatched output from interactive.diffFilter"));
	.help_patch_text =
static struct patch_mode patch_mode_checkout_head = {
static void reassemble_patch(struct add_p_state *s,
	.apply_check_args = { NULL },
			file_diff->mode_change = 1;
		else if (patch_update_file(&s, s.file_diff + i))
					   merged->end - merged->start);
				SUMMARY_HEADER_WIDTH + len - out->len);
	if (hunk_index >= file_diff->hunk_nr)
				continue;
	const char *diff_algorithm = s->s.interactive_diff_algorithm;
	strbuf_reset(&s->buf);

		/*
	}
		if (starts_with(p, "diff ")) {
			 *
		} else if (s->answer.buf[0] == 'k') {
				    (int)header->new_count);
		header->old_count += context_line_count;
			     NULL, 0, NULL, 0);
		colored_current = hunk->colored_start;
		 */
				if (plain[overlap_end] != ' ')
	if (!s->colored.len)

		    header->new_offset >= next->new_offset + merged->delta ||

		next = &hunk->header;
			if (ch == '\\')
			/*
			      _("If it does not apply cleanly, you will be "
	putchar('\n');

			size_t splittable_into = hunk->splittable_into;
			marker = '\0';
	p = memmem(p + 4, eol - p - 4, " @@", 3);
			}
	if (s->revision) {
	cp->git_cmd = 1;
		} else {
			if (!run_apply_check(s, file_diff))
			break;


	.apply_for_checkout = 1,
			   struct strbuf *out)
			const char *p = _(help_patch_remainder), *eol = p;
			      s->s.file_new_color :
	return eol - sb->buf + 1;
			     struct strbuf *out)
		N_("Apply this hunk to index [y,n,q,a,d%s,?]? "),
			}
	 * hunk header, e.g. the function signature. This is expected to
static int split_hunk(struct add_p_state *s, struct file_diff *file_diff,
			goto soft_increment;
		strbuf_release(&s.colored);
		strbuf_reset(&s->buf);
			  struct file_diff *file_diff, struct hunk *hunk)
	},



	struct hunk *hunk;
		return;
#include "color.h"
	const char *prompt_mode[PROMPT_MODE_MAX];
			"ones\n"

				    "apply", reverse, NULL);
	size_t i = *hunk_index, delta;
					  file_diff->hunk_nr),
	va_start(args, fmt);
				if (overlap_next > hunk->end)

						     (int)(j + 1),
			strbuf_add(&s->colored, plain + eol, next - eol);
		N_("y - stash this hunk\n"
			merged->colored_end = hunk->colored_end;

			header->old_count++;

		header->new_count += context_line_count;
				 * always available.
		if (res > 0) {
	 * provide enough space for three command-line arguments followed by a
				hunk_index++;
				break;
	.help_patch_text =
	}
		if (!ch)
	return 0;
			else
		if ((!use_all && hunk->use != USE_HUNK) ||
			size_t overlap_start = overlap_end;
			      s->mode->is_reverse ? '-' : '+',

		if (undecided_previous >= 0)
			 * is _part of_ the header "hunk".
					  NULL, NULL, NULL) < 0) ||
	for (;;) {

		header->new_count = next->new_offset + delta
		case '-':
N_("j - leave this hunk undecided, see next undecided hunk\n"
	/* We simply skip the colored part (if any) when merging hunks */
		strbuf_add(out, plain->buf + i, find_next_line(plain, i) - i);
				size_t start = s->plain.len;
			    "apply", "--check", reverse, NULL);
		undecided_previous = -1;
struct add_p_state {
		       size_t hunk_index)
				i = file_diff->mode_change;
	.edit_hunk_hint = N_("If the patch applies cleanly, the edited hunk "
	 * messages.
	argv_array_pushf(&cp->env_array,
			delta = merged->delta;
	render_diff_header(s, file_diff, colored, &s->buf);
	 */
	.diff_cmd = { "diff-files", NULL },
			return 0;

	current = hunk->start;
	for (i = hunk->start; i < hunk->end; ) {
			hunk->use = USE_HUNK;
						     1, NULL, NULL, NULL);
	struct child_process cp = CHILD_PROCESS_INIT;
		 * Last hunk ended in non-context line (i.e. it appended lines
		remaining.new_count -= header->new_count;
	struct hunk_header *header = &hunk->header;
		if (file_diff->deleted && file_diff->mode_change)
					 "more)? ") : _("go to which hunk? "));
				colored_p = colored_pend;
		/* At least one hunk selected: apply */
{
			merged->end = s->plain.len;
			     "will immediately be marked for unstaging."),
		if (hunk_index >= file_diff->hunk_nr)
		hunk = file_diff->hunk + i;
	for (i = 0; i < ps->nr; i++)
			   skip_prefix(p, "old mode ", &mode_change) &&

		argv_array_push(&args, ps->items[i].original);
	}
			context_line_count = 0;
				      NULL, 0, NULL, 0);
			strbuf_remove(&s->answer, 0, 1);
	if (want_color_fd(1, -1)) {
				merged->end = s->plain.len;
		 * with the next line.
			"the file\n"),
	*offset = strtoul(*p, &pend, 10);
}
			new_offset += delta;
		strbuf_add(out, p + first->colored_end,
		 * If the hunks were not edited, and overlap, we can simply
		/*
{
	size_t len = out->len, i;
		*count = 1;
	if (applies_worktree && applies_index) {
#define SUMMARY_LINE_WIDTH 80
			      _("---\n"
			ALLOC_GROW(file_diff->hunk, file_diff->hunk_nr,
			len = header->extra_end - header->extra_start;
	struct hunk_header header;
	*count = strtoul(pend + 1, (char **)p, 10);

				file_diff->hunk->colored_end = hunk->colored_end;
	/* Use `--no-color` explicitly, just in case `diff.color = always`. */
		if (*p < '0' || *(p++) > '7')
		color_fprintf(stdout, s->s.prompt_color,
			render_hunk(s, hunk, delta, 0, out);
	}
		   "n - do not apply this hunk to index\n"
}
{
			}
		   "a - apply this hunk and all later hunks in the file\n"
#include "cache.h"
				break;

				hunk[1].colored_start = colored_current;
		/*

		render_hunk(s, hunk, 0, colored, &s->buf);
			   is_octal(mode_change, eol - mode_change)) {
		N_("y - apply this hunk to index\n"
			/* merge overlapping hunks into a temporary hunk */
			BUG("diff starts with unexpected line:\n"
	while ((arg = va_arg(ap, const char *)))
	struct hunk *head = &file_diff->head, *first = file_diff->hunk;
						    backup.header.new_count);
	.help_patch_text =
			current = find_next_line(&s->plain, current);
			      _(s->mode->prompt_mode[prompt_mode_type]),
	return 0;
				if (hunk->use == UNDECIDED_HUNK)
	size_t file_diff_nr;
			break;
		argv_array_push(&cp->args, arg);

				    (int)(eol - plain->buf), plain->buf);
	 * TRANSLATORS: 'it' refers to the patch mentioned in the previous
			struct child_process filter_cp = CHILD_PROCESS_INIT;
	if (end_index > file_diff->hunk_nr)
			 * the "new mode" line.
	.apply_args = { "--cached", NULL },
			    "apply", "--cached", "--check", reverse, NULL);
					continue;
			strbuf_addstr(&s->buf, ",g,/");
	};
	size_t i;
			}
	}
					break;
	fputc('\n', stderr);

	if (!p)
					find_next_line(&s->colored,
	setup_child_process(s, &cp, NULL);


		strbuf_reset(&s->buf);
			file_diff->binary = 1;
		hunk[1].header.new_offset =
	memset(hunk + 1, 0, (splittable_into - 1) * sizeof(*hunk));
		       unsigned long *offset, unsigned long *count)
	struct patch_mode *mode;

		hunk = file_diff->hunk + hunk_index;
	return 0;
		end_index = file_diff->hunk_nr;
		else if (file_diff->mode_change && !hunk_index)
	.apply_args = { "--cached", NULL },
				       _("go to which hunk (<ret> to see "
	int res;
	if (hunk->end == hunk->start)
	ALLOC_GROW(file_diff->hunk, file_diff->hunk_nr, file_diff->hunk_alloc);
			marker = *p;
			     (int)(eol - line), line);
}
	}
					     diff_filter);
				err(s, _("No next hunk"));
				fflush(stdout);
		N_("Apply deletion to index [y,n,q,a,d%s,?]? "),
			"the file\n"),
	if (out->len - len < SUMMARY_HEADER_WIDTH)
	hunk->start = eol - s->plain.buf + (*eol == '\n');
				if (strbuf_getline(&s->answer,
		return 0;
			if (colored_p)
		size_t len;

		/*
	if (*pend != ',') {
static int run_apply_check(struct add_p_state *s,
				    (int)file_diff->hunk_nr);
				printf("%s", i < file_diff->hunk_nr ?
	if (pend == *p)
					break;
		hunk->end = p - plain->buf;
		return;
				err(s, _("No hunk matches the given pattern"));
		strbuf_reset(&s->buf);
	if (i < hunk->end)
			if (hunk_index + 1 == file_diff->mode_change)
					    "apply", reverse, NULL);
		err(s, _("Nothing was applied.\n"));
		else
			   struct file_diff *file_diff)
		header->colored_extra_start = header->colored_extra_end = 0;
static void render_hunk(struct add_p_state *s, struct hunk *hunk,
				/* colored shorter than non-colored? */
		N_("Stash deletion [y,n,q,a,d%s,?]? "),
		ch = tolower(s->answer.buf[0]);
static int prompt_yesno(struct add_p_state *s, const char *prompt)
				/*
			else if (edit_hunk_loop(s, file_diff, hunk) >= 0) {
		}
			break;

				hunk->colored_start = colored_p - colored->buf;
		   "q - quit; do not apply this hunk or any of the remaining "

	argv_array_pushl(&args, "--no-color", "-p", "--", NULL);
			if (colored_p)
		}
				   file_diff_alloc);
			eol--;
					       "\tdoes not end with:\n%.*s"),
				"To remove '%c' lines, delete them.\n"
			marker = ch;
{
		N_("Unstage mode change [y,n,q,a,d%s,?]? "),
	header->colored_extra_end = hunk->colored_start;
			delta += hunk->delta;
	struct child_process check_worktree = CHILD_PROCESS_INIT;
			hunk_index = 0;

			 */
	/* last hunk simply gets the rest */
		return -1;
   "J - leave this hunk undecided, see next hunk\n"
				BUG("mode change in hunk #%d???",
				hunk_index = response - 1;
			old_offset -= delta;
		strbuf_add(out, p + head->start, first->start - head->start);
		N_("Apply mode change to index and worktree [y,n,q,a,d%s,?]? "),
	.apply_check_args = { "--cached", NULL },
		N_("Stash this hunk [y,n,q,a,d%s,?]? "),

		 */
soft_increment:
		N_("Stage mode change [y,n,q,a,d%s,?]? "),
	 * to stage that "hunk", we actually have to cut it out from the header.
static void err(struct add_p_state *s, const char *fmt, ...)
mismatched_output:
			memset(file_diff->hunk, 0, sizeof(struct hunk));
	.edit_hunk_hint = N_("If the patch applies cleanly, the edited hunk "


	struct hunk_header *header = &hunk->header;

	hunk->colored_start = eol - s->colored.buf + (*eol == '\n');
	enum { UNDECIDED_HUNK = 0, SKIP_HUNK, USE_HUNK } use;
		/* initialize next hunk header's offsets */
						     plain + hunk->start);
						   colored_pend - colored_p);
	 */
	for (i = 0; i < file_diff->hunk_nr; i++)

			      plain[current] == '-' ?
			}

		if (res == 0) {
				BUG("mode change in the middle?\n\n%.*s",
	.prompt_mode = {
				    s->answer.buf);
				break;
	/* strip out commented lines */
	if (!applies_index) {
	while (len--)
					   s->mode->is_reverse);
	return end_index;
			ALLOC_GROW(file_diff->hunk, file_diff->hunk_nr,
		else

				BUG("'new mode' does not immediately follow "
	unsigned is_reverse:1, index_only:1, apply_for_checkout:1;
	}
		   "q - quit; do not stage this hunk or any of the remaining "
		color_fprintf(stdout, s->s.prompt_color, "%s", _(prompt));
			 * Since the start-end ranges are not adjacent, we
	while (p != pend) {
	if (s.file_diff_nr == 0)
	strbuf_release(&s.buf);
	} *file_diff;
		return sb->len;
static struct patch_mode patch_mode_worktree_nothead = {
			       struct strbuf *out)
				i++;
		colored = &s->colored;
	return *p == pend + 1 ? -1 : 0;
	.prompt_mode = {
	},
	if (git_read_line_interactively(&s->answer) == EOF)
			   hunk->colored_end - hunk->colored_start);
		strbuf_add(out, p + head->colored_start,
		 * of the word "no" does not start with n.
			else if (!split_hunk(s, file_diff,
			strbuf_remove(&s->answer, 0, 1);
	struct hunk *hunk = NULL;
					hunk->use = USE_HUNK;

		else
		 * hunk, if any.
	setup_child_process(s, &check_worktree,
			merged->delta += hunk->delta;
					 NULL, 0, NULL, 0))
	}
	if (!eol)
	size_t end, colored_end, current, colored_current = 0, context_line_count;
}
	struct argv_array args = ARGV_ARRAY_INIT;
			hunk_index = undecided_next < 0 ?
			      int is_reverse)
	hunk = file_diff->hunk + hunk_index;
#include "strbuf.h"
			 INDEX_ENVIRONMENT "=%s", s->s.r->index_file);
	char marker, ch;
	p = memmem(line, eol - line, "@@ -", 4);
			 */
	},
	if (res) {
	strbuf_commented_addf(&s->buf, _("Manual hunk edit mode -- see bottom for "
			      comment_line_char);
		strbuf_complete_line(colored);
				err(s, _("Invalid number: '%s'"),
							      overlap_end);


		fwrite(diff->buf, diff->len, 1, stderr);
		 * We got us the start of a new hunk!
	struct strbuf answer, buf;
	 * Start/end offsets to the extra text after the second `@@` in the
}
				/* could be on an unborn branch */
			hunk->start = p - plain->buf;


	.apply_check_args = { "-R", "--cached", NULL },
	fputs(s->s.error_color, stderr);
	applies_worktree = !pipe_command(&check_worktree, diff->buf, diff->len,
{
		} else {
				undecided_next = i;
		strbuf_add(out, p + first->end, head->end - first->end);
			break;
						   stdin) == EOF)
			setup_child_process(s, &cp, "apply", NULL);
	.edit_hunk_hint = N_("If the patch applies cleanly, the edited hunk "
	for (i = 0; i < s.file_diff_nr; i++)
		s.mode = &patch_mode_stash;
		if (s->mode->apply_for_checkout)
			 * pad (this happens when an edited hunk had to be
static void render_diff_header(struct add_p_state *s,
	if (header->old_offset != remaining.old_offset)
		pipe_command(&apply_index, diff->buf, diff->len,
			if (plain[eol] == '\n')
			/* Adjust the end of the "mode change" pseudo-hunk */
			     "will immediately be marked for applying."),

	return 0;
			    memcmp(plain + merged->end - len,
				!strcmp("HEAD", s->revision) &&
				file_diff->hunk_nr : undecided_next;
		remaining.old_offset += header->old_count;
			strbuf_trim_trailing_newline(&s->answer);

				color_fprintf_ln(stdout, s->s.header_color,

				overlap_end = overlap_next;
			break;
			/*

			argv_array_pushv(&cp.args, s->mode->apply_args);

   "g - select a hunk to go to\n"
					 &s->buf, colored->len,
					 colored->buf, colored->len,
	    (!s.mode->index_only &&
					    &s->buf);
			setup_child_process(s, &apply_worktree,
int run_add_p(struct repository *r, enum add_p_mode mode,
}
			/* Comment lines are attached to the previous line */
			memset(file_diff, 0, sizeof(*file_diff));
				 */
	/* parse files and hunks */
			 * appended to the strbuf `s->plain`.
static int edit_hunk_manually(struct add_p_state *s, struct hunk *hunk)
				return error(_("failed to run '%s'"),
	struct child_process check_index = CHILD_PROCESS_INIT;
				err(s, _("No next hunk"));
				      "a quick guide.\n"));
	char *eol;
		} else if (hunk == &file_diff->head &&

		    !file_diff->deleted)
{

	else
		if (marker != ' ' || (ch != '-' && ch != '+')) {
	int colored = !!s->colored.len, first = 1;


				BUG("double mode change?\n\n%.*s",

		hunk++;
		hunk->use = hunk[-1].use;
		   "d - do not stash this hunk or any of the later hunks in "
		return 0;
			for (j = 0; j < overlapping_line_count; j++) {
	}
			     "will immediately be marked for staging."),
			 * of the second hunk, and then merge.
				"To remove '%c' lines, make them ' ' lines "
		next = eol + (eol < hunk->end);
	},
	strbuf_commented_addf(&s->buf,
}
	.diff_cmd = { "diff-index", "HEAD", NULL },
			strbuf_setlen(&s->plain, save_len);

	applies_index = !pipe_command(&check_index, diff->buf, diff->len,
					 NULL, 0) < 0)
			if (file_diff->hunk_nr != 1)
	for (i = file_diff->mode_change; i < file_diff->hunk_nr; i++) {
			char *colored_eol = memchr(colored_p, '\n',
		unsigned long old_offset = header->old_offset;
struct patch_mode {
			 * coalesced with another hunk).
			s.mode = &patch_mode_worktree_head;
}
		if (next > eol)

	.prompt_mode = {
static const char help_patch_remainder[] =

};
			       struct file_diff *file_diff, int colored,
		 */
			*hunk = backup;
		if (plain->buf[i] != ' ')
					    diff_filter, NULL);

	.diff_cmd = { "diff-index", NULL },
}
		- header->old_count + header->new_count;

	.apply_check_args = { "-R", NULL },
			"ones\n"
				char errbuf[1024];
	struct hunk_header *header = &hunk->header;
		for (eol = current; eol < hunk->end; eol++)

				 * in a context line? Handle it anyway.
	ssize_t delta = 0;
				get_oid("HEAD", &oid) ?
				      REG_EXTENDED | REG_NOSUB | REG_NEWLINE);

		} else if (ch == 'd' || ch == 'q') {
				undecided_previous = i;
		hunk->splittable_into = 1;
		i = next;
		const char *p = s->colored.buf;
	.is_reverse = 1,
			 * In case `merge_hunks()` used `plain` as a scratch
							   - hunk->start),
	/*
	if (colored)
			else if (ch == '+')
			 */
{
		printf("%s\n", res == EOF ? "" : s->answer.buf);
		} else if (s->answer.buf[0] == 's') {
		header = &hunk->header;
			len = overlap_end - overlap_start;
			break;
					    "in:\n%.*s",
	} else

{

			if (colored)
	struct child_process cp = CHILD_PROCESS_INIT;
		else if (file_diff->deleted)
		if (colored)
			     "will immediately be marked for discarding."),
				overlap_next = find_next_line(&s->plain,
		return -1;
				err(s, _("No previous hunk"));
			unsigned long response;
			apply_for_checkout(s, &s->buf,
	const char *revision;
		return 1;
					     plain + merged->start,
			binary_count++;
		undecided_next = -1;
			s.mode = &patch_mode_checkout_index;
				"Lines starting with %c will be removed.\n"),
		switch (tolower(s->answer.buf[0])) {
			}
};
	if (hunk->header.old_offset != 0 || hunk->header.new_offset != 0) {
		strbuf_setlen(out, len + SUMMARY_LINE_WIDTH);
				printf("%s", _("search for regex? "));
		return 0;
	render_diff_header(s, file_diff, 0, out);
		i = find_next_line(&s->plain, i);
				context_line_count++;
};
	.edit_hunk_hint = N_("If the patch applies cleanly, the edited hunk "
			"ones\n"
{
	if (!len)
		if (file_diff->hunk[i].use == USE_HUNK)
				hunk_index--;
			else
	const char *line = s->plain.buf + hunk->start, *p = line;
	strbuf_release(&s.answer);
	size_t i, binary_count = 0;
			if (undecided_next >= 0)

	size_t end_index = start_index + DISPLAY_HUNKS_LINES;
		 * extend the line range.
		if (res)
		return -1;
				strbuf_trim_trailing_newline(&s->answer);

			 */
		if (eol > current && plain[eol - 1] == '\r')
			strbuf_reset(&s->buf);
	struct file_diff {
	va_list args;
	.apply_check_args = { "-R", NULL },
		}
				hunk_index = undecided_previous;
		remaining.new_offset += header->new_count;
			/* current hunk not done yet */
				 */
	return 0;

				    (int)(eol - plain->buf), plain->buf);

	struct hunk backup;
	if (!p)
					continue;
{
	header = &hunk->header;
			 * the first hunk overlaps with the corresponding line
	.help_patch_text =
			     NULL, 0, NULL, 0);

				    (int)file_diff->hunk_nr);

	color_arg_index = args.argc;
	.help_patch_text =
	if (!s->colored.len) {
		return error(_("'git apply --cached' failed"));
					i = 0;
				strbuf_add(&s->plain, plain + merged->start,
		hunk->splittable_into++;
static int read_single_character(struct add_p_state *s)
			prompt_mode_type = PROMPT_MODE_CHANGE;
	.apply_args = { "--cached", NULL },
#include "add-interactive.h"
				struct child_process *cp, ...)

};
	/*
		if (file_diff->deleted)
			}
			const char *plain = s->plain.buf;
		   "a - discard this hunk and all later hunks in the file\n"
		}
			p = s->colored.buf + header->colored_extra_start;
		current = next;
			/*
		}
		case '+':
		colored_pend = colored_p + colored->len;
		if (s->mode->is_reverse)
		if (s.file_diff[i].binary && !s.file_diff[i].hunk_nr)
	return quit;
	enum prompt_mode_type prompt_mode_type;
		}
		else if (!strcmp(revision, "HEAD"))
		} else if (ch == 'n') {
	if (mode == ADD_P_STASH)
			strbuf_swap(colored, &s->buf);
		} else {
		N_("Unstage this hunk [y,n,q,a,d%s,?]? "),
		return EOF;
	p = plain->buf;
			if (ret) {
		if ((marker == '-' || marker == '+') && *p == ' ')
   "K - leave this hunk undecided, see previous hunk\n"
			strbuf_addstr(&s->buf, ",k");
		if (read_single_character(s) == EOF)
		 * This is a context line, so it is shared with the previous
		}

	argv_array_clear(&args);

			hunk->delta +=
	va_end(args);
	PROMPT_MODE_MAX, /* must be last */
	} else {
		if (undecided_next >= 0)

		BUG("miscounted new_offset: %lu != %lu",
		}


		   "d - do not discard this hunk or any of the later hunks in "
	if (hunk->splittable_into < 2)
	}
