#include "config.h"
	    todo_list_write_to_file(r, todo_list, todo_backup,
			 "THAT COMMIT WILL BE LOST.\n");
		*todo_backup = rebase_path_todo_backup();
	}
		"the level of warnings.\n"
			"To continue rebase after editing, run:\n"
			strbuf_addf(&missing, " - %s %.*s\n",
void append_todo_help(int command_count,
static enum missing_commit_check_level get_missing_commit_check_level(void)
		return -4;
		fprintf(stderr, _(edit_todo_list_advice));
		"The possible behaviours are: ignore, warn, error.\n\n"));
	if (!res)
"p, pick <commit> = use commit\n"

					      command_count),
}
	MISSING_COMMIT_CHECK_IGNORE = 0,
			write_file(rebase_path_dropped(), "%s", "");
		msg = _("\nDo not remove any line. Use 'drop' "

	return 0;
	if (incorrect) {
{
"b, break = stop here (continue rebase later with 'git rebase --continue')\n"
out:
#include "dir.h"
			unlink(rebase_path_dropped());

		return MISSING_COMMIT_CHECK_WARN;
					      "Rebase %s onto %s (%d commands)",
	unsigned edit_todo = !(shortrevisions && shortonto);
	todo_list_release(&old_todo);
	enum missing_commit_check_level check_level = get_missing_commit_check_level();
		incorrect = todo_list_parse_insn_buffer(r, todo_list->buf.buf, todo_list) |
{


#include "commit-slab.h"
	const char *todo_file = rebase_path_todo(),
#include "rebase-interactive.h"
	return MISSING_COMMIT_CHECK_IGNORE;
"m, merge [-C <commit> | -c <commit>] <label> [# <oneline>]\n"
			!strcasecmp("ignore", value))
		res = error(_("could not read '%s'."), rebase_path_todo());
	}
	else
				    shortrevisions, shortonto, -1,


" --abort'.\n");
"t, reset <label> = reset HEAD to a label\n"
	warning(_("unrecognized setting %s for option "
	for (i = old_todo->nr - 1; i >= 0; i--) {
 * Check if there is an unrecognized command or a
				    find_unique_abbrev(&commit->object.oid, DEFAULT_ABBREV),
		todo_list_parse_insn_buffer(r, backup.buf.buf, &backup);
}
"s, squash <commit> = use commit, but meld into previous commit\n"
int check_todo_list_from_file(struct repository *r)
		struct todo_item *item = old_todo->items + i;
		strbuf_commented_addf(buf, Q_("Rebase %s onto %s (%d command)",
"d, drop <commit> = remove commit\n"

	return res;
			file_exists(rebase_path_dropped());
	if (res)
"l, label <label> = label current HEAD with a name\n"
		return error(_("could not write '%s'."), rebase_path_todo_backup());
				    todo_item_get_arg(old_todo, item));
		"Use 'git config rebase.missingCommitsCheck' to change "

		      const char *shortrevisions, const char *shortonto,

	if (launch_sequence_editor(todo_file, &new_todo->buf, NULL))
	if (initial && new_todo->buf.len == 0)
				    (flags | TODO_LIST_APPEND_TODO_HELP) & ~TODO_LIST_SHORTEN_IDS) < 0)
	else
	if (check_level == MISSING_COMMIT_CHECK_IGNORE)
			return -4;
int todo_list_check(struct todo_list *old_todo, struct todo_list *new_todo)
	fprintf(stderr, _(edit_todo_list_advice));
	strbuf_add_commented_lines(buf, msg, strlen(msg));

		strbuf_addch(buf, '\n');
	strbuf_stripspace(&new_todo->buf, 1);
	struct strbuf missing = STRBUF_INIT;

	res = todo_list_parse_insn_buffer(r, old_todo.buf.buf, &old_todo);

		res = todo_list_parse_insn_buffer(r, new_todo.buf.buf, &new_todo);
		goto out;

#include "cache.h"

			"    git rebase --continue\n\n");
			"of an ongoing interactive rebase.\n"
		goto out;
enum missing_commit_check_level {

	clear_commit_seen(&commit_seen);
};
				    -1, flags | TODO_LIST_SHORTEN_IDS | TODO_LIST_APPEND_TODO_HELP))

"x, exec <command> = run command (the rest of the line) using shell\n"
	for (i = 0; i < new_todo->nr; i++) {
		res = error(_("could not read '%s'."), rebase_path_todo_backup());
".       specified). Use -c <commit> to reword the commit message.\n"
	if (strbuf_read_file(&backup.buf, rebase_path_todo_backup(), 0) > 0) {
#include "strbuf.h"
	int incorrect = 0;
	if (edit_todo)


{
int edit_todo_list(struct repository *r, struct todo_list *todo_list,
	}
	fprintf(stderr, _("To avoid this message, use \"drop\" to "
}
		_("Warning: some commits may have been dropped accidentally.\n"
		msg = _("\nYou are editing the todo file "
		return -4;




	struct todo_list old_todo = TODO_LIST_INIT, new_todo = TODO_LIST_INIT;
	if (todo_list_write_to_file(r, todo_list, todo_file, shortrevisions, shortonto,
#include "commit.h"
		msg = _("\nIf you remove a line here "
			 "explicitly to remove a commit.\n");
	/* Make the list user-friendly and display */
	 * might want to fix it in the first place. */
	}

	return res;
	 * it.  If there is an error, we do not return, because the user
	if (!initial)
	if (!incorrect &&

	init_commit_seen(&commit_seen);
		if (incorrect > 0)
		return -2;
		if (commit && !*commit_seen_at(&commit_seen, commit)) {
	fprintf(stderr,
".       create a merge commit using the original merge commit's\n"
	/* Find commits in git-rebase-todo.backup yet unseen */
	strbuf_add_commented_lines(buf, msg, strlen(msg));
				      shortrevisions, shortonto, command_count);
	if (todo_list_parse_insn_buffer(r, new_todo->buf.buf, new_todo)) {
#include "sequencer.h"
	if (!res)

		msg = _("\nHowever, if you remove everything, "
	if (strbuf_read_file(&new_todo.buf, rebase_path_todo(), 0) < 0) {
		struct commit *commit = item->commit;
"These lines can be re-ordered; they are executed from top to bottom.\n");
		}
"r, reword <commit> = use commit, but edit the commit message\n"
		}

		"explicitly remove a commit.\n\n"
			*commit_seen_at(&commit_seen, commit) = 1;
{
	return res;
	if (strbuf_read_file(&old_todo.buf, rebase_path_todo_backup(), 0) < 0) {
		return error_errno(_("could not write '%s'"), todo_file);
	/* Warn about missing commits */
	if (get_missing_commit_check_level() == MISSING_COMMIT_CHECK_ERROR)
"f, fixup <commit> = like \"squash\", but discard this commit's log message\n"
			"the rebase will be aborted.\n\n");
		fprintf(stderr, _(edit_todo_list_advice));

	if (!missing.len)
/*
		   const char *shortonto, unsigned flags)
	}
}
".       message (or the oneline, if no original merge commit was\n"
	if (!strcasecmp("error", value))
	unsigned initial = shortrevisions && shortonto;
{
	const char *msg = _("\nCommands:\n"

	struct todo_list backup = TODO_LIST_INIT;
 * Check if the user dropped some commits by mistake
		res = todo_list_check(&old_todo, &new_todo);
		goto leave_check;
	if (!strcasecmp("warn", value))

		write_file(rebase_path_dropped(), "%s", "");
				    item->arg_len,
	todo_list_release(&new_todo);
	MISSING_COMMIT_CHECK_WARN,
	fputs(missing.buf, stderr);

		if (todo_list_check_against_backup(r, new_todo)) {
	todo_list_release(&backup);
}
	MISSING_COMMIT_CHECK_ERROR
			*commit_seen_at(&commit_seen, commit) = 1;
	}
		"Dropped commits (newer to older):\n"));
"Or you can abort the rebase with 'git rebase"
int todo_list_check_against_backup(struct repository *r, struct todo_list *todo_list)
	int res = 0;
	const char *value;
{
 */
	}
 * Behaviour determined by rebase.missingCommitsCheck.
	/* Mark the commits in git-rebase-todo as seen */
"e, edit <commit> = use commit, but stop for amending\n"
	} else if (todo_list_check(todo_list, new_todo)) {
		      struct strbuf *buf)

"and then run 'git rebase --continue'.\n"
	strbuf_add_commented_lines(buf, msg, strlen(msg));
 * bad SHA-1 in a command.
		res = todo_list_check(&backup, todo_list);
	int res = 0, i;


	/* If the user is editing the todo list, we first try to parse


		goto leave_check;
	if (check_level == MISSING_COMMIT_CHECK_ERROR)
N_("You can fix this with 'git rebase --edit-todo' "
		struct commit *commit = new_todo->items[i].commit;
		if (commit)
}

leave_check:
static const char edit_todo_list_advice[] =
		return -3;
define_commit_slab(commit_seen, unsigned char);
		return MISSING_COMMIT_CHECK_IGNORE;
	}
		  "rebase.missingCommitsCheck. Ignoring."), value);


		res = 1;

		return MISSING_COMMIT_CHECK_ERROR;
	if (!edit_todo) {
	struct commit_seen commit_seen;
	int res = 0;
"\n"
		   struct todo_list *new_todo, const char *shortrevisions,

	if (git_config_get_value("rebase.missingcommitscheck", &value) ||
	strbuf_release(&missing);
