			}
				  " refusing to clean"));
		result = xcalloc(st_add(nr, 1), sizeof(int));
		 * default selections.
static void pretty_print_dels(void)
		}
		}
{
	if (ignored_only)
		}
	strbuf_list_free(choice_list);
	for (i = 0; i < dir.nr; i++) {
{
				}
		    "-...       - unselect specified items\n"
			p = menu_item->title;
		dir.flags |= DIR_SHOW_IGNORED;
static int *list_and_choose(struct menu_opts *opts, struct menu_stuff *stuff)
	if (!interactive && !dry_run && !force) {
	} else {
			return 0;
					break;
		} else {
			return config_error_nonbool(var);

 *
			strbuf_addstr(&abs_path, prefix);
	printf(singleton ?
{
	}
		clean_use_color = git_config_colorbool(var, value);
{

	menu_stuff.type = MENU_STUFF_TYPE_STRING_LIST;
	}
static unsigned int colopts;
		int choose = 1;
				warning_errno(_(msg_warn_remove_failed), qname);
			} else if (!quiet) {
			int saved_errno = errno;
			{'a', "ask each",		0, ask_each_cmd},
	if (!strcmp(var, "color.interactive")) {
		       PATHSPEC_PREFER_CWD,
	switch (stuff->type) {
				continue;
 *         2-3,6-9    - select multiple ranges
		    "           - (empty) select nothing\n") :

	}

	return (errors != 0);

			qname = quote_path_relative(item->string, NULL, &buf);
 *   - The array ends with EOF.
	struct strbuf buf = STRBUF_INIT;


#include "column.h"
			continue;
	N_("git clean [-d] [-f] [-i] [-n] [-q] [-e <pattern>] [-x | -X] [--] <paths>..."),
	copts.padding = 2;
			if (remove_dirs(&abs_path, prefix, rm_flags, dry_run, quiet, &gone))
			matches = dir_path_match(&the_index, ent, &pathspec, 0, NULL);

	string_list_append(exclude_list, arg);

	copts.indent = "  ";
}
		  _("Prompt help:\n"
		    "ask each            - confirm each deletion (like \"rm -i\")\n"
	struct string_list_item *item;
			ign++;
		for (i = 0; ignore_list[i]; i++) {
 *         -...       - unselect specified items
				top = atoi(strchr((*ptr)->buf, '-') + 1);
 *         foo        - select item based on menu title
	const char *qname;

		chosen = list_and_choose(&menu_opts, &menu_stuff);
	}
		 */
}
};
		/*
		 */
			strbuf_trim(ignore_list[i]);
			*(items[i].string) = '\0';
		if (git_read_line_interactively(&choice) == EOF) {
		strbuf_reset(&abs_path);
	};
	NULL
					is_number = 0;
			{'q', "quit",			0, quit_cmd},
		menu_stuff.type = MENU_STUFF_TYPE_MENU_ITEM;
	string_list_clear(&menu_list, 0);
			strbuf_remove((*ptr), 0, 1);

	struct string_list_item *string_list_item;
			if ('-' == *p) {
			if (len == 1 && *choice == menu_item->hotkey) {
}
		}
			string_list_append(&menu_list, menu.buf);
		i = 0;

	if (ignored && ignored_only)
		strbuf_addstr(path, e->d_name);
		menu_stuff.stuff = menus;
	struct strbuf confirm = STRBUF_INIT;
	memset(&dir, 0, sizeof(dir));
			putchar('\n');
		goto out;
			if (is_excluded(&dir, &the_index, item->string, &dtype)) {
#include "color.h"
		}
	menu_opts.header = NULL;
	/* inspect the color.ui config variable and others */
		if (*(*ptr)->buf == '-') {

		die("Bad type of menu_stuff when parse choice");
			{'c', "clean",			0, clean_cmd},
		} else {

			{'s', "select by numbers",	0, select_by_numbers_cmd},
	free(chosen);
			}
	items = del_list.items;
		if (opts->flags & MENU_OPTS_LIST_ONLY)
 *         foo        - select item based on menu title
					strbuf_addstr(&menu, clean_get_color(CLEAN_COLOR_RESET));
{


			i++;
			if (git_read_line_interactively(&confirm) == EOF) {
		int i;

 *   - , and it is up to you to free the allocated memory.


 * "git clean" builtin command
		 * recalculate nr, if return back from menu directly with
		rm_flags = 0;
	[CLEAN_COLOR_PLAIN]  = "plain",
				  "refusing to clean"));

	*dir_gone = 1;

/*
		if (i < chosen[j]) {
static int help_cmd(void)
		    "           - (empty) finish selecting\n"));
	struct strbuf confirm = STRBUF_INIT;
	struct string_list_item *item;

		menu_opts.prompt = N_("What now");
			*dir_gone = 0;
	[CLEAN_COLOR_HEADER] = "header",
	struct dirent *e;
		 */

 * Parse user input, and return choice(s) for menu (menu_stuff).
		} else if (opts->flags & MENU_OPTS_IMMEDIATE) {
struct menu_item {


	clean_print_color(CLEAN_COLOR_RESET);

	for_each_string_list_item(item, &del_list) {
			int ret;
		if (!nr) {


	struct dir_struct dir;
				top = menu_stuff->nr;
	for (i = 0; i < dir.nr; i++)

			for (; *p; p++) {
}
		}
	closedir(dir);
		OPT_END()
#include "string-list.h"
		}
			break;
		break;
		setup_standard_excludes(&dir);
		} else {
 * The parse result will be saved in array **chosen, and
	struct strbuf quoted = STRBUF_INIT;
		if (slot < 0)
	string_list_clear(&del_list, 0);
		res = dry_run ? 0 : rmdir(path->buf);
 *                    - (empty) select nothing
				printf(dry_run ? _(msg_would_remove) : _(msg_remove), qname);
			clean_print_color(CLEAN_COLOR_RESET);
	[CLEAN_COLOR_PROMPT] = GIT_COLOR_BOLD_BLUE,
			continue;
	if (skip_prefix(var, "color.interactive.", &slot_name)) {
		interactive_main_loop();
		for_each_string_list_item(item, &del_list) {
	menu_stuff.nr = del_list.nr;
	if (is_single) {
			if ((*chosen)[i] < 0)
			warning_errno(_(msg_warn_lstat_failed), path->buf);


	[CLEAN_COLOR_HELP]   = "help",
				changed++;
			clean_print_color(CLEAN_COLOR_RESET);
		}
{

#include "quote.h"
	strbuf_release(&buf);

	struct column_options copts;
		struct dir_entry *ent = dir.entries[i];
		  N_("add <pattern> to ignore rules"), PARSE_OPT_NONEG, exclude_cb },
		for (p = (*ptr)->buf; *p; p++) {
			struct dir_entry *ent = dir->entries[src++];
static int interactive;

					is_range = 0;
}
		int slot = LOOKUP_CONFIG(color_interactive_slots, slot_name);
		struct menu_opts menu_opts;
			continue;
		if (!del_list.nr)
	[CLEAN_COLOR_RESET] = GIT_COLOR_RESET,
}
			     0);
	len = path->len;
	if (remove_directories)
 */
		menu_item = (struct menu_item *)stuff->stuff;

		}
		int bottom = 0, top = 0;
				(*chosen)[i] = 0;
		struct stat st;

				  choice,
		strbuf_addstr(&abs_path, item->string);
		for (i = 0; i < dels.nr; i++)

	CLEAN_COLOR_PROMPT = 2,
	struct menu_opts menu_opts;
{
	    is_nonbare_repository_dir(path)) {
			for (i = 0; i < stuff->nr; i++)
					clean_print_color(CLEAN_COLOR_ERROR);
				  clean_get_color(CLEAN_COLOR_RESET));
static int git_clean_config(const char *var, const char *value, void *cb)
enum menu_stuff_type {

		}
			int is_single,
		clear_directory(&dir);
			/* entries[src] contains an ignored path, so we drop it */

		if (git_read_line_interactively(&confirm) == EOF)
	struct dir_struct dir;
{
				} else {
		    "2-3,6-9    - select multiple ranges\n"
			else

		*dir_gone = 0;
		} else {
		/* quit filter_by_pattern mode if press ENTER or Ctrl-D */
					quoted.buf);
			const char *p;
static const char *msg_would_skip_git_dir = N_("Would skip repository %s\n");
static void prompt_help_cmd(int singleton)
		struct menu_stuff menu_stuff;
	}
		die("Bad type of menu_stuff when print menu");
		       0 <= cmp_dir_entry(&dir->entries[src], &dir->ignored[ign]))
	void *stuff;
	print_columns(menu_list, local_colopts, &copts);
			src--;
	struct string_list_item *items;
				quote_path_relative(path->buf, prefix, &quoted);

};
static int parse_choice(struct menu_stuff *menu_stuff,
			/* end of chosen (chosen[j] == EOF), won't delete */
	int *chosen;
		is_number = 1;
				*dir_gone = 0;

		if (opts->prompt) {
	pretty_print_menus(&menu_list);
	memset(&copts, 0, sizeof(copts));
			continue;
	for (;;) {
					found = 0;
		if (changed)
		/*
				if (!is_range) {

 * Input
	int selected;
	if (want_color(clean_use_color))

		OPT__QUIET(&quiet, N_("do not print names of files removed")),
		config_set = 1;
			res = dry_run ? 0 : unlink(path->buf);
		}
static const char *color_interactive_slots[] = {
		    matches != MATCHED_EXACTLY)

		    "1          - select a numbered item\n"
			if (!*(strchr((*ptr)->buf, '-') + 1))
	}

		die(_("index file corrupt"));
 */
	printf_ln(_(

		while (ign < dir->ignored_nr &&

}
			strbuf_addf(&menu, "%s%2d: %s",
 */
		}
			errno = saved_errno;
		dir.flags |= DIR_SHOW_IGNORED_TOO | DIR_KEEP_UNTRACKED_CONTENTS;
	int i, len, found = 0;
	else
}
		nr = parse_choice(stuff,
			/* then discard paths in entries[] contained inside entries[src] */
	int res = 0, ret = 0, gone = 1, original_len = path->len, len;
static int select_by_numbers_cmd(void)
	case MENU_STUFF_TYPE_MENU_ITEM:
		free(dir.entries[i]);
		for (i = 0; i < menu_stuff->nr; i++, menu_item++) {
	strbuf_complete(path, '/');
				qname = quote_path_relative(item->string, NULL, &buf);
		if (S_ISDIR(st.st_mode)) {
		else if (S_ISDIR(st.st_mode)) {
		}
	}
	strbuf_release(&menu);
	[CLEAN_COLOR_PROMPT] = "prompt",
			*(items[i].string) = '\0';
			}
			if (remove_dirs(path, prefix, force_flag, dry_run, quiet, &gone))
			clean_print_color(CLEAN_COLOR_ERROR);
	if (starts_with(var, "column."))

		/* skip paths in ignored[] that cannot be inside entries[src] */
	[CLEAN_COLOR_RESET]  = "reset",
		if (ign < dir->ignored_nr &&
	string_list_clear(&dels, 0);
		};
				errno = saved_errno;
			strbuf_reset(&menu);
		}
		force = !git_config_bool(var, value);
		if (is_dot_or_dotdot(e->d_name))
	}
		OPT__FORCE(&force, N_("force"), PARSE_OPT_NOCOMPLETE),
	strbuf_release(&buf);
}
			warning_errno(_(msg_warn_remove_failed), quoted.buf);

{
					highlighted = 1;
 *
	default:


	print_columns(&list, colopts, &copts);
				}
{
}
						found = -1;
	const char *qname;
			       opts->flags & MENU_OPTS_SINGLETON ? "> " : ">> ",
			/* delete selected item */
		char *p;
		string_list_append(&list, qname);
		    "?                   - help for prompt selection"
				N_("remove whole directories")),
	const char *title;

	struct strbuf **choice_list, **ptr;
		FREE_AND_NULL(chosen);

		if (!(opts->flags & MENU_OPTS_SINGLETON) && !choice.len)
	for (i = 0; i < dir.ignored_nr; i++)
	strbuf_release(&confirm);

				is_number = 0;
			die(_("clean.requireForce defaults to true and neither -i, -n, nor -f given;"
						/* continue for hotkey matching */
		add_pattern(exclude_list.items[i].string, "", 0, pl, -(i+1));
			top = menu_stuff->nr;
	CLEAN_COLOR_HEADER = 3,
}
 *
	return result;
		int is_range, is_number;
			free(dir->entries[src]);
	return 0;
				nr += chosen[i];
	struct menu_stuff menu_stuff;


	struct column_options copts;

		  _("Prompt help:\n"
			strbuf_addf(&menu, "%s%2d: ", (*chosen)[i] ? "*" : " ", i+1);
		if (res) {
			bottom = 1;
	case MENU_STUFF_TYPE_STRING_LIST:
		if (is_number) {
		struct menu_item menus[] = {
	return MENU_RETURN_NO_LOOP;
	}
static const char *msg_would_remove = N_("Would remove %s\n");
		    "select by numbers   - select items to be deleted by numbers\n"
				  clean_get_color(CLEAN_COLOR_HEADER),
			strbuf_reset(&menu);
		}

	menu_opts.flags = 0;
				*item->string = '\0';

		/* Ctrl-D should stop removing files */


			} else if (!isdigit(*p)) {
	string_list_clear(&del_list, 0);
			while (src < dir->nr &&

		 * fail with ENOENT.
	while (del_list.nr) {
	if (argc) {
			ret = 1;

			j++;
/*
			     "Would remove the following items:",
	for (i = 0; i < stuff->nr; i++)
			if (!strncasecmp(choice, string_list_item->string, len)) {

		}
	strbuf_release(&choice);
	if (!dir) {

static void pretty_print_menus(struct string_list *menu_list)
		/* an empty dir could be removed even if it is unreadble */
	strbuf_release(&buf);
	struct strbuf choice = STRBUF_INIT;
	}
		/* for a multiple-choice menu, press ENTER (empty) will return back */
		 * recurse within those.
			continue;
		if (top <= 0 || bottom <= 0 || top > menu_stuff->nr || bottom > top ||
		return 0;
#define MENU_OPTS_LIST_ONLY		04
	}

			eof = 1;
		break;

		ignore_list = strbuf_split_max(&confirm, ' ', 0);
				result[j++] = i;
		{ OPTION_CALLBACK, 'e', "exclude", &exclude_list, N_("pattern"),
			       clean_get_color(CLEAN_COLOR_RESET));
 *         *          - choose all items
	default:
{
					if (len == 1) {
#include "prompt.h"
	struct menu_item *menu_item;

		int *chosen;
	}
static void interactive_main_loop(void)
			}
	 * about layout strategy and stuff
	int i, res;
		}
	[CLEAN_COLOR_ERROR] = GIT_COLOR_BOLD_RED,
		struct stat st;
	case MENU_STUFF_TYPE_MENU_ITEM:
		memset(&dir, 0, sizeof(dir));
			bottom = find_unique((*ptr)->buf, menu_stuff);
		return 0;
				  _(opts->header),
	} else {
			/* entries[src] does not contain an ignored path, so we keep it */
			if (chosen[i])
					is_range = 1;
	if (!ignored)
	int rm_flags = REMOVE_DIR_KEEP_NESTED_GIT;
			continue;
static int remove_dirs(struct strbuf *path, const char *prefix, int force_flag,
	struct strbuf abs_path = STRBUF_INIT;
}
	strbuf_release(&confirm);
				if (found) {
	if (force > 1)
		}
			break;
			printf_ln(_("WARNING: Cannot find items matched by: %s"), confirm.buf);

		const char *rel;
		if (opts->header) {
				if (!del_list.nr) {
static int ask_each_cmd(void)
	}
{
				*dir_gone = 0;
	if (read_cache() < 0)
			}
		} while (*p++);
 *         3-5        - select a range of items
static int clean_use_color = -1;
			*dir_gone = 1;

	DIR *dir;
static void correct_untracked_entries(struct dir_struct *dir)
		choice_list = strbuf_split_max(&input, ' ', 0);
			quote_path_relative(path->buf, prefix, &quoted);
		if (pathspec.nr)
	struct string_list menu_list = STRING_LIST_INIT_DUP;
			*item->string = '\0';
				break;

		for (i = 0; i < stuff->nr; i++, menu_item++) {
		die(_("-x and -X cannot be used together"));
	struct string_list dels = STRING_LIST_INIT_DUP;
		menu_opts.header = N_("*** Commands ***");
	struct menu_item *menu_item;
 * Implement a git-add-interactive compatible UI, which is borrowed
		} else if (i == chosen[j]) {

			(*chosen)[i-1] = choose;
			top = bottom;
			string_list_remove_empty_items(&del_list, 0);
		chosen[i] = -1;



				string_list_append(&dels, quoted.buf);
	int dry_run = 0, remove_directories = 0, quiet = 0, ignored = 0;
}

	unsigned int local_colopts = 0;
		is_range = 0;
			printf(_("Huh (%s)?\n"), (*ptr)->buf);
	fill_directory(&dir, &the_index, &pathspec);
	struct option options[] = {
	}
		struct stat st;
		goto out;
			bottom = atoi((*ptr)->buf);
static const char *msg_warn_lstat_failed = N_("could not lstat %s\n");
		strbuf_trim(*ptr);
					break;
			if (gone) {
					found = i + 1;
		if (*chosen != EOF) {
	struct pattern_list *pl;
#define MENU_RETURN_NO_LOOP		10
			if (ret != MENU_RETURN_NO_LOOP) {
			int dtype = DT_UNKNOWN;
				}
		if (!eof) {
					clean_print_color(CLEAN_COLOR_RESET);

{
 *                    - (empty) finish selecting
 *     (for multiple choice)
			*dir_gone = 0;

		    "help                - this screen\n"


		    "3-5        - select a range of items\n"

			if (*p == ',')
		dir.flags |= DIR_SKIP_NESTED_GIT;
	memset(&copts, 0, sizeof(copts));
		choice_list = strbuf_split_max(&input, '\n', 0);
int cmd_clean(int argc, const char **argv, const char *prefix)
	for (ptr = choice_list; *ptr; ptr++) {
					strbuf_addch(&menu, *p);
	if (!*dir_gone && !quiet) {
	if (*dir_gone) {

		if (prefix)
			/* TRANSLATORS: Make sure to keep [y/N] as is */
			dir->entries[dst++] = ent;
				errors++;
	for (;;) {
	for (i = 0, j = 0; i < del_list.nr; i++) {
{
			}
		printf_ln(Q_("Would remove the following item:",
		int matches = 0;
			break;
 *   - Return an array of integers

		char *p = input.buf;

		 * recursive directory removal, so lstat() here could
			     del_list.nr));
		if (!strcmp(choice.buf, "?")) {
	struct strbuf menu = STRBUF_INIT;
		*result = EOF;
	switch (menu_stuff->type) {
	   applied in git-add--interactive and git-stash */
				}
	return 0;
{
		if (S_ISDIR(st.st_mode) && !remove_directories &&
	struct string_list *exclude_list = opt->value;
static const char *msg_skip_git_dir = N_("Skipping repository %s\n");
		for (i = 0; i < menu_stuff->nr; i++, string_list_item++) {
define_list_config_array(color_interactive_slots);
	}
	int *chosen, *result;

			choose = 0;
				break;
		} else {
			break;
struct menu_opts {
	chosen = list_and_choose(&menu_opts, &menu_stuff);

		 * Remaining args implies pathspecs specified, and we should
	/* honors the color.interactive* config variables which also
				errno = saved_errno;
		OPT_BOOL('x', NULL, &ignored, N_("remove ignored files, too")),
	return ret;
enum color_clean {
	}
		OPT_BOOL('i', "interactive", &interactive, N_("interactive cleaning")),
			res = dry_run ? 0 : unlink(abs_path.buf);
	copts.padding = 2;
			die_errno("Cannot lstat '%s'", ent->name);
				if (!highlighted && *p == menu_item->hotkey) {
		result[j] = EOF;
			int highlighted = 0;
		}


	 * always enable column display, we only consult column.*
			continue;
		for (i = bottom; i <= top; i++)
				string_list_append(&dels, quoted.buf);
		menu_opts.flags = MENU_OPTS_SINGLETON;
		if (lstat(ent->name, &st))
	if (force < 0)
	int changed = 0, eof = 0;
		break;

		break;
			continue;

		menu_item = (struct menu_item *)menu_stuff->stuff;
static const char *clean_get_color(enum color_clean ix)
	len = strlen(choice);
	}
		} else {
	struct pattern_list *pl;
			}
			string_list_append(&menu_list, menu.buf);
 *     (for single choice)
		}
static int exclude_cb(const struct option *opt, const char *arg, int unset)
		force = 0;

		}
		printf(_("Input ignore patterns>> "));
		    check_dir_entry_contains(dir->entries[src], dir->ignored[ign])) {
				} else {
out:
 *
	[CLEAN_COLOR_HELP] = GIT_COLOR_BOLD_RED,
		pretty_print_dels();
		changed = 0;

	int eof = 0;
	struct pathspec pathspec;
static void print_highlight_menu_stuff(struct menu_stuff *stuff, int **chosen)



				warning_errno(_(msg_warn_remove_failed), quoted.buf);
	strbuf_release(&quoted);
	return "";
		return clean_colors[ix];
};
		if (!res)
			printf("%s%s%s%s",
		clean_print_color(CLEAN_COLOR_PROMPT);
			quote_path_relative(path->buf, prefix, &quoted);
			if (!res) {

				  opts->flags & MENU_OPTS_SINGLETON,
	for (src = dst = ign = 0; src < dir->nr; src++) {
			}
			if (gone && !quiet) {

	clean_print_color(CLEAN_COLOR_HELP);
		    "filter by pattern   - exclude items from deletion\n"
		res = dry_run ? 0 : rmdir(path->buf);
					printf_ln(_("No more files to clean, exiting."));

	string_list_clear(&list, 0);

	int i;
	dir.flags |= DIR_SHOW_OTHER_DIRECTORIES;
	struct strbuf buf = STRBUF_INIT;
	copts.indent = "  ";
	strbuf_setlen(path, original_len);
}
			continue;
		if (!confirm.len || strncasecmp(confirm.buf, "yes", confirm.len)) {
	if (!strcmp(var, "clean.requireforce")) {
	MENU_STUFF_TYPE_MENU_ITEM
	menu_stuff.stuff = &del_list;
		strbuf_setlen(path, len);
		string_list_item = ((struct string_list *)menu_stuff->stuff)->items;
static int force = -1; /* unset */
		free(dir.ignored[i]);
		}

}
		remove_directories = 1;
					strbuf_addstr(&menu, clean_get_color(CLEAN_COLOR_PROMPT));

	else
}
		return color_parse(value, clean_colors[slot]);
	[CLEAN_COLOR_PLAIN] = GIT_COLOR_NORMAL,
			       check_dir_entry_contains(ent, dir->entries[src]))
				    (*chosen)[i] ? "*" : " ", i+1, string_list_item->string);
{
}
	/*
		else {
				(*chosen)[i] = menu_item->selected ? 1 : 0;
		break;
	return found;
	}
					} else {

		if (!value)
						found = 0;


				ret = 1;
	pl = add_pattern_list(&dir, EXC_CMDL, "--exclude option");

		    (is_single && bottom != top)) {
		} else if (is_range) {
				quote_path_relative(path->buf, prefix, &quoted);

		clean_print_color(CLEAN_COLOR_HEADER);

			       _(opts->prompt),

			} else
	struct string_list exclude_list = STRING_LIST_INIT_NODUP;
		menu_stuff.nr = sizeof(menus) / sizeof(struct menu_item);

		if (!(*ptr)->len)
			bottom = atoi((*ptr)->buf);
				eof = 1;
				free(dir->entries[src++]);
		}
			continue;
		    "*          - choose all items\n"

		    "quit                - stop cleaning\n"
				quote_path_relative(path->buf, prefix, &quoted);
		break;
		OPT_BOOL('d', NULL, &remove_directories,
		strbuf_list_free(ignore_list);
	local_colopts = COL_ENABLED | COL_ROW;


{

		if (changed) {
#include "builtin.h"
 * from git-add--interactive.perl.
					is_number = 0;
			quit_cmd();

			pretty_print_dels();
	struct string_list_item *item;

			/* compensate for the outer loop's loop control */
			break;
	enum menu_stuff_type type;

				int saved_errno = errno;
			int saved_errno = errno;

};
	const char *prompt;

		*dir_gone = 0;
{
		} else if (!strcmp((*ptr)->buf, "*")) {
			int **chosen)
 * return number of total selections.
		OPT_BOOL('X', NULL, &ignored_only,
			top = bottom;
		clean_print_color(CLEAN_COLOR_RESET);
			printf_ln("%s%s%s",
				break;
				FREE_AND_NULL(chosen);
				found = i + 1;
		/* path too long, stat fails, or non-directory still exists */
}

		int dry_run, int quiet, int *dir_gone)
	struct string_list list = STRING_LIST_INIT_DUP;
		ret = res;
	int (*fn)(void);
	for (i = 0; i < menu_stuff->nr; i++)
		/* chosen will be initialized by print_highlight_menu_stuff */
	CLEAN_COLOR_ERROR = 5

			printf(dry_run ?  _(msg_would_remove) : _(msg_remove), dels.items[i].string);
static int find_unique(const char *choice, struct menu_stuff *menu_stuff)
{
			{'h', "help",			0, help_cmd},
static int quit_cmd(void)
			} else {
};
static const char *msg_remove = N_("Removing %s\n");
	menu_opts.prompt = N_("Select items to delete");
#define MENU_OPTS_IMMEDIATE		02
	CLEAN_COLOR_PLAIN = 1,
	BUG_ON_OPT_NEG(unset);
				} else {
	printf("%s", clean_get_color(ix));
	[CLEAN_COLOR_ERROR]  = "error",
#define MENU_OPTS_SINGLETON		01
	if ((force_flag & REMOVE_DIR_KEEP_NESTED_GIT) &&
 *         1          - select a numbered item
struct menu_stuff {
			add_pattern(ignore_list[i]->buf, "", 0, pl, -(i+1));
			/* a range can be specified like 5-7 or 5- */
			break;
{
	argc = parse_options(argc, argv, prefix, options, builtin_clean_usage,
		for (i = 0; i < stuff->nr && j < nr; i++) {
	 */

			die(_("clean.requireForce set to true and neither -i, -n, nor -f given; "
		    "1          - select a single item\n"
		    "foo        - select item based on unique prefix\n"
	while ((e = readdir(dir)) != NULL) {
		/*
		/* Input that begins with '-'; unchoose */
		ret = 1;
		nr += (*chosen)[i];
	dir->nr = dst;
			quote_path_relative(path->buf, prefix, &quoted);
#include "pathspec.h"
static void clean_print_color(enum color_clean ix)
	parse_pathspec(&pathspec, 0,
				found = i + 1;
		print_highlight_menu_stuff(stuff, &chosen);
		if (lstat(abs_path.buf, &st))
	git_config(git_clean_config, NULL);
				qname = quote_path_relative(item->string, NULL, &buf);
	return 0;
		    "clean               - start cleaning\n"
			struct strbuf input,
	correct_untracked_entries(&dir);
	struct strbuf **ignore_list;
					break;
	CLEAN_COLOR_HELP = 4,

				errors++;
/*
	colopts = (colopts & ~COL_ENABLE_MASK) | COL_ENABLED;
#include "parse-options.h"
		return git_column_config(var, value, "clean", &colopts);
				qname = quote_path_relative(item->string, NULL, &buf);
		if (pathspec.nr && !matches)

		/* help for prompt */
	int i, j;

		if (!cache_name_is_other(ent->name, ent->len))
		if (config_set)
	}
	[CLEAN_COLOR_HEADER] = GIT_COLOR_BOLD,
static const char *msg_warn_remove_failed = N_("failed to remove %s");
	}
		}
	dir = opendir(path->buf);
	for_each_string_list_item(item, &del_list) {
		string_list_append(&del_list, rel);
	if (eof) {
						break;
	int nr;
	int nr = 0;


#include "config.h"
		   ));
	if (interactive && del_list.nr > 0)

		       prefix, argv);

	}
			}
#include "dir.h"
	printf(_("Bye.\n"));
	const char *qname;
}
{
static struct string_list del_list = STRING_LIST_INIT_DUP;
		pl = add_pattern_list(&dir, EXC_CMDL, "manual exclude");
				putchar('\n');
	}
 * Based on git-clean.sh by Pavel Roskin
	MENU_STUFF_TYPE_STRING_LIST = 1,
			}
static char clean_colors[][COLOR_MAXLEN] = {
	for (i = 0; i < exclude_list.nr; i++)
	ALLOC_ARRAY(chosen, stuff->nr);
	int i;
				ret = 1;
		if (lstat(path->buf, &st))
/*
				}
	struct strbuf buf = STRBUF_INIT;
				int saved_errno = errno;

			}

 *
#include "cache.h"
 * Return value:
			if (!strncasecmp(choice, menu_item->title, len)) {
			       clean_get_color(CLEAN_COLOR_PROMPT),

	CLEAN_COLOR_RESET = 0,
static int clean_cmd(void)
				*p = ' ';
	int flags;
	string_list_remove_empty_items(&del_list, 0);
			warning_errno(_(msg_warn_remove_failed), quoted.buf);
#include "help.h"
	return MENU_RETURN_NO_LOOP;
};
static const char *const builtin_clean_usage[] = {

	return MENU_RETURN_NO_LOOP;

};
				  &chosen);
		} else {
			prompt_help_cmd(opts->flags & MENU_OPTS_SINGLETON);
			if (!ignore_list[i]->len)
 * Copyright (C) 2007 Shawn Bohrer
	strbuf_release(&abs_path);
 * display menu stuff with number prefix and hotkey highlight
			if ((*chosen)[i] < 0)
	clean_print_color(CLEAN_COLOR_RESET);
	struct string_list_item *item;
		if (!quiet) {
		if (opts->flags & MENU_OPTS_SINGLETON) {
	return git_color_default_config(var, value, cb);
			continue;
				if (found) {
	const char *header;
}
		result = xmalloc(sizeof(int));
};
	if (changed)


	return nr;
 *         1          - select a single item
	/* set chosen as uninitialized */
 */
		int j = 0;
		}
			changed++;
		do {
		if (!confirm.len)
		OPT__DRY_RUN(&dry_run, N_("dry run")),
		rel = relative_path(ent->name, prefix, &buf);
					}
	const char *slot_name;
				continue;
		    "foo        - select item based on unique prefix\n"
		else
		}

		string_list_remove_empty_items(&del_list, 0);
			printf(dry_run ?  _(msg_would_skip_git_dir) : _(msg_skip_git_dir),
			if (res) {
			{'f', "filter by pattern",	0, filter_by_patterns_cmd},
			if (nr)
			ret = menus[*chosen].fn();
	char hotkey;
				N_("remove only ignored files")),
			clean_print_color(CLEAN_COLOR_ERROR);
		clean_print_color(CLEAN_COLOR_RESET);
	string_list_clear(&exclude_list, 0);

	int src, dst, ign;
	}
			errno = saved_errno;
	}
	case MENU_STUFF_TYPE_STRING_LIST:
 *


}
	int changed = -1, i;
	int i;
#define USE_THE_INDEX_COMPATIBILITY_MACROS
 *   - If user pressed CTRL-D (i.e. EOF), no selection returned.
static int filter_by_patterns_cmd(void)
 *
		for_each_string_list_item(string_list_item, (struct string_list *)stuff->stuff) {
		}
	clean_print_color(CLEAN_COLOR_HELP);
	return 0;
		}
	int ignored_only = 0, config_set = 0, errors = 0, gone = 1;
	struct string_list_item *string_list_item;

					strbuf_addch(&menu, *p);
			printf(_("Remove %s [y/N]? "), qname);

	int nr = 0;

				is_range = 0;
				printf(dry_run ? _(msg_would_remove) : _(msg_remove), qname);

	for_each_string_list_item(item, &del_list) {
		 * we might have removed this as part of earlier
	free(chosen);

		qname = quote_path_relative(item->string, NULL, &buf);
