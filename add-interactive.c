	command_t command;
	const char *modified_fmt, *color, *reset;
	clear_add_i_state(&s);
	fd = repo_hold_locked_index(s->r, &index_lock, LOCK_REPORT_ON_ERROR);
	    repo_read_index_preload(r, ps, 0) < 0)
	if (repo_read_index(r) < 0)
			 struct prefix_item_list *files,
			       const struct pathspec *ps)
		 * work than strictly necessary.
		res = error(_("could not write index"));

		struct string_list_item *item = sorted_item->util;
		const char *string;

	FREE_AND_NULL(s->interactive_diff_filter);


		res = run_command_v_opt(args.argv, 0);
	if (is_initial)
		list->sorted.items[i].string = list->items.items[i].string;
 * a unique prefix (if any) is determined for each item.
#include "revision.h"
		    (uintmax_t)list->items.nr, (uintmax_t)list->sorted.nr);
	struct object_id head_oid;

		SINGLETON = (1<<0),
		res = repo_refresh_and_write_index(s->r, REFRESH_QUIET, 0, 1,
					if (isdigit(*(++endp)))
		struct dir_entry *ent = dir.entries[i];

		      struct list_and_choose_options *opts)
	}
	ssize_t res = singleton ? LIST_AND_CHOOSE_ERROR : 0;
	strbuf_reset(&d->index);
	}
					 NULL, NULL, NULL) < 0)
	return 0;
	for (i = j = 0; i < files->items.nr; i++)
{

	opts->prompt = N_("Update");
	struct print_file_item_data print_file_item_data = {
	 * When color was asked for, use the prompt color for
	setup_standard_excludes(&dir);
						from = -1;

		if (filter == INDEX_ONLY)

	string_list_clear(&list->sorted, 0);
	return res;
			if (!sep) {
	s->use_color = want_color(s->use_color);
	if (count <= 0)
		if ((immediate && res != LIST_AND_CHOOSE_ERROR) ||
		}

}
	FREE_AND_NULL(list->selected);
 * will be set to zero if no valid, unique prefix could be found.
			if (s->skip_unseen)
	size_t *len = p->util;
		 * maximal length of the prefix? Or is the current character a
	int res = 0, fd;
	size_t unmerged_count = 0, binary_count = 0;

		goto finish_revert;
		item = list->sorted.items[index].util;
				res = LIST_AND_CHOOSE_QUIT;
	    is_valid_prefix(item->string, c->prefix_length)) {
				 opts->print_item_data);
		else
				free(item);
	list->sorted.nr = list->sorted.alloc = list->items.nr;

		opt.def = is_initial ?

 * Returns the selected index in singleton mode, the number of selected items

		 * prefix.
	}
	strbuf_release(&header);
				if (endp == p + sep)
		}
			entry->item = s->files->items[s->files->nr - 1].util;
	opts->prompt = N_("Review diff");
}
			       &unmerged_count, &binary_count) < 0)
	struct string_list sorted;


		if (index_name_is_other(r->index, ent->name, ent->len)) {
{
		adddel->add = stat.files[i]->added;

			rev.diffopt.flags.ignore_dirty_submodules = 1;
		}
	strbuf_release(&print_file_item_data.name);
			}
#include "diffcore.h"

		       const char *slot_name, char *dst,
	if (!files->items.nr) {
	struct strbuf buf = STRBUF_INIT;
				char *endp;
}
	else if (index > 0 &&
	init_color(r, s, "old", s->file_old_color,
		BUG("singleton requires immediate");
}
			opts->print_help(s);
	if (!files->items.nr) {
 * duplicating the strings, with the `util` field pointing at a structure whose
struct prefix_item_list {
		struct argv_array args = ARGV_ARRAY_INIT;
	if (binary_count)


{
	color_fprintf_ln(stdout, s->help_color, "-...       - %s",
						    struct pathname_entry, ent);
			}
	free_diffstat_info(&stat);
			adddel->binary = 1;

	}
	count = list_and_choose(s, files, opts);
	}
	}
			       struct string_list_item *item,
	struct diffstat_t stat = { 0 };
		strbuf_addstr(buf, no_changes);
		struct adddel *adddel, *other_adddel;
		s->use_color =

	struct string_list *files;
				 * Note: `from` is 0-based while the user input
 * sorted by `find_unique_prefixes()`.
	}

		return -1;
			fprintf(stderr, _("Only binary files changed.\n"));
		}
			extend_prefix_length(item, sorted_item[1].string,
			break;
			       struct prefix_item_list *items,
		if ((opts->columns) && ((i + 1) % (opts->columns))) {
	if (!files->items.nr) {
}
	free(key);
	init_color(r, s, "error", s->error_color, GIT_COLOR_BOLD_RED);
	color_fprintf_ln(stdout, s->help_color, "status        - %s",
	struct prefix_item_list files = PREFIX_ITEM_LIST_INIT;
	if (count <= 0) {
		  *prefix != '?'));				/* prompt help */

	color_fprintf_ln(stdout, help_color, "foo        - %s",
#define PREFIX_ITEM_LIST_INIT \
}

			 _("select item based on unique prefix"));

			 _("(empty) select nothing"));
	struct list_options list_opts;
		struct diff_filespec *one = q->queue[i]->one;
				}
			    (int)c->prefix_length, item->string, d->reset,

 * the `string_item_list` of the first `string_list`. It  will be populated and
			      const struct hashmap_entry *he1,
		return error(_("could not read index"));
			 _("select a range of items"));
}
	color_fprintf_ln(stdout, s->help_color, "2-3,6-9    - %s",

		return -1;
/*
	opts->flags = IMMEDIATE;
	int is_initial = !resolve_ref_unsafe("HEAD", RESOLVE_REF_READING,

		}
	diffopt.output_format = DIFF_FORMAT_CALLBACK;
			if (p[sep])
			       PATHSPEC_ALL_MAGIC & ~PATHSPEC_LITERAL,
	if (repo_config_get_value(r, "color.interactive", &value))
static void print_command_item(int i, int selected,

static void init_color(struct repository *r, struct add_i_state *s,
			 _("(empty) finish selecting"));
	const char *highlighted = NULL;
#include "refs.h"
#include "dir.h"
		else {
		{ "update", run_update },
		files->items.nr = j;
			       struct list_and_choose_options *opts)
				continue;
		      struct prefix_item_list *files,
	struct print_command_item_data data = { "[", "]" };

{
			 _("select multiple ranges"));
		return;
}
	}
};

	opts->prompt = N_("Patch update");
		const char *name = stat.files[i]->name;
	}
finish_revert:
		diff_get_color(s->use_color, DIFF_CONTEXT));
		struct string_list_item *sorted_item = list->sorted.items + i;
		argv_array_clear(&args);
				 * boundary.
		if (i + 1 < list->sorted.nr)
	print_file_item_data.color = data.color;
			 struct list_and_choose_options *opts);
		oidcpy(&oid, s->r->hash_algo->empty_tree);

			}
	int res = 0;

	diffopt.flags.override_submodule_config = 1;
{
	d->only_names = 1;
struct file_item {
	if (!last_lf)
	for (i = 0; i < stat.nr; i++) {
		if (!c || ++*len > max_length || !isascii(c)) {
}
		printf(Q_("added %d path\n",
			      size_t *binary_count)

		if (git_read_line_interactively(&input) == EOF) {
		struct command_item *util = xcalloc(sizeof(*util), 1);

		oidcpy(&oid, &tree->object.oid);
#include "prompt.h"
	list(s, &files->items, NULL, &opts->list_opts);
			      const struct pathspec *ps,
	if (discard_index(r->index) < 0 ||
		while (*len < list->min_length) {
	if (do_diff_cache(&oid, &diffopt))
			}
	else
	struct command_item *util = item->util;
	}
	{ STRING_LIST_INIT_DUP, STRING_LIST_INIT_NODUP, NULL, 1, 4 }
				 "--", NULL);
	if (s.use_color) {


	return 0;
	}
	INDEX_ONLY = 2,
	strbuf_addf(&d->buf, d->modified_fmt, d->index.buf, d->worktree.buf,

		opts->print_item(i, selected ? selected[i] : 0, list->items + i,
		{ "diff", run_diff },
			paths[j++] = files->items.items[i].string;
			 _("select a numbered item"));

	if (!files->items.nr) {

		 * We expect `prefix` to be NUL terminated, therefore this
			  "reverted %d paths\n", count), (int)count);
struct list_options {
			      size_t *unmerged_count,
			}
		return error(_("could not read index"));
	struct lock_file index_lock;
		    " vs %"PRIuMAX")",
	color_fprintf_ln(stdout, s->help_color, "           - %s",
		 starts_with(list->sorted.items[index + 1].string, string))
	void (*print_item)(int i, int selected, struct string_list_item *item,
		printf(" %2d: %s%.*s%s%s", i + 1,
	if (fd < 0) {


		{ "add untracked", run_add_untracked },
	struct object_id oid;
				free(files->items.items[i].string);
}
		goto finish_add_untracked;
			      enum modified_files_filter filter,
			  "updated %d paths\n", count), (int)count);
	init_color(r, s, "header", s->header_color, GIT_COLOR_BOLD);
	color_fprintf_ln(stdout, s->help_color, "3-5        - %s",

			ssize_t from = -1, to = -1;
 *
	color_fprintf_ln(stdout, s->help_color, "patch         - %s",
					     list->max_length);



			if (!other_adddel->unmerged)
	strbuf_release(&print_file_item_data.buf);
		char c = p->string[*len];
	list->sorted.items = xmalloc(st_mult(sizeof(*list->sorted.items),
		const char *name = files->items.items[i].string;
	memset(s, 0, sizeof(*s));
 *
	git_config_get_string("interactive.difffilter",
	int i, last_lf = 0;
{
	init_color(r, s, "fraginfo", s->fraginfo_color,
	putchar('\n');
		s->use_color = -1;
						to = items->items.nr;

		if (s.mode == FROM_INDEX)

		putchar('\n');
	struct file_item *item;
				if (!*p)
	void *print_item_data;
	for (i = 0; i < dir.nr; i++) {
		}
			util = NULL;
						 _("ignoring unmerged: %s"),
					/* extra characters after the range? */
		entry = hashmap_get_entry_from_hash(&s->file_map, hash, name,

			int choose = 1;
	init_color(r, s, "new", s->file_new_color,
		color_fprintf(stdout, s->prompt_color, "%s", opts->prompt);
	struct print_file_item_data *d = print_file_item_data;
		    add_file_to_index(s->r->index, name, 0) < 0) {
	const char *value;
			       struct diff_options *options,

	git_config_get_bool("interactive.singlekey", &s->use_single_key);

		}
			entry = xcalloc(sizeof(*entry), 1);

			 _("add working tree state to the staged set of changes"));


static int run_add_untracked(struct add_i_state *s, const struct pathspec *ps,
			strbuf_add(&buf, ent->name, ent->len);

struct print_command_item_data {
	if (!list->nr)

		       d->color, (int)util->prefix_length, item->string,


	} command_list[] = {
						 _("Huh (%s)?"), p);

			    item->string + c->prefix_length);
	/*
{
};



			 _("select item based on unique prefix"));
{
 * `LIST_AND_CHOOSE_QUIT` is returned.
{
	if (count > 0) {
				p++;
				to = items->items.nr;
/* filters out prefixes which have special meaning to list_and_choose() */
	return res;
			      const void *name)
		putchar('\n');
				to = items->items.nr;

	size_t i;
		    !strcmp(input.buf, "*"))
		if (!input.len)
	string_list_sort(&list->sorted);
		struct pathname_entry *entry;
	FREE_AND_NULL(s->interactive_diff_algorithm);
		struct file_item *file_item;
};

				 oid_to_hex(!is_initial ? &oid :
	for (i = 0; i < list->sorted.nr; i++) {
#include "config.h"
			add_index_entry(opt->repo->index, ce, add_flags);
		goto finish_revert;

	color_fprintf_ln(stdout, s->help_color, "update        - %s",
		}
		printf(Q_("updated %d path\n",
		 struct list_options *opts)
				p[sep++] = '\0';
static void revert_from_diff(struct diff_queue_struct *q,

	if (!singleton) {
	fd = repo_hold_locked_index(s->r, &index_lock, LOCK_REPORT_ON_ERROR);
	struct list_and_choose_options main_loop_opts = {
	hashmap_free_entries(&s.file_map, struct pathname_entry, ent);
		adddel = s->mode == FROM_INDEX ?

			       struct prefix_item_list *files,
			    (uintmax_t)ad->add, (uintmax_t)ad->del);
	color_fprintf_ln(stdout, s->help_color, "1          - %s",
					     &head_oid, NULL);
		list(s, &items->items, items->selected, &opts->list_opts);
			if (!ce)
	if (!res &&
	size_t i;

		init_revisions(&rev, NULL);
			       void *data)
				else if (*endp == '-') {
			strbuf_reset(&buf);
	struct diff_options diffopt = { NULL };


	}
	opts->flags = 0;
	for (i = 0; i < files->items.nr; i++) {
	for (;;) {
{
				files->items.items[j++] = files->items.items[i];
	if (get_modified_files(s->r, WORKTREE_ONLY, files, ps, NULL, NULL) < 0)
	fd = repo_hold_locked_index(s->r, &index_lock, LOCK_REPORT_ON_ERROR);
			empty_tree_oid_hex() : oid_to_hex(&head_oid);
 *
 * strings but simply reuses the first one's, with the `util` field pointing at
				*len = 0;
struct pathname_entry {
	return prefix_len && prefix &&
			putchar('\t');
		*unmerged_count = s.unmerged_count;
	color_fprintf_ln(stdout, s->help_color, "%s",
				free(item);
	} flags;
		diff_get_color(s->use_color, DIFF_FILE_NEW));
		for (i = 0; i < files->items.nr; i++)
	}
static int run_patch(struct add_i_state *s, const struct pathspec *ps,
{
#define LIST_AND_CHOOSE_QUIT  (-2)

 * That `prefix_length` field will be computed by `find_unique_prefixes()`; It

	if (!*len || memcmp(p->string, other_string, *len))
		return -1;
	if (!res)
				 * one. We do not have to decrement `to` even
		return -1;
struct print_file_item_data {
	int is_initial = !resolve_ref_unsafe("HEAD", RESOLVE_REF_READING, &oid,
	d->only_names = 0;
			entry->name = s->files->items[s->files->nr - 1].string;
			s.mode = (i == 0) ? FROM_INDEX : FROM_WORKTREE;

	init_color(r, s, "help", s->help_color, GIT_COLOR_BOLD_RED);
				argv_array_push(&args,
static int run_revert(struct add_i_state *s, const struct pathspec *ps,
	strbuf_release(&print_file_item_data.index);
{


}

				 */
	unsigned only_names:1;

	}
			res = error(_("could not stage '%s'"), name);
static int get_modified_files(struct repository *r,

	ALLOC_ARRAY(paths, count + 1);
}
		       NULL, paths);
		putchar('\n');

#include "add-interactive.h"

}
			&file_item->index : &file_item->worktree;
static int run_status(struct add_i_state *s, const struct pathspec *ps,
{
	else
		      struct prefix_item_list *files,
	init_add_i_state(&s, r);


		 * `strcspn()` call is okay, even if it might do much more
		}
	}
		 color_parse(value, dst))
	string_list_clear(&list->items, 1);
		}
		container_of(he1, const struct pathname_entry, ent);

					to = from + 1;
		int hash = strhash(name);
			 _("choose all items"));
			for (; from < to; from++)
		BUG("prefix_item_list in inconsistent state (%"PRIuMAX
		{ "revert", run_revert },
#define LIST_AND_CHOOSE_ERROR (-1)
	int res = 0, fd;
	s->r = r;

					     list->max_length);

		       const char *default_color)

 * The second `string_list` is called `sorted` and does _not_ duplicate the
	if (singleton && !immediate)
{
				 "%s", opts->header);
			adddel->unmerged = 1;
		res = -1;
	const char **paths;
	prefix_item_list_clear(&commands);
		else
	struct prefix_item_list commands = PREFIX_ITEM_LIST_INIT;
	    repo_refresh_and_write_index(r, REFRESH_QUIET, 0, 1,
				die(_("make_cache_entry failed for path '%s'"),
	struct list_and_choose_options opts = {

				free(files->items.items[i].string);
	for (;;) {
	color_fprintf_ln(stdout, s->help_color, "diff          - %s",
			hashmap_entry_init(&entry->ent, hash);
 */
	strbuf_addstr(&header, "      ");
				struct adddel *ad, const char *no_changes)
	}
	int columns;

	/* While the diffs are ordered already, we ran *two* diffs... */
/*

 */
			break;

	string_list_sort(&files->items);
			} else
	else if (repo_config_get_value(r, key, &value) ||

		strbuf_reset(&d->name);
		return;
			} else if (isdigit(*p)) {
static ssize_t find_unique(const char *string, struct prefix_item_list *list)

		if (files->selected[i] &&
struct list_and_choose_options {
	const char *name;
	int i;
	return res;

			last_lf = 0;
	else
	/* Avoid reallocating incrementally */
	const char *reference;
	struct object_id oid;
	if (c->prefix_length > 0 &&
	struct {
		 starts_with(list->sorted.items[index - 1].string, string))
		if (!(one->mode && !is_null_oid(&one->oid))) {
		parse_pathspec(&ps_selected,
		res = run_add_p(s->r, ADD_P_ADD, NULL, &ps_selected);
	else if (index + 1 < list->sorted.nr &&
		diff_flush(&diffopt);
		if (!entry) {

};
#include "run-command.h"
		      struct prefix_item_list *files,
	struct lock_file index_lock;
{
			run_diff_files(&rev, 0);
		{ "help", run_help },
	struct strbuf input = STRBUF_INIT;
		i = list_and_choose(&s, &commands, &main_loop_opts);

	init_color(r, s, "context", s->context_color,
				from = 0;
			putchar('\n');
		rev.diffopt.format_callback = collect_changes_cb;
		return -1;
				if (from >= 0)

	int i, add_flags = ADD_CACHE_OK_TO_ADD | ADD_CACHE_OK_TO_REPLACE;
static int run_update(struct add_i_state *s, const struct pathspec *ps,
	}
	}
				break;
	color_fprintf_ln(stdout, help_color, "           - %s",
		 (*prefix != '*' &&				/* "all" wildcard */
		size_t *len = item->util;
{

{

		 * multi-byte UTF-8 one? If so, there is no valid, unique
	if (ad->binary)
 * It is implemented in the form of a pair of `string_list`s, the first one
			*len = 0;
	clear_pathspec(&diffopt.pathspec);

		struct pathspec ps_selected = { 0 };
	 * highlighting, otherwise use square brackets.
		else {

finish_add_untracked:

		return 0;
};
	const char *help_color = s->help_color;
		struct rev_info rev;
		if (i < 0 || i >= commands.items.nr)
{

				choose = 0;
				continue;
			if (!other_adddel->binary)
		if (i == LIST_AND_CHOOSE_QUIT || (util && !util->command)) {

	count = list_and_choose(s, files, opts);
	else
};
	ssize_t count, i;
		{ 0, NULL, print_file_item, &print_file_item_data },
			util = commands.items.items[i].util;
	}


		if (!strcmp(input.buf, "?")) {

		      struct list_and_choose_options *opts)
				from = find_unique(p, items);

{
 * A "prefix item list" is a list of items that are identified by a string, and
	size_t count, i;
	const struct pathname_entry *e1 =
	}
	else

		printf(_("No untracked files.\n"));

		res = -1;
		NULL, 0, choose_prompt_help
	for (i = 0; i < ARRAY_SIZE(command_list); i++) {
		warning(_("could not refresh index"));
		printf("%c%2d: %s", selected ? '*' : ' ', i + 1,
			last_lf = 1;
		}
			if (files->selected[i])
			if (item->index.binary || item->worktree.binary) {

 * first field must be `size_t prefix_length`.
		if (util)
		      struct prefix_item_list *files,
				break;
		       PATHSPEC_PREFER_FULL | PATHSPEC_LITERAL_PATH,
	ssize_t count, i, j;
		if (c != other_string[*len - 1])
static void add_file_item(struct string_list *files, const char *name)
			continue;
	git_config_get_string("diff.algorithm",
	int index = string_list_find_insert_index(&list->sorted, string, 1);
	strbuf_release(&buf);
	for (i = 0; i < list->nr; i++) {

	unsigned skip_unseen:1;
}
#include "color.h"
		return;
			 _("pick hunks and update selectively"));
	if (index < 0)
		return;
	const struct pathname_entry *e2 =
struct collection_status {
}
			res = error(_("could not stage '%s'"), name);
		container_of(he2, const struct pathname_entry, ent);
	find_unique_prefixes(items);
		    struct prefix_item_list *files,

					if (endp != p + sep)
	if (get_modified_files(s->r, WORKTREE_ONLY, files, ps,
	count = list_and_choose(s, files, opts);
				argv_array_push(&args,
		printf(" %2d: %s", i + 1, item->string);
		putchar('\n');
	};
		return -1;
	opts->prompt = N_("Add untracked");
	for (i = 0; i < files->items.nr; i++) {
		strcspn(prefix, " \t\r\n,") >= prefix_len &&	/* separators */
	color_fprintf_ln(stdout, help_color, "1          - %s",


}
	return res;
		IMMEDIATE = (1<<1),
	uintmax_t add, del;
	putchar('\n');
	struct hashmap_entry ent;
			 _("show paths with changes"));
	}
	compute_diffstat(options, &stat, q);
			remove_file_from_index(opt->repo->index, one->path);

						   NULL, NULL, NULL);

				p++;
		      struct list_and_choose_options *opts)
			copy_pathspec(&rev.prune_data, ps);
		for (i = j = 0; i < files->items.nr; i++) {
			if (to > items->items.nr)

		strbuf_reset(&input);
}
			extend_prefix_length(item, sorted_item[-1].string,
	color_fprintf_ln(stdout, help_color, "%s", _("Prompt help:"));
typedef int (*command_t)(struct add_i_state *s, const struct pathspec *ps,
		putchar('\n');
				/*
	struct add_i_state s = { NULL };

		argv_array_pushl(&args, "git", "diff", "-p", "--cached",
					     list->items.nr));
				s->unmerged_count++;
		s.skip_unseen = filter && i;
	struct strbuf header = STRBUF_INIT;
			printf(_("note: %s is untracked now.\n"), one->path);
			if (immediate)

			 _("unselect specified items"));
	if (get_modified_files(s->r, INDEX_ONLY, files, ps, NULL, NULL) < 0)
		struct cache_entry *ce;
		item = list->sorted.items[-1 - index].util;
			if (sep == 1 && *p == '*') {
			 _("revert staged set of changes back to the HEAD version"));
	struct string_list items;

		/*
			   void *print_item_data);
			&file_item->worktree : &file_item->index;
{
		       highlighted ? highlighted : item->string);
		if (stat.files[i]->is_binary) {
	size_t prefix_length;
		else


		if (ps)
static int pathname_entry_cmp(const void *unused_cmp_data,
	else if (ad->seen)
		*prefix != '-' &&				/* deselection */
		!isdigit(*prefix) &&				/* selection */
	return res;
			s.mode = (i == 0) ? FROM_WORKTREE : FROM_INDEX;
		struct command_item *util;
{
			git_config_colorbool("color.interactive", value);
				res = from;
			      &s->interactive_diff_filter);
		STRBUF_INIT, STRBUF_INIT, STRBUF_INIT, STRBUF_INIT

		rev.diffopt.format_callback_data = &s;
		 */

			       PATHSPEC_LITERAL_PATH, "", args.argv);
		res = error(_("could not write index"));
			ce = make_cache_entry(opt->repo->index, one->mode,
		clear_pathspec(&ps_selected);
	if (get_untracked_files(s->r, files, ps) < 0)
	/* Format the item with the prefix highlighted. */
					items->selected[from] = choose;
				 const char *other_string, size_t max_length)
		    highlighted ? highlighted : item->string);
	parse_pathspec(&diffopt.pathspec, 0,
struct adddel {
	}
		putchar('\n');
void clear_add_i_state(struct add_i_state *s)
	count = list_and_choose(s, files, opts);
		*binary_count = s.binary_count;
		printf(Q_("reverted %d path\n",
			res = 0;
	s->use_color = -1;
	if (unmerged_count)
static void choose_prompt_help(struct add_i_state *s)
	strbuf_reset(&d->buf);
				break;
	FREE_AND_NULL(s->interactive_diff_algorithm);
		      struct list_and_choose_options *opts)
static void list(struct add_i_state *s, struct string_list *list, int *selected,
	if (!util->prefix_length ||

}
			break;

			 _("Prompt help:"));
	add_pattern_list(&dir, EXC_CMDL, "--exclude option");
static void extend_prefix_length(struct string_list_item *p,
	strbuf_release(&input);
			     struct diff_options *opt, void *data)
struct command_item {
	size_t count, i, j;
		setup_revisions(0, NULL, &rev, &opt);
	for (i = 0; i < 2; i++) {

	if (!res)
	}


		    struct list_and_choose_options *opts)

 * If an error occurred, returns `LIST_AND_CHOOSE_ERROR`. Upon EOF,
			clear_pathspec(&rev.prune_data);
			hashmap_add(&s->file_map, &entry->ent);
enum modified_files_filter {
			/* Input that begins with '-'; de-select */


	size_t prefix_length;



		argv_array_clear(&args);
					     NULL);
}
		adddel->seen = 1;
				from = strtoul(p, &endp, 10) - 1;
	struct hashmap file_map;
	    !is_valid_prefix(item->string, util->prefix_length))
				if (items->selected[from] != choose) {
		for (;;) {
				 item->worktree.unmerged) {
			      struct prefix_item_list *files,
		"%12s %12s %s", NULL, NULL,
	    repo_read_index(r) < 0 ||
	init_color(r, s, "prompt", s->prompt_color, GIT_COLOR_BOLD_BLUE);
	WORKTREE_ONLY = 1,
	const char *header;
	struct file_item *item = xcalloc(sizeof(*item), 1);

	color_fprintf_ln(stdout, s->help_color, "foo        - %s",


	int singleton = opts->flags & SINGLETON;
		if (!tree) {
		{ "patch", run_patch },

		return -1;
		dst[0] = '\0';
	};
			goto finish_revert;
			res = error(_("Could not parse HEAD^{tree}"));
		res = -1;
	opts.list_opts.header = header.buf;
	FREE_AND_NULL(s->interactive_diff_filter);
		N_("What now"), SINGLETON | IMMEDIATE, command_prompt_help
		strbuf_addf(buf, "+%"PRIuMAX"/-%"PRIuMAX,
						files->items.items[i].string);
static int get_untracked_files(struct repository *r,
static int run_diff(struct add_i_state *s, const struct pathspec *ps,
{
		 * Is `p` a strict prefix of `other`? Or have we exhausted the
		}

	size_t min_length, max_length;
	if (opts->header)
		tree = parse_tree_indirect(&oid);
	color_fprintf_ln(stdout, s->help_color, "*          - %s",
	if (fd < 0) {

	};
		highlighted = d->name.buf;
	for (i = 0; i < list->items.nr; i++) {
{
		}
static void render_adddel(struct strbuf *buf,
		struct argv_array args = ARGV_ARRAY_INIT;
	size_t count, i;
	unsigned seen:1, unmerged:1, binary:1;
			if (*p == '-') {
};
static void print_file_item(int i, int selected, struct string_list_item *item,
	if (unmerged_count || binary_count) {

		for (i = 0; i < files->items.nr; i++)
	struct adddel index, worktree;
}
{
	    write_locked_index(s->r->index, &index_lock, COMMIT_LOCK) < 0)
	string_list_clear(&list->sorted, 0);
		fflush(stdout);
	 */
	const char *prompt;

		{ "quit", NULL },
	if (!s->use_color)
};
				sep--;
		}
				color_fprintf_ln(stdout, s->error_color,
	}

	printf("%c%2d: %s", selected ? '*' : ' ', i + 1, d->buf.buf);
		string_list_append(&commands.items, command_list[i].string)
	int i;
			run_diff_index(&rev, 1);
	prefix_item_list_clear(files);
	opts->prompt = N_("Revert");
	strbuf_release(&print_file_item_data.worktree);
			->util = util;
	return 0;

	free(paths);
		}
	diffopt.format_callback = revert_from_diff;
			if (from < 0 || from >= items->items.nr ||
				color_fprintf_ln(stderr, s->error_color,

		color_fprintf_ln(stdout, s->header_color,
	return strcmp(e1->name, name ? (const char *)name : e2->name);
	diffopt.repo = s->r;
	}

	struct print_command_item_data *d = print_command_item_data;
{
	int immediate = opts->flags & IMMEDIATE;
}
			if (files->selected[i])
			break;
					to = from + 1;

		return -1;
	putchar('\n');
			add_file_item(s->files, name);
			if (!c || !isascii(c)) {
	if (list->items.nr != list->sorted.nr)

		    struct prefix_item_list *unused_files,
		command_t command;
	size_t unmerged_count, binary_count;
				s->binary_count++;
		/*
	res = run_status(&s, ps, &files, &opts);

		return -1;
		diff_get_color(s->use_color, DIFF_FILE_OLD));
	strbuf_reset(&d->worktree);
			} else if (singleton) {
	print_file_item_data.reset = data.reset;
	char *key = xstrfmt("color.interactive.%s", slot_name);
		   diff_get_color(s->use_color, DIFF_FRAGINFO));
	struct file_item *c = item->util;
	return res;
		strbuf_addf(&d->name, "%s%.*s%s%s", d->color,
	struct string_list_item *item;
			putchar('\n');

	return item - list->items.items;
	if (list->sorted.nr == list->items.nr)

		{ "status", run_status },
		goto finish_add_untracked;
	struct strbuf buf, name, index, worktree;
		{ 4, N_("*** Commands ***"), print_command_item, &data },

						 files->items.items[i].string);
	const char *value;
{
		if (ps)
						to = strtoul(endp, &endp, 10);
#include "lockfile.h"
	putchar('\n');

		    _("staged"), _("unstaged"), _("path"));
	return 0;
	prefix_item_list_clear(files);
	paths[j] = NULL;
static void prefix_item_list_clear(struct prefix_item_list *list)


	string_list_append(files, name)->util = item;
	struct tree *tree;
	if (discard_index(r->index) < 0 ||
		if (stat.files[i]->is_unmerged) {
				 *
	color_fprintf_ln(stdout, s->help_color, "revert        - %s",
		*len = 0;



		struct setup_revision_opt opt = { 0 };
}
			    void *print_file_item_data)
	const char *color, *reset;
		strbuf_addstr(buf, _("binary"));
	color_fprintf_ln(stdout, s->help_color, "add untracked - %s",
			       void *print_command_item_data)
	}
{
}
	if (get_modified_files(s->r, INDEX_ONLY, files, ps, NULL, NULL) < 0)
			res = util->command(&s, ps, &files, &opts);
			 _("view diff between HEAD and index"));
static ssize_t list_and_choose(struct add_i_state *s,
						files->items.items[i].string);
static void collect_changes_cb(struct diff_queue_struct *q,

};
					break;
			      &s->interactive_diff_algorithm);
	}
		list->sorted.items[i].util = list->items.items + i;

				 * if it is 0-based because it is an exclusive
		strlcpy(dst, default_color, COLOR_MAXLEN);
		if (i > 0)

};
	void (*print_help)(struct add_i_state *s);
	int res = 0, fd;
			 _("add contents of untracked files to the staged set of changes"));
static int run_help(struct add_i_state *s, const struct pathspec *unused_ps,
	enum { FROM_WORKTREE = 0, FROM_INDEX = 1 } mode;
	}
		     struct list_and_choose_options *opts)
	prefix_item_list_clear(&files);
	enum {
		return 0;

		other_adddel = s->mode == FROM_INDEX ?
	struct collection_status *s = data;
	count = list_and_choose(s, files, opts);

		data.color = s.prompt_color;
	else {
		util->command = command_list[i].command;
		const char *name = files->items.items[i].string;
		file_item = entry->item;
}

					res += choose ? +1 : -1;
		(prefix_len != 1 ||
			/* `from` is inclusive, `to` is exclusive */
		if (files->selected[i])
	int *selected; /* for multi-selections */
	}
		return;

				    one->path);
	init_color(r, s, "reset", s->reset_color, GIT_COLOR_RESET);
		res = -1;
 * otherwise.
#include "cache.h"
			size_t sep = strcspn(p, " \t\r\n,");
	}
static int is_valid_prefix(const char *prefix, size_t prefix_len)


	if (count <= 0)
	struct lock_file index_lock;
	strbuf_addf(&header, print_file_item_data.modified_fmt,
static void find_unique_prefixes(struct prefix_item_list *list)
#include "string-list.h"
					    s->r->hash_algo->empty_tree),
static void command_prompt_help(struct add_i_state *s)
	s.files = &files->items;

			add_file_item(&files->items, buf.buf);
		     struct prefix_item_list *files,
	else if (index < list->sorted.nr)
		free(items->selected);
			break;
		diffcore_std(&diffopt);
}
		adddel->del = stat.files[i]->deleted;
				       COMMIT_LOCK) < 0)
	return res;
		    struct list_and_choose_options *unused_opts)
			struct file_item *item = files->items.items[i].util;
		return 0;
	putchar('\n');
			if (from < 0) {
			} else if (item->index.unmerged ||
{
					else
}
	int res = 0;
		if (files->selected[i] &&
				 * A range can be specified like 5-7 or 5-.
			printf(_("Bye.\n"));
			 _("select a single item"));
	for (;;) {
	struct dir_struct dir = { 0 };


	struct collection_status s = { 0 };
	render_adddel(&d->worktree, &c->worktree, _("nothing"));

{
	NO_FILTER = 0,
		rev.diffopt.output_format = DIFF_FORMAT_CALLBACK;
					      &one->oid, one->path, 0, 0);
}
	if (!res)
		}
 *


		fputs(singleton ? "> " : ">> ", stdout);
	if (!res && write_locked_index(s->r->index, &index_lock, COMMIT_LOCK) < 0)
	int is_initial = !resolve_ref_unsafe("HEAD", RESOLVE_REF_READING, &oid,
			char c = item->string[(*len)++];
	if (!q->nr)
}
		       d->reset, item->string + util->prefix_length);
			  "added %d paths\n", count), (int)count);
			}
	render_adddel(&d->index, &c->index, _("unchanged"));

			    (singleton && from + 1 != to)) {
		char *p;
};

		}
	int res = 0;
		return 0;
int run_add_i(struct repository *r, const struct pathspec *ps)
	}
	if (count > 0) {
		data.reset = s.reset_color;
	else {
		} else {
		if (binary_count)

		return 0;
	if (!files->items.nr) {
	fill_directory(&dir, r->index, ps);
			break;

}
	for (i = 0; i < q->nr; i++) {
		    add_file_to_index(s->r->index, name, 0) < 0) {
void init_add_i_state(struct add_i_state *s, struct repository *r)
	struct print_file_item_data *d = opts->list_opts.print_item_data;

			break;
	ssize_t i;
		p = input.buf;

	if (!res && write_locked_index(s->r->index, &index_lock,
			      const struct hashmap_entry *he2,
			break;
			p += sep;
		goto finish_add_untracked;
	if (get_modified_files(s->r, NO_FILTER, files, ps, NULL, NULL) < 0)
		return -1;
	hashmap_init(&s.file_map, pathname_entry_cmp, NULL, 0);
					     NULL);
	if (d->only_names) {
				}
		 */

			fprintf(stderr, _("No changes.\n"));
		CALLOC_ARRAY(items->selected, items->items.nr);
	if (fd < 0) {
		}
	};


				 * is 1-based, hence we have to decrement by

