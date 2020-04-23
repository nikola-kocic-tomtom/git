	e->pattern = strbuf_detach(path, NULL);
	result = write_patterns_and_update(&pl);
{
		if (!strcmp(argv[0], "set"))
}
	struct pattern_entry *e = xmalloc(sizeof(*e));

	o.fn = oneway_merge;
	git_config_set_in_file_gently(config_path,
				strbuf_setlen(&line, 0);
		mode = MODE_CONE_PATTERNS;
		add_patterns_from_input(&pl, argc, argv);
	if (line->buf[0] != '/')
					pe->pattern, &buffer) ||
	struct string_list sl = STRING_LIST_INIT_DUP;
		OPT_END(),
	resolve_undo_clear_index(r->index);
	core_apply_sparse_checkout = 1;
				   struct pattern_list *pl)
		free(pattern);
	char *sparse_filename = get_sparse_checkout_filename();
					pe->pattern, &buffer)) {
	repo_hold_locked_index(r, &lock_file, LOCK_DIE_ON_ERROR);


		fprintf(fp, "\n");


		else
				   strihash(e->pattern) :
{
			add_patterns_literal(argc, argv, &pl);
	insert_recursive_pattern(pl, line);
	res = add_patterns_from_file_to_list(sparse_filename, "", 0, &pl, NULL);
			return sparse_checkout_set(argc, argv, prefix, REPLACE);
	o.head_idx = -1;
	}
				      LOCK_DIE_ON_ERROR);
	o.src_index = r->index;
	if (get_oid("HEAD", &oid)) {
				      "core.sparseCheckout",
			     builtin_sparse_checkout_usage,
			     builtin_sparse_checkout_set_options,

	}
	setup_work_tree();
	struct hashmap_iter iter;

				}
		set_config(MODE_ALL_PATTERNS);
		struct string_list sl = STRING_LIST_INIT_DUP;

	sparse_filename = get_sparse_checkout_filename();

	for (i = 0; i < sl.nr; i++) {
		error(_("failed to set extensions.worktreeConfig setting"));
		die(_("error while refreshing working directory"));
		int i;
			strbuf_addstr(&buffer, pe->pattern);
	hashmap_for_each_entry(&existing.recursive_hashmap, &iter, pe, ent) {
	result = update_working_directory(pl);
		rollback_lock_file(&lk);
};
		hashmap_entry_init(&e->ent,
	hashmap_init(&pl.recursive_hashmap, pl_hashmap_cmp, NULL, 0);
static void insert_recursive_pattern(struct pattern_list *pl, struct strbuf *path)
	if (init_opts.cone_mode) {
					   &existing, NULL))
	}
		strbuf_addch(&final, *p);


		mode = MODE_ALL_PATTERNS;
	string_list_clear(&sl, 0);
	struct hashmap_iter iter;
	return strbuf_detach(&final, NULL);
				   builtin_sparse_checkout_options);
	}
			return sparse_checkout_set(argc, argv, prefix, ADD);

{
{
	char *sparse_filename;
	return 0;
		return result;
	int result;
	commit_lock_file(&lk);
}
} init_opts;

static char const * const builtin_sparse_checkout_init_usage[] = {
	struct pattern_list pl;
	}
#include "quote.h"
			/* pe->pattern starts with "/", skip it */
					if (unquote_c_style(&unquoted, line.buf, NULL))
		/* assume we are in a fresh repo, but update the sparse-checkout file */
	struct pattern_list existing;
	struct strbuf buffer = STRBUF_INIT;
static char const * const builtin_sparse_checkout_usage[] = {

static struct sparse_checkout_set_opts {
static struct sparse_checkout_init_opts {
	if (res < 0) {
		if (!strcmp(argv[0], "list"))
	argc = parse_options(argc, argv, NULL,

	char *p = pattern;
	o.dst_index = r->index;
#include "builtin.h"
				strbuf_to_cone_pattern(&line, pl);

	argc = parse_options(argc, argv, prefix,

		if (!hashmap_get_entry(&pl->parent_hashmap, e, ent, NULL))
			insert_recursive_pattern(pl, &buffer);

		return update_working_directory(NULL);
{
}
	struct pattern_list pl;

	static struct option builtin_sparse_checkout_set_options[] = {
	add_pattern(strbuf_detach(&pattern, NULL), empty_base, 0, &pl, 0);
};
	require_clean_work_tree(the_repository,
		if (!hashmap_contains_parent(&pl->recursive_hashmap,
		struct path_pattern *p = pl->patterns[i];
	strbuf_addstr(&pattern, "/*");
	MODE_ALL_PATTERNS = 1,
	git_config_set_in_file_gently(config_path,
			       enum modify_type m)
	struct lock_file lock_file = LOCK_INIT;
	if (result) {
static int sparse_checkout_disable(int argc, const char **argv)
#include "dir.h"
	}

	return 0;
		if (!strcmp(argv[0], "init"))
				    int argc, const char **argv)
				size_t len;
	strbuf_trim_trailing_dir_sep(line);
	}
			fprintf(fp, "/");
		update_working_directory(NULL);
			   strhash(e->pattern));
}

	e->patternlen = path->len;




	struct unpack_trees_options o;
	strbuf_addstr(&match_all, "/*");

				N_("set sparse-checkout patterns"), NULL, 1, 0);
			     PARSE_OPT_STOP_AT_NON_OPTION);
	} else {
		set_config(MODE_NO_PATTERNS);

	free(sparse_filename);
					     pe->pattern,
		core_sparse_checkout_cone = 1;
		    !hashmap_contains_parent(&pl->parent_hashmap,



	free(sparse_filename);
	pl.use_cone_patterns = 0;

		OPT_BOOL(0, "cone", &init_opts.cone_mode,
			   builtin_sparse_checkout_options);

static void add_patterns_cone_mode(int argc, const char **argv,


static void write_cone_to_file(FILE *fp, struct pattern_list *pl)
#include "cache-tree.h"

	}
}

static char *get_sparse_checkout_filename(void)

			     builtin_sparse_checkout_set_usage,
	if (add_patterns_from_file_to_list(sparse_filename, "", 0,
{
			   strihash(e->pattern) :
	return result;

		break;
		strbuf_insertstr(line, 0, "/");
		if (set_opts.use_stdin) {
	int result = 0;
						die(_("unable to unquote C-style string '%s'"),

		return 0;
	if (res >= 0) {
				   strhash(e->pattern));
{
		string_list_sort(&sl);
	result = unpack_trees(1, &t, &o);
	struct object_id oid;
	cache_tree_free(&r->index->cache_tree);
{
		if (!hashmap_contains_parent(&pl->recursive_hashmap,

	};
	argc = parse_options(argc, argv, prefix,
	return 0;
			while (!strbuf_getline(&line, stdin)) {

static int sparse_checkout_list(int argc, const char **argv)
		clear_pattern_list(pl);

int cmd_sparse_checkout(int argc, const char **argv, const char *prefix)
	struct pattern_entry *pe;
#include "resolve-undo.h"
		if (strlen(pattern))

					     &parent_pattern))
	write_patterns_to_file(stdout, &pl);
{
}

	string_list_remove_duplicates(&sl, 0);
	tree = parse_tree_indirect(&oid);

			     builtin_sparse_checkout_init_options,
	N_("git sparse-checkout (set|add) (--stdin | <patterns>)"),

	int i;
	}
		struct strbuf line = STRBUF_INIT;
	char *sparse_filename = get_sparse_checkout_filename();
	add_patterns_from_input(pl, argc, argv);
	memset(&o, 0, sizeof(o));
}

	o.update = 1;
	int mode;
	}
	N_("git sparse-checkout (init|list|set|add|disable) <options>"),
#include "cache.h"
				   ignore_case ?
					strbuf_reset(&unquoted);

				strbuf_addstr(&line, argv[i]);
					   pl, NULL))

	hashmap_init(&pl.parent_hashmap, pl_hashmap_cmp, NULL, 0);
	return set_config(MODE_NO_PATTERNS);

		p++;
	clear_pattern_list(&pl);
}
	memset(&pl, 0, sizeof(pl));
	int i;



	if (pl.use_cone_patterns) {
		}

				if (line.buf[0] == '"') {
static int write_patterns_and_update(struct pattern_list *pl)


	}
		if (core_sparse_checkout_cone)

		return 0;
	};
			struct strbuf unquoted = STRBUF_INIT;

				      mode ? "true" : NULL);
	free(sparse_filename);
	fprintf(fp, "/*\n!/*/\n");
				char *buf = strbuf_detach(&line, &len);

	switch (m) {


	for (i = 0; i < sl.nr; i++) {

			 N_("initialize the sparse-checkout in cone mode")),
			for (i = 0; i < argc; i++)
				      mode == MODE_CONE_PATTERNS ? "true" : NULL);
					     pe->pattern,
		return 1;

	if (core_sparse_checkout_cone)
		if (hashmap_get_entry(&pl->recursive_hashmap, pe, ent, NULL))
	char *sparse_filename;
			hashmap_add(&pl->parent_hashmap, &e->ent);
	init_tree_desc(&t, tree->buffer, tree->size);
	struct repository *r = the_repository;
			string_list_insert(&sl, pe->pattern + 1);

			     builtin_sparse_checkout_init_usage, 0);
		die(_("unable to load existing sparse-checkout patterns"));
		if (slash == e->pattern)
	fd = hold_lock_file_for_update(&lk, sparse_filename,
	while (*p) {

	core_apply_sparse_checkout = 1;

		usage_with_options(builtin_sparse_checkout_usage,
		fp = xfopen(sparse_filename, "w");
	struct pattern_entry *pe;
	case ADD:
		write_locked_index(r->index, &lock_file, COMMIT_LOCK);


	repo_read_index(the_repository);
		hashmap_init(&pl->parent_hashmap, pl_hashmap_cmp, NULL, 0);

			     builtin_sparse_checkout_options,
};
	if (!result) {
			fprintf(fp, "%s/\n!%s/*/\n", pattern, pattern);
	int i;
	res = add_patterns_from_file_to_list(sparse_filename, "", 0, &pl, NULL);
#include "wt-status.h"
#include "parse-options.h"

	if (result && changed_config)

		fclose(fp);
}
	static struct option builtin_sparse_checkout_options[] = {

	for (i = 0; i < pl->nr; i++) {
		fprintf(fp, "%s/\n", pattern);

	struct tree *tree;

enum sparse_checkout_mode {
			break;
	o.skip_sparse_checkout = 0;

		if (p->flags & PATTERN_FLAG_NEGATIVE)
	if (git_config_set_gently("extensions.worktreeConfig", "true")) {

		OPT_BOOL(0, "stdin", &set_opts.use_stdin,
	o.pl = pl;
	fp = xfdopen(fd, "w");
		if (p->flags & PATTERN_FLAG_MUSTBEDIR)
	int use_stdin;

{
static void add_patterns_from_input(struct pattern_list *pl,
			add_patterns_cone_mode(argc, argv, &pl);
				add_pattern(buf, empty_base, 0, pl, 0);
	git_config(git_default_config, NULL);

static char *escaped_pattern(char *pattern)
		warning(_("this worktree is not sparse (sparse-checkout file may not exist)"));
	if (!line->len)

	const char *config_path;
		rollback_lock_file(&lock_file);
		if (!strcmp(argv[0], "disable"))
	struct strbuf pattern = STRBUF_INIT;
static int modify_pattern_list(int argc, const char **argv, enum modify_type m)
	N_("git sparse-checkout init [--cone]"),
	char *sparse_filename;
	int res;
#include "pathspec.h"
		}

	require_clean_work_tree(the_repository,
		char *oldpattern = e->pattern;

enum modify_type {
	memset(&pl, 0, sizeof(pl));
}
	struct lock_file lk = LOCK_INIT;
		free(pattern);
		}
	hashmap_for_each_entry(&pl->recursive_hashmap, &iter, pe, ent) {

						line.buf);


	if (argc == 2 && !strcmp(argv[1], "-h"))
	add_pattern(strbuf_detach(&pattern, NULL), empty_base, 0, &pl, 0);
					     &parent_pattern))
	int cone_mode;

	MODE_NO_PATTERNS = 0,
			}
			die(_("failed to open '%s'"), sparse_filename);
	while (e->patternlen) {
	struct strbuf parent_pattern = STRBUF_INIT;

	repo_read_index(the_repository);
		write_patterns_to_file(fp, pl);
	if (!core_apply_sparse_checkout) {

		}
				strbuf_to_cone_pattern(&line, pl);
		if (is_glob_special(*p))
	fflush(fp);

		die(_("you need to resolve your current index first"));
		OPT_END(),

	struct pattern_list pl;
	struct strbuf match_all = STRBUF_INIT;
	o.keep_pattern_list = !!pl;

	require_clean_work_tree(the_repository,
}
		struct pattern_entry *pe;

}
	pl.use_cone_patterns = core_sparse_checkout_cone;
	}
	static struct option builtin_sparse_checkout_init_options[] = {
static void add_patterns_literal(int argc, const char **argv,
	}
			strbuf_addch(&final, '\\');
	}
	hashmap_add(&pl->recursive_hashmap, &e->ent);
	o.merge = 1;
		return 0;
		core_apply_sparse_checkout = 1;
	NULL

			     PARSE_OPT_KEEP_UNKNOWN);
{
}
	usage_with_options(builtin_sparse_checkout_usage,
			}
	}

				 struct pattern_list *pl)
		FILE *fp;

	int result;
	if (add_patterns_from_file_to_list(sparse_filename, "", 0,
	return result;
			struct strbuf line = STRBUF_INIT;
	memset(&existing, 0, sizeof(existing));

	struct pattern_list pl;
			quote_c_style(sl.items[i].string, NULL, stdout, 0);
	sparse_filename = get_sparse_checkout_filename();
	if (set_config(mode))
	ADD,
	struct strbuf final = STRBUF_INIT;
	string_list_sort(&sl);
{
			for (i = 0; i < argc; i++) {
	parse_tree(tree);

	sparse_filename = get_sparse_checkout_filename();
		char *pattern = escaped_pattern(sl.items[i].string);
		hashmap_for_each_entry(&pl.recursive_hashmap, &iter, pe, ent) {


	NULL

static int update_working_directory(struct pattern_list *pl)
			}
			string_list_insert(&sl, pe->pattern);
};

		e->pattern = xstrndup(oldpattern, newlen);



	strbuf_addstr(&pattern, "!/*/");
}
		prime_cache_tree(r, r->index, tree);

};

	if (update_working_directory(&pl))
		OPT_END(),


		core_apply_sparse_checkout = 1;
	clear_pattern_list(&existing);

			string_list_insert(&sl, pe->pattern);
	if (argc > 0) {
}

}
	strbuf_release(&buffer);
			return sparse_checkout_list(argc, argv);
			   ignore_case ?
		size_t newlen;
	REPLACE,

static const char *empty_base = "";

	string_list_sort(&sl);
	}
		char *pattern = escaped_pattern(sl.items[i].string);
static void strbuf_to_cone_pattern(struct strbuf *line, struct pattern_list *pl)
#include "unpack-trees.h"
		changed_config = 1;
{
		newlen = slash - e->pattern;

	if (safe_create_leading_directories(sparse_filename))
		if (!fp)
}
static int sparse_checkout_set(int argc, const char **argv, const char *prefix,
	clear_pattern_list(&pl);

		e->patternlen = newlen;
	case REPLACE:

			strbuf_release(&unquoted);
	FILE *fp;

{
	memset(&pl, 0, sizeof(pl));
		}

			return sparse_checkout_init(argc, argv);
	strbuf_release(&parent_pattern);
{


		return 0;

	return modify_pattern_list(argc, argv, m);
	add_pattern(strbuf_detach(&match_all, NULL), empty_base, 0, &pl, 0);
{
	} else
			fprintf(fp, "!");
	else
			return sparse_checkout_disable(argc, argv);
		break;
		fprintf(fp, "%s", p->pattern);
static int set_config(enum sparse_checkout_mode mode)
	MODE_CONE_PATTERNS = 2,
		if (set_opts.use_stdin) {
	int res;
			strbuf_reset(&buffer);
			 N_("read patterns from standard in")),
		write_cone_to_file(fp, pl);
				add_pattern(argv[i], empty_base, 0, pl, 0);
		fprintf(fp, "/*\n!/*/\n");
	NULL
	int fd;

		free(sparse_filename);

		die(_("failed to create directory for sparse-checkout file"));
	}


	clear_pattern_list(&pl);

	hashmap_entry_init(&e->ent,


	existing.use_cone_patterns = core_sparse_checkout_cone;
	if (repo_read_index_unmerged(r))
				N_("initialize sparse-checkout"), NULL, 1, 0);
	clear_pattern_list(pl);
static int sparse_checkout_init(int argc, const char **argv)
		} else {
#include "config.h"
	int changed_config = 0;
	memset(&pl, 0, sizeof(pl));
		free(sparse_filename);
			continue;
}
	/* If we already have a sparse-checkout file, use it. */
	if (strbuf_normalize_path(line))
	return write_patterns_and_update(&pl);
		char *slash = strrchr(e->pattern, '/');
	if (get_oid("HEAD", &oid))

	} else
	repo_read_index(the_repository);
	hashmap_for_each_entry(&pl->parent_hashmap, &iter, pe, ent) {
			printf("\n");
	struct object_id oid;
#include "run-command.h"
		for (i = 0; i < sl.nr; i++) {
	return git_pathdup("info/sparse-checkout");
	}

		return;
	struct tree_desc t;
static char const * const builtin_sparse_checkout_set_usage[] = {
	strbuf_trim(line);
		free(sparse_filename);
#include "repository.h"
				      "core.sparseCheckoutCone",

	string_list_remove_duplicates(&sl, 0);


		die(_("could not normalize path %s"), line->buf);
		struct hashmap_iter iter;
		} else {
		e = xmalloc(sizeof(struct pattern_entry));
#include "lockfile.h"
		pl->use_cone_patterns = 1;
} set_opts;
				N_("disable sparse-checkout"), NULL, 1, 0);
	if (core_sparse_checkout_cone) {
#include "strbuf.h"
	add_patterns_from_input(pl, argc, argv);
		if (!hashmap_contains_parent(&pl->recursive_hashmap,
	free(sparse_filename);
{
{
		if (!strcmp(argv[0], "add"))
		die(_("unable to load existing sparse-checkout patterns"));
			while (!strbuf_getline(&line, stdin)) {
		hashmap_init(&pl->recursive_hashmap, pl_hashmap_cmp, NULL, 0);
#include "string-list.h"
					strbuf_swap(&unquoted, &line);
	config_path = git_path("config.worktree");

	o.verbose_update = isatty(2);
		return 1;
	};
static void write_patterns_to_file(FILE *fp, struct pattern_list *pl)
