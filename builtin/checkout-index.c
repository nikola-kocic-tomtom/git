		fputs(topath[checkout_stage], stdout);
			N_("copy out the files from named stage"),
	 */
			N_("read list of paths from the standard input")),
	int read_from_stdin = 0;
			builtin_checkout_index_usage, 0);
				if (unquote_c_style(&unquoted, buf.buf, NULL))
	/* Check out named files first */
	state.not_new = not_new;

	 * when --prefix is specified we do not want to update cache.
	int pos = cache_name_pos(name, namelen);
		pos++;
	if (all)
		free(p);
 * Copyright (C) 2005 Linus Torvalds
		}
	if (pos < 0)
	} else {
			fprintf(stderr, "does not exist at stage %d",
			 N_("update stat information in the index file")),
		if (ce_stage(ce) != checkout_stage
		p = prefix_path(prefix, prefix_length, arg);
	if (errs)
		fprintf(stderr, "git checkout-index: %s ", name);
		if (ce_namelen(ce) != namelen ||
	return 0;
#include "config.h"
	int errs = 0;
			continue;
			break;
			errs++;

		OPT__QUIET(&quiet,
			die("git checkout-index: don't mix '--stdin' and explicit filenames");
#define CHECKOUT_ALL 4
		if (prefix && *prefix &&
	} else
#include "lockfile.h"
	BUG_ON_OPT_NEG(unset);
		state.base_dir = "";
static int checkout_stage; /* default to checkout stage0 */
			if (ce_namelen(last_ce) != ce_namelen(ce)
				checkout_stage);
		struct strbuf buf = STRBUF_INIT;
static int to_tempfile;
static char topath[4][TEMPORARY_FILENAME_LENGTH + 1];
	if (argc == 2 && !strcmp(argv[1], "-h"))
		    memcmp(ce->name, name, namelen))
	N_("git checkout-index [<options>] [--] [<file>...]"),
 *


		exit(128);
		else if (checkout_stage)
	while (pos < active_nr) {
	if (is_lock_file_locked(&lock_file) &&
			char *p;
	return -1;
		 * exit with the same code as die().
	if (!state.quiet) {
		     memcmp(prefix, ce->name, prefix_length)))
		if (ce_stage(ce) != checkout_stage
	state.quiet = quiet;
static int nul_term_line;
	}


			N_("paths are separated with NUL character")),

}
		strbuf_release(&buf);

	int i;
	int namelen = strlen(name);

			die("git checkout-index: don't mix '--all' and explicit filenames");
		strbuf_release(&unquoted);
	NULL
			continue;
				   to_tempfile ? topath[ce_stage(ce)] : NULL,
				putchar('.');
		if ('1' <= ch && ch <= '3')
		checkout_stage = CHECKOUT_ALL;
			N_("check out all files in the index")),
	int force = 0, quiet = 0, not_new = 0;
		checkout_file(p, prefix);
			die("git checkout-index: don't mix '--all' and '--stdin'");
	if (did_checkout) {
		int ch = arg[0];
				   nul_term_line ? '\0' : '\n');

		OPT_BOOL(0, "stdin", &read_from_stdin,
					die("line is badly quoted");
			if (i > 1)
	argc = parse_options(argc, argv, prefix, builtin_checkout_index_options,
	state.base_dir_len = strlen(state.base_dir);
			      const char *arg, int unset)
	int has_same_name = 0;
	int did_checkout = 0;
		has_same_name = 1;
	    write_locked_index(&the_index, &lock_file, COMMIT_LOCK))
		    && (CHECKOUT_ALL != checkout_stage || !ce_stage(ce)))
			write_tempfile_record(name, prefix);
	}
			    || memcmp(last_ce->name, ce->name, ce_namelen(ce)))
		strbuf_getline_fn getline_fn;
				write_tempfile_record(last_ce->name, prefix);
#include "cache-tree.h"

			}
		OPT_STRING(0, "prefix", &state.base_dir, N_("string"),
		write_tempfile_record(last_ce->name, prefix);
		if (checkout_entry(ce, &state,
		OPT_BOOL('a', "all", &all,
		OPT_BOOL('n', "no-create", &not_new,
		else
		if (all)
			checkout_file(p, prefix);
			N_("write the content to temporary files")),
	git_config(git_default_config, NULL);

#include "builtin.h"

		OPT_END()
	state.force = force;
			free(p);
		const char *arg = argv[i];
			continue;


		topath[i][0] = 0;
		hold_locked_index(&lock_file, LOCK_DIE_ON_ERROR);
	}
		state.refresh_cache = 1;
		{ OPTION_CALLBACK, 0, "stage", NULL, "(1|2|3|all)",
	if (read_from_stdin) {
	write_name_quoted_relative(name, prefix, stdout,
		    && (CHECKOUT_ALL != checkout_stage || !ce_stage(ce)))
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		struct cache_entry *ce = active_cache[pos];
static void checkout_all(const char *prefix, int prefix_length)
		did_checkout = 1;
}
		OPT_BOOL('u', "index", &index_opt,
		state.istate = &the_index;
};
	}
	if (!strcmp(arg, "all")) {
		if (last_ce && to_tempfile) {
{
int cmd_checkout_index(int argc, const char **argv, const char *prefix)
	}
		checkout_all(prefix, prefix_length);
	prefix_length = prefix ? strlen(prefix) : 0;

		for (i = 1; i < 4; i++) {
{
{

static void write_tempfile_record(const char *name, const char *prefix)
	for (i = 0; i < 4; i++) {
		if (checkout_entry(ce, &state,
	putchar('\t');
				   NULL) < 0)

		usage_with_options(builtin_checkout_index_usage,
		if (read_from_stdin)
}
				strbuf_swap(&buf, &unquoted);

		OPT__FORCE(&force, N_("force overwrite of existing files"), 0),
		die("Unable to write new index file");
		/* we have already done our error reporting.
		char *p;
/*
		pos = -pos - 1;
}

	if (CHECKOUT_ALL == checkout_stage) {
		if (to_tempfile)
		 */
{
		OPT_BOOL(0, "temp", &to_tempfile,

			if (!nul_term_line && buf.buf[0] == '"') {

	struct cache_entry *last_ce = NULL;
		    (ce_namelen(ce) <= prefix_length ||
		to_tempfile = 1;
#include "parse-options.h"
	struct option builtin_checkout_index_options[] = {
static struct checkout state = CHECKOUT_INIT;
		getline_fn = nul_term_line ? strbuf_getline_nul : strbuf_getline_lf;

static const char * const builtin_checkout_index_usage[] = {
			die(_("stage should be between 1 and 3 or all"));
				   to_tempfile ? topath[ce_stage(ce)] : NULL,
				   NULL) < 0)
			errs++;
	if (index_opt && !state.base_dir_len && !to_tempfile) {
	if (read_cache() < 0) {
			checkout_stage = arg[0] - '0';
#include "quote.h"
		return errs > 0 ? -1 : 0;

		fputc('\n', stderr);
			fprintf(stderr, "is not in the cache");
		if (!has_same_name)
static int checkout_file(const char *name, const char *prefix)

{
	struct lock_file lock_file = LOCK_INIT;
				fputs(topath[i], stdout);
	int i, errs = 0;
}
			PARSE_OPT_NONEG, option_parse_stage },
 *
				strbuf_reset(&unquoted);
		if (all)
	for (i = 0; i < argc; i++) {
			else
	}
				putchar(' ');
	}
	int index_opt = 0;
	if (!state.base_dir)
	}
	int i;
		last_ce = ce;
	int all = 0;
	}
	};
	int prefix_length;

		die("invalid cache");

			N_("don't checkout new files")),
 * Check-out files from the "current cache directory"
	for (i = 0; i < active_nr ; i++) {
				   builtin_checkout_index_options);
	if (last_ce && to_tempfile)
		}
		struct cache_entry *ce = active_cache[i];
		struct strbuf unquoted = STRBUF_INIT;
			N_("when creating files, prepend <string>")),
	}

	/*
static int option_parse_stage(const struct option *opt,
			p = prefix_path(prefix, prefix_length, buf.buf);
	return 0;
		else
			fprintf(stderr, "is unmerged");
	state.istate = &the_index;
			if (topath[i][0])
 */
		}
			N_("no warning for existing files and files not in index")),
		OPT_BOOL('z', NULL, &nul_term_line,

		while (getline_fn(&buf, stdin) != EOF) {
