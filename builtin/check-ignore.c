	}
#include "quote.h"
	clear_directory(&dir);
			fprintf(stderr, "no pathspec given.\n");
				       pattern->srcpos,
		if (argc > 0)
			else
};
		return 0;
			output_pattern(pathspec.items[i].original, pattern);
	 * irrelevant.

			die(_("cannot specify pathnames with --stdin"));
			int dtype = DT_UNKNOWN;
	}
	 */
	setup_standard_excludes(&dir);
	return num_ignored;
	 * 'git status', 'git add' etc.
			write_name_quoted(path, stdout, '\n');
	struct strbuf unquoted = STRBUF_INIT;
		if (argc == 0)

				printf("%s%c%d%c%s%s%s%c%s%c",

		 N_("show non-matching input paths")),
		maybe_flush_or_die(stdout, "check-ignore to stdout");
}

		num_ignored += check_ignore(dir, prefix,

static const char * const check_ignore_usage[] = {
			quote_c_style(path, NULL, stdout, 0);
	 * look for pathspecs matching entries in the index, since these
		if (nul_term_line)
	if (!argc) {
	OPT_GROUP(""),
	if (!no_index && read_cache() < 0)
	} else {
				quote_c_style(pattern->pl->src, NULL, stdout, 0);

	OPT_BOOL('z', NULL, &nul_term_line,
	die_path_inside_submodule(&the_index, &pathspec);
		if (argc > 1)
	while (getline_fn(&buf, stdin) != EOF) {
static int check_ignore(struct dir_struct *dir,
	strbuf_release(&unquoted);
	argc = parse_options(argc, argv, prefix, check_ignore_options,
static int nul_term_line;
		pattern = NULL;
	} else {
	/*
		if (!verbose) {
	OPT__QUIET(&quiet, N_("suppress progress reporting")),
		if (verbose)
	int num_ignored;
	 */
	struct strbuf buf = STRBUF_INIT;
	char *pathspec[2] = { NULL, NULL };
			}

				printf("%c%c%c%s%c", '\0', '\0', '\0', path, '\0');

NULL

			die(_("no path specified"));
		       PATHSPEC_KEEP_ORDER,
		if (!quiet)
	}

{
	const char *full_path;
"git check-ignore [<options>] --stdin",
static void output_pattern(const char *path, struct path_pattern *pattern)
	 * should not be ignored, in order to be consistent with

	/*
		die(_("--non-matching is only valid with --verbose"));
#include "parse-options.h"
			else {
			if (pattern)
#include "pathspec.h"
				die("line is badly quoted");
				       pattern->pl->src, '\0',
		       prefix, argv);
	char *seen;
	OPT_BOOL(0, "stdin", &stdin_paths,

	if (stdin_paths) {

	for (i = 0; i < pathspec.nr; i++) {
			if (unquote_c_style(&unquoted, buf.buf, NULL))
"git check-ignore [<options>] <pathname>...",
		       PATHSPEC_SYMLINK_LEADING_PATH |
		maybe_flush_or_die(stdout, "ignore to stdout");
			num_ignored++;
	if (stdin_paths) {
				       pattern->srcpos, '\0',
	}
			die(_("-z only makes sense with --stdin"));
	seen = find_pathspecs_matching_against_index(&pathspec, &the_index);
	int num_ignored = 0, i;
	char *slash = (pattern && pattern->flags & PATTERN_FLAG_MUSTBEDIR) ? "/" : "";

				       bang, pattern->pattern, slash, '\0',
			pattern = last_matching_pattern(dir, &the_index,
		 N_("read file names from stdin")),
#include "submodule.h"
	char *bang  = (pattern && pattern->flags & PATTERN_FLAG_NEGATIVE)  ? "!" : "";
	}
#define USE_THE_INDEX_COMPATIBILITY_MACROS
}
	free(seen);
#include "cache.h"
				       path, '\0');
		} else {
	OPT_BOOL('n', "non-matching", &show_non_matching,
	return num_ignored;
		}
	/* read_cache() is only necessary so we can watch out for submodules. */
				printf(":%d:%s%s%s\t",
				pattern = NULL;
			if (!verbose && pattern &&
	git_config(git_default_config, NULL);
int cmd_check_ignore(int argc, const char **argv, const char *prefix)

		die(_("index file corrupt"));
		if (!seen[i]) {
	if (!nul_term_line) {

#include "dir.h"
	strbuf_getline_fn getline_fn;
	OPT_BOOL(0, "no-index", &no_index,
		num_ignored = check_ignore(&dir, prefix, argc, argv);
	return !num_ignored;
				printf("::\t");
	 * check-ignore just needs paths. Magic beyond :/ is really
		}
	} else {
static int quiet, verbose, stdin_paths, show_non_matching, no_index;
				       bang, pattern->pattern, slash);
			const char *prefix, int argc, const char **argv)
	}
		pathspec[0] = buf.buf;
		if (!verbose) {
		 N_("terminate input and output records by a NUL character")),
			strbuf_swap(&buf, &unquoted);
{
		} else {

	strbuf_release(&buf);
					    1, (const char **)pathspec);

	getline_fn = nul_term_line ? strbuf_getline_nul : strbuf_getline_lf;
	memset(&dir, 0, sizeof(dir));
{
	struct path_pattern *pattern;
	}
};
static const struct option check_ignore_options[] = {
		full_path = pathspec.items[i].match;
#include "builtin.h"
		if (!nul_term_line && buf.buf[0] == '"') {
{
	if (show_non_matching && !verbose)
#include "config.h"
		 N_("ignore index when checking")),


			strbuf_reset(&unquoted);
	OPT__VERBOSE(&verbose, N_("be verbose")),
	int num_ignored = 0;
			die(_("--quiet is only valid with a single pathname"));

			     check_ignore_usage, 0);
			die(_("cannot have both --quiet and --verbose"));
}
							full_path, &dtype);
		if (pattern)
		}
			fputc('\n', stdout);
			if (pattern) {
	if (quiet) {
static int check_ignore_stdin_paths(struct dir_struct *dir, const char *prefix)
			printf("%s%c", path, '\0');
		if (!quiet && (pattern || show_non_matching))
}
			    pattern->flags & PATTERN_FLAG_NEGATIVE)
		}
			}
		num_ignored = check_ignore_stdin_paths(&dir, prefix);
	struct pathspec pathspec;
		       PATHSPEC_ALL_MAGIC & ~PATHSPEC_FROMTOP,
	struct dir_struct dir;
	OPT_END()
	parse_pathspec(&pathspec,
