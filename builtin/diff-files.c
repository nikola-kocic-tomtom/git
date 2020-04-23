	if (!rev.diffopt.output_format)
	    3 < rev.max_count)
	}
			usage(diff_files_usage);
		else if (!strcmp(argv[1], "--theirs"))
	 * Make sure there are NO revision (i.e. pending object) parameter,
		if (!strcmp(argv[1], "--base"))

	 */
			rev.max_count = 2;
 */
	    rev.min_age != -1 || rev.max_age != -1 ||
	if (argc == 2 && !strcmp(argv[1], "-h"))
			rev.max_count = 3;
			rev.max_count = 1;
}
#include "builtin.h"
#include "submodule.h"
static const char diff_files_usage[] =

#include "config.h"
	git_config(git_diff_basic_config, NULL); /* no "diff" UI options */
 * Copyright (C) Linus Torvalds, 2005

/*
"git diff-files [-q] [-0 | -1 | -2 | -3 | -c | --cc] [<common-diff-options>] [<path>...]"
		else
	return diff_result_code(&rev.diffopt, result);
		perror("read_cache_preload");
	/*
		rev.diffopt.output_format = DIFF_FORMAT_RAW;
	 * rev.max_count is reasonable (0 <= n <= 3), and
	unsigned options = 0;

	result = run_diff_files(&rev, options);
COMMON_DIFF_OPTIONS_HELP;
int cmd_diff_files(int argc, const char **argv, const char *prefix)
	 * "diff-files --base -p" should not combine merges because it
#include "cache.h"
 * GIT - The information manager from hell
			options |= DIFF_SILENT_ON_REMOVED;
	repo_init_revisions(the_repository, &rev, prefix);
	if (rev.pending.nr ||
	    (rev.diffopt.output_format & DIFF_FORMAT_PATCH))
	/*
	if (rev.max_count == -1 && !rev.combine_merges &&
#include "diff.h"
	precompose_argv(argc, argv);
	argc = setup_revisions(argc, argv, &rev, NULL);
#include "commit.h"

	 * was not asked to.  "diff-files -c -p" should not densify
#include "revision.h"
	 * (the user should ask with "diff-files --cc" explicitly).
		usage(diff_files_usage);
	while (1 < argc && argv[1][0] == '-') {
		argv++; argc--;

	int result;

	rev.abbrev = 0;
		else if (!strcmp(argv[1], "-q"))
{
	struct rev_info rev;
	 */
	if (read_cache_preload(&rev.diffopt.pathspec) < 0) {
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		return -1;
		usage(diff_files_usage);
	 * there is no other revision filtering parameters.

 *
		else if (!strcmp(argv[1], "--ours"))
		rev.combine_merges = rev.dense_combined_merges = 1;
	}
