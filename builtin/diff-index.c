	int i;
		if (!strcmp(arg, "--cached"))
	git_config(git_diff_basic_config, NULL); /* no "diff" UI options */
	    rev.max_count != -1 || rev.min_age != -1 || rev.max_age != -1)
	}
#include "commit.h"

			return -1;
{
		const char *arg = argv[i];
	repo_init_revisions(the_repository, &rev, prefix);
	result = run_diff_index(&rev, cached);
#define USE_THE_INDEX_COMPATIBILITY_MACROS
		return -1;
	argc = setup_revisions(argc, argv, &rev, NULL);
#include "diff.h"

int cmd_diff_index(int argc, const char **argv, const char *prefix)
	rev.abbrev = 0;
	struct rev_info rev;
	 * and there is no revision filtering parameters.

#include "builtin.h"
		rev.diffopt.output_format = DIFF_FORMAT_RAW;
		if (read_cache_preload(&rev.diffopt.pathspec) < 0) {
}
#include "submodule.h"
	if (argc == 2 && !strcmp(argv[1], "-h"))
"git diff-index [-m] [--cached] "
#include "cache.h"
			cached = 1;

	if (!cached) {
			usage(diff_cache_usage);
	 * Make sure there is one revision (i.e. pending object),
	int cached = 0;
		}
		setup_work_tree();
"[<common-diff-options>] <tree-ish> [<path>...]"
#include "config.h"
	for (i = 1; i < argc; i++) {

	UNLEAK(rev);
	/*
static const char diff_cache_usage[] =
#include "revision.h"
		perror("read_cache");
	if (!rev.diffopt.output_format)
		usage(diff_cache_usage);
COMMON_DIFF_OPTIONS_HELP;
	 */
	}
	precompose_argv(argc, argv);
		usage(diff_cache_usage);
	} else if (read_cache() < 0) {

		else
	return diff_result_code(&rev.diffopt, result);
	if (rev.pending.nr != 1 ||
			perror("read_cache_preload");

	int result;
