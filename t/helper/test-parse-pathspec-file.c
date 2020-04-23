	clear_pathspec(&pathspec);
		OPT_END()
		printf("%s\n", pathspec.items[i].original);

	for (i = 0; i < pathspec.nr; i++)
	static const char *const usage[] = {
#include "gettext.h"
{
		OPT_PATHSPEC_FILE_NUL(&pathspec_file_nul),
	int pathspec_file_nul = 0, i;

		"test-tool parse-pathspec-file --pathspec-from-file [--pathspec-file-nul]",
#include "pathspec.h"
}
	};

	};
int cmd__parse_pathspec_file(int argc, const char **argv)
	parse_pathspec_file(&pathspec, 0, 0, 0, pathspec_from_file,

		OPT_PATHSPEC_FROM_FILE(&pathspec_from_file),


	struct option options[] = {
		NULL

#include "parse-options.h"
	struct pathspec pathspec;
	return 0;
			    pathspec_file_nul);
#include "test-tool.h"
	const char *pathspec_from_file = 0;
	parse_options(argc, argv, 0, options, usage, 0);
