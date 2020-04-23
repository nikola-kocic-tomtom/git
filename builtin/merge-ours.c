 * Copyright (c) 2007 Thomas Harning Jr
 * Original:
/*
		usage(builtin_merge_ours_usage);
 * Pretend we resolved the heads, but declare our tree trumps everybody else.
	 * through.
	 * The contents of the current index becomes the tree we
 */
	"git merge-ours <base>... -- HEAD <remote>...";
#include "diff.h"
	if (read_cache() < 0)
 * Original Copyright (c) 2005 Junio C Hamano
}
	 * commit.  The index must match HEAD, or this merge cannot go


		die_errno("read_cache failed");
		exit(2);
	if (index_differs_from(the_repository, "HEAD", NULL, 0))
#define USE_THE_INDEX_COMPATIBILITY_MACROS
	 */
 * Implementation of git-merge-ours.sh as builtin
	exit(0);
#include "builtin.h"
	/*
	if (argc == 2 && !strcmp(argv[1], "-h"))
#include "git-compat-util.h"
static const char builtin_merge_ours_usage[] =
int cmd_merge_ours(int argc, const char **argv, const char *prefix)

{
 *
 *
