		break;
	NULL
	struct object_id oid;
			   N_("write tree object for a subdirectory <prefix>")),
		break;
 * Copyright (C) Linus Torvalds, 2005
		die("%s: prefix %s not found", me, tree_prefix);
		OPT_STRING(0, "prefix", &tree_prefix, N_("<prefix>/"),
		die("%s: error reading the index", me);
		  N_("only useful for debugging"),
	case WRITE_TREE_UNREADABLE_INDEX:
		OPT_END()
	return ret;
			WRITE_TREE_MISSING_OK),
		printf("%s\n", oid_to_hex(&oid));
	case WRITE_TREE_UNMERGED_INDEX:
/*
	};
		{ OPTION_BIT, 0, "ignore-cache-tree", &flags, NULL,
int cmd_write_tree(int argc, const char **argv, const char *cmd_prefix)
	struct option write_tree_options[] = {
	argc = parse_options(argc, argv, cmd_prefix, write_tree_options,
		break;
		die("%s: error building trees", me);
 * GIT - The information manager from hell
			     write_tree_usage, 0);
	switch (ret) {
#include "config.h"
	const char *tree_prefix = NULL;
		  WRITE_TREE_IGNORE_CACHE_TREE },
	const char *me = "git-write-tree";
{
}
#include "tree.h"
	N_("git write-tree [--missing-ok] [--prefix=<prefix>/]"),
	case WRITE_TREE_PREFIX_ERROR:
	int flags = 0, ret;
#define USE_THE_INDEX_COMPATIBILITY_MACROS
};
	ret = write_cache_as_tree(&oid, flags, tree_prefix);
		break;
 *
		  PARSE_OPT_HIDDEN | PARSE_OPT_NOARG, NULL,
#include "parse-options.h"

static const char * const write_tree_usage[] = {
		OPT_BIT(0, "missing-ok", &flags, N_("allow missing objects"),
#include "builtin.h"
#include "cache-tree.h"

 */

	git_config(git_default_config, NULL);

#include "cache.h"
	}
	case 0:
