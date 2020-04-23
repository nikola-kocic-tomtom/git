		argv_array_push(&args, argv[i]);

	argv_array_pushl(&args, "annotate", "-c", NULL);
/*
	return cmd_blame(args.argc, args.argv, prefix);


 * "git annotate" builtin alias
	}
	int i;
int cmd_annotate(int argc, const char **argv, const char *prefix)
#include "git-compat-util.h"
	struct argv_array args = ARGV_ARRAY_INIT;

 * Copyright (C) 2006 Ryan Anderson
{
#include "argv-array.h"
 *
	for (i = 1; i < argc; i++) {
#include "builtin.h"
}
 */
